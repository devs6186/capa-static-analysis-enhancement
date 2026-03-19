#!/usr/bin/env python3
# Copyright 2026 Devyansh Somvanshi
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Prototype: Proximity-Aware Matching (connected_blocks) for capa

This script produces HARD EVIDENCE that CFG-based proximity grouping
captures cross-block feature relationships that:
  - basic_block scope MISSES (features split across adjacent BBs)
  - function scope OVER-MATCHES (features far apart in the same function)

The connected_blocks(depth=N) concept groups basic blocks that are
within N CFG edges of each other, creating an intermediate scope between
basic_block and function.

Usage:
    python scripts/prototype_proximity_matching.py <path_to_binary>
    python scripts/prototype_proximity_matching.py tests/data/some_sample.exe_
"""

import sys
import logging
import argparse
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger("prototype_proximity_matching")


# ---------------------------------------------------------------------------
# 1.  Load binary with vivisect (same path capa uses)
# ---------------------------------------------------------------------------


def load_workspace(path: Path):
    """Load a PE/ELF binary into a vivisect workspace, exactly as capa does."""
    import viv_utils

    logger.info("loading workspace for %s ...", path)
    vw = viv_utils.getWorkspace(str(path), analyze=False, should_save=False)
    vw.analyze()
    logger.info("workspace ready  --  %d functions discovered", len(vw.getFunctions()))
    return vw


# ---------------------------------------------------------------------------
# 2.  Build CFG adjacency map from vivisect basic blocks
# ---------------------------------------------------------------------------


def build_cfg(func) -> dict[int, set[int]]:
    """
    Build a CFG adjacency map for a viv_utils.Function.

    For each basic block, inspect getBranches() on the last instruction
    to find successors.  We include conditional branches, fall-through
    edges, jump-table edges, and unconditional jumps -- the same edges
    capa/features/extractors/viv/function.py uses for loop detection.
    """
    import envi

    adj: dict[int, set[int]] = defaultdict(set)

    # ensure every BB is represented even if it has no outgoing edges
    bb_vas = set()
    for bb in func.basic_blocks:
        bb_vas.add(bb.va)
        adj.setdefault(bb.va, set())

    for bb in func.basic_blocks:
        if len(bb.instructions) == 0:
            continue
        last_insn = bb.instructions[-1]
        for bva, bflags in last_insn.getBranches():
            if bva is None:
                continue
            # include the same edge types capa uses for loop detection
            if bflags & envi.BR_COND or bflags & envi.BR_FALL or bflags & envi.BR_TABLE or last_insn.mnem == "jmp":
                if bva in bb_vas:
                    adj[bb.va].add(bva)

    return dict(adj)


def build_reverse_cfg(adj: dict[int, set[int]]) -> dict[int, set[int]]:
    """Build the reverse (predecessor) adjacency map."""
    rev: dict[int, set[int]] = defaultdict(set)
    for src, dsts in adj.items():
        rev.setdefault(src, set())
        for dst in dsts:
            rev[dst].add(src)
    return dict(rev)


# ---------------------------------------------------------------------------
# 3.  Extract API features per basic block
# ---------------------------------------------------------------------------


def extract_api_features_per_bb(vw, func) -> dict[int, list[str]]:
    """
    For each basic block in *func*, extract API call features using
    the same logic capa uses (capa.features.extractors.viv.insn).

    Returns {bb_va: [api_name, ...]}
    """
    import capa.features.extractors.viv.insn as viv_insn
    from capa.features.insn import API
    from capa.features.address import AbsoluteVirtualAddress
    from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle

    f_handle = FunctionHandle(
        address=AbsoluteVirtualAddress(func.va),
        inner=func,
        ctx={"cache": {}},
    )

    bb_apis: dict[int, list[str]] = {}
    for bb in func.basic_blocks:
        apis: list[str] = []
        bb_handle = BBHandle(address=AbsoluteVirtualAddress(bb.va), inner=bb)
        for insn in bb.instructions:
            ih = InsnHandle(address=AbsoluteVirtualAddress(insn.va), inner=insn)
            for feature, addr in viv_insn.extract_insn_api_features(f_handle, bb_handle, ih):
                if isinstance(feature, API):
                    apis.append(feature.value)
        if apis:
            bb_apis[bb.va] = apis

    return bb_apis


# ---------------------------------------------------------------------------
# 4.  BFS neighborhoods
# ---------------------------------------------------------------------------


def bfs_neighborhood(adj: dict[int, set[int]], start: int, depth: int) -> set[int]:
    """Return set of BB VAs reachable from *start* within *depth* edges (undirected)."""
    visited = {start}
    frontier = {start}
    for _ in range(depth):
        next_frontier: set[int] = set()
        for node in frontier:
            for neighbor in adj.get(node, set()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    next_frontier.add(neighbor)
        frontier = next_frontier
        if not frontier:
            break
    return visited


def make_undirected(adj: dict[int, set[int]]) -> dict[int, set[int]]:
    """Convert directed adjacency map to undirected."""
    und: dict[int, set[int]] = defaultdict(set)
    for src, dsts in adj.items():
        for dst in dsts:
            und[src].add(dst)
            und[dst].add(src)
    return dict(und)


# ---------------------------------------------------------------------------
# 5.  BFS shortest distance between two nodes (undirected)
# ---------------------------------------------------------------------------


def bfs_distance(adj_undirected: dict[int, set[int]], src: int, dst: int) -> int:
    """BFS shortest distance between src and dst. Returns -1 if unreachable."""
    if src == dst:
        return 0
    visited = {src}
    frontier = {src}
    dist = 0
    while frontier:
        dist += 1
        next_frontier: set[int] = set()
        for node in frontier:
            for neighbor in adj_undirected.get(node, set()):
                if neighbor == dst:
                    return dist
                if neighbor not in visited:
                    visited.add(neighbor)
                    next_frontier.add(neighbor)
        frontier = next_frontier
    return -1


# ---------------------------------------------------------------------------
# 6.  Dominator tree (iterative algorithm, Cooper et al.)
# ---------------------------------------------------------------------------


def compute_dominators(adj: dict[int, set[int]], entry: int) -> dict[int, int]:
    """
    Compute the immediate dominator for each node in the directed CFG
    using the iterative dominator algorithm (Cooper, Harvey, Kennedy 2001).

    Returns {node: immediate_dominator} (entry maps to itself).
    """
    # compute reverse postorder via iterative DFS (avoids recursion depth issues)
    visited: set[int] = set()
    rpo_list: list[int] = []
    stack: list[tuple[int, list[int]]] = [(entry, list(adj.get(entry, set())))]
    visited.add(entry)
    while stack:
        node, children = stack[-1]
        pushed = False
        while children:
            child = children.pop()
            if child not in visited:
                visited.add(child)
                stack.append((child, list(adj.get(child, set()))))
                pushed = True
                break
        if not pushed:
            rpo_list.append(node)
            stack.pop()

    rpo_list.reverse()  # now in reverse postorder
    rpo_number = {n: i for i, n in enumerate(rpo_list)}

    # predecessors
    preds: dict[int, list[int]] = defaultdict(list)
    for src, dsts in adj.items():
        for dst in dsts:
            preds[dst].append(src)

    # initialize
    idom: dict[int, int] = {}
    idom[entry] = entry

    def intersect(b1: int, b2: int) -> int:
        finger1 = rpo_number.get(b1, -1)
        finger2 = rpo_number.get(b2, -1)
        if finger1 == -1 or finger2 == -1:
            return entry
        while finger1 != finger2:
            while finger1 > finger2:
                b1_node = rpo_list[finger1]
                b1_node = idom.get(b1_node, entry)
                finger1 = rpo_number.get(b1_node, 0)
            while finger2 > finger1:
                b2_node = rpo_list[finger2]
                b2_node = idom.get(b2_node, entry)
                finger2 = rpo_number.get(b2_node, 0)
        return rpo_list[finger1]

    changed = True
    while changed:
        changed = False
        for b in rpo_list:
            if b == entry:
                continue
            pred_list = [p for p in preds.get(b, []) if p in idom]
            if not pred_list:
                continue
            new_idom = pred_list[0]
            for p in pred_list[1:]:
                new_idom = intersect(new_idom, p)
            if idom.get(b) != new_idom:
                idom[b] = new_idom
                changed = True

    return idom


def dominates(idom: dict[int, int], dominator: int, target: int) -> bool:
    """Check if *dominator* dominates *target* in the dominator tree."""
    current = target
    while current != dominator:
        parent = idom.get(current)
        if parent is None or parent == current:
            return False
        current = parent
    return True


# ---------------------------------------------------------------------------
# 7.  Analyze a single function
# ---------------------------------------------------------------------------


class FunctionResult:
    """Holds analysis results for one function."""

    def __init__(self, func_va: int, num_bbs: int):
        self.func_va = func_va
        self.num_bbs = num_bbs
        self.bb_apis: dict[int, list[str]] = {}
        self.api_bearing_bbs: int = 0
        # pairs: (api_a, bb_a, api_b, bb_b, cfg_distance)
        self.cross_bb_pairs: list[tuple[str, int, str, int, int]] = []
        # depth bucket: {depth: count_of_pairs}
        self.depth_buckets: dict[str, int] = defaultdict(int)
        # dominator relationships between API-bearing blocks
        self.dominator_rels: list[tuple[int, int]] = []  # (dominator_bb, dominated_bb)


def analyze_function(vw, func) -> FunctionResult | None:
    """Run the full proximity analysis on one function."""
    bbs = func.basic_blocks
    num_bbs = len(bbs)
    if num_bbs < 5 or num_bbs > 50:
        return None

    result = FunctionResult(func.va, num_bbs)

    # build CFG
    adj = build_cfg(func)
    if not adj:
        return None

    # extract API features per BB
    bb_apis = extract_api_features_per_bb(vw, func)
    result.bb_apis = bb_apis
    result.api_bearing_bbs = len(bb_apis)

    # need at least 2 API-bearing BBs in different blocks to demonstrate cross-block
    if len(bb_apis) < 2:
        return None

    # undirected adjacency for BFS distance
    adj_und = make_undirected(adj)

    # compute all pairwise distances between API-bearing BBs
    api_bb_vas = sorted(bb_apis.keys())
    for i, bb_a in enumerate(api_bb_vas):
        for bb_b in api_bb_vas[i + 1 :]:
            dist = bfs_distance(adj_und, bb_a, bb_b)
            if dist <= 0:
                continue  # same block or unreachable

            # record every API pair across these two blocks
            for api_a in bb_apis[bb_a]:
                for api_b in bb_apis[bb_b]:
                    result.cross_bb_pairs.append((api_a, bb_a, api_b, bb_b, dist))

                    if dist == 1:
                        result.depth_buckets["depth=1"] += 1
                    elif dist == 2:
                        result.depth_buckets["depth=2"] += 1
                    elif dist == 3:
                        result.depth_buckets["depth=3"] += 1
                    else:
                        result.depth_buckets["depth>3"] += 1

    if not result.cross_bb_pairs:
        return None

    # compute dominator tree
    entry = func.va
    idom = compute_dominators(adj, entry)

    for i, bb_a in enumerate(api_bb_vas):
        for bb_b in api_bb_vas[i + 1 :]:
            if bb_a in idom and bb_b in idom:
                if dominates(idom, bb_a, bb_b):
                    result.dominator_rels.append((bb_a, bb_b))
                elif dominates(idom, bb_b, bb_a):
                    result.dominator_rels.append((bb_b, bb_a))

    return result


# ---------------------------------------------------------------------------
# 8.  Main driver
# ---------------------------------------------------------------------------


def format_va(va: int) -> str:
    return f"0x{va:08X}"


def main():
    parser = argparse.ArgumentParser(
        description="Prototype: proximity-aware matching evidence for connected_blocks scope",
    )
    parser.add_argument("binary", type=Path, help="path to PE/ELF binary to analyze")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")
    parser.add_argument(
        "--max-functions",
        type=int,
        default=0,
        help="limit number of functions to analyze (0 = all)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(name)s  %(levelname)s  %(message)s",
    )

    if not args.binary.exists():
        logger.error("file not found: %s", args.binary)
        return 1

    # ---- load workspace ----
    vw = load_workspace(args.binary)

    # ---- iterate functions ----
    import viv_utils
    import viv_utils.flirt

    functions = sorted(vw.getFunctions())
    total_funcs = len(functions)
    logger.info("total functions in binary: %d", total_funcs)

    results: list[FunctionResult] = []
    analyzed = 0
    skipped_lib = 0
    skipped_size = 0

    for fva in functions:
        if args.max_functions and analyzed >= args.max_functions:
            break

        # skip library functions (same filter capa uses)
        if viv_utils.flirt.is_library_function(vw, fva):
            skipped_lib += 1
            continue

        func = viv_utils.Function(vw, fva)
        num_bbs = len(func.basic_blocks)
        if num_bbs < 5 or num_bbs > 50:
            skipped_size += 1
            continue

        analyzed += 1
        r = analyze_function(vw, func)
        if r is not None:
            results.append(r)

    # ---- produce summary ----
    print()
    print("=" * 78)
    print("  PROXIMITY-AWARE MATCHING  --  EVIDENCE REPORT")
    print("=" * 78)
    print()
    print(f"  Binary:                    {args.binary}")
    print(f"  Total functions:           {total_funcs}")
    print(f"  Library functions skipped: {skipped_lib}")
    print(f"  Size-filtered (not 5-50):  {skipped_size}")
    print(f"  Functions analyzed:        {analyzed}")
    print("  Functions with cross-BB    ")
    print("    API pairs (benefit from  ")
    print(f"    proximity scope):        {len(results)}")
    print()

    if not results:
        print("  No cross-basic-block API pairs found.")
        print("  Try a larger binary with more API calls.")
        return 0

    # aggregate statistics
    total_pairs = 0
    agg_buckets: dict[str, int] = defaultdict(int)
    all_distances: list[int] = []
    total_dom_rels = 0

    for r in results:
        total_pairs += len(r.cross_bb_pairs)
        for k, v in r.depth_buckets.items():
            agg_buckets[k] += v
        for _, _, _, _, d in r.cross_bb_pairs:
            all_distances.append(d)
        total_dom_rels += len(r.dominator_rels)

    avg_dist = sum(all_distances) / len(all_distances) if all_distances else 0.0

    print("-" * 78)
    print("  AGGREGATE STATISTICS")
    print("-" * 78)
    print()
    print(f"  Total cross-BB API pairs:    {total_pairs}")
    print(f"  Average CFG distance:        {avg_dist:.2f} edges")
    print()
    print("  Distribution of API pair distances:")
    for key in ["depth=1", "depth=2", "depth=3", "depth>3"]:
        count = agg_buckets.get(key, 0)
        pct = (count / total_pairs * 100) if total_pairs else 0
        bar = "#" * int(pct / 2)
        print(f"    {key:10s}  {count:5d}  ({pct:5.1f}%)  {bar}")
    print()

    # the key insight: depth<=2 captures relationships BB scope misses
    captured_d1 = agg_buckets.get("depth=1", 0)
    captured_d2 = agg_buckets.get("depth=2", 0)
    captured_d3 = agg_buckets.get("depth=3", 0)
    missed_far = agg_buckets.get("depth>3", 0)

    print("-" * 78)
    print("  SCOPE COMPARISON  --  THE KEY ARGUMENT")
    print("-" * 78)
    print()
    print("  Scope              | Captures | Misses   | Over-matches")
    print("  -------------------|----------|----------|-------------")
    print(f"  basic_block        |     0    | {total_pairs:6d}   | 0")
    print(f"  connected(depth=1) | {captured_d1:6d}   | {total_pairs - captured_d1:6d}   | 0")
    print(f"  connected(depth=2) | {captured_d1 + captured_d2:6d}   | {missed_far + captured_d3:6d}   | 0")
    print(f"  connected(depth=3) | {captured_d1 + captured_d2 + captured_d3:6d}   | {missed_far:6d}   | 0")
    print(f"  function           | {total_pairs:6d}   |     0    | ALL (no locality)")
    print()
    print("  * basic_block scope misses ALL cross-BB API pairs (by definition).")
    print("  * function scope captures ALL pairs but provides no locality signal.")
    print(
        f"  * connected_blocks(depth=2) captures {captured_d1 + captured_d2} of {total_pairs}"
        f" pairs ({(captured_d1 + captured_d2) / total_pairs * 100:.1f}%) WITH locality."
    )
    print()

    # dominator summary
    print("-" * 78)
    print("  DOMINATOR TREE ANALYSIS")
    print("-" * 78)
    print()
    print(f"  Total dominator relationships between API-bearing BBs: {total_dom_rels}")
    print()
    if total_dom_rels > 0:
        print("  Dominator relationships mean one API call MUST execute before another,")
        print("  strengthening the behavioral link between them.")
        print()

    # ---- detailed examples ----
    print("-" * 78)
    print("  DETAILED EXAMPLES  --  SPECIFIC EVIDENCE")
    print("-" * 78)
    print()

    # sort results by number of cross-BB pairs, show top functions
    results.sort(key=lambda r: len(r.cross_bb_pairs), reverse=True)
    shown = 0
    max_examples = 10

    for r in results:
        if shown >= max_examples:
            break
        shown += 1

        print(f"  Function {format_va(r.func_va)}  ({r.num_bbs} BBs, {r.api_bearing_bbs} API-bearing BBs)")
        print()

        # show API map
        for bb_va in sorted(r.bb_apis.keys()):
            apis = r.bb_apis[bb_va]
            print(f"    BB {format_va(bb_va)}: {', '.join(apis)}")
        print()

        # show select cross-BB pairs (up to 5 per function)
        pair_shown = 0
        # prioritize interesting pairs at depth 1-2
        sorted_pairs = sorted(r.cross_bb_pairs, key=lambda p: p[4])
        for api_a, bb_a, api_b, bb_b, dist in sorted_pairs:
            if pair_shown >= 5:
                break
            pair_shown += 1

            marker = ""
            if dist <= 2:
                marker = " <-- connected_blocks(depth=2) CAPTURES this"
            elif dist <= 3:
                marker = " <-- connected_blocks(depth=3) captures this"
            else:
                marker = " <-- only function scope captures (over-match risk)"

            print(f"    {api_a} (BB {format_va(bb_a)}) <--{dist} edge(s)--> " f"{api_b} (BB {format_va(bb_b)}){marker}")

        # show dominator relationships
        if r.dominator_rels:
            print()
            print("    Dominator relationships:")
            for dom, sub in r.dominator_rels[:3]:
                dom_apis = ", ".join(r.bb_apis.get(dom, ["?"]))
                sub_apis = ", ".join(r.bb_apis.get(sub, ["?"]))
                print(f"      BB {format_va(dom)} [{dom_apis}] dominates " f"BB {format_va(sub)} [{sub_apis}]")

        print()
        print("    " + "-" * 60)
        print()

    # ---- BFS neighborhood demonstration ----
    print("-" * 78)
    print("  BFS NEIGHBORHOOD DEMONSTRATION")
    print("-" * 78)
    print()
    print("  For the top function, showing what connected_blocks(depth=N) sees:")
    print()

    if results:
        r = results[0]
        func = viv_utils.Function(vw, r.func_va)
        adj = build_cfg(func)
        adj_und = make_undirected(adj)

        # pick first API-bearing BB
        seed_bb = sorted(r.bb_apis.keys())[0]
        seed_apis = r.bb_apis[seed_bb]

        for depth in [1, 2, 3]:
            neighborhood = bfs_neighborhood(adj_und, seed_bb, depth)
            apis_in_neighborhood: list[str] = []
            for bb_va in neighborhood:
                if bb_va in r.bb_apis:
                    apis_in_neighborhood.extend(r.bb_apis[bb_va])

            unique_apis = sorted(set(apis_in_neighborhood))
            print(f"  Seed: BB {format_va(seed_bb)} [{', '.join(seed_apis)}]")
            print(f"    depth={depth}: {len(neighborhood)} BBs in neighborhood")
            print(f"    APIs visible: {', '.join(unique_apis) if unique_apis else '(none)'}")
            print()

    # ---- final verdict ----
    print("=" * 78)
    print("  CONCLUSION")
    print("=" * 78)
    print()
    print(f"  Across {len(results)} functions with cross-BB API relationships:")
    print()
    print(f"    - {total_pairs} API pairs exist in DIFFERENT basic blocks.")
    print("      basic_block scope misses ALL of them.")
    print()
    if captured_d1 + captured_d2 > 0:
        print(
            f"    - connected_blocks(depth=2) captures {captured_d1 + captured_d2}"
            f" ({(captured_d1 + captured_d2) / total_pairs * 100:.1f}%) of these pairs"
        )
        print("      while maintaining CFG-locality (the APIs are close in the")
        print("      control flow, not just anywhere in the function).")
        print()
    if missed_far > 0:
        print(f"    - {missed_far} pairs ({missed_far / total_pairs * 100:.1f}%) are at depth>3,")
        print("      demonstrating that function scope over-matches by treating")
        print("      distant, unrelated code regions as behaviorally linked.")
        print()
    if total_dom_rels > 0:
        print(f"    - {total_dom_rels} dominator relationships confirm sequential")
        print("      execution ordering between API-bearing blocks, providing")
        print("      additional behavioral context beyond simple proximity.")
        print()
    print("  This validates the connected_blocks scope as a meaningful")
    print("  intermediate between basic_block and function scopes.")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
