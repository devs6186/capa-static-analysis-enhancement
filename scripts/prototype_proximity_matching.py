#!/usr/bin/env python3
# Copyright 2026 Google LLC
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
Prototype: CFG-Aware Proximity Matching — Measurement Script

Measures API co-occurrence across basic blocks at various BFS depths.
Validates claims about connected_blocks depth configurability need.

Usage:
    python scripts/prototype_proximity_matching.py <sample> [sample2 ...]
"""

import collections
import argparse
import logging
import contextlib
from pathlib import Path
from typing import Iterator

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

import capa.loader
import capa.features.insn
from capa.features.common import OS_AUTO, FORMAT_AUTO
from capa.features.extractors.viv.extractor import VivisectFeatureExtractor
from capa.features.extractors.base_extractor import FunctionHandle, BBHandle

logger = logging.getLogger(__name__)


@contextlib.contextmanager
def _suppress_vivisect_noise():
    """Silence Vivisect's WARNING spam during workspace loading."""
    viv_loggers = [
        logging.getLogger(name)
        for name in logging.root.manager.loggerDict
        if name.startswith("vivisect")
    ]
    viv_root = logging.getLogger("vivisect")
    saved = {lg: lg.level for lg in viv_loggers}
    saved[viv_root] = viv_root.level
    for lg in [viv_root] + viv_loggers:
        lg.setLevel(logging.ERROR)
    try:
        yield
    finally:
        for lg, lvl in saved.items():
            lg.setLevel(lvl)

console = Console()

MAX_DEPTHS = [1, 2, 3, 4, 5]
MAX_EXAMPLE_PAIRS = 5


# ---------------------------------------------------------------------------
# Core graph / distance utilities
# ---------------------------------------------------------------------------


def build_adjacency(extractor: VivisectFeatureExtractor, fh: FunctionHandle, bbs: tuple) -> dict:
    """Build an undirected CFG adjacency map for the given function.

    Mirrors the logic of _build_connected_block_adjacency in static.py so
    that distance measurements are consistent with the capa engine.
    """
    adjacency: dict = collections.defaultdict(set)
    bb_by_address = {bb.address: bb for bb in bbs}
    for bb in bbs:
        # Ensure every BB has an entry even if it has no successors.
        adjacency[bb.address]
        for succ in extractor.get_cfg_edges(fh, bb):
            if succ.address in bb_by_address:
                adjacency[bb.address].add(succ.address)
                adjacency[succ.address].add(bb.address)
    return adjacency


def bfs_distance(adjacency: dict, start: int, end: int) -> int:
    """BFS shortest path distance. Returns -1 if unreachable."""
    if start == end:
        return 0
    seen = {start}
    queue = collections.deque([(start, 0)])
    while queue:
        node, dist = queue.popleft()
        for neighbor in adjacency.get(node, ()):
            if neighbor == end:
                return dist + 1
            if neighbor not in seen:
                seen.add(neighbor)
                queue.append((neighbor, dist + 1))
    return -1  # unreachable


# ---------------------------------------------------------------------------
# Feature extraction helpers
# ---------------------------------------------------------------------------


def collect_api_names_for_bb(
    extractor: VivisectFeatureExtractor,
    fh: FunctionHandle,
    bb: BBHandle,
) -> list[str]:
    """Return a list of API feature names found in the given basic block."""
    names: list[str] = []
    for insn_handle in extractor.get_instructions(fh, bb):
        for feature, _addr in extractor.extract_insn_features(fh, bb, insn_handle):
            if isinstance(feature, capa.features.insn.API):
                # feature.value holds the full qualified name, e.g. "kernel32.LoadLibraryW"
                names.append(str(feature.value))
    return names


# ---------------------------------------------------------------------------
# Per-binary analysis
# ---------------------------------------------------------------------------


def _file_size_kb(path: Path) -> float:
    return path.stat().st_size / 1024.0


def _file_format_label(path: Path) -> str:
    """Return a short human-readable format label (PE32, PE32+, ELF, …)."""
    try:
        buf = path.read_bytes()[:0x40]
        if buf[:2] == b"MZ":
            # Peek at Optional Header Magic offset (0x3C -> e_lfanew, then +0x18)
            import struct

            e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0] if len(buf) >= 0x40 else 0
            full = path.read_bytes()
            if e_lfanew + 0x1A <= len(full):
                magic = struct.unpack_from("<H", full, e_lfanew + 0x18)[0]
                if magic == 0x10B:
                    return "PE32"
                elif magic == 0x20B:
                    return "PE32+"
            return "PE"
        if buf[:4] == b"\x7fELF":
            return "ELF"
    except Exception:
        pass
    return "unknown"


def analyze_binary(path: Path) -> dict:
    """
    Load a binary with Vivisect and measure CFG-aware API pair distances.

    Returns a result dict with the fields used by render_binary_report().
    """
    console.print(f"  Loading [bold]{path.name}[/bold] …", highlight=False)

    with _suppress_vivisect_noise():
        vw = capa.loader.get_workspace(path, FORMAT_AUTO, sigpaths=[])
    extractor = VivisectFeatureExtractor(vw, path, OS_AUTO)

    # Counters across the whole binary.
    total_funcs_with_cross_bb_pairs = 0
    total_cross_bb_pairs = 0
    depth_captures: dict[int, int] = {d: 0 for d in MAX_DEPTHS}
    reachable_distance_sum = 0
    reachable_pair_count = 0
    pairs_beyond_depth3 = 0
    example_pairs: list[tuple[str, str, int, int]] = []  # (api_a, api_b, dist, seed_va)

    for fh in extractor.get_functions():
        if extractor.is_library_function(fh.address):
            continue

        bbs = tuple(extractor.get_basic_blocks(fh))
        if not bbs:
            continue

        adjacency = build_adjacency(extractor, fh, bbs)

        # Skip functions with no CFG edges at all.
        if not any(adjacency[bb.address] for bb in bbs):
            continue

        # Collect basic blocks that contain at least one API feature.
        api_bbs: list[tuple[BBHandle, list[str]]] = []
        for bb in bbs:
            apis = collect_api_names_for_bb(extractor, fh, bb)
            if apis:
                api_bbs.append((bb, apis))

        if len(api_bbs) < 2:
            continue

        # Enumerate all ordered pairs (bb_a, bb_b) where bb_a != bb_b.
        func_has_cross_bb = False
        for i, (bb_a, apis_a) in enumerate(api_bbs):
            for j, (bb_b, apis_b) in enumerate(api_bbs):
                if i == j:
                    continue
                dist = bfs_distance(adjacency, bb_a.address, bb_b.address)
                if dist < 1:
                    # dist == 0 means same BB (shouldn't happen here since i != j
                    # and bbs have unique addresses); dist == -1 means unreachable.
                    continue

                # This is a reachable cross-BB pair.
                func_has_cross_bb = True
                total_cross_bb_pairs += 1
                reachable_distance_sum += dist
                reachable_pair_count += 1

                for d in MAX_DEPTHS:
                    if dist <= d:
                        depth_captures[d] += 1

                if dist > 3:
                    pairs_beyond_depth3 += 1

                # Collect example pairs at distance == 1.
                if dist == 1 and len(example_pairs) < MAX_EXAMPLE_PAIRS:
                    api_a_name = apis_a[0]
                    api_b_name = apis_b[0]
                    example_pairs.append((api_a_name, api_b_name, dist, int(fh.address)))

        if func_has_cross_bb:
            total_funcs_with_cross_bb_pairs += 1

    avg_distance = (reachable_distance_sum / reachable_pair_count) if reachable_pair_count > 0 else 0.0

    return {
        "path": path,
        "size_kb": _file_size_kb(path),
        "format": _file_format_label(path),
        "funcs_with_cross_bb": total_funcs_with_cross_bb_pairs,
        "total_cross_bb_pairs": total_cross_bb_pairs,
        "depth_captures": depth_captures,
        "avg_distance": avg_distance,
        "pairs_beyond_depth3": pairs_beyond_depth3,
        "example_pairs": example_pairs,
    }


# ---------------------------------------------------------------------------
# Rich rendering
# ---------------------------------------------------------------------------


def render_binary_report(result: dict) -> None:
    path: Path = result["path"]
    size_kb: float = result["size_kb"]
    fmt: str = result["format"]
    funcs: int = result["funcs_with_cross_bb"]
    total_pairs: int = result["total_cross_bb_pairs"]
    depth_captures: dict = result["depth_captures"]
    avg_dist: float = result["avg_distance"]
    beyond3: int = result["pairs_beyond_depth3"]
    examples: list = result["example_pairs"]

    # Header line
    console.print(f"\n[bold cyan]Binary:[/bold cyan] {path.name} ({size_kb:.0f} KB, {fmt})")

    # Key metrics
    console.print(f"  Functions with cross-BB API relationships : [bold]{funcs}[/bold]")
    console.print(f"  Total cross-BB API pairs                  : [bold]{total_pairs}[/bold]")

    if total_pairs == 0:
        console.print("  [dim](no cross-BB API pairs found)[/dim]")
        console.print("-" * 50)
        return

    # Coverage-by-depth table
    console.print("  Coverage by depth:")
    for d in MAX_DEPTHS:
        captured = depth_captures[d]
        pct = 100.0 * captured / total_pairs if total_pairs else 0.0
        marker = "   [dim]<- current fixed default[/dim]" if d == 2 else ""
        console.print(f"    depth={d}  : {captured:>6} / {total_pairs} ({pct:5.1f}%){marker}")

    # Average distance
    console.print(f"  Average CFG distance (reachable pairs)    : [bold]{avg_dist:.2f}[/bold] edges")

    # Pairs beyond depth=3
    pct_beyond3 = 100.0 * beyond3 / total_pairs if total_pairs else 0.0
    console.print(f"  Pairs at depth > 3                        : {beyond3} / {total_pairs} ({pct_beyond3:.1f}%)")

    # Example pairs at distance=1
    if examples:
        console.print("\n  Example API pairs (distance=1):")
        for api_a, api_b, dist, seed_va in examples:
            console.print(f"    [green]{api_a}[/green] -> [green]{api_b}[/green]  "
                          f"(distance={dist}, seed=0x{seed_va:X})")
    else:
        console.print("\n  [dim](no distance=1 API pairs found)[/dim]")

    console.print("-" * 50)


def render_aggregate(results: list[dict]) -> None:
    if len(results) < 2:
        return

    total_funcs = sum(r["funcs_with_cross_bb"] for r in results)
    total_pairs = sum(r["total_cross_bb_pairs"] for r in results)
    agg_depth: dict[int, int] = {d: sum(r["depth_captures"][d] for r in results) for d in MAX_DEPTHS}
    total_beyond3 = sum(r["pairs_beyond_depth3"] for r in results)

    # Weighted average distance.
    weighted_sum = sum(r["avg_distance"] * r["total_cross_bb_pairs"] for r in results if r["total_cross_bb_pairs"] > 0)
    total_reachable = sum(r["total_cross_bb_pairs"] for r in results if r["total_cross_bb_pairs"] > 0)
    agg_avg = (weighted_sum / total_reachable) if total_reachable > 0 else 0.0

    console.rule("[bold]Aggregate across all binaries[/bold]")
    console.print(f"  Total functions with cross-BB pairs : {total_funcs}")
    console.print(f"  Total cross-BB API pairs            : {total_pairs}")
    console.print("  Coverage by depth:")
    for d in MAX_DEPTHS:
        pct = 100.0 * agg_depth[d] / total_pairs if total_pairs else 0.0
        marker = "   [dim]<- current fixed default[/dim]" if d == 2 else ""
        console.print(f"    depth={d}  : {agg_depth[d]:>6} / {total_pairs} ({pct:5.1f}%){marker}")
    console.print(f"  Weighted average CFG distance       : {agg_avg:.2f} edges")
    pct_beyond3 = 100.0 * total_beyond3 / total_pairs if total_pairs else 0.0
    console.print(f"  Pairs at depth > 3                  : {total_beyond3} / {total_pairs} ({pct_beyond3:.1f}%)")
    console.print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "CFG-Aware Proximity Matching Prototype — "
            "measures API co-occurrence across basic blocks at various BFS depths."
        )
    )
    parser.add_argument("samples", nargs="+", type=Path, metavar="SAMPLE", help="one or more binary samples to analyze")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    console.print(Panel.fit("[bold]CFG-Aware Proximity Matching Prototype[/bold]", box=box.DOUBLE))

    results: list[dict] = []
    for sample_path in args.samples:
        sample_path = sample_path.resolve()
        if not sample_path.exists():
            console.print(f"[red]ERROR:[/red] file not found: {sample_path}")
            continue
        try:
            result = analyze_binary(sample_path)
            render_binary_report(result)
            results.append(result)
        except Exception as exc:
            console.print(f"[red]ERROR:[/red] failed to analyze {sample_path.name}: {exc}")
            if args.verbose:
                import traceback
                traceback.print_exc()

    if results:
        render_aggregate(results)


if __name__ == "__main__":
    main()
