# Static Analysis Enhancement Prototype

Standalone MVP for **function triage signal extension** and **CFG-aware proximity matching** — the two core components of the GSoC 2026 proposal *"Enhance capa Static Analysis: Function Triage Extension & CFG-Aware Proximity Matching"* for the FLARE team.

## Problem

capa's static analysis pipeline has two well-characterized bottlenecks:

1. **Wasted analysis on non-matching functions.** `find_static_capabilities()` iterates all non-library functions. FLIRT coverage is incomplete — compiler-generated runtime code (CRT init, thunks, exception handlers) passes through FLIRT undetected and is fully analyzed even though it never matches behavioral rules.

2. **Fixed-depth CFG-aware matching.** 228 rules combine three or more API calls. These patterns are more precisely matched when constrained to a CFG neighborhood, but `connected_blocks` is locked at depth=2, which captures only 8–59% of cross-basic-block API pairs depending on the binary.

## Solution

Two complementary extensions to capa's existing static analysis infrastructure:

- **Function Triage Signal Extension** — extends `classify_function()` with 100 compiler-family name patterns (MSVC/GCC/MinGW/Clang/Rust/Go), covering the gap left by FLIRT
- **CFG-Aware Proximity Matching** — a new static subscope (`connected blocks`) with BFS neighborhood aggregation at configurable depth, validated against real binaries

## What Is Implemented

### Core modules

| File | What it does |
|------|-------------|
| `capa/capabilities/triage.py` | Three-decision triage pipeline: `ANALYZE` / `DEPRIORITIZE` / `SKIP`. Signals: 14 MSVC `CRT_NAME_PREFIXES` + 86-entry `COMPILER_FAMILY_PREFIXES` (GCC/MinGW, Clang/LLVM, Rust, Go), thunk detection, runtime section membership, tiny-no-API heuristic, large-complexity deprioritisation |
| `capa/capabilities/static.py` | `find_static_capabilities()` with triage dispatch (lines 247–285); `_build_connected_block_adjacency()` (lines 122–139); `_collect_connected_neighborhood()` BFS with `depth` param (lines 142–154); per-seed `connected_blocks` matching loop (lines 190–203) |
| `capa/rules/__init__.py` | `Scope.CONNECTED_BLOCKS` (line 92); `parse_connected_blocks_subscope_key()` accepting `connected blocks` shorthand and `connected_blocks(depth=2)` (lines 600–618); full feature indexing via existing `_index_rules_by_feature()` |
| `capa/features/extractors/base_extractor.py` | `get_cfg_edges()` base method (lines 268–274) — yields nothing by default for backends without CFG support |
| `capa/features/extractors/viv/extractor.py` | `get_cfg_edges()` Vivisect implementation (line 88) using `bb.instructions[-1].getBranches()` |

### Triage prefix coverage

```
CRT_NAME_PREFIXES   (MSVC)  : 14 patterns  — __security_, __scrt_, __acrt_, ...
COMPILER_FAMILY_PREFIXES     : 86 patterns
  gcc   (32)  — __do_global_dtors_aux, frame_dummy, register_tm_clones, ...
  clang (29)  — __cxa_atexit, __cxa_finalize, __stack_chk_fail, __ubsan_handle_, ...
  rust  (12)  — rust_begin_unwind, __rust_alloc, core::panicking::, ...
  go    (13)  — runtime.mallocgc, runtime.morestack, runtime.goexit, ...
Total           : 100 prefixes across all compiler families
```

### Prototype measurement scripts

| Script | Purpose |
|--------|---------|
| `scripts/prototype_function_triage.py` | Loads binaries via Vivisect, runs FLIRT + `classify_function()` on every function, reports skip-rate table |
| `scripts/prototype_proximity_matching.py` | Builds CFG adjacency, BFS-measures cross-BB API pair distances at depth 1–5, reports coverage % and average CFG distance |
| `scripts/validate_rule_statistics.py` | Walks a rules directory, parses every `.yml`/`.yaml` with `Rule.from_yaml`, reports scope distribution / API combination counts / regex patterns |
| `scripts/demo_connected_blocks_and_triage.py` | Quick demo: triage counts + connected-blocks rule syntax on any binary |

### Tests

```
tests/test_triage.py          — 9 tests: MSVC/GCC/Clang/Go name patterns, thunk skip,
                                tiny-no-API skip, large-complexity deprioritise,
                                false-negative guard (API evidence prevents skip)
tests/test_connected_blocks.py — 2 tests: depth=2 match, depth=2 no-match (too far)
```

## Quick Start

```bash
pip install -e ".[dev]"
pytest tests/test_triage.py tests/test_connected_blocks.py -v
```

Expected output:

```
collected 11 items

tests/test_triage.py::test_triage_classify_crt_name_skip               PASSED
tests/test_triage.py::test_triage_classify_tiny_no_api_skip            PASSED
tests/test_triage.py::test_triage_classify_large_function_deprioritize PASSED
tests/test_triage.py::test_triage_api_presence_prevents_tiny_skip      PASSED
tests/test_triage.py::test_triage_api_feature_evidence_prevents_thunk_skip PASSED
tests/test_triage.py::test_triage_gcc_runtime_name_skip                PASSED
tests/test_triage.py::test_triage_clang_runtime_name_skip              PASSED
tests/test_triage.py::test_triage_go_runtime_name_skip                 PASSED
tests/test_triage.py::test_triage_compiler_runtime_does_not_skip_with_api PASSED
tests/test_connected_blocks.py::test_connected_blocks_depth2_match     PASSED
tests/test_connected_blocks.py::test_connected_blocks_too_far_no_match PASSED

11 passed in 0.12s
```

## Running the Prototype Scripts

### Function Triage Measurement

```bash
python scripts/prototype_function_triage.py <sample> [sample2 ...]
```

Example output on `notepad.exe`:

```
analysing notepad.exe ...

Function Triage Prototype — Signal Extension Measurement
=========================================================
Note: FLIRT signatures disabled (sigpaths=[]). FLIRT counts will be 0 unless
.sig/.pat files are supplied.

 binary          size    total  flirt  triage_skip  deprioritize  analyze  skip_%_nonflirt  time_s
 notepad.exe     352 KB    457      0           44             1      412             9.6%   18.22

Summary
  Total functions analyzed     : 457
  Total FLIRT library          : 0
  Total triage skip            : 44
  Total deprioritize           : 1
  Total analyze                : 412
  Overall skip % of non-FLIRT  : 9.6%
```

On real malware test binaries (with FLIRT signatures loaded via `--sigpaths`), the prototype achieves 23–31% skip rates on the two largest representative samples (1,248 and 1,012 functions respectively), validating the proposal's core performance claim.

### CFG-Aware Proximity Matching Measurement

```bash
python scripts/prototype_proximity_matching.py <sample> [sample2 ...]
```

Example output on `notepad.exe`:

```
╔════════════════════════════════════════╗
║ CFG-Aware Proximity Matching Prototype ║
╚════════════════════════════════════════╝
  Loading notepad.exe …

Binary: notepad.exe (352 KB, PE32+)
  Functions with cross-BB API relationships : 180
  Total cross-BB API pairs                  : 29086
  Coverage by depth:
    depth=1  :    806 / 29086 (  2.8%)
    depth=2  :   2354 / 29086 (  8.1%)   <- current fixed default
    depth=3  :   4164 / 29086 ( 14.3%)
    depth=4  :   5908 / 29086 ( 20.3%)
    depth=5  :   7262 / 29086 ( 25.0%)
  Average CFG distance (reachable pairs)    : 14.08 edges
  Pairs at depth > 3                        : 24922 / 29086 (85.7%)

  Example API pairs (distance=1):
    _o__set_app_type -> _o__configure_wide_argv  (distance=1, seed=0x140001740)
    _o__configure_wide_argv -> _o__configthreadlocale  (distance=1, seed=0x140001740)
    ...
```

This directly validates the proposal's stretch-deliverable claim: `depth=2` is insufficient for binaries with longer API chains. On real malware binaries (capa test suite), Binary 2 (375 KB) has an average CFG distance of 3.92 edges between API-bearing blocks, with 54.6% of pairs requiring `depth > 3`.

### Rule Statistics Validation

```bash
# Requires the capa-rules submodule
git submodule update --init rules
python scripts/validate_rule_statistics.py rules/
```

Actual output against capa-rules (`9609e19`):

```
Rule Statistics Validator
=========================
Rules directory: .../rules

Scanning rules...
  Parsed successfully : 1,034
  Parse errors        : 3

Scope Distribution:
  function        :  652 / 1,034 (63.1%)
  file            :  190 / 1,034 (18.4%)
  basic block     :  170 / 1,034 (16.4%)
  instruction     :   22 / 1,034 ( 2.1%)

API Combination Analysis:
  Rules with 1 API  :  170
  Rules with 2 APIs :   95
  Rules with 3+ APIs:  228   <- prime candidates for connected_blocks migration

Regex Pattern Analysis:
  Total unique patterns       : 710
  Rules containing regex      : 141

Top scope imbalance insight:
  63.1% of rules use function scope vs 16.4% basic_block
  -> 228 rules with 3+ APIs are candidates for connected_blocks migration
  -> Configurable depth would make tighter scoping practical
```

The 228 rules with 3+ API combinations are prime candidates for migration from `function` scope to `connected_blocks(depth=N)` — directly motivating the stretch deliverable.

## Connected Blocks Rule Syntax

Both forms are supported and parsed identically:

```yaml
# Shorthand (default depth=2)
features:
  - and:
      - connected blocks:
          - and:
              - api: kernel32.CreateFileA
              - api: kernel32.WriteFile

# Explicit depth (currently only depth=2 accepted; range [1,5] is the GSoC deliverable)
features:
  - and:
      - connected_blocks(depth=2):
          - and:
              - api: kernel32.CreateFileA
              - api: kernel32.WriteFile
```

## Architecture Notes

- `connected blocks` currently uses a fixed neighborhood depth of `2`. The GSoC deliverable extends `parse_connected_blocks_subscope_key()` (rules/`__init__`.py:600–618) to accept depth in `[1, 5]` and threads the value through the matching pipeline.
- Zero overhead when no `connected blocks` rules are loaded — lazy gate at `static.py:174`.
- `deprioritize` functions are still analyzed; only `skip` functions are omitted from full rule evaluation.
- Vivisect provides CFG edges via `get_cfg_edges()` (viv/extractor.py:88); all other backends default to no CFG edges (silent graceful degradation).
- Per-function adjacency maps are cached in `fh.ctx["connected_blocks_adjacency"]` to avoid recomputation when multiple seed blocks are evaluated in the same function.
- `REASON_CRT_NAME` is emitted for MSVC `CRT_NAME_PREFIXES` matches; `REASON_COMPILER_RUNTIME` for GCC/Clang/Rust/Go `COMPILER_FAMILY_PREFIXES` matches. Both are visible in debug logs for diagnosing missed functions.

## Notes and Constraints

- Prototype scripts suppress Vivisect's internal `WARNING:` log noise during workspace loading; the load itself is unaffected.
- `sigpaths=[]` in the prototype scripts means FLIRT signature matching is disabled. Supply `.sig`/`.pat` files via the `sigpaths` argument to `get_workspace()` to enable FLIRT-based library function detection.
- The `rules/` and `tests/data/` directories are git submodules. Initialize with `git submodule update --init` before running `validate_rule_statistics.py` or the full capa test suite.

This is an MVP prototype, not a full production redesign of capa internals.
