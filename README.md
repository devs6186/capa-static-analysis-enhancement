# capa: Function Triage & Proximity-Aware Matching — GSoC 2026 Prototype

## Overview

This repository contains prototype scripts validating two proposed enhancements to
[FLARE/capa](https://github.com/mandiant/capa) for GSoC 2026.

**Function Triage** (`prototype_function_triage.py`) implements a lightweight pre-filter that classifies functions before full rule evaluation, skipping compiler-generated, runtime, and library functions that FLIRT signatures miss. It was tested on 5 real malware binaries and observed 23–31% additional skip rate beyond FLIRT on typical samples.

**Proximity-Aware Matching** (`prototype_proximity_matching.py`) implements `connected_blocks(depth=N)` — a BFS-based CFG neighborhood scope between `basic_block` and `function`. On a 485KB PE32 sample, depth=2 captures 59.1% of cross-basic-block API pairs that `basic_block` scope misses entirely, with no false-positive risk from function-wide over-matching.

Both scripts run on top of capa's existing vivisect loading pipeline with no external dependencies beyond a standard capa dev install.

## Requirements

```bash
pip install -e ".[dev]"   # from the capa repository root
```

Both scripts require a working capa + vivisect installation.

## Usage

### Function Triage

```bash
python prototype_function_triage.py <path_to_binary>
python prototype_function_triage.py tests/data/5fbbfeed28b258c42e0cfeb16718b31c.exe_
python prototype_function_triage.py tests/data/5fbbfeed28b258c42e0cfeb16718b31c.exe_ -v  # per-function detail
```

### Proximity-Aware Matching

```bash
python prototype_proximity_matching.py <path_to_binary>
python prototype_proximity_matching.py tests/data/321338196a46b600ea330fc5d98d0699.exe_
```

### Rule Statistics Validation

```bash
python validate_rule_statistics.py          # requires capa-rules submodule
python validate_rule_statistics.py --verbose
```

## Results

### Function Triage — measured on capa test binaries

| Binary | Total Funcs | FLIRT Library | Triage Skip | Triage Depri | Analyze | Skip % of non-FLIRT |
|---|---:|---:|---:|---:|---:|---:|
| 5fbbfeed (878KB) | 1,248 | 3 (0.2%) | 382 (30.6%) | 2 (0.2%) | 861 (69.0%) | 30.7% |
| a74ee820 (227KB) | 1,012 | 52 (5.1%) | 223 (22.0%) | 2 (0.2%) | 735 (72.6%) | 23.4% |

Triage pass overhead: ~0.2 ms/function (0.29s total for 1,248 functions).

### Proximity-Aware Matching — measured on 321338196 (485KB PE32)

| Scope | Captures | Misses | Over-matches |
|---|---:|---:|---|
| `basic_block` | 0 | 318 | 0 |
| `connected_blocks(depth=1)` | 115 | 203 | 0 |
| `connected_blocks(depth=2)` | 188 | 130 | 0 |
| `connected_blocks(depth=3)` | 255 | 63 | 0 |
| `function` | 318 | 0 | ALL |

188/318 cross-BB API pairs (59.1%) captured at depth=2.  
107 dominator relationships confirm sequential execution ordering.

Example captures:
- `LoadLibraryW` → `GetProcAddress` (1 CFG edge)
- `GetCurrentThreadId` → `SuspendThread` → `GetThreadContext` (1 edge each)
- `EnterCriticalSection` → `LeaveCriticalSection` (1–2 edges)

## How it works

### Function Triage signals (in priority order)

1. FLIRT signature match (existing)
2. CRT/runtime name patterns (100+ known MSVC/GCC/MinGW prefixes)
3. Thunk detection (1-BB functions ending in JMP/RET with ≤3 instructions)
4. Init/fini section membership (`.init`, `.fini`, `.init_array`, `.fini_array`)
5. Non-code section membership (`.rdata`, `.data`, etc.)
6. Trivial complexity (< 3 BBs, < 6 instructions, 0 API calls)
7. Obfuscation signal (> 500 basic blocks → DEPRIORITIZE)

Classification outcomes:
- `FLIRT_LIBRARY` — skipped (existing behavior)
- `TRIAGE_SKIP` — skipped entirely (high-confidence non-user-code)
- `TRIAGE_DEPRI` — analyzed in full, results available but lower scheduling priority
- `ANALYZE` — full rule-matching pipeline (unchanged behavior)

### Proximity Matching — BFS over CFG

For each basic block `B` and depth `N`, the neighborhood is all blocks reachable from `B`
within `N` undirected CFG edges. Features from the neighborhood are merged into a single
FeatureSet and matched against `connected_blocks`-scoped rules. The optional dominator tree
(Cooper-Harvey-Kennedy iterative algorithm) can prune the neighborhood to blocks with guaranteed
execution-path relationships (`strict=true`).

## Relationship to capa issues

- Directly addresses https://github.com/mandiant/capa/issues/1286 (filter library/runtime functions)
- Directly addresses https://github.com/mandiant/capa/issues/1453 (proximity scope)
- Complements https://github.com/mandiant/capa/pull/2816 (sequence statement — ordering within a scope)

## GSoC 2026

This prototype is submitted as evidence for the GSoC 2026 proposal:
**"capa: Function Triage and Proximity-Aware Static Analysis Enhancement"**
under the FLARE/Mandiant organization, mentored by @mike-hunhoff.
