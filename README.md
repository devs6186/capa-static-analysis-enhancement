# Static Analysis Enhancement Prototype

This repository is a standalone MVP for **static function triage + CFG-aware proximity matching** inspired by `static_analysis_idea.md`.

## Problem

Pure function-scope static matching can over-analyze large binaries and miss useful proximity context that spans nearby basic blocks.

## Solution

This MVP adds two complementary capabilities to static analysis:

- **Function Triage** before full function matching (`analyze` / `deprioritize` / `skip`)
- **CFG-Aware Proximity Matching** via a new static subscope: `connected blocks`

## What is implemented

- New triage module: `capa/capabilities/triage.py`
- Static pipeline integration before code matching (`find_static_capabilities()`)
- New static scope + parser support:
  - `Scope.CONNECTED_BLOCKS`
  - `connected blocks:` and `connected_blocks(depth=2)`
- Extractor CFG edge API:
  - `get_cfg_edges()` in base extractor
  - Vivisect implementation for CFG successors
- BFS neighborhood aggregation (depth=2) for connected-block matching
- Adjacency cache in `FunctionHandle.ctx` to avoid recomputation
- IDA rulegen integration for connected-block matches
- Unit/integration-like tests and demo script

## Demo

```bash
python scripts/demo_connected_blocks_and_triage.py <sample>
```

Expected output (shape):

```text
triage counts:
  analyze      : <N>
  deprioritize : <M>
  skip         : <K>

connected blocks rule syntax:
rule:
  meta:
    name: demo connected blocks
    scopes:
      static: function
      dynamic: process
  features:
    - connected blocks:
        - and:
            - api: kernel32.CreateFileA
            - api: kernel32.WriteFile
```

## Example rule syntax

```yaml
features:
  - and:
      - connected blocks:
          - and:
              - api: kernel32.CreateFileA
              - api: kernel32.WriteFile
```

## Quick start

```bash
pip install -e ".[dev]"
pytest tests/test_triage.py tests/test_connected_blocks.py -q
python scripts/demo_connected_blocks_and_triage.py <sample>
```

## Notes and constraints

- `connected blocks` currently uses a fixed neighborhood depth of `2`.
- Zero overhead when no `connected blocks` rules are loaded.
- `deprioritize` functions are still analyzed; only `skip` functions are omitted.
- Vivisect provides CFG edges; other backends default to no CFG edges.

This is an MVP prototype, not a full production redesign of capa internals.
