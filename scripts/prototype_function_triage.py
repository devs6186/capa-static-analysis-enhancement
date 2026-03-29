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
Prototype: Function Triage Signal Extension — Measurement Script

Demonstrates skip rate measurements using capa's actual Vivisect loading
pipeline with FLIRT signatures. Validates the 23-31% skip rate claim for
the two largest representative test binaries.

Signals applied per non-FLIRT function:
  - CRT name patterns (MSVC/GCC/MinGW/Clang/Rust/Go prefixes)
  - Thunk detection (single basic block, <=3 instructions, ends jmp/ret)
  - Runtime section membership (.plt, .init, .fini, etc.)
  - Tiny-no-API heuristic (bb <= 1, insn <= 4, no API evidence)
  - Large-complexity deprioritise (bb >= 512 or insn >= 4096)

Note: sigpaths=[] means FLIRT signature matching is disabled. FLIRT counts
will therefore be zero unless caller supplies pre-built .sig/.pat files.
This is expected for the prototype; see FINAL_STATIC.pdf §4.2.

Usage:
    python scripts/prototype_function_triage.py <sample> [sample2 ...]
    python scripts/prototype_function_triage.py tests/data/mimikatz.exe_
"""

import time
import logging
import argparse
import collections
import contextlib
from pathlib import Path
from typing import Optional

from rich.table import Table
from rich.console import Console

import capa.loader
from capa.features.common import OS_AUTO, FORMAT_AUTO
from capa.features.extractors.viv.extractor import VivisectFeatureExtractor
from capa.capabilities.triage import TriageDecision, classify_function


@contextlib.contextmanager
def _suppress_vivisect_noise():
    """Silence Vivisect's WARNING spam during workspace loading.

    Vivisect uses Python's logging module (logger.warning / logger.info),
    so raising the log level for every 'vivisect.*' logger to ERROR is
    sufficient to suppress the noise without any fd-level tricks.
    """
    viv_loggers = [
        logging.getLogger(name)
        for name in logging.root.manager.loggerDict
        if name.startswith("vivisect")
    ]
    # Also capture any vivisect loggers created lazily after this point.
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

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# per-binary result dataclass (plain namedtuple to stay dependency-free)
# ---------------------------------------------------------------------------

BinaryResult = collections.namedtuple(
    "BinaryResult",
    [
        "path",
        "size_bytes",
        "total",
        "flirt",
        "triage_skip",
        "deprioritize",
        "analyze",
        "elapsed_s",
        "error",
    ],
)


def _fmt_size(size_bytes: int) -> str:
    """Return human-readable file size (KB / MB)."""
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    return f"{size_bytes / 1024:.0f} KB"


def _truncate_name(path: Path, max_len: int = 24) -> str:
    """Return stem truncated to max_len characters with ellipsis if needed."""
    name = path.name
    if len(name) <= max_len:
        return name
    return name[: max_len - 3] + "..."


def analyze_binary(path: Path) -> BinaryResult:
    """
    Load *path* with Vivisect, run triage classification on every function,
    and return a populated BinaryResult.

    FLIRT signatures are intentionally not loaded (sigpaths=[]) so that
    is_library_function() reflects only embedded symbol information.
    """
    size_bytes = path.stat().st_size
    t0 = time.perf_counter()

    try:
        with _suppress_vivisect_noise():
            vw = capa.loader.get_workspace(path, FORMAT_AUTO, sigpaths=[])
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        logger.warning("failed to load %s: %s", path, exc)
        return BinaryResult(
            path=path,
            size_bytes=size_bytes,
            total=0,
            flirt=0,
            triage_skip=0,
            deprioritize=0,
            analyze=0,
            elapsed_s=elapsed,
            error=str(exc),
        )

    try:
        extractor = VivisectFeatureExtractor(vw, path, OS_AUTO)
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        logger.warning("failed to build extractor for %s: %s", path, exc)
        return BinaryResult(
            path=path,
            size_bytes=size_bytes,
            total=0,
            flirt=0,
            triage_skip=0,
            deprioritize=0,
            analyze=0,
            elapsed_s=elapsed,
            error=str(exc),
        )

    total = 0
    flirt = 0
    triage_skip = 0
    deprioritize = 0
    analyze = 0

    for fh in extractor.get_functions():
        total += 1

        if extractor.is_library_function(fh.address):
            flirt += 1
            continue

        result = classify_function(extractor, fh)

        if result.decision == TriageDecision.SKIP:
            triage_skip += 1
        elif result.decision == TriageDecision.DEPRIORITIZE:
            deprioritize += 1
        else:
            analyze += 1

    elapsed = time.perf_counter() - t0

    return BinaryResult(
        path=path,
        size_bytes=size_bytes,
        total=total,
        flirt=flirt,
        triage_skip=triage_skip,
        deprioritize=deprioritize,
        analyze=analyze,
        elapsed_s=elapsed,
        error=None,
    )


def _skip_pct_non_flirt(result: BinaryResult) -> Optional[float]:
    """Return skip % relative to non-FLIRT functions, or None if undefined."""
    non_flirt = result.total - result.flirt
    if non_flirt <= 0:
        return None
    return (result.triage_skip / non_flirt) * 100.0


def print_report(results: list[BinaryResult], console: Optional[Console] = None) -> None:
    """Render the measurement table and summary block to *console*."""
    if console is None:
        console = Console()

    console.print()
    console.print("[bold]Function Triage Prototype — Signal Extension Measurement[/bold]")
    console.print("=" * 57)
    console.print(
        "[dim]Note: FLIRT signatures disabled (sigpaths=[]). "
        "FLIRT counts will be 0 unless .sig/.pat files are supplied.[/dim]"
    )
    console.print()

    table = Table(show_header=True, header_style="bold cyan", box=None, padding=(0, 1))
    table.add_column("binary", style="white", min_width=24, max_width=30)
    table.add_column("size", justify="right", style="white")
    table.add_column("total", justify="right", style="white")
    table.add_column("flirt", justify="right", style="green")
    table.add_column("triage_skip", justify="right", style="yellow")
    table.add_column("deprioritize", justify="right", style="blue")
    table.add_column("analyze", justify="right", style="white")
    table.add_column("skip_%_nonflirt", justify="right", style="magenta")
    table.add_column("time_s", justify="right", style="white")

    for r in results:
        if r.error:
            table.add_row(
                _truncate_name(r.path),
                _fmt_size(r.size_bytes),
                "[red]ERROR[/red]",
                "-",
                "-",
                "-",
                "-",
                "-",
                f"{r.elapsed_s:.2f}",
            )
            continue

        pct = _skip_pct_non_flirt(r)
        pct_str = f"{pct:.1f}%" if pct is not None else "n/a"

        table.add_row(
            _truncate_name(r.path),
            _fmt_size(r.size_bytes),
            f"{r.total:,}",
            f"{r.flirt:,}",
            f"{r.triage_skip:,}",
            f"{r.deprioritize:,}",
            f"{r.analyze:,}",
            pct_str,
            f"{r.elapsed_s:.2f}",
        )

    console.print(table)
    console.print()

    # --- summary block ---
    ok = [r for r in results if not r.error]
    if not ok:
        console.print("[red]No binaries were processed successfully.[/red]")
        return

    total_funcs = sum(r.total for r in ok)
    total_flirt = sum(r.flirt for r in ok)
    total_skip = sum(r.triage_skip for r in ok)
    total_deprio = sum(r.deprioritize for r in ok)
    total_analyze = sum(r.analyze for r in ok)
    total_non_flirt = total_funcs - total_flirt
    overall_pct = (total_skip / total_non_flirt * 100.0) if total_non_flirt > 0 else 0.0

    console.print("[bold]Summary[/bold]")
    console.print(f"  Total functions analyzed     : {total_funcs:,}")
    console.print(f"  Total FLIRT library          : {total_flirt:,}")
    console.print(f"  Total triage skip            : {total_skip:,}")
    console.print(f"  Total deprioritize           : {total_deprio:,}")
    console.print(f"  Total analyze                : {total_analyze:,}")
    console.print(f"  Overall skip % of non-FLIRT  : {overall_pct:.1f}%")
    console.print()


def main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    parser = argparse.ArgumentParser(
        description=(
            "Function Triage Signal Extension — Measurement Script. "
            "Loads each binary via Vivisect and reports FLIRT + triage skip rates."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "samples",
        nargs="+",
        type=Path,
        metavar="SAMPLE",
        help="one or more binary paths to analyse",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable DEBUG logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    console = Console()

    # validate paths before doing any heavy work
    valid_paths: list[Path] = []
    for p in args.samples:
        if not p.exists():
            console.print(f"[red]warning:[/red] path not found, skipping: {p}")
        elif not p.is_file():
            console.print(f"[red]warning:[/red] not a file, skipping: {p}")
        else:
            valid_paths.append(p)

    if not valid_paths:
        console.print("[red]error:[/red] no valid sample paths provided.")
        raise SystemExit(1)

    results: list[BinaryResult] = []
    for path in valid_paths:
        console.print(f"[dim]analysing {path.name} ...[/dim]")
        result = analyze_binary(path)
        if result.error:
            console.print(f"  [red]failed:[/red] {result.error}")
        results.append(result)

    print_report(results, console=console)


if __name__ == "__main__":
    main()
