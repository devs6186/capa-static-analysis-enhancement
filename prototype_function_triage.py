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
prototype_function_triage.py - Function Triage Prototype for capa GSoC 2026

Demonstrates that a lightweight triage pass can identify 20-40% of functions
beyond FLIRT as skippable, without needing full rule evaluation.

Triage signals collected per function:
  - FLIRT library identification (is_library_function)
  - Function name pattern matching (CRT/runtime/compiler-generated patterns)
  - Section membership (.text, .rdata, .plt, .init, etc.)
  - Complexity metrics: basic block count, instruction count, function size
  - API call presence: whether the function references any imports
  - Thunk detection: single-BB functions with just a JMP

Classification:
  FLIRT_LIBRARY   - already detected by FLIRT signatures
  TRIAGE_SKIP     - additional functions triage identifies as skippable
  TRIAGE_DEPRI    - deprioritized (likely obfuscated or runtime glue)
  ANALYZE         - must be fully analyzed by capa's rule engine

Usage:
  python scripts/prototype_function_triage.py <path_to_binary>
  python scripts/prototype_function_triage.py tests/data/mimikatz.exe_
"""

import re
import sys
import time
import logging
import argparse
from typing import Optional
from pathlib import Path
from dataclasses import field, dataclass

# ---------------------------------------------------------------------------
# CRT / compiler runtime function name patterns
# These are well-known MSVC, GCC, and MinGW runtime helper names that
# never contain user logic.  FLIRT may miss some of them.
# ---------------------------------------------------------------------------
CRT_EXACT_PREFIXES = (
    "__security_check_cookie",
    "__security_init_cookie",
    "__GSHandlerCheck",
    "__GSHandlerCheck_SEH",
    "__GSHandlerCheck_EH",
    "_alloca_probe",
    "__alloca_probe",
    "__chkstk",
    "_chkstk",
    "__SEH_",
    "_SEH_",
    "__seh_",
    "_CxxThrowException",
    "__CxxFrameHandler",
    "_CxxCallCatchBlock",
    "__CxxCallUnwindDtor",
    "__CxxDetectRethrow",
    "__InternalCxxFrameHandler",
    "__FrameHandler3",
    "__scrt_",
    "__acrt_",
    "__vcrt_",
    "_onexit",
    "__onexit",
    "__dllonexit",
    "_except_handler",
    "__except_handler",
    "_guard_",
    "__guard_",
    "__report_gsfailure",
    "_RTC_",
    "__RTC_",
    "__report_rangecheckfailure",
    "__imp_",
    "_imp__",
    "__delayLoadHelper",
    "__tailMerge_",
    "___security_cookie",
    "__security_cookie",
    "_amsg_exit",
    "__crtCorExitProcess",
    "__crtExitProcess",
    "__crtUnhandledException",
    "_initterm",
    "__initterm",
    "_initterm_e",
    "__initterm_e",
    "_atexit",
    "__crt_atexit",
    "__crt_at_quick_exit",
    "__xi_a",
    "__xi_z",
    "__xc_a",
    "__xc_z",
    "__dyn_tls_init",
    "__tlregdtor",
    "__dyn_tls_dtor",
    "__DllMainCRTStartup",
    "_DllMainCRTStartup",
    "__mainCRTStartup",
    "_mainCRTStartup",
    "__wmainCRTStartup",
    "_wmainCRTStartup",
    "__tmainCRTStartup",
    "__wgetmainargs",
    "__getmainargs",
    "__set_app_type",
    "__setusermatherr",
    "__p__commode",
    "__p__fmode",
    "_controlfp",
    "__control87_2",
    "_configthreadlocale",
    "_register_thread_local_exe_atexit_callback",
    "__stdio_common_",
    "__acrt_iob_func",
    "_get_initial_narrow_environment",
    "_initialize_narrow_environment",
    "_configure_narrow_argv",
    "_initialize_onexit_table",
    "_register_onexit_function",
    "_execute_onexit_table",
    "_crt_atexit",
    "_crt_at_quick_exit",
    "_cexit",
    "_c_exit",
    "__crtSetUnhandledExceptionFilter",
    "_XcptFilter",
    "__CppXcptFilter",
    "_EH_prolog",
    "__EH_prolog",
    "_EH_epilog",
    "__EH_epilog",
    "___CxxFrameHandler",
    "___CxxFrameHandler3",
    "__local_unwind",
    "__local_unwind2",
    "__local_unwind4",
    "__global_unwind2",
    "__unwind_handler",
    "__NLG_",
    "_NLG_",
    # GCC / MinGW runtime
    "__do_global_dtors",
    "__do_global_ctors",
    "__libc_csu_init",
    "__libc_csu_fini",
    "__libc_start_main",
    "_start",
    "__gmon_start__",
    "_fini",
    "_init",
    "__x86.get_pc_thunk",
    "register_tm_clones",
    "deregister_tm_clones",
    "frame_dummy",
    "__stack_chk_fail",
    "__cxa_atexit",
    "__cxa_finalize",
    "__cxa_pure_virtual",
)

# Regex for names that look like compiler-generated stubs.
# NOTE: sub_XXXXXX is vivisect's default for unnamed functions -- NOT a triage signal.
# Only match names that positively indicate compiler/linker-generated code.
CRT_NAME_RE = re.compile(
    r"(?i)"
    r"(?:^_?_?(?:thunk|trampoline|stub)_)"  # thunk / trampoline stubs
    r"|(?:^nullsub_)"  # IDA-style null stubs
    r"|(?:^j_)"  # IDA-style jump wrappers
)

# Sections that typically do NOT contain user logic
NON_CODE_SECTIONS = {
    ".rdata",
    ".rodata",
    ".data",
    ".bss",
    ".rsrc",
    ".reloc",
    ".idata",
    ".edata",
    ".tls",
    ".pdata",
    ".xdata",
    ".debug_info",
    ".debug_abbrev",
    ".debug_line",
    ".gnu.hash",
    ".dynsym",
    ".dynstr",
    ".note",
    ".eh_frame",
    ".eh_frame_hdr",
    ".got",
    ".got.plt",
}

# Sections associated with init/fini code
INIT_FINI_SECTIONS = {".init", ".fini", ".init_array", ".fini_array", ".ctors", ".dtors"}

# High BB count threshold suggesting obfuscation or a very large switch table
OBFUSCATION_BB_THRESHOLD = 500

# Minimum complexity to be interesting without any API calls
MIN_BB_FOR_INTEREST = 3
MIN_INSN_FOR_INTEREST = 6


@dataclass
class FunctionInfo:
    address: int
    name: str
    size: int
    bb_count: int
    insn_count: int
    section_name: str
    is_flirt_library: bool
    has_api_calls: bool
    api_names: list = field(default_factory=list)
    is_thunk: bool = False
    classification: str = "ANALYZE"
    skip_reason: str = ""


def get_section_name_for_va(vw, va: int) -> str:
    """Return the section/segment name that contains the given VA."""
    for seg_va, seg_size, seg_name, _seg_fname in vw.getSegments():
        if seg_va <= va < seg_va + seg_size:
            return seg_name
    # Fall back to memory map names
    for mva, msize, mperms, mfname in vw.getMemoryMaps():
        if mva <= va < mva + msize:
            return mfname
    return "<unknown>"


def check_crt_name(name: str) -> Optional[str]:
    """Return the matching CRT prefix if the name looks like a CRT/runtime function."""
    if not name:
        return None
    name_lower = name.lower()
    for prefix in CRT_EXACT_PREFIXES:
        if name_lower.startswith(prefix.lower()):
            return prefix
    if CRT_NAME_RE.match(name):
        return "compiler-generated pattern"
    return None


def is_thunk_function(vw, func_va: int, bbs) -> bool:
    """
    Check if a function is a simple thunk (1 basic block, ends with JMP,
    no significant logic).
    """
    if len(bbs) != 1:
        return False
    bb = bbs[0]
    insns = bb.instructions
    # A thunk is typically 1-3 instructions ending with a jmp
    if len(insns) > 3:
        return False
    if len(insns) == 0:
        return False
    last = insns[-1]
    if last.mnem == "jmp":
        return True
    # Also consider single-ret stubs
    if len(insns) == 1 and last.mnem == "ret":
        return True
    return False


def check_api_calls(vw, func_va: int, bbs, imports: dict) -> tuple[bool, list]:
    """
    Lightweight check: scan instructions for call/jmp targets that resolve to imports.
    Returns (has_api_calls, list_of_api_names).
    """
    import envi.archs.i386.disasm
    import envi.archs.amd64.disasm

    api_names = []
    for bb in bbs:
        for insn in bb.instructions:
            if insn.mnem not in ("call", "jmp"):
                continue
            if len(insn.opers) == 0:
                continue

            target = None
            oper = insn.opers[0]

            # IAT call on x86: call dword [0x...]
            if isinstance(oper, envi.archs.i386.disasm.i386ImmMemOper):
                target = oper.getOperAddr(insn)
            # Direct call/jmp: call 0x...
            elif isinstance(oper, envi.archs.i386.disasm.i386PcRelOper):
                target = oper.getOperValue(insn)
            # RIP-relative on x64: call qword [rip+...]
            elif isinstance(oper, envi.archs.amd64.disasm.Amd64RipRelOper):
                target = oper.getOperAddr(insn)

            if target is not None and target in imports:
                dll, symbol = imports[target]
                api_names.append(f"{dll}.{symbol}")

    return (len(api_names) > 0, api_names)


def get_imports_cached(vw) -> dict:
    """Cache and return {va: (dll, symbol)} for all imports."""
    if "imports" in vw.metadata:
        return vw.metadata["imports"]
    imports = {p[0]: (p[3].rpartition(".")[0], p[3].replace(".ord", ".#").rpartition(".")[2]) for p in vw.getImports()}
    vw.metadata["imports"] = imports
    return imports


def classify_function(fi: FunctionInfo) -> None:
    """Apply triage classification logic to a single function."""

    # 1) Already FLIRT-identified
    if fi.is_flirt_library:
        fi.classification = "FLIRT_LIBRARY"
        fi.skip_reason = "FLIRT signature match"
        return

    # 2) CRT / compiler runtime name match
    crt_match = check_crt_name(fi.name)
    if crt_match:
        fi.classification = "TRIAGE_SKIP"
        fi.skip_reason = f"CRT/runtime pattern: {crt_match}"
        return

    # 3) Thunk functions (single-BB jmp wrappers)
    if fi.is_thunk:
        fi.classification = "TRIAGE_SKIP"
        fi.skip_reason = "thunk/stub function (1 BB, ends with jmp/ret)"
        return

    # 4) Init/fini sections
    if fi.section_name.lower() in INIT_FINI_SECTIONS:
        fi.classification = "TRIAGE_SKIP"
        fi.skip_reason = f"init/fini section: {fi.section_name}"
        return

    # 5) Non-code sections (unlikely to contain analyzed functions, but viv may find them)
    if fi.section_name.lower() in NON_CODE_SECTIONS:
        fi.classification = "TRIAGE_DEPRI"
        fi.skip_reason = f"non-code section: {fi.section_name}"
        return

    # 6) Tiny functions with no API calls -- too simple to match meaningful rules
    if not fi.has_api_calls and fi.bb_count < MIN_BB_FOR_INTEREST and fi.insn_count < MIN_INSN_FOR_INTEREST:
        fi.classification = "TRIAGE_SKIP"
        fi.skip_reason = f"trivial: {fi.bb_count} BBs, {fi.insn_count} insns, 0 API calls"
        return

    # 7) Suspiciously high BB count (potential obfuscation / flattened CFG)
    if fi.bb_count > OBFUSCATION_BB_THRESHOLD:
        fi.classification = "TRIAGE_DEPRI"
        fi.skip_reason = f"potential obfuscation: {fi.bb_count} basic blocks"
        return

    # 8) Everything else: full analysis
    fi.classification = "ANALYZE"
    fi.skip_reason = ""


def analyze_binary(path: Path, sigpaths: list[Path], input_format: str = "auto") -> list[FunctionInfo]:
    """
    Load a binary with vivisect (same as capa does), then triage every function.
    """
    import viv_utils
    import viv_utils.flirt

    import capa.loader

    print(f"[*] Loading binary: {path}")
    t0 = time.time()
    vw = capa.loader.get_workspace(path, input_format, sigpaths)
    t_load = time.time() - t0
    print(f"[*] Vivisect analysis complete in {t_load:.1f}s")

    imports = get_imports_cached(vw)
    functions = sorted(vw.getFunctions())
    print(f"[*] Found {len(functions)} functions, {len(imports)} imports")

    results: list[FunctionInfo] = []

    t0 = time.time()
    for va in functions:
        # Get function name
        try:
            name = viv_utils.get_function_name(vw, va)
            if not name:
                name = f"sub_{va:x}"
        except (KeyError, Exception):
            name = f"sub_{va:x}"

        # Enumerate basic blocks and instructions
        try:
            func = viv_utils.Function(vw, va)
            bbs = list(func.basic_blocks)
        except Exception:
            bbs = []

        bb_count = len(bbs)
        insn_count = 0
        func_size = 0
        for bb in bbs:
            insn_count += len(bb.instructions)
            func_size += bb.size

        # Section name
        section_name = get_section_name_for_va(vw, va)

        # FLIRT check
        is_lib = viv_utils.flirt.is_library_function(vw, va)

        # Thunk check
        thunk = is_thunk_function(vw, va, bbs)

        # API calls (lightweight -- only checks direct import references)
        has_api, api_names = check_api_calls(vw, va, bbs, imports)

        fi = FunctionInfo(
            address=va,
            name=name,
            size=func_size,
            bb_count=bb_count,
            insn_count=insn_count,
            section_name=section_name,
            is_flirt_library=is_lib,
            has_api_calls=has_api,
            api_names=api_names,
            is_thunk=thunk,
        )
        classify_function(fi)
        results.append(fi)

    t_triage = time.time() - t0
    print(f"[*] Triage pass complete in {t_triage:.2f}s ({t_triage/max(len(functions),1)*1000:.1f}ms/function)")
    return results


def print_report(results: list[FunctionInfo], verbose: bool = False) -> None:
    """Print the summary report and optionally per-function details."""

    total = len(results)
    if total == 0:
        print("[!] No functions found.")
        return

    counts = {"FLIRT_LIBRARY": 0, "TRIAGE_SKIP": 0, "TRIAGE_DEPRI": 0, "ANALYZE": 0}
    for fi in results:
        counts[fi.classification] += 1

    flirt_n = counts["FLIRT_LIBRARY"]
    skip_n = counts["TRIAGE_SKIP"]
    depri_n = counts["TRIAGE_DEPRI"]
    analyze_n = counts["ANALYZE"]
    non_flirt = total - flirt_n

    print()
    print("=" * 78)
    print("  FUNCTION TRIAGE PROTOTYPE -- SUMMARY REPORT")
    print("=" * 78)
    print()
    print(f"  Total functions discovered:           {total:>6}")
    print()
    print(f"  FLIRT-identified library functions:    {flirt_n:>6}  ({100*flirt_n/total:5.1f}%)")
    print(f"  Triage-skippable (beyond FLIRT):       {skip_n:>6}  ({100*skip_n/total:5.1f}%)")
    print(f"  Triage-deprioritized:                  {depri_n:>6}  ({100*depri_n/total:5.1f}%)")
    print(f"  Remaining for full analysis:           {analyze_n:>6}  ({100*analyze_n/total:5.1f}%)")
    print()

    if non_flirt > 0:
        print("  --- Triage impact beyond FLIRT ---")
        print(f"  Non-FLIRT functions:                  {non_flirt:>6}")
        print(f"  Additional skip by triage:             {skip_n:>6}  ({100*skip_n/non_flirt:5.1f}% of non-FLIRT)")
        print(f"  Additional deprioritize:               {depri_n:>6}  ({100*depri_n/non_flirt:5.1f}% of non-FLIRT)")
        combined = skip_n + depri_n
        print(f"  Combined triage reduction:             {combined:>6}  ({100*combined/non_flirt:5.1f}% of non-FLIRT)")
    print()

    # Break down TRIAGE_SKIP reasons
    skip_reasons: dict[str, int] = {}
    for fi in results:
        if fi.classification == "TRIAGE_SKIP":
            # normalize reason categories
            if fi.skip_reason.startswith("CRT"):
                key = "CRT/runtime name"
            elif fi.skip_reason.startswith("thunk"):
                key = "thunk/stub"
            elif fi.skip_reason.startswith("trivial"):
                key = "trivial (low complexity, 0 APIs)"
            elif fi.skip_reason.startswith("init/fini"):
                key = "init/fini section"
            else:
                key = fi.skip_reason
            skip_reasons[key] = skip_reasons.get(key, 0) + 1

    if skip_reasons:
        print("  TRIAGE_SKIP breakdown:")
        for reason, count in sorted(skip_reasons.items(), key=lambda x: -x[1]):
            print(f"    {reason:<45s} {count:>5}")
        print()

    # Deprioritize breakdown
    depri_reasons: dict[str, int] = {}
    for fi in results:
        if fi.classification == "TRIAGE_DEPRI":
            if "obfuscation" in fi.skip_reason:
                key = "potential obfuscation (high BB count)"
            elif "non-code" in fi.skip_reason:
                key = "non-code section"
            else:
                key = fi.skip_reason
            depri_reasons[key] = depri_reasons.get(key, 0) + 1

    if depri_reasons:
        print("  TRIAGE_DEPRI breakdown:")
        for reason, count in sorted(depri_reasons.items(), key=lambda x: -x[1]):
            print(f"    {reason:<45s} {count:>5}")
        print()

    # Complexity distribution of ANALYZE functions
    analyze_fns = [fi for fi in results if fi.classification == "ANALYZE"]
    if analyze_fns:
        bb_counts = [fi.bb_count for fi in analyze_fns]
        insn_counts = [fi.insn_count for fi in analyze_fns]
        api_counts = [len(fi.api_names) for fi in analyze_fns]
        print("  ANALYZE function complexity distribution:")
        print(
            f"    BB count:   min={min(bb_counts):>4}  median={sorted(bb_counts)[len(bb_counts)//2]:>4}  max={max(bb_counts):>4}"
        )
        print(
            f"    Insn count: min={min(insn_counts):>4}  median={sorted(insn_counts)[len(insn_counts)//2]:>4}  max={max(insn_counts):>4}"
        )
        print(
            f"    API refs:   min={min(api_counts):>4}  median={sorted(api_counts)[len(api_counts)//2]:>4}  max={max(api_counts):>4}"
        )
        with_apis = sum(1 for c in api_counts if c > 0)
        print(f"    Functions with API calls: {with_apis}/{len(analyze_fns)} ({100*with_apis/len(analyze_fns):.1f}%)")
        print()

    print("=" * 78)

    if verbose:
        print()
        print("  PER-FUNCTION DETAILS")
        print("  " + "-" * 76)
        fmt = "  {addr:<12s} {cls:<16s} {bbs:>4s} {insns:>5s} {size:>6s} {apis:>4s}  {name}"
        print(
            fmt.format(
                addr="ADDRESS",
                cls="CLASSIFICATION",
                bbs="BBs",
                insns="Insns",
                size="Size",
                apis="APIs",
                name="NAME / REASON",
            )
        )
        print("  " + "-" * 76)

        # Group by classification for readability
        for cls in ("FLIRT_LIBRARY", "TRIAGE_SKIP", "TRIAGE_DEPRI", "ANALYZE"):
            group = [fi for fi in results if fi.classification == cls]
            if not group:
                continue
            for fi in sorted(group, key=lambda x: x.address):
                reason_suffix = f"  [{fi.skip_reason}]" if fi.skip_reason else ""
                print(
                    fmt.format(
                        addr=f"0x{fi.address:08x}",
                        cls=fi.classification,
                        bbs=str(fi.bb_count),
                        insns=str(fi.insn_count),
                        size=str(fi.size),
                        apis=str(len(fi.api_names)),
                        name=fi.name + reason_suffix,
                    )
                )
            print()


def resolve_sigpaths(capa_root: Path) -> list[Path]:
    """Find FLIRT signature files the same way capa does."""
    sigs_dir = capa_root / "sigs"
    sigpaths = []
    if sigs_dir.is_dir():
        for f in sigs_dir.rglob("*"):
            if f.is_file() and f.suffix.lower() in (".pat", ".pat.gz", ".sig"):
                sigpaths.append(f)

    # Also check test sigs
    test_sigs = capa_root / "tests" / "data" / "sigs"
    if test_sigs.is_dir():
        for f in test_sigs.rglob("*"):
            if f.is_file() and f.suffix.lower() in (".pat", ".pat.gz", ".sig"):
                sigpaths.append(f)

    return sigpaths


def main():
    parser = argparse.ArgumentParser(
        description="Function Triage Prototype - measures how many functions can be skipped beyond FLIRT"
    )
    parser.add_argument("binary", help="Path to the PE/ELF binary to analyze")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show per-function details")
    parser.add_argument(
        "-f",
        "--format",
        default="auto",
        choices=["auto", "pe", "elf", "sc32", "sc64"],
        help="Input format (default: auto)",
    )
    parser.add_argument("--sigs", nargs="*", help="Additional FLIRT signature paths")
    args = parser.parse_args()

    binary_path = Path(args.binary).resolve()
    if not binary_path.exists():
        print(f"[!] File not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    # Determine capa root (parent of scripts/)
    capa_root = Path(__file__).resolve().parent.parent
    sigpaths = resolve_sigpaths(capa_root)
    if args.sigs:
        sigpaths.extend(Path(s).resolve() for s in args.sigs)

    print(f"[*] Using {len(sigpaths)} FLIRT signature files")

    # Suppress noisy vivisect logging
    logging.basicConfig(level=logging.WARNING)
    logging.getLogger("vivisect").setLevel(logging.WARNING)
    logging.getLogger("vtrace").setLevel(logging.WARNING)
    logging.getLogger("envi").setLevel(logging.WARNING)

    results = analyze_binary(binary_path, sigpaths, args.format)
    print_report(results, verbose=args.verbose)


if __name__ == "__main__":
    main()
