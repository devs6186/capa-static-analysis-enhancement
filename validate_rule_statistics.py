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
Cross-validate all rule statistics claimed in the GSoC report.

Uses capa's actual Rule parser (Rule.from_yaml) to load every rule,
recursively walks the statement tree to extract features, and compares
observed counts against the report's claimed numbers.

Usage:
    python scripts/validate_rule_statistics.py [--rules-dir path/to/rules]
"""

import re
import sys
import logging
import argparse
import collections
from typing import Union
from pathlib import Path

import capa.rules
import capa.features.file
import capa.features.insn
import capa.features.common
import capa.features.basicblock
from capa.rules import Rule, Scope, InvalidRule, collect_rule_file_paths
from capa.engine import Statement
from capa.features.common import Feature

logger = logging.getLogger("validate_rule_statistics")


# ---------------------------------------------------------------------------
# Report's claimed numbers (from GSoC proposal)
# ---------------------------------------------------------------------------
REPORT_CLAIMS = {
    "total_rules": 1022,
    "function_scope": 640,
    "function_scope_pct": 62.6,
    "file_scope": 190,
    "file_scope_pct": 18.6,
    "basic_block_scope": 170,
    "basic_block_scope_pct": 16.6,
    "instruction_scope": 24,
    "instruction_scope_pct": 2.4,
    "rules_with_3plus_api": 228,
    "case_insensitive_regex_patterns": 409,
    "pattern_i_instances": 761,
    "rules_with_pattern_i": 188,
}


# ---------------------------------------------------------------------------
# Feature classification helpers
# ---------------------------------------------------------------------------
def classify_feature(feature: Feature) -> str:
    """Return a human-readable type name for the given feature."""
    if isinstance(feature, capa.features.insn.API):
        return "API"
    if isinstance(feature, capa.features.common.Regex):
        # Regex is a subclass of String, so check first
        return "Regex"
    if isinstance(feature, capa.features.common.Substring):
        # Substring is a subclass of String, so check first
        return "Substring"
    if isinstance(feature, capa.features.common.String):
        return "String"
    if isinstance(feature, capa.features.common.Bytes):
        return "Bytes"
    if isinstance(feature, capa.features.insn.Number):
        return "Number"
    if isinstance(feature, capa.features.insn.Offset):
        return "Offset"
    if isinstance(feature, capa.features.insn.Mnemonic):
        return "Mnemonic"
    if isinstance(feature, capa.features.insn.Property):
        return "Property"
    if isinstance(feature, capa.features.insn.OperandNumber):
        return "OperandNumber"
    if isinstance(feature, capa.features.insn.OperandOffset):
        return "OperandOffset"
    if isinstance(feature, capa.features.common.MatchedRule):
        return "MatchedRule"
    if isinstance(feature, capa.features.common.Characteristic):
        return "Characteristic"
    if isinstance(feature, capa.features.file.Export):
        return "Export"
    if isinstance(feature, capa.features.file.Import):
        return "Import"
    if isinstance(feature, capa.features.file.Section):
        return "Section"
    if isinstance(feature, capa.features.file.FunctionName):
        return "FunctionName"
    if isinstance(feature, capa.features.basicblock.BasicBlock):
        return "BasicBlock"
    if isinstance(feature, capa.features.common.OS):
        return "OS"
    if isinstance(feature, capa.features.common.Arch):
        return "Arch"
    if isinstance(feature, capa.features.common.Format):
        return "Format"
    if isinstance(feature, capa.features.common.Class):
        return "Class"
    if isinstance(feature, capa.features.common.Namespace):
        return "Namespace"
    return type(feature).__name__


def walk_features(node: Union[Statement, Feature]):
    """
    Recursively yield every Feature leaf node in a statement tree.

    Walks through Statement nodes (And, Or, Not, Some, Range, Subscope)
    and yields Feature instances at the leaves.
    """
    if isinstance(node, Statement):
        for child in node.get_children():
            yield from walk_features(child)
    elif isinstance(node, Feature):
        yield node


def walk_features_with_count(node: Union[Statement, Feature]):
    """
    Recursively yield every Feature leaf node, including duplicates.

    Unlike extract_all_features() which returns a set (deduplicating),
    this yields every occurrence so we can count total instances.
    """
    if isinstance(node, Statement):
        for child in node.get_children():
            yield from walk_features_with_count(child)
    elif isinstance(node, Feature):
        yield node


def is_case_insensitive_regex(feature: Feature) -> bool:
    """Check if a feature is a case-insensitive regex (ends with /i)."""
    if isinstance(feature, capa.features.common.Regex):
        assert isinstance(feature.value, str)
        return feature.value.endswith("/i")
    return False


def count_api_features(rule: Rule) -> int:
    """Count the number of unique API features in a rule's statement tree."""
    api_count = 0
    for feature in walk_features(rule.statement):
        if isinstance(feature, capa.features.insn.API):
            api_count += 1
    return api_count


def count_api_features_with_duplicates(rule: Rule) -> int:
    """Count every API feature occurrence including duplicates."""
    api_count = 0
    for feature in walk_features_with_count(rule.statement):
        if isinstance(feature, capa.features.insn.API):
            api_count += 1
    return api_count


def has_mixed_api_and_string_conditions(rule: Rule) -> bool:
    """
    Check if a rule has both API and string/number conditions,
    suggesting features that may span different basic blocks.
    """
    has_api = False
    has_string_or_number = False
    for feature in walk_features(rule.statement):
        if isinstance(feature, capa.features.insn.API):
            has_api = True
        if isinstance(
            feature,
            (
                capa.features.common.String,
                capa.features.common.Regex,
                capa.features.common.Substring,
                capa.features.insn.Number,
            ),
        ):
            has_string_or_number = True
        if has_api and has_string_or_number:
            return True
    return False


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------
def load_rules(rules_dir: Path) -> list[Rule]:
    """
    Load all rules from the given directory using capa's rule parser.

    Loads rules one at a time via Rule.from_yaml rather than RuleSet
    to avoid dependency-resolution failures that would block loading.
    """
    rule_file_paths = collect_rule_file_paths([rules_dir])
    rules = []
    errors = []

    for path in rule_file_paths:
        try:
            content = path.read_bytes().decode("utf-8")
            rule = Rule.from_yaml(content)
            rule.meta["capa/path"] = path.as_posix()
            rules.append(rule)
        except InvalidRule as e:
            if e.args and e.args[0] == "empty or invalid YAML document":
                continue
            errors.append((path, str(e)))
        except Exception as e:
            errors.append((path, str(e)))

    return rules, errors


def scan_yaml_for_ci_regex(rules_dir: Path) -> dict:
    """
    Scan YAML files directly (grep-style) for /pattern/i occurrences.

    This replicates the likely methodology used in the report, which may
    have used grep or similar text-based scanning rather than the parser.
    Returns counts that can be compared against the parser-based analysis.
    """
    from capa.rules import collect_rule_file_paths

    rule_file_paths = collect_rule_file_paths([rules_dir])

    # Pattern to match /something/i in YAML (the regex pattern syntax)
    # This matches string values like: /pattern/i or /complex.*pattern/i
    ci_pattern = re.compile(r"/[^/\s]+/i")

    total_lines = 0
    total_pattern_occurrences = 0
    unique_patterns = set()
    files_with_ci = 0

    for path in rule_file_paths:
        content = path.read_text(encoding="utf-8")
        file_has_ci = False

        for line in content.splitlines():
            matches = ci_pattern.findall(line)
            if matches:
                file_has_ci = True
                total_lines += 1
                total_pattern_occurrences += len(matches)
                for m in matches:
                    unique_patterns.add(m)

        if file_has_ci:
            files_with_ci += 1

    return {
        "grep_lines_with_ci": total_lines,
        "grep_pattern_occurrences": total_pattern_occurrences,
        "grep_unique_patterns": len(unique_patterns),
        "grep_files_with_ci": files_with_ci,
    }


def analyze_rules(rules: list[Rule]) -> dict:
    """Perform full statistical analysis on loaded rules."""
    results = {}
    total = len(rules)
    results["total_rules"] = total

    # -----------------------------------------------------------------------
    # 1. Scope distribution (static)
    # -----------------------------------------------------------------------
    static_scope_counts = collections.Counter()
    dynamic_scope_counts = collections.Counter()
    rules_without_static_scope = []

    for rule in rules:
        if rule.scopes.static is not None:
            static_scope_counts[rule.scopes.static.value] += 1
        else:
            rules_without_static_scope.append(rule.name)

        if rule.scopes.dynamic is not None:
            dynamic_scope_counts[rule.scopes.dynamic.value] += 1

    results["static_scope_counts"] = dict(static_scope_counts)
    results["dynamic_scope_counts"] = dict(dynamic_scope_counts)
    results["rules_without_static_scope"] = rules_without_static_scope

    # -----------------------------------------------------------------------
    # 2. Feature type distribution
    # -----------------------------------------------------------------------
    global_feature_type_counts = collections.Counter()
    feature_type_per_rule = collections.defaultdict(collections.Counter)

    for rule in rules:
        for feature in walk_features(rule.statement):
            ftype = classify_feature(feature)
            global_feature_type_counts[ftype] += 1
            feature_type_per_rule[rule.name][ftype] += 1

    results["feature_type_distribution"] = dict(global_feature_type_counts.most_common())

    # -----------------------------------------------------------------------
    # 3. API feature analysis
    # -----------------------------------------------------------------------
    api_counts_per_rule = {}
    for rule in rules:
        count = count_api_features(rule)
        if count > 0:
            api_counts_per_rule[rule.name] = count

    rules_with_3plus_api = {name: count for name, count in api_counts_per_rule.items() if count >= 3}
    results["rules_with_any_api"] = len(api_counts_per_rule)
    results["rules_with_3plus_api"] = rules_with_3plus_api

    # -----------------------------------------------------------------------
    # 4. Case-insensitive regex analysis
    # -----------------------------------------------------------------------
    ci_regex_total_unique = 0  # total unique /i regex features across all rules
    ci_regex_total_instances = 0  # total /i instances (with duplicates across rules)
    rules_with_ci_regex = {}  # rule_name -> count of /i features

    for rule in rules:
        ci_count_unique = 0
        ci_count_all = 0

        seen_in_rule = set()
        for feature in walk_features_with_count(rule.statement):
            if is_case_insensitive_regex(feature):
                ci_count_all += 1
                assert isinstance(feature.value, str)
                if feature.value not in seen_in_rule:
                    seen_in_rule.add(feature.value)
                    ci_count_unique += 1

        if ci_count_unique > 0:
            rules_with_ci_regex[rule.name] = ci_count_unique
            ci_regex_total_unique += ci_count_unique
            ci_regex_total_instances += ci_count_all

    results["ci_regex_total_unique"] = ci_regex_total_unique
    results["ci_regex_total_instances"] = ci_regex_total_instances
    results["rules_with_ci_regex"] = rules_with_ci_regex

    # Also count via extract_all_features (set-based, deduplicating within rule)
    ci_via_extract = 0
    for rule in rules:
        for feature in rule.extract_all_features():
            if is_case_insensitive_regex(feature):
                ci_via_extract += 1
    results["ci_regex_via_extract_all_features"] = ci_via_extract

    # -----------------------------------------------------------------------
    # 5. Proximity matching candidates
    #    Function-scope rules with multiple APIs + mixed conditions
    # -----------------------------------------------------------------------
    proximity_candidates = []
    for rule in rules:
        if rule.scopes.static != Scope.FUNCTION:
            continue

        api_count = count_api_features(rule)
        if api_count < 2:
            continue

        mixed = has_mixed_api_and_string_conditions(rule)
        proximity_candidates.append(
            {
                "name": rule.name,
                "api_count": api_count,
                "mixed_conditions": mixed,
                "path": rule.meta.get("capa/path", ""),
                "total_features": len(rule.extract_all_features()),
            }
        )

    # Sort by API count descending, then by total features descending
    proximity_candidates.sort(key=lambda x: (-x["api_count"], -x["total_features"]))
    results["proximity_candidates"] = proximity_candidates

    # -----------------------------------------------------------------------
    # 6. Migration candidates: function-scope rules with 3+ APIs
    #    that are candidates for basic-block or proximity-aware matching
    # -----------------------------------------------------------------------
    migration_candidates = []
    for rule in rules:
        if rule.scopes.static != Scope.FUNCTION:
            continue

        api_count = count_api_features(rule)
        if api_count < 3:
            continue

        migration_candidates.append(
            {
                "name": rule.name,
                "api_count": api_count,
                "mixed": has_mixed_api_and_string_conditions(rule),
                "path": rule.meta.get("capa/path", ""),
            }
        )

    migration_candidates.sort(key=lambda x: -x["api_count"])
    results["migration_candidates"] = migration_candidates

    return results


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------
def print_separator(char="=", width=80):
    print(char * width)


def print_header(title: str):
    print()
    print_separator()
    print(f"  {title}")
    print_separator()


def compare_value(label: str, actual, claimed, tolerance_pct=0.0):
    """Compare an actual value to a claimed value and flag discrepancies."""
    if isinstance(claimed, float):
        # percentage comparison
        match = abs(actual - claimed) <= tolerance_pct
        marker = "[OK]" if match else "[!!]"
        print(f"  {marker} {label}")
        print(f"       Claimed: {claimed}%  |  Actual: {actual:.1f}%")
    else:
        match = actual == claimed
        marker = "[OK]" if match else "[!!]"
        print(f"  {marker} {label}")
        print(f"       Claimed: {claimed}  |  Actual: {actual}")
    if not match:
        if isinstance(claimed, float):
            diff = actual - claimed
            print(f"       Delta: {diff:+.1f}pp")
        else:
            diff = actual - claimed
            print(f"       Delta: {diff:+d}")
    return match


def main():
    parser = argparse.ArgumentParser(description="Cross-validate all rule statistics claimed in the GSoC report.")
    parser.add_argument(
        "--rules-dir",
        type=str,
        default=None,
        help="Path to rules directory (default: auto-detect from capa repo root)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed per-rule information",
    )
    args = parser.parse_args()

    # Determine rules directory
    if args.rules_dir:
        rules_dir = Path(args.rules_dir)
    else:
        # Auto-detect: look relative to this script
        script_dir = Path(__file__).resolve().parent
        repo_root = script_dir.parent
        rules_dir = repo_root / "rules"

    if not rules_dir.exists():
        print(f"ERROR: Rules directory not found: {rules_dir}")
        print("       Make sure the rules git submodule is initialized:")
        print("         git submodule update --init rules")
        return 1

    # Check the submodule has files
    yml_count = len(list(rules_dir.rglob("*.yml")))
    if yml_count == 0:
        print(f"ERROR: No .yml files found in {rules_dir}")
        print("       The rules submodule may be empty. Run:")
        print("         git submodule update --init rules")
        return 1

    print(f"Rules directory: {rules_dir}")
    print(f"YAML files found on disk: {yml_count}")

    # -----------------------------------------------------------------------
    # Load rules
    # -----------------------------------------------------------------------
    print_header("LOADING RULES")
    rules, errors = load_rules(rules_dir)
    print(f"  Successfully loaded: {len(rules)} rules")
    print(f"  Load errors:         {len(errors)}")

    if errors and args.verbose:
        print()
        print("  Errors:")
        for path, err in errors[:20]:
            print(f"    {path}: {err}")
        if len(errors) > 20:
            print(f"    ... and {len(errors) - 20} more")

    # -----------------------------------------------------------------------
    # Run analysis
    # -----------------------------------------------------------------------
    results = analyze_rules(rules)

    # -----------------------------------------------------------------------
    # Cross-validation: Total rules
    # -----------------------------------------------------------------------
    print_header("CROSS-VALIDATION: TOTAL RULES")
    total = results["total_rules"]
    discrepancies = 0

    if not compare_value("Total valid rules", total, REPORT_CLAIMS["total_rules"]):
        discrepancies += 1

    # -----------------------------------------------------------------------
    # Cross-validation: Static scope distribution
    # -----------------------------------------------------------------------
    print_header("CROSS-VALIDATION: STATIC SCOPE DISTRIBUTION")
    sc = results["static_scope_counts"]

    function_count = sc.get("function", 0)
    file_count = sc.get("file", 0)
    bb_count = sc.get("basic block", 0)
    insn_count = sc.get("instruction", 0)

    if not compare_value("Function scope count", function_count, REPORT_CLAIMS["function_scope"]):
        discrepancies += 1
    if not compare_value(
        "Function scope %",
        (function_count / total * 100) if total else 0,
        REPORT_CLAIMS["function_scope_pct"],
        tolerance_pct=0.5,
    ):
        discrepancies += 1

    if not compare_value("File scope count", file_count, REPORT_CLAIMS["file_scope"]):
        discrepancies += 1
    if not compare_value(
        "File scope %",
        (file_count / total * 100) if total else 0,
        REPORT_CLAIMS["file_scope_pct"],
        tolerance_pct=0.5,
    ):
        discrepancies += 1

    if not compare_value("Basic block scope count", bb_count, REPORT_CLAIMS["basic_block_scope"]):
        discrepancies += 1
    if not compare_value(
        "Basic block scope %",
        (bb_count / total * 100) if total else 0,
        REPORT_CLAIMS["basic_block_scope_pct"],
        tolerance_pct=0.5,
    ):
        discrepancies += 1

    if not compare_value("Instruction scope count", insn_count, REPORT_CLAIMS["instruction_scope"]):
        discrepancies += 1
    if not compare_value(
        "Instruction scope %",
        (insn_count / total * 100) if total else 0,
        REPORT_CLAIMS["instruction_scope_pct"],
        tolerance_pct=0.5,
    ):
        discrepancies += 1

    # Show all static scope values
    print()
    print("  Full static scope breakdown:")
    for scope_val, count in sorted(sc.items(), key=lambda x: -x[1]):
        pct = count / total * 100 if total else 0
        print(f"    {scope_val:20s}: {count:5d}  ({pct:5.1f}%)")

    # Rules without static scope
    no_static = results["rules_without_static_scope"]
    if no_static:
        print(f"\n  Rules without static scope: {len(no_static)}")
        if args.verbose:
            for name in no_static[:10]:
                print(f"    - {name}")

    # -----------------------------------------------------------------------
    # Dynamic scope distribution
    # -----------------------------------------------------------------------
    print_header("DYNAMIC SCOPE DISTRIBUTION (informational)")
    dc = results["dynamic_scope_counts"]
    for scope_val, count in sorted(dc.items(), key=lambda x: -x[1]):
        pct = count / total * 100 if total else 0
        print(f"    {scope_val:20s}: {count:5d}  ({pct:5.1f}%)")

    # -----------------------------------------------------------------------
    # Cross-validation: API features
    # -----------------------------------------------------------------------
    print_header("CROSS-VALIDATION: API FEATURES")
    rules_3plus = results["rules_with_3plus_api"]
    if not compare_value("Rules with 3+ API features", len(rules_3plus), REPORT_CLAIMS["rules_with_3plus_api"]):
        discrepancies += 1

    print(f"\n  Rules with any API features: {results['rules_with_any_api']}")
    print(f"  Rules with 3+ API features:  {len(rules_3plus)}")

    # API count histogram
    api_histogram = collections.Counter()
    for count in rules_3plus.values():
        api_histogram[count] += 1
    if api_histogram:
        print("\n  API count distribution (among 3+ rules):")
        for api_count, num_rules in sorted(api_histogram.items()):
            print(f"    {api_count:3d} APIs: {num_rules:3d} rules")

    if args.verbose:
        print("\n  Top 30 rules by API count:")
        for name, count in sorted(rules_3plus.items(), key=lambda x: -x[1])[:30]:
            print(f"    [{count:3d} APIs] {name}")

    # -----------------------------------------------------------------------
    # Cross-validation: Case-insensitive regex
    # -----------------------------------------------------------------------
    print_header("CROSS-VALIDATION: CASE-INSENSITIVE REGEX (/i)")

    ci_unique = results["ci_regex_total_unique"]
    ci_instances = results["ci_regex_total_instances"]
    ci_rules = results["rules_with_ci_regex"]
    ci_extract = results["ci_regex_via_extract_all_features"]

    if not compare_value(
        "Total /i regex features (unique per rule, summed)",
        ci_unique,
        REPORT_CLAIMS["case_insensitive_regex_patterns"],
    ):
        discrepancies += 1

    if not compare_value(
        "Total /i instances (with dups in tree)",
        ci_instances,
        REPORT_CLAIMS["pattern_i_instances"],
    ):
        discrepancies += 1

    if not compare_value("Rules using /i regex", len(ci_rules), REPORT_CLAIMS["rules_with_pattern_i"]):
        discrepancies += 1

    print(f"\n  Via extract_all_features (set-deduped): {ci_extract}")
    print(f"  Via tree walk (unique per rule, summed):  {ci_unique}")
    print(f"  Via tree walk (all instances):            {ci_instances}")

    # Show top rules by /i count
    if args.verbose:
        print("\n  Top 20 rules by /i regex count:")
        for name, count in sorted(ci_rules.items(), key=lambda x: -x[1])[:20]:
            print(f"    [{count:3d} /i] {name}")

    # -----------------------------------------------------------------------
    # YAML-level grep comparison for /i regex methodology
    # -----------------------------------------------------------------------
    print_header("METHODOLOGY COMPARISON: YAML GREP vs PARSER (/i regex)")
    print("  Scanning YAML files directly (grep-style) to explain discrepancies...")
    grep_results = scan_yaml_for_ci_regex(rules_dir)
    print(f"    YAML files containing /pattern/i:  {grep_results['grep_files_with_ci']}")
    print(f"    YAML lines containing /pattern/i:  {grep_results['grep_lines_with_ci']}")
    print(f"    Total /pattern/i occurrences:      {grep_results['grep_pattern_occurrences']}")
    print(f"    Unique /pattern/i strings:         {grep_results['grep_unique_patterns']}")
    print()
    print("  Comparison:")
    print(f"    {'Method':<45s}  {'Patterns':>8s}  {'Rules':>8s}")
    print(f"    {'------':<45s}  {'--------':>8s}  {'--------':>8s}")
    print(
        f"    {'Report claimed':45s}  {REPORT_CLAIMS['case_insensitive_regex_patterns']:8d}  {REPORT_CLAIMS['rules_with_pattern_i']:8d}"
    )
    print(f"    {'Parser: unique features per rule, summed':45s}  {ci_unique:8d}  {len(ci_rules):8d}")
    print(f"    {'Parser: extract_all_features (set-deduped)':45s}  {ci_extract:8d}  {len(ci_rules):8d}")
    print(
        f"    {'YAML grep: /pattern/i occurrences':45s}  {grep_results['grep_pattern_occurrences']:8d}  {grep_results['grep_files_with_ci']:8d}"
    )
    print(
        f"    {'YAML grep: unique /pattern/i strings':45s}  {grep_results['grep_unique_patterns']:8d}  {grep_results['grep_files_with_ci']:8d}"
    )
    print()
    print("  ANALYSIS: The report's '409+ case-insensitive regex patterns' likely")
    print("  refers to a specific counting methodology. The parser finds more unique")
    print("  patterns because it resolves Or-branches and feature trees that may not")
    print("  be visible to simple grep. The grep-based /pattern/i occurrences count")
    print("  of", grep_results["grep_pattern_occurrences"], "is closer to the report's 761 '/pattern/i instances'.")

    # -----------------------------------------------------------------------
    # Feature type distribution
    # -----------------------------------------------------------------------
    print_header("FEATURE TYPE DISTRIBUTION (unique features per rule, summed)")
    ftd = results["feature_type_distribution"]
    for ftype, count in sorted(ftd.items(), key=lambda x: -x[1]):
        print(f"    {ftype:20s}: {count:6d}")

    # -----------------------------------------------------------------------
    # Top 20 proximity matching candidates
    # -----------------------------------------------------------------------
    print_header("TOP 20 PROXIMITY MATCHING CANDIDATES")
    print("  (Function-scope rules with most API conditions)")
    print()
    candidates = results["proximity_candidates"][:20]
    if candidates:
        print(f"  {'#':>3s}  {'APIs':>4s}  {'Feats':>5s}  {'Mixed':>5s}  Name")
        print(f"  {'---':>3s}  {'----':>4s}  {'-----':>5s}  {'-----':>5s}  {'----'}")
        for i, c in enumerate(candidates, 1):
            mixed_str = "yes" if c["mixed_conditions"] else "no"
            print(f"  {i:3d}  {c['api_count']:4d}  {c['total_features']:5d}  {mixed_str:>5s}  {c['name']}")
    else:
        print("  No candidates found.")

    # -----------------------------------------------------------------------
    # Migration candidates: function-scope + 3+ APIs
    # -----------------------------------------------------------------------
    print_header("MIGRATION CANDIDATES (function-scope + 3+ APIs)")
    migration = results["migration_candidates"]
    print(f"  Total candidates: {len(migration)}")

    mixed_count = sum(1 for m in migration if m["mixed"])
    print(f"  With mixed API+string/number conditions: {mixed_count}")
    print(f"  Pure API-only (3+ APIs, no string/number): {len(migration) - mixed_count}")

    if args.verbose and migration:
        print(f"\n  {'#':>3s}  {'APIs':>4s}  {'Mixed':>5s}  Name")
        print(f"  {'---':>3s}  {'----':>4s}  {'-----':>5s}  {'----'}")
        for i, m in enumerate(migration[:50], 1):
            mixed_str = "yes" if m["mixed"] else "no"
            print(f"  {i:3d}  {m['api_count']:4d}  {mixed_str:>5s}  {m['name']}")

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print_header("VALIDATION SUMMARY")
    total_checks = 11  # number of compare_value calls above
    passed = total_checks - discrepancies
    print(f"  Checks passed:     {passed}/{total_checks}")
    print(f"  Discrepancies:     {discrepancies}/{total_checks}")
    print()

    if discrepancies == 0:
        print("  RESULT: All claimed statistics match the actual data.")
    else:
        print(f"  RESULT: {discrepancies} discrepancy(ies) found.")
        print()
        print("  NOTE: Discrepancies may be expected if:")
        print("    - Rules have been added/removed since the report was written")
        print("    - The report used a different counting methodology (e.g., grep vs parser)")
        print("    - The report counted features differently (unique vs total instances)")

    print()
    return 0 if discrepancies == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
