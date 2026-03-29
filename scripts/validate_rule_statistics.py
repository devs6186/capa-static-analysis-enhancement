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
Rule Statistics Validator

Independently validates rule distribution statistics using capa's actual
Rule.from_yaml parser with recursive statement-tree walking.

Expected results (against capa-rules):
  - 640/1,022 rules (62.6%) at function scope
  - 228 rules with 3+ API combinations
  - 677 unique case-insensitive regex patterns across 116 rules

Usage:
    python scripts/validate_rule_statistics.py rules/
    python scripts/validate_rule_statistics.py /path/to/capa-rules
"""

import sys
import argparse
import collections
from pathlib import Path
from typing import Union

import capa.engine as ceng
import capa.features.insn
import capa.features.common
from capa.features.common import Feature
from capa.rules import Rule, Scope


def count_api_features(node: Union[ceng.Statement, Feature]) -> int:
    """Recursively count API feature instances in a statement tree."""
    if isinstance(node, ceng.Statement):
        return sum(count_api_features(child) for child in node.get_children())
    elif isinstance(node, capa.features.insn.API):
        return 1
    return 0


def collect_regex_patterns(node: Union[ceng.Statement, Feature], patterns: set) -> None:
    """Collect all unique regex pattern strings (case-insensitive) from a statement tree."""
    if isinstance(node, ceng.Statement):
        for child in node.get_children():
            collect_regex_patterns(child, patterns)
    elif isinstance(node, capa.features.common.Regex):
        # Regex.value stores the raw pattern string including delimiters, e.g. /foo/i
        patterns.add(node.value.lower())


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate rule distribution statistics using capa's Rule.from_yaml parser."
    )
    parser.add_argument("rules_dir", type=Path, help="path to the capa rules directory")
    args = parser.parse_args()

    rules_dir: Path = args.rules_dir

    print("Rule Statistics Validator")
    print("=========================")
    print(f"Rules directory: {rules_dir.resolve()}")
    print()

    if not rules_dir.exists():
        print(f"ERROR: rules directory does not exist: {rules_dir.resolve()}")
        sys.exit(1)

    rule_files = list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml"))

    if not rule_files:
        print("0 files found - no .yml or .yaml files in the given directory.")
        print("If you are using a git submodule, run: git submodule update --init")
        sys.exit(0)

    print(f"Scanning rules...")

    total_parsed = 0
    total_errors = 0

    scope_counts: collections.Counter = collections.Counter()
    api_count_histogram: collections.Counter = collections.Counter()
    all_regex_patterns: set = set()
    rules_with_regex: set = set()

    for rule_file in rule_files:
        try:
            content = rule_file.read_text(encoding="utf-8")
            rule = Rule.from_yaml(content)
        except Exception:
            total_errors += 1
            continue

        total_parsed += 1

        # --- scope distribution ---
        static_scope = rule.scopes.static
        if static_scope is not None:
            scope_counts[static_scope] += 1

        # --- API feature count ---
        api_count = count_api_features(rule.statement)
        api_count_histogram[api_count] += 1

        # --- regex patterns ---
        rule_patterns: set = set()
        collect_regex_patterns(rule.statement, rule_patterns)
        if rule_patterns:
            rules_with_regex.add(rule.name)
            all_regex_patterns.update(rule_patterns)

    print(f"  Parsed successfully : {total_parsed:,}")
    print(f"  Parse errors        : {total_errors:,}")
    print()

    # --- scope distribution table ---
    scope_order = [
        Scope.FUNCTION,
        Scope.FILE,
        Scope.BASIC_BLOCK,
        Scope.INSTRUCTION,
        Scope.CONNECTED_BLOCKS,
        Scope.PROCESS,
        Scope.THREAD,
        Scope.SPAN_OF_CALLS,
        Scope.CALL,
    ]

    print("Scope Distribution:")
    for scope in scope_order:
        count = scope_counts.get(scope, 0)
        if count == 0:
            continue
        pct = (count / total_parsed * 100) if total_parsed else 0.0
        label = scope.value
        print(f"  {label:<16}: {count:>4} / {total_parsed:,} ({pct:4.1f}%)")

    # catch any scopes not listed above
    for scope, count in scope_counts.items():
        if scope not in scope_order:
            pct = (count / total_parsed * 100) if total_parsed else 0.0
            print(f"  {scope.value:<16}: {count:>4} / {total_parsed:,} ({pct:4.1f}%)")
    print()

    # --- API combination analysis ---
    rules_1_api = api_count_histogram.get(1, 0)
    rules_2_api = api_count_histogram.get(2, 0)
    rules_3plus_api = sum(v for k, v in api_count_histogram.items() if k >= 3)

    print("API Combination Analysis:")
    print(f"  Rules with 1 API  : {rules_1_api:>4}")
    print(f"  Rules with 2 APIs : {rules_2_api:>4}")
    print(f"  Rules with 3+ APIs: {rules_3plus_api:>4}   <- prime candidates for connected_blocks migration")
    print()

    # --- regex pattern analysis ---
    total_patterns = len(all_regex_patterns)
    total_regex_rules = len(rules_with_regex)

    print("Regex Pattern Analysis:")
    print(f"  Total unique patterns       : {total_patterns:,}")
    print(f"  Rules containing regex      : {total_regex_rules:,}")
    print()

    # --- insight summary ---
    fn_scope_count = scope_counts.get(Scope.FUNCTION, 0)
    bb_scope_count = scope_counts.get(Scope.BASIC_BLOCK, 0)
    fn_pct = (fn_scope_count / total_parsed * 100) if total_parsed else 0.0
    bb_pct = (bb_scope_count / total_parsed * 100) if total_parsed else 0.0

    print("Top scope imbalance insight:")
    print(f"  {fn_pct:.1f}% of rules use function scope vs {bb_pct:.1f}% basic_block")
    print(f"  -> {rules_3plus_api} rules with 3+ APIs are candidates for connected_blocks migration")
    print(f"  -> Configurable depth would make tighter scoping practical")


if __name__ == "__main__":
    main()
