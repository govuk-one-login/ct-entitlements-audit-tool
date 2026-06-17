#!/usr/bin/env python3

# -*- coding: utf-8 -*-


"""
JSON Diff for Entitlements Exports

Compares all.json (baseline) and all-new.json (updated) and produces
a diff of changes to users, groups, roles, permission sets, and accounts.

Usage:
    python jsondiff.py [--old OLD_FILE] [--new NEW_FILE] [--output OUTPUT_FILE]
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# from typing import Any


def load_json(filepath: Path) -> dict:
    """Load and parse a JSON file.

    Args:
        filepath: Path to the JSON file

    Returns:
        dict: parsed JSON content
    """
    with open(filepath, "r") as file_handle:
        return json.load(file_handle)


def index_by_key(items: list, key: str) -> dict:
    """Index a list of dicts by a specified key field.

    Args:
        items: list of dicts to index
        key: str field name to use as the index key

    Returns:
        dict: mapping of key values to their corresponding dicts
    """
    return {item[key]: item for item in items if item is not None}


def diff_dict(old_dict: dict, new_dict: dict) -> dict | None:
    """Compute field-level differences between two dicts.

    Args:
        old_dict: dict representing the old state
        new_dict: dict representing the new state

    Returns:
        dict: mapping of changed field names to {"old": ..., "new": ...},
                or None if no differences
    """
    changes = {}
    all_keys = set(old_dict.keys()) | set(new_dict.keys())
    for field_key in sorted(all_keys):
        old_value = old_dict.get(field_key)
        # # Sort old_value if it's a list
        # if isinstance(old_value, list):
        #     old_value = sorted(old_value)
        #     # logging.info("  Sorting old_value for %s: %s", field_key, old_value)
        new_value = new_dict.get(field_key)
        # if isinstance(new_value, list):
        #     new_value = sorted(new_value)
        #     # logging.info("  Sorting new_value for %s: %s", field_key, new_value)
        if old_value != new_value:
            changes[field_key] = {"old": old_value, "new": new_value}
    return changes if changes else None


def diff_section(old_items: list, new_items: list, key_field: str) -> dict:
    """Diff a section (users, groups, etc.) between old and new exports.

    Args:
        old_items: list of dicts from the baseline export
        new_items: list of dicts from the updated export
        key_field: str field name used to identify items (e.g. 'alias', 'name')

    Returns:
        dict: with keys 'added', 'removed', 'modified' listing the changes
    """
    old_indexed = index_by_key(old_items, key_field)
    new_indexed = index_by_key(new_items, key_field)

    old_keys = set(old_indexed.keys())
    new_keys = set(new_indexed.keys())

    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)

    for key in added:
        logging.info("  Added: %s", key)
    for key in removed:
        logging.info("  Removed: %s", key)

    modified = {}
    for item_key in sorted(old_keys & new_keys):
        changes = diff_dict(old_indexed[item_key], new_indexed[item_key])
        if changes:
            logging.info(
                "  Modified: %s (fields: %s)", item_key, ", ".join(changes.keys())
            )
            modified[item_key] = changes
    logging.info("Done diffing section %s", key_field)
    return {
        "added": [new_indexed[key] for key in added],
        "removed": [old_indexed[key] for key in removed],
        "modified": modified,
    }


def compute_diff(old_data: dict, new_data: dict) -> dict:
    """Compute full diff across all sections of the entitlements export.

    Args:
        old_data: dict full baseline export (from 'export all')
        new_data: dict full updated export (from 'export all')

    Returns:
        dict: diff results keyed by section name
    """
    sections = {
        "users": "alias",
        "groups": "name",
        "roles": "name",
        "permission_sets": "name",
        "accounts": "account",
    }

    result = {}
    for section, key_field in sections.items():
        old_items = old_data.get(section, [])
        new_items = new_data.get(section, [])
        logging.info(
            "Diffing section '%s' (old: %d items, new: %d items)",
            section,
            len(old_items),
            len(new_items),
        )
        section_diff = diff_section(old_items, new_items, key_field)
        logging.info(
            "  Section %s: added=%d, removed=%d, modified=%d",
            section,
            len(section_diff["added"]),
            len(section_diff["removed"]),
            len(section_diff["modified"]),
        )
        if section_diff["added"] or section_diff["removed"] or section_diff["modified"]:
            result[section] = section_diff
        else:
            logging.info("  No changes in '%s'", section)

    logging.info(
        "Done computing full diff. Changed sections: %s", ", ".join(result.keys())
    )
    return result


def print_summary(
    diff_result: dict, use_colour: bool = True, compact: bool = True
) -> None:
    """Print a human-readable summary of the diff.

    Args:
        diff_result: dict output from compute_diff
        use_colour: bool whether to use ANSI color codes in output
        compact: bool whether to trim long lines with '...'
    """
    if not diff_result:
        print("No changes detected.")
        return

    for section, changes in diff_result.items():
        logging.info("Printing summary for section '%s'", section)
        added_count = len(changes["added"])
        removed_count = len(changes["removed"])
        modified_count = len(changes["modified"])

        print(f"\n{'=' * 60}")
        print(
            f"  {section.upper()}: "
            f"+{added_count} added, "
            f"-{removed_count} removed, "
            f"~{modified_count} modified"
        )
        print(f"{'=' * 60}")

        if changes["added"]:
            print("\n  Added:")
            for item in changes["added"]:
                identifier = next(iter(item.values()))
                print(f"    + {identifier}")

        if changes["removed"]:
            print("\n  Removed:")
            for item in changes["removed"]:
                identifier = next(iter(item.values()))
                print(f"    - {identifier}")

        if changes["modified"]:
            print("\n  Modified:")
            for item_key, field_changes in sorted(changes["modified"].items()):
                print_diff(
                    item_key, field_changes, use_colour=use_colour, compact=compact
                )


# ANSI color codes
MAX_LINE_LENGTH = 70


def _color_codes(use_colour: bool) -> tuple:
    """Return ANSI color code strings based on colour toggle.

    Args:
        use_colour: bool whether to emit ANSI color codes

    Returns:
        tuple: (red, green, reset) strings
    """
    if use_colour:
        return "\033[31m", "\033[32m", "\033[0m"
    return "", "", ""


def _format_diff_line(
    items: list,
    removed: set,
    added: set,
    is_old: bool,
    use_colour: bool = True,
    compact: bool = True,
) -> str:
    """Format a diff line with color-highlighted changes, trimmed if too long.

    Args:
        items: list of all items on this line
        removed: set of items that were removed (only in old)
        added: set of items that were added (only in new)
        is_old: bool True if formatting the old line, False for new
        use_colour: bool whether to use ANSI color codes
        compact: bool whether to trim long lines with '...'

    Returns:
        str: formatted line with optional ANSI colors and trimming if needed
    """
    red, green, reset = _color_codes(use_colour)
    changed_set = removed if is_old else added
    color = red if is_old else green

    parts = []
    for item in items:
        item_str = str(item)
        if item_str in changed_set:
            parts.append(f"{color}{item_str}{reset}")
        else:
            parts.append(item_str)

    full_line = ", ".join(parts)

    if not compact:
        return full_line

    plain_line = ", ".join(str(item) for item in items)

    if len(plain_line) <= MAX_LINE_LENGTH:
        return full_line

    # Trim unchanged items around changes, keeping context
    trimmed_parts = []
    last_was_ellipsis = False
    for item in items:
        item_str = str(item)
        if item_str in changed_set:
            if last_was_ellipsis:
                pass  # ellipsis already added
            trimmed_parts.append(f"{color}{item_str}{reset}")
            last_was_ellipsis = False
        else:
            if not last_was_ellipsis:
                trimmed_parts.append("...")
                last_was_ellipsis = True

    return ", ".join(trimmed_parts)


def print_diff(
    item_key: str, field_changes: dict, use_colour: bool = True, compact: bool = True
) -> None:
    """Print the field-level changes for a single modified item with git-diff style coloring.

    Args:
        item_key: str identifier of the modified item
        field_changes: dict mapping field names to {'old': ..., 'new': ...}
        use_colour: bool whether to use ANSI color codes
        compact: bool whether to trim long lines with '...'
    """
    red, green, reset = _color_codes(use_colour)
    print(f"    ~ {item_key}:")
    try:
        sorted_fields = sorted(field_changes.items())
    except TypeError:
        sorted_fields = list(field_changes.items())
    for field_name, values in sorted_fields:
        try:
            old = sorted(values["old"], key=str)
        except TypeError:
            old = values["old"]
        try:
            new = sorted(values["new"], key=str)
        except TypeError:
            new = values["new"]

        old_set = set(str(item) for item in old)
        new_set = set(str(item) for item in new)
        removed = old_set - new_set
        added = new_set - old_set

        old_line = _format_diff_line(
            old, removed, added, is_old=True, use_colour=use_colour, compact=compact
        )
        new_line = _format_diff_line(
            new, removed, added, is_old=False, use_colour=use_colour, compact=compact
        )

        print(f"        {field_name}:")
        print(f"      {red}-{reset} {old_line}")
        print(f"      {green}+{reset} {new_line}")


def build_parser() -> argparse.ArgumentParser:
    """Build argument parser for the jsondiff script.

    Returns:
        argparse.ArgumentParser: configured parser
    """
    parser = argparse.ArgumentParser(description="Diff two entitlements JSON exports")
    parser.add_argument(
        "--old",
        type=str,
        default="all.json",
        help="Path to baseline JSON export (default: all.json)",
    )
    parser.add_argument(
        "--new",
        type=str,
        default="all-new.json",
        help="Path to updated JSON export (default: all-new.json)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Write diff as JSON to this file (default: print summary to stdout)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )
    colour_group = parser.add_mutually_exclusive_group()
    colour_group.add_argument(
        "--colour",
        "--color",
        dest="colour",
        action="store_true",
        default=True,
        help="Enable coloured output (default)",
    )
    colour_group.add_argument(
        "--no-colour",
        "--no-color",
        dest="colour",
        action="store_false",
        help="Disable coloured output",
    )
    compact_group = parser.add_mutually_exclusive_group()
    compact_group.add_argument(
        "--compact",
        dest="compact",
        action="store_true",
        default=True,
        help="Trim long lines with '...' (default)",
    )
    compact_group.add_argument(
        "--no-compact",
        dest="compact",
        action="store_false",
        help="Show full old/new lists without trimming",
    )
    return parser


def main():
    """Entry point for the jsondiff script."""
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )
    logging.getLogger().setLevel(logging.CRITICAL)

    old_path = Path(args.old)
    new_path = Path(args.new)

    if not old_path.exists():
        print(f"Error: file not found: {old_path}", file=sys.stderr)
        sys.exit(1)
    if not new_path.exists():
        print(f"Error: file not found: {new_path}", file=sys.stderr)
        sys.exit(1)

    logging.info("Loading old file: %s", old_path)
    try:
        old_data = load_json(old_path)
    except (json.JSONDecodeError, ValueError) as error:
        print(f"Error: failed to parse {old_path}: {error}", file=sys.stderr)
        sys.exit(1)

    logging.info("Loading new file: %s", new_path)
    try:
        new_data = load_json(new_path)
    except (json.JSONDecodeError, ValueError) as error:
        print(f"Error: failed to parse {new_path}: {error}", file=sys.stderr)
        sys.exit(1)

    logging.info("Computing diff...")
    diff_result = compute_diff(old_data, new_data)
    logging.info("Diff complete. %d section(s) with changes.", len(diff_result))

    if args.output:
        output_path = Path(args.output)
        with open(output_path, "w") as output_file:
            json.dump(diff_result, output_file, indent=2, default=str)
        print(f"Diff written to {output_path}")
    else:
        print_summary(diff_result, use_colour=args.colour, compact=args.compact)
        # if diff_result:
        #     print(f"\n{'='*60}")
        #     print("  JSON diff:")
        #     print(f"{'='*60}")
        #     print(json.dumps(diff_result, indent=2, default=str))


if __name__ == "__main__":
    import signal

    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    try:
        main()
    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)
