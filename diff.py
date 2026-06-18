import argparse
import csv
import sys
from collections import defaultdict


def load(path):
    with open(path) as f:
        reader = csv.reader(f)
        header = next(reader)
        rows = set(tuple(r) for r in reader)
    return header, rows


def detect_key_columns(header):
    """Determine which columns form the identity key vs mutable attributes.

    For user-permission CSVs (user, account, permission_set, type): key is user+account+permission_set.
    For list-users CSVs (alias, display_name, email, pod, team): key is alias+pod+team
    (a user can belong to multiple teams).
    """
    lower = [h.lower() for h in header]
    if "alias" in lower and "pod" in lower and "team" in lower:
        return [lower.index("alias"), lower.index("pod"), lower.index("team")]
    if "alias" in lower:
        return [lower.index("alias")]
    if "user" in lower and "account" in lower and "permission_set" in lower:
        return [lower.index("user"), lower.index("account"), lower.index("permission_set")]
    # Default: entire row is the key (no MODIFIED detection)
    return list(range(len(header)))


def compute_diff(header, before, after):
    key_cols = detect_key_columns(header)
    all_cols = key_cols == list(range(len(header)))

    if all_cols:
        # No MODIFIED detection possible
        removed = [("REMOVED", row) for row in (before - after)]
        added = [("ADDED", row) for row in (after - before)]
        return removed + added

    def make_key(row):
        return tuple(row[i] for i in key_cols)

    before_by_key = {make_key(row): row for row in before}
    after_by_key = {make_key(row): row for row in after}

    before_keys = set(before_by_key.keys())
    after_keys = set(after_by_key.keys())

    changes = []
    for key in before_keys - after_keys:
        changes.append(("REMOVED", before_by_key[key]))
    for key in after_keys - before_keys:
        changes.append(("ADDED", after_by_key[key]))
    for key in before_keys & after_keys:
        if before_by_key[key] != after_by_key[key]:
            changes.append(("MODIFIED", after_by_key[key], before_by_key[key]))

    return changes


def get_group_key(header, row):
    """Group by user/alias if available, otherwise by account."""
    lower = [h.lower() for h in header]
    for field in ("user", "alias"):
        if field in lower:
            return row[lower.index(field)]
    if "account" in lower:
        return row[lower.index("account")]
    return "all"


def get_group_label(header):
    lower = [h.lower() for h in header]
    for field in ("user", "alias"):
        if field in lower:
            return field.capitalize()
    if "account" in lower:
        return "Account"
    return "Group"


def sort_changes(changes):
    """Sort: REMOVED first, then MODIFIED, then ADDED. Within each, alphabetical."""
    order = {"REMOVED": 0, "MODIFIED": 1, "ADDED": 2}
    return sorted(changes, key=lambda c: (order.get(c[0], 9), c[1]))


def filter_changes(changes, header, account=None, user=None):
    if not account and not user:
        return changes
    lower = [h.lower() for h in header]
    filtered = []
    for change in changes:
        row = change[1]
        if account and "account" in lower:
            if row[lower.index("account")] != account:
                continue
        if user:
            for field in ("user", "alias"):
                if field in lower and row[lower.index(field)] != user:
                    break
            else:
                if user and not any(f in lower for f in ("user", "alias")):
                    continue
        filtered.append(change)
    return filtered


def write_csv(output_path, header, changes):
    with open(output_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Change"] + header)
        for change in changes:
            if change[0] == "MODIFIED":
                # Show the new state with a note about what changed
                w.writerow(["MODIFIED"] + list(change[1]))
            else:
                w.writerow([change[0]] + list(change[1]))


def write_summary(summary_path, header, changes):
    with open(summary_path, "a") as f:
        if not changes:
            f.write("No entitlement changes detected.\n")
            return

        lower = [h.lower() for h in header]

        # Summary counts
        counts = defaultdict(int)
        for c in changes:
            counts[c[0]] += 1
        parts = []
        if counts["ADDED"]:
            parts.append(f"{counts['ADDED']} added")
        if counts["REMOVED"]:
            parts.append(f"{counts['REMOVED']} removed")
        if counts["MODIFIED"]:
            parts.append(f"{counts['MODIFIED']} modified")
        f.write(f"**{', '.join(parts)}** ({sum(counts.values())} total changes)\n\n")

        # Detect if this is a detailed user-permission CSV
        has_user = "user" in lower or "alias" in lower
        has_account = "account" in lower
        has_permission = "permission_set" in lower
        has_chain = "group" in lower and "role" in lower and "assignment_set" in lower

        if has_user and has_account and has_permission:
            _write_detailed_user_summary(f, header, lower, changes, has_chain)
        else:
            _write_table_summary(f, header, changes)


def _write_detailed_user_summary(f, header, lower, changes, has_chain):
    """Write a rich summary grouped by user, showing accounts and permissions."""
    user_col = lower.index("user") if "user" in lower else lower.index("alias")
    account_col = lower.index("account")
    perm_col = lower.index("permission_set")
    type_col = lower.index("type")
    group_col = lower.index("group") if has_chain else None
    role_col = lower.index("role") if has_chain else None
    assignment_col = lower.index("assignment_set") if has_chain else None

    # Group changes by user
    by_user = defaultdict(list)
    for change in changes:
        row = change[1]
        by_user[row[user_col]].append(change)

    for user in sorted(by_user.keys()):
        user_changes = sort_changes(by_user[user])
        f.write(f"### {user}\n\n")

        # Sub-group by account
        by_account = defaultdict(list)
        for change in user_changes:
            by_account[change[1][account_col]].append(change)

        for account in sorted(by_account.keys()):
            f.write(f"**Account: {account}**\n\n")
            for change in by_account[account]:
                row = change[1]
                prefix = "+" if change[0] == "ADDED" else "-" if change[0] == "REMOVED" else "~"
                perm = row[perm_col]
                perm_type = row[type_col]

                if has_chain:
                    chain = f"{row[group_col]} → {row[role_col]} → {row[assignment_col]}"
                    f.write(f"- {prefix} **{change[0]}** `{perm}` ({perm_type}) via `{chain}`\n")
                else:
                    f.write(f"- {prefix} **{change[0]}** `{perm}` ({perm_type})\n")

                if change[0] == "MODIFIED":
                    old_row = change[2]
                    diffs = []
                    for i, (new, old) in enumerate(zip(row, old_row)):
                        if new != old:
                            diffs.append(f"{header[i]}: ~~{old}~~ → **{new}**")
                    if diffs:
                        f.write(f"  - Changed: {', '.join(diffs)}\n")

            f.write("\n")


def _write_table_summary(f, header, changes):
    """Fallback table-based summary for non-user-permission CSVs."""
    group_label = get_group_label(header)
    grouped = defaultdict(list)
    for change in changes:
        key = get_group_key(header, change[1])
        grouped[key].append(change)

    for group_name in sorted(grouped.keys()):
        group_changes = sort_changes(grouped[group_name])
        f.write(f"### {group_label}: {group_name}\n\n")
        f.write("| Change | " + " | ".join(header) + " |\n")
        f.write("| --- | " + " | ".join(["---"] * len(header)) + " |\n")
        for change in group_changes:
            row = list(change[1])
            if change[0] == "MODIFIED":
                old_row = list(change[2])
                display = []
                for i, (new, old) in enumerate(zip(row, old_row)):
                    if new != old:
                        display.append(f"~~{old}~~ → **{new}**")
                    else:
                        display.append(new)
                f.write(f"| MODIFIED | " + " | ".join(display) + " |\n")
            else:
                f.write(f"| {change[0]} | " + " | ".join(row) + " |\n")
        f.write("\n")


def main():
    parser = argparse.ArgumentParser(description="Diff two entitlements CSVs")
    parser.add_argument("before", help="Path to before CSV")
    parser.add_argument("after", help="Path to after CSV")
    parser.add_argument("--output", default="entitlements-diff.csv", help="Output CSV path")
    parser.add_argument("--summary", help="Path to write markdown summary")
    parser.add_argument("--account", help="Filter diff to a specific account")
    parser.add_argument("--user", help="Filter diff to a specific user/alias")
    args = parser.parse_args()

    header, before = load(args.before)
    _, after = load(args.after)

    changes = compute_diff(header, before, after)
    changes = filter_changes(changes, header, account=args.account, user=args.user)
    changes = sort_changes(changes)

    write_csv(args.output, header, changes)

    if args.summary:
        write_summary(args.summary, header, changes)


if __name__ == "__main__":
    main()
