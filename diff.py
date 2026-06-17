import argparse
import csv
import sys


def load(path):
    with open(path) as f:
        return set(tuple(r) for r in csv.reader(f))


def main():
    parser = argparse.ArgumentParser(description="Diff two entitlements CSVs")
    parser.add_argument("before", help="Path to before CSV")
    parser.add_argument("after", help="Path to after CSV")
    parser.add_argument("--output", default="entitlements-diff.csv", help="Output CSV path")
    parser.add_argument("--summary", help="Path to write markdown summary (e.g. $GITHUB_STEP_SUMMARY)")
    args = parser.parse_args()

    before = load(args.before)
    after = load(args.after)
    removed = before - after
    added = after - before

    with open(args.after) as af:
        header = next(csv.reader(af))

    with open(args.output, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Change"] + header)
        for row in sorted(removed):
            w.writerow(["REMOVED"] + list(row))
        for row in sorted(added):
            w.writerow(["ADDED"] + list(row))

    if args.summary:
        with open(args.output) as f:
            rows = list(csv.reader(f))

        if len(rows) <= 1:
            md = "No entitlement changes detected.\n"
        else:
            h = rows[0]
            md = "| " + " | ".join(h) + " |\n"
            md += "| " + " | ".join(["---"] * len(h)) + " |\n"
            for row in rows[1:]:
                md += "| " + " | ".join(row) + " |\n"

        with open(args.summary, "a") as f:
            f.write(md)


if __name__ == "__main__":
    main()
