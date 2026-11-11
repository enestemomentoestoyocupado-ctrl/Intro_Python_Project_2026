#!/usr/bin/env python3
"""Pick CVSS tasks and save agent prompts separately from their answers."""

import argparse
import csv
import json
import random
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
URL_PATTERN = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
VECTOR_PATTERN = re.compile(r"CVSS:3\.1(?:/[A-Z]{1,2}:[A-Z]){8}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Select tasks from a tab-separated CVSS data file."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=ROOT / "cti-vsp.tsv",
        help="TSV input file (default: cti-vsp.tsv beside this script)",
    )
    parser.add_argument("--total", type=int, default=50, help="number of tasks")
    parser.add_argument(
        "--practice", type=int, default=20, help="number of practice tasks"
    )
    parser.add_argument("--seed", type=int, default=42, help="random seed")
    args = parser.parse_args()

    if args.total <= 0:
        parser.error("--total must be greater than zero")
    if args.practice < 0:
        parser.error("--practice cannot be negative")
    if args.practice > args.total:
        parser.error("--practice cannot be greater than --total")
    return args


def read_rows(input_path):
    # Read the TSV and check that each row has the fields we need.
    required = {"URL", "Prompt", "GT"}
    try:
        with input_path.open(encoding="utf-8-sig", newline="") as source:
            reader = csv.DictReader(source, delimiter="\t")
            if not reader.fieldnames or not required.issubset(reader.fieldnames):
                raise ValueError(
                    "input must have URL, Prompt, and GT columns in its header"
                )
            rows = []
            for line_number, row in enumerate(reader, start=2):
                if None in row or any(not row.get(key) for key in required):
                    raise ValueError(f"missing data at line {line_number}")
                rows.append(row)
    except OSError as error:
        raise ValueError(f"cannot read input file {input_path}: {error}") from error

    if not rows:
        raise ValueError("input file has no data rows")
    return rows


def write_jsonl(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as output:
        for record in records:
            output.write(json.dumps(record, ensure_ascii=False) + "\n")


def main():
    args = parse_args()
    try:
        rows = read_rows(args.input)
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    if args.total > len(rows):
        print(
            f"Error: requested {args.total} tasks, but the input has only "
            f"{len(rows)} rows.",
            file=sys.stderr,
        )
        return 2

    # Pick rows first, then assign ids so ids do not show source row order.
    picked = random.Random(args.seed).sample(rows, args.total)
    dev_tasks = []
    test_tasks = []
    gold = []
    example_answers = 0

    for index, row in enumerate(picked, start=1):
        task_id = f"t{index:03d}"
        split = "dev" if index <= args.practice else "test"
        # Keep the prompt text exactly as it appears in the source file.
        prompt = row["Prompt"]
        own_cve = CVE_PATTERN.search(row["URL"])
        assert own_cve is not None, f"no CVE number in the URL for {task_id}"
        assert own_cve.group(0).casefold() not in prompt.casefold(), (
            f"{task_id} prompt contains its own CVE number"
        )
        assert URL_PATTERN.search(prompt) is None, (
            f"{task_id} prompt contains a URL"
        )

        # Count when the example vector is also the correct answer.
        if row["GT"] in VECTOR_PATTERN.findall(row["Prompt"]):
            example_answers += 1

        task = {"id": task_id, "prompt": prompt}
        assert task["prompt"] == row["Prompt"]
        assert set(task) == {"id", "prompt"}
        (dev_tasks if split == "dev" else test_tasks).append(task)
        gold.append(
            {"id": task_id, "split": split, "gt": row["GT"], "url": row["URL"]}
        )

    # Find repeated prompt text and keep the ids and splits for the report.
    prompts = {}
    for split, tasks in (("dev", dev_tasks), ("test", test_tasks)):
        for task in tasks:
            prompts.setdefault(task["prompt"], []).append((task["id"], split))
    duplicate_prompts = [
        ids_and_splits for ids_and_splits in prompts.values() if len(ids_and_splits) > 1
    ]

    # Save agent prompts separately from their answer key.
    write_jsonl(ROOT / "tasks" / "dev.jsonl", dev_tasks)
    write_jsonl(ROOT / "tasks" / "test.jsonl", test_tasks)
    write_jsonl(ROOT / "private" / "gold.jsonl", gold)

    print(
        f"Wrote {len(dev_tasks)} practice and {len(test_tasks)} test tasks "
        f"from {len(rows)} rows (seed {args.seed})."
    )
    print(
        f"The example vector is the correct answer for "
        f"{example_answers} of {args.total} selected tasks."
    )
    if duplicate_prompts:
        print("Duplicate prompt text:")
        for ids_and_splits in duplicate_prompts:
            ids = ", ".join(f"{task_id} ({split})" for task_id, split in ids_and_splits)
            split_names = {split for _, split in ids_and_splits}
            split_note = (
                "different splits" if len(split_names) > 1 else "same split"
            )
            print(f"  {ids} — {split_note}")
    else:
        print(f"No duplicate prompt text among {args.total} tasks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
