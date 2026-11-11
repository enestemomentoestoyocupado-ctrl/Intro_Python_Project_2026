#!/usr/bin/env python3
"""Find CVSS vectors in agent replies and score their answers."""

import argparse
import json
import sys
from pathlib import Path


METRIC_VALUES = (
    ("AV", {"N", "A", "L", "P"}),
    ("AC", {"L", "H"}),
    ("PR", {"N", "L", "H"}),
    ("UI", {"N", "R"}),
    ("S", {"U", "C"}),
    ("C", {"N", "L", "H"}),
    ("I", {"N", "L", "H"}),
    ("A", {"N", "L", "H"}),
)
TRAILING_PUNCTUATION = ".,;:!?`\"')]} "
ROOT = Path(__file__).resolve().parent


def find_vector(reply):
    """Return the last valid CVSS vector, or 'invalid'."""
    start = reply.rfind("CVSS:3.1")
    if start == -1:
        return "invalid"

    # Read the vector up to the next space and ignore sentence punctuation.
    candidate = reply[start:].split(maxsplit=1)[0].rstrip(TRAILING_PUNCTUATION)
    parts = candidate.split("/")
    if len(parts) != len(METRIC_VALUES) + 1 or parts[0] != "CVSS:3.1":
        return "invalid"

    for part, (expected_metric, allowed_values) in zip(parts[1:], METRIC_VALUES):
        pieces = part.split(":")
        if (
            len(pieces) != 2
            or pieces[0] != expected_metric
            or pieces[1] not in allowed_values
        ):
            return "invalid"

    return candidate


def check_examples():
    """Check one, two, missing, and broken vectors."""
    one_vector = "The result is CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H."
    two_vectors = (
        "First CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H; "
        "then CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:H"
    )
    no_vector = "The reply does not contain a score."
    broken_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"

    assert find_vector(one_vector) == (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    assert find_vector(two_vectors) == (
        "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:H"
    )
    assert find_vector(no_vector) == "invalid"
    assert find_vector(broken_vector) == "invalid"


def score_vector(vector):
    """Return a CVSS base score using the cvss package."""
    try:
        from cvss import CVSS3, CVSS3Error
    except ImportError as error:
        raise ValueError(
            "Install the required package with: python3 -m pip install cvss"
        ) from error

    try:
        return float(CVSS3(vector).base_score)
    except CVSS3Error as error:
        raise ValueError(f"cannot score CVSS vector {vector}: {error}") from error


def read_jsonl(path, required_fields, label):
    """Read JSON records and check the fields we need."""
    records = []
    try:
        with path.open(encoding="utf-8") as source:
            for line_number, line in enumerate(source, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError(
                        f"{label} line {line_number} is not valid JSON"
                    ) from error
                if not isinstance(record, dict) or not required_fields.issubset(record):
                    raise ValueError(
                        f"{label} line {line_number} needs these keys: "
                        f"{', '.join(sorted(required_fields))}"
                    )
                if not isinstance(record["id"], str) or not record["id"]:
                    raise ValueError(f"{label} line {line_number} has an invalid id")
                records.append(record)
    except OSError as error:
        raise ValueError(f"cannot read {label} file {path}: {error}") from error

    return records


def build_results(gold_records, answer_records):
    """Score each gold task and keep a row for missing answers."""
    gold_by_id = {}
    for record in gold_records:
        task_id = record["id"]
        if task_id in gold_by_id:
            raise ValueError(f"duplicate id in gold file: {task_id}")
        if record["split"] not in {"dev", "test"}:
            raise ValueError(f"unknown split for {task_id}: {record['split']}")
        if not isinstance(record["gt"], str):
            raise ValueError(f"invalid gold vector for {task_id}")
        gold_by_id[task_id] = record

    if not gold_records:
        raise ValueError("gold file has no tasks")

    answers_by_id = {}
    for record in answer_records:
        task_id = record["id"]
        if task_id in answers_by_id:
            raise ValueError(f"duplicate id in answers file: {task_id}")
        if not isinstance(record["response"], str):
            raise ValueError(f"response for {task_id} must be text")
        answers_by_id[task_id] = record["response"]

    unknown_ids = sorted(set(answers_by_id) - set(gold_by_id))
    missing_ids = [task_id for task_id in gold_by_id if task_id not in answers_by_id]
    results = []

    for task_id, gold in gold_by_id.items():
        missing = task_id not in answers_by_id
        response = None if missing else answers_by_id[task_id]
        agent_vector = "invalid" if missing else find_vector(response)
        gold_vector = gold["gt"]
        gold_score = score_vector(gold_vector)

        if agent_vector == "invalid":
            agent_score = None
            difference = 10.0
            exact = False
            status = "missing" if missing else "invalid"
        else:
            agent_score = score_vector(agent_vector)
            difference = abs(gold_score - agent_score)
            exact = agent_vector == gold_vector
            status = "valid"

        results.append(
            {
                "id": task_id,
                "split": gold["split"],
                "response": response,
                "agent_vector": agent_vector,
                "gold_vector": gold_vector,
                "agent_score": agent_score,
                "gold_score": gold_score,
                "difference": difference,
                "exact": exact,
                "status": status,
            }
        )

    return results, missing_ids, unknown_ids


def summarize(results, label):
    """Print the average difference and answer counts."""
    count = len(results)
    if count == 0:
        print(f"{label}: no tasks")
        return

    average = sum(row["difference"] for row in results) / count
    invalid = sum(row["status"] == "invalid" for row in results)
    missing = sum(row["status"] == "missing" for row in results)
    exact = sum(row["exact"] for row in results)
    percentage = exact * 100 / count
    print(
        f"{label}: mean difference {average:.2f}; invalid {invalid}; "
        f"missing {missing}; exact {exact}/{count} ({percentage:.1f}%)."
    )


def main():
    parser = argparse.ArgumentParser(
        description="Score agent CVSS answers against the private answer key."
    )
    parser.add_argument("answers", type=Path, help="JSONL file with id and response")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "scores.jsonl",
        help="per-task results file (default: scores.jsonl beside this script)",
    )
    args = parser.parse_args()

    try:
        gold_records = read_jsonl(
            ROOT / "private" / "gold.jsonl", {"id", "split", "gt", "url"}, "gold"
        )
        answer_records = read_jsonl(args.answers, {"id", "response"}, "answers")
        results, missing_ids, unknown_ids = build_results(
            gold_records, answer_records
        )
        with args.output.open("w", encoding="utf-8", newline="\n") as output:
            for result in results:
                output.write(json.dumps(result, ensure_ascii=False) + "\n")
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    summarize([row for row in results if row["split"] == "dev"], "Practice")
    summarize([row for row in results if row["split"] == "test"], "Test")
    summarize(results, "All")

    print(f"Saved per-task results to {args.output}.")
    print(f"Missing answer ids: {', '.join(missing_ids) if missing_ids else 'none'}")
    print(f"Unknown answer ids: {', '.join(unknown_ids) if unknown_ids else 'none'}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        check_examples()
        print("Vector parser checks passed.")
    else:
        raise SystemExit(main())
