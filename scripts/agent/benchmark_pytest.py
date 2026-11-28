"""Compare pytest serial and file-grouped process workers with outcome checks."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKER_COUNTS = (0, 2, 4)
DEFAULT_FILES = ("tests/test_provider_live_schemas.py", "tests/test_web_api_allowlist_validation.py")


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_part(directory, name, workers, selection, *, allow_empty=False):
    evidence = directory / f"{name}.json"
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-p",
        "scripts.agent.pytest_profile_plugin",
        "--cops-profile",
        str(evidence),
        "--basetemp",
        str(directory / f"{name}-tmp"),
        "-p",
        "no:cacheprovider",
        "-n",
        str(workers),
        *selection,
    ]
    if workers:
        command.extend(["--dist", "loadfile", "--max-worker-restart", "0"])
    start = time.monotonic()
    with (directory / f"{name}.log").open("w", encoding="utf-8") as log:
        result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=False)
    elapsed = time.monotonic() - start
    if result.returncode and (result.returncode != 5 or not allow_empty):
        raise ValueError(f"{name} exited {result.returncode}. See {name}.log")
    data = json.loads(evidence.read_text(encoding="utf-8"))
    if data["exit_code"] != result.returncode:
        raise ValueError(f"{name} recorded conflicting pytest exit codes")
    return elapsed, data


def validate_part(data, workers, *, allow_empty=False):
    if data["exit_code"] != 0 and (data["exit_code"] != 5 or not allow_empty):
        raise ValueError(f"pytest failed with exit code {data['exit_code']}")
    collections = list(data["collections"].values())
    expected_collections = workers or 1
    if len(collections) != expected_collections or any(ids != collections[0] for ids in collections):
        raise ValueError("workers did not all collect the same test IDs")
    ids = set(collections[0])
    if len(ids) != len(collections[0]):
        raise ValueError("collection contains duplicate node IDs")
    if not ids and not allow_empty:
        raise ValueError("pytest collected no test IDs")

    reports = {nodeid: {"phases": {}, "subtests": []} for nodeid in ids}
    durations = dict.fromkeys(ids, 0.0)
    for report in data["reports"]:
        nodeid, phase = report["nodeid"], report["phase"]
        if nodeid not in reports or phase not in {"setup", "call", "teardown"}:
            raise ValueError(f"unexpected report for {nodeid} ({phase})")
        result = reports[nodeid]
        outcome = (report["outcome"], report["skip_reason"], report["xfail_reason"])
        if "subtest" in report:
            result["subtests"].append((phase, report["subtest"], *outcome))
            continue
        if phase in result["phases"]:
            raise ValueError(f"unexpected or repeated report for {nodeid} ({phase})")
        result["phases"][phase] = outcome
        durations[nodeid] += report["seconds"]
    for nodeid, result in reports.items():
        phases = result["phases"]
        if "setup" not in phases or "teardown" not in phases:
            raise ValueError(f"incomplete execution for {nodeid}")
        if ("call" in phases) != (phases["setup"][0] == "passed"):
            raise ValueError(f"unexpected call phase for {nodeid}")
    return reports, durations


def compare(reference, candidate):
    missing = sorted(reference.keys() - candidate.keys())
    extra = sorted(candidate.keys() - reference.keys())
    changed = sorted(nodeid for nodeid in reference.keys() & candidate.keys() if reference[nodeid] != candidate[nodeid])
    if missing or extra or changed:
        raise ValueError(f"execution drift: missing={missing[:10]}, extra={extra[:10]}, changed={changed[:10]}")


def run_benchmark(output, rounds, files, suite):
    samples = []
    reference = None
    serial_profiles = {}
    for index in range(rounds):
        # Rotate the first mode to spread cache and thermal effects across modes.
        order = WORKER_COUNTS[index % len(WORKER_COUNTS) :] + WORKER_COUNTS[: index % len(WORKER_COUNTS)]
        for workers in order:
            elapsed, raw = run_part(
                output, f"round-{index + 1}-workers-{workers}", workers, files if workers or not suite else [suite]
            )
            reports, durations = validate_part(raw, workers)
            if workers and suite:
                ignore = [f"--ignore={path}" for path in files]
                remainder_time, remainder = run_part(
                    output, f"round-{index + 1}-workers-{workers}-remainder", 0, [suite, *ignore], allow_empty=True
                )
                remainder_reports, _ = validate_part(remainder, 0, allow_empty=True)
                if reports.keys() & remainder_reports.keys():
                    raise ValueError("parallel files and the serial remainder overlap")
                reports.update(remainder_reports)
                elapsed += remainder_time
            if reference is None:
                reference = reports
            compare(reference, reports)
            if not workers:
                for nodeid, seconds in durations.items():
                    serial_profiles.setdefault(nodeid, []).append(seconds)
            skipped = sum(
                any(outcome[0] == "skipped" for outcome in result["phases"].values()) for result in reports.values()
            )
            skipped_subtests = sum(
                outcome == "skipped" for result in reports.values() for _, _, outcome, _, _ in result["subtests"]
            )
            samples.append(
                dict(
                    round=index + 1,
                    workers=workers,
                    seconds=round(elapsed, 3),
                    tests=len(reports),
                    skipped=skipped,
                    skipped_subtests=skipped_subtests,
                )
            )
            print(
                f"Round {index + 1}, workers={workers}: {elapsed:.3f}s, {len(reports)} tests, "
                f"{skipped} skipped, {skipped_subtests} skipped subtests",
                flush=True,
            )
    medians = {
        str(workers): statistics.median(sample["seconds"] for sample in samples if sample["workers"] == workers)
        for workers in WORKER_COUNTS
    }
    profile = sorted(
        ((statistics.median(seconds), nodeid) for nodeid, seconds in serial_profiles.items()), reverse=True
    )
    modules = {}
    for seconds, nodeid in profile:
        path = nodeid.partition("::")[0]
        modules[path] = modules.get(path, 0) + seconds
    write_json(
        output / "summary.json",
        {
            "parallel_files": files,
            "serial_suite": suite,
            "samples": samples,
            "median_seconds": medians,
            "slowest_serial_tests": profile[:20],
            "serial_modules_by_seconds": sorted(((total, path) for path, total in modules.items()), reverse=True),
            "outcome_parity": True,
            "environment": {
                "os": platform.platform(),
                "distribution": platform.freedesktop_os_release().get("PRETTY_NAME")
                if sys.platform == "linux"
                else None,
                "python": platform.python_version(),
                "logical_cpus": os.cpu_count(),
                "usable_cpus": getattr(os, "process_cpu_count", os.cpu_count)(),
                "dependencies": {
                    name: importlib.metadata.version(name)
                    for name in ("pytest", "pytest-xdist", "pytest-bdd", "jsonschema", "cryptography")
                },
            },
        },
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new directory for the run's evidence")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--parallel-file", action="append", type=Path, help="test module to run with workers")
    parser.add_argument("--suite", type=Path, help="run this directory too, keeping other files serial")
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("--rounds must be positive")
    suite = (ROOT / args.suite).resolve() if args.suite else None
    files = [(ROOT / path).resolve() for path in (args.parallel_file or DEFAULT_FILES)]
    if suite and (not suite.is_dir() or not suite.is_relative_to(ROOT / "tests")):
        parser.error("--suite must be a directory under tests/")
    if len(set(files)) != len(files) or any(
        not path.is_file() or path.suffix != ".py" or not path.is_relative_to(suite or ROOT / "tests") for path in files
    ):
        parser.error("--parallel-file must name distinct Python test files inside the selected suite")
    try:
        args.output.resolve().mkdir(parents=True)
        run_benchmark(
            args.output.resolve(),
            args.rounds,
            [str(path.relative_to(ROOT)) for path in files],
            str(suite.relative_to(ROOT)) if suite else None,
        )
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
