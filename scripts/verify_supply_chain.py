"""Reproduce history, current-submission and pinned pre-commit checks.

Activate the project environment first. Gitleaks 8.30.1 must be on PATH,
or available in the locally downloaded .tools/gitleaks directory.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("task", choices=("history", "current-submission", "hook", "versions"))
    task = parser.parse_args().task
    binary = shutil.which("gitleaks")
    if binary is None:
        candidates = [Path(sys.executable).parent / "gitleaks.exe",
                      ROOT / ".tools/gitleaks/gitleaks.exe"]
        binary = next((str(path) for path in candidates if path.is_file()), None)
    if binary is None:
        raise SystemExit("Install the official Gitleaks 8.30.1 release before running this check.")
    environment = os.environ.copy()
    environment["PATH"] = os.pathsep.join([str(Path(binary).parent), str(Path(sys.executable).parent), environment["PATH"]])
    environment["PRE_COMMIT_HOME"] = str(ROOT / ".tools/pre-commit-cache")
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["NO_COLOR"] = "1"
    version = subprocess.check_output([binary, "version"], text=True).strip()
    if version.lstrip("v") != "8.30.1":
        raise SystemExit(f"Expected Gitleaks 8.30.1, got {version}")
    commands = {
        "history": [binary, "git", "--config", ".gitleaks.toml", "--redact", "--no-color", "--verbose", "."],
        "current-submission": [binary, "dir", "--config", ".gitleaks.toml", "--redact", "--no-color", "--verbose", "."],
        "hook": [sys.executable, "-m", "pre_commit", "run", "--all-files"],
        "versions": [binary, "version"],
    }
    command = commands[task]
    snapshot = None
    directory = ROOT
    metadata = ""
    if task == "current-submission":
        paths = subprocess.check_output(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
        ).decode("utf-8").split("\0")
        paths += ["reports/attack-before.log", "reports/attack-after.log", "reports/ledger.jsonl"]
        snapshot = tempfile.TemporaryDirectory(prefix="lab24-submission-")
        directory = Path(snapshot.name)
        copied = []
        for relative in sorted(set(paths)):
            source = ROOT / relative
            if not relative or not source.is_file():
                continue
            destination = directory / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            copied.append(relative)
        metadata = "Scope: source and submission evidence; vendor/cache directories excluded. No scanner rule suppressed.\nFiles scanned:\n" + "\n".join(copied) + "\n\n"
    try:
        result = subprocess.run(command, cwd=directory, env=environment, capture_output=True,
                                text=True, encoding="utf-8", errors="replace")
        output = (f"Command: {subprocess.list2cmdline(command)}\nWorking directory: {directory}\n\n"
                  + metadata + result.stdout + result.stderr + f"\nExit code: {result.returncode}\n")
    finally:
        if snapshot is not None:
            snapshot.cleanup()
    (ROOT / "reports" / f"supply-chain-{task}.log").write_text(output, encoding="utf-8")
    print(output, end="")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
