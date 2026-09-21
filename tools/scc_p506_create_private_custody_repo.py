#!/usr/bin/env python3
"""Create the dedicated SCC private custody repository and verify privacy.

No SCC source bytes, benchmark bytes, API keys, PATs, or other secrets are read.
Prerequisite: GitHub CLI 'gh' authenticated as the intended owner.
"""

from __future__ import annotations
import argparse, json, shutil, subprocess, sys

DEFAULT_REPO = "fulviobennato/scc-private-custody"

def run(*args: str, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["gh", *args],
        check=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=None,
        text=True,
    )

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=DEFAULT_REPO)
    ns = ap.parse_args()

    if shutil.which("gh") is None:
        raise SystemExit("GitHub CLI 'gh' is not installed")

    run("auth", "status", "--hostname", "github.com")

    owner, name = ns.repo.split("/", 1)

    probe = subprocess.run(
        ["gh", "repo", "view", ns.repo, "--json", "nameWithOwner,visibility,isArchived"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    if probe.returncode != 0:
        run(
            "repo", "create", ns.repo,
            "--private",
            "--add-readme",
            "--description",
            "Private custody repository for frozen SCC real-model execution inputs and receipts.",
        )

    out = run(
        "repo", "view", ns.repo,
        "--json", "nameWithOwner,visibility,isArchived,defaultBranchRef",
        capture=True,
    )
    meta = json.loads(out.stdout)

    if meta.get("nameWithOwner") != ns.repo:
        raise SystemExit(f"repository identity mismatch: {meta!r}")
    if str(meta.get("visibility", "")).upper() != "PRIVATE":
        raise SystemExit(f"refuse non-private repository: {meta!r}")
    if meta.get("isArchived"):
        raise SystemExit("refuse archived custody repository")
    branch = (meta.get("defaultBranchRef") or {}).get("name")
    if not branch:
        raise SystemExit("default branch missing after --add-readme")

    receipt = {
        "schema": "scc-private-custody-repo-bootstrap-local/1",
        "repository": ns.repo,
        "visibility": "PRIVATE",
        "archived": False,
        "default_branch": branch,
        "private_bytes_uploaded": False,
        "secrets_installed": False,
        "next_step": "connector ingest of frozen Drive bytes with pre/post SHA parity",
    }
    print(json.dumps(receipt, sort_keys=True, indent=2))

if __name__ == "__main__":
    main()
