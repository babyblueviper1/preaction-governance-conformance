#!/usr/bin/env python3
"""Check a second-issuer RUN ATTESTATION for the issuer-neutral marker checkers (trace-spec #397 / #398). Stdlib + git.

    python3 tools/issuer_run_check.py RUN_ATTESTATION.json

An attestation (schema trace-issuer-run.v1, see examples/trace-marker-second-issuer-demo/ACCEPTANCE.md) names the checker
commit, the issuer profile and every input by sha256, the exact argv and the exit code and output sha256 the issuer got.
This tool re-establishes all of it from the repository instead of trusting it:
  1. the checker commit exists here and the checker plus everything it loads (CHECKER_FILES) is byte-identical at HEAD
     and at that commit ("unchanged");
  2. the profile and every input file match their declared sha256;
  3. re-running the named checker with the declared argv gives the declared exit code and output sha256;
  4. the declared exit is 0 (a pass) and the independence declarations are present and all true.
Every line is PASS / FAIL / CANNOT_ESTABLISH. Exit 1 on any FAIL, else 2 on any CANNOT_ESTABLISH, else 0.
It does NOT decide independence: it checks that the issuer made the declarations. Whether they are true is for the
TRACE maintainers to adjudicate (ACCEPTANCE.md), never for the proposer.
"""
import hashlib
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKERS = {"vantage_limitation": "tools/vantage_limitation_check.py", "related_claims": "tools/related_claims_check.py"}
DECLARATIONS = ("not_controlled_by_proposer", "not_funded_by_proposer", "not_maintainer_affiliated",
                "records_emitted_by_issuer_own_software", "published_by_issuer")
CHECKER_FILES = ("_bip340_nostr.py", "tools/issuer_profile.py", "tools/_ed25519.py", "tools/vantage_notes_by_policy.json",
                 *CHECKERS.values())
PASS, FAIL, CANNOT = "PASS", "FAIL", "CANNOT_ESTABLISH"


def sha(path):
    return hashlib.sha256(open(os.path.join(ROOT, path), "rb").read()).hexdigest()


def git(*a):
    return subprocess.run(["git", "-C", ROOT, *a], capture_output=True, text=True)


def check(att):
    out = []
    add = lambda s, n, d="": out.append((s, n, d))  # noqa: E731
    if att.get("schema") != "trace-issuer-run.v1":
        add(FAIL, "schema is trace-issuer-run.v1", str(att.get("schema"))); return out
    commit = str(att.get("checker_commit", ""))
    if git("cat-file", "-e", f"{commit}^{{commit}}").returncode != 0:
        add(CANNOT, "checker commit exists in this repository", commit or "<missing>"); return out
    add(PASS, "checker commit exists in this repository", commit[:12])
    same = git("diff", "--quiet", commit, "--", *CHECKER_FILES).returncode == 0      # working tree vs the commit
    add(PASS if same else FAIL, "checker and its dependencies are byte-identical to the checker commit (unchanged)")
    tool = CHECKERS.get(att.get("checker"))
    if not tool:
        add(FAIL, "checker is one of " + "/".join(CHECKERS), str(att.get("checker"))); return out
    files = [att.get("profile") or {}] + list(att.get("inputs") or [])
    ok_files = True
    for f in files:
        p, want = f.get("path"), str(f.get("sha256", "")).lower()
        if not p or not os.path.exists(os.path.join(ROOT, p)):
            add(CANNOT, f"file present: {p}"); ok_files = False; continue
        good = sha(p) == want
        ok_files &= good
        add(PASS if good else FAIL, f"sha256 matches: {p}")
    argv = att.get("argv")
    if not (isinstance(argv, list) and all(isinstance(a, str) for a in argv)):
        add(FAIL, "argv is a list of strings"); return out
    if "--profile" not in argv or argv[argv.index("--profile") + 1:argv.index("--profile") + 2] != [(att.get("profile") or {}).get("path")]:
        add(FAIL, "argv passes the declared profile with --profile")
    if not ok_files:
        return out
    r = subprocess.run([sys.executable, os.path.join(ROOT, tool), *argv], cwd=ROOT, capture_output=True)
    got = hashlib.sha256(r.stdout).hexdigest()
    add(PASS if r.returncode == att.get("exit_code") else FAIL, "re-run exit code == declared", f"got {r.returncode} declared {att.get('exit_code')}")
    add(PASS if got == str(att.get("output_sha256", "")).lower() else FAIL, "re-run output sha256 == declared", got[:16])
    add(PASS if att.get("exit_code") == 0 else FAIL, "declared result is a pass (exit 0)")
    dec = att.get("independence") or {}
    missing = [k for k in DECLARATIONS if dec.get(k) is not True]
    add(PASS if not missing else FAIL, "all independence declarations made (adjudicated by TRACE maintainers, not here)",
        ",".join(missing))
    add(PASS if str(att.get("published_at_url", "")).startswith("https://") else FAIL,
        "attestation published by the issuer at an https URL", str(att.get("published_at_url", "")))
    return out


def main(argv):
    if len(argv) != 2:
        print(__doc__); return 2
    res = check(json.load(open(argv[1])))
    for s, n, d in res:
        print(f"{s:<17} {n}" + (f"  [{d}]" if d else ""))
    print("NOTE: a PASS means the run reproduces and the declarations were made; it does not establish that they are true.")
    return 1 if any(s == FAIL for s, _, _ in res) else (2 if any(s == CANNOT for s, _, _ in res) else 0)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
