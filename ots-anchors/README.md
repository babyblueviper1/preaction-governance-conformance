# Suite repo commit anchors

Each file pair here is a Bitcoin OpenTimestamps anchor over a small canonical manifest
(`{schema, repo, branch, commit_sha, claimed_at}`), not the raw commit SHA directly — see
`scripts/suite_repo_ots_anchor.py` in the main invinoveritas repo for the exact construction and
verification steps. This exists to close the "single-maintainer repo is a trust bottleneck"
question raised in crewAIInc/crewAI#4877: the fix isn't a neutral host, it's making the host's
trust irrelevant — anyone can verify the commit history hasn't been silently rewritten or
backdated, independent of who holds write access.

**How to verify, trusting nothing from us:** recompute `sha256(JCS(manifest))` from the
`.manifest.json` file, confirm it equals the digest in the filename, then run
`ots verify -d <digest> <digest>.ots` against any Bitcoin explorer. Independently confirm via
`git log` / the GitHub API that `commit_sha` was reachable from `branch` at or before
`claimed_at`.

## Known gap, disclosed (2026-08-10)

The `b92d2c69...` anchor (commit `45c9b2b8`, claimed 2026-07-23T15:37:44Z) was submitted to 4
OpenTimestamps calendar servers successfully at the time, but was never polled/upgraded
afterward. Checked again on 2026-08-10 (17 days later): all 4 calendars now return
`CommitmentNotFoundError` for its digest — the pending commitment was lost, most likely pruned by
the calendar servers' own retention window for unconfirmed submissions. Its `.ots`/`.manifest.json`
files are kept here as an honest record of the gap, not removed — the manifest and commit_sha are
still independently checkable via `git log` even without the OTS proof.

Fix shipped the same day: `suite-repo-ots-anchor.timer` (systemd, every 6h) now runs
`suite_repo_ots_anchor.py --upgrade` on a recurring cadence so a future pending anchor gets
polled/firmed to Bitcoin-confirmed well within any calendar's retention window, instead of relying
on a manual re-run that might not happen. The `6b8aefca...` anchor (commit `62d32e51`, claimed
2026-08-10) is the fresh replacement, now covering the repo's current work (the independent second
checker, the recomputable policy_commitment spec) that the lost anchor never reached.
