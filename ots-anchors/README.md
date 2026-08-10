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

## Correction (2026-08-10) — the anchor below was never lost, an earlier version of this file was wrong

**`b92d2c69...` (commit `45c9b2b8`) is Bitcoin-confirmed: block 959284, existence attested as of
2026-07-23 UTC.** Verify yourself: `ots verify -d b92d2c6945bb96d97e5dbf8b552c9d7c957a10fb34b30bb6f17fad5cbac45018 b92d2c6945bb96d97e5dbf8b552c9d7c957a10fb34b30bb6f17fad5cbac45018.ots`.

An earlier version of this README claimed this anchor was "lost" — that was our own bug, not a
real gap in the anchor. The verification code queried a hardcoded generic pool-subdomain calendar
list (`a.pool.opentimestamps.org`, meant for *submission*) instead of the specific calendar server
each pending attestation actually resolves through (embedded in the `.ots` file itself, e.g.
`bob.btc.calendar.opentimestamps.org`). Querying the wrong hostname for the right digest returns
`CommitmentNotFoundError`, which got misread as "the commitment was lost." Caught by a direct
question ("that anchor is definitely lost?") that prompted re-verifying with the official `ots`
CLI instead of trusting the first (buggy) answer — full fix in `suite_repo_ots_anchor.py`
(invinoveritas repo, `upgrade_pending()`), now shells out to the real `ots upgrade`/`ots verify`
CLI instead of hand-rolling calendar resolution.

The `6b8aefca...` anchor (commit `62d32e51`, claimed 2026-08-10) still stands as a genuine,
separate anchor — it covers real work shipped since 2026-07-23 (the independent second checker,
the recomputable `policy_commitment` spec), not a replacement for a "lost" predecessor. Both
anchors are real and both are kept. `suite-repo-ots-anchor.timer` (systemd, every 6h) still runs
`suite_repo_ots_anchor.py --upgrade` on a recurring cadence — genuinely useful for firming a
*newly pending* anchor to confirmed status sooner, just not the fix for the bug that caused this
correction (that was in the verification code, not the anchor's cadence).
