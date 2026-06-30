# Benchmark grade — recompute a submitted trace dump from its own bytes

A zero-dependency referee grader for a **submitted benchmark of verification traces**. Given a JSONL
where each row carries a verdict plus the scores/thresholds/jitter behind it, it re-derives each row's
grade **from the bytes** — never by running the producer's own grader — in the recompute-depth
vocabulary the [conformance registry](https://api.babyblueviper.com/conformance) uses:

| Grade | Meaning |
|---|---|
| **CERTIFIED** | the pass/fail verdict is logic-consistent **and** tolerance-stable: the row's own observed scorer jitter cannot flip it (`\|score − threshold\| > jitter_margin`). |
| **PARTIAL** | verdict is logic-consistent but sits **inside** the jitter band — bounded by scorer reproducibility, not the verdict. |
| **DEPTH-0** | not recomputable: an injected/observed fault (a `diagnosis` is set), or the verdict contradicts its own numbers. |

The scores themselves are producer-asserted (there's no live scorer for a third party to re-run), so
**CERTIFIED is a claim about the verdict, not the score** — the pass/fail recomputes and survives the
producer's own recorded jitter. Model/probe digests are graded separately as a reproducible-fingerprint
tier (recomputed from the published recipe).

## Run it

```bash
python3 grade_traces.py                       # the bundled real sample (offline, what CI runs)
python3 grade_traces.py --traces traces.jsonl # a full dump
```

Exit 0 iff every graded row's verdict is logic-consistent with its own score/threshold (the property a
benchmark must satisfy to be gradeable at all). The tier mix is **reported, not gated** — it's the grade.

## Worked example — the Correctover v1.1.0 benchmark (20,071 traces)

[Correctover](https://github.com/Correctover/Correctover-) published its full decision-trace dump and
invited an independent grade. Against the pinned commit:

```bash
git clone https://github.com/Correctover/Correctover-.git
python3 grade_traces.py --traces Correctover-/correctover-benchmark/traces.jsonl
```

Result (recomputed from the bytes, not via their `recompute.py`):

- `model_digest` and `probe_digest` reproduce from the published recipe on **100%** of rows; every
  row's verdict is logic-consistent with its own score/threshold (**120,426 / 120,426**).
- per-row grade: **CERTIFIED 26.5% · PARTIAL 52.8% · DEPTH-0 20.7%**.

The `sample_traces.jsonl` bundled here is six real rows from that dump (a clean CERTIFIED, two
inside-band PARTIALs, a fault DEPTH-0, a healed row), so this example runs offline on real bytes.

## Referee-of-referees

The grader also replicates the producer's **own** cut and reports where the two diverge. Correctover's
`recompute.py` certifies a dimension when `jitter_margin > 0.01`, which never checks whether the margin
actually *beats* the jitter — so it grades CERTIFIED a large set of inside-band verdicts the
tolerance-stable rule (`\|score − threshold\| > jitter_margin`) holds to PARTIAL. On the full dump the
two grades diverge on **57.8%** of rows, all in that one direction. Tightening that one line converges
them. That divergence — *recomputing the recomputer* — is the signal neither party can suppress, and is
why a board that grades the graders is non-circular.
