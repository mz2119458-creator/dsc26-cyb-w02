# dsc26-cyb-w02 · Rawaj Pay threat model as code

DSC Summer Internship 2026 · Cybersecurity track · Week 2 (Threat modelling with STRIDE)
**Python 3.12 · PyYAML 6.0.3 · pytest 9.1.1** · expected time 3 to 3.5 hours · everything runs offline

## Scenario

Rawaj Pay's Cyber pod keeps its threat model as YAML in the repository. Dina wants a check in CI that
fails the build when the model has holes: broken references, impossible flows, threats with no
decision, boundary-crossing flows nobody has threat-modelled, unencrypted crossings. You build that
checker, `tmcheck`, and then use it to finish the Sprint 0 draft of the scoring-service model so that
it passes.

## Set up

1. On GitHub create a **public** repository in your own account named exactly `dsc26-cyb-w02`
   (not `dsc26-cyb-w2`, not `DSC26-cyb-w02`), with no README.
2. Unzip this starter into a folder called `dsc26-cyb-w02`, then:

```bash
git init -b main
uv venv --python 3.12
source .venv/bin/activate            # Windows: .venv\Scripts\activate
uv pip install -r requirements.txt   # pinned versions; you cannot add packages
python -m pytest -q                  # the 5 public tests fail until you build the task
git add . && git commit -m "chore: starter from DSC"
git remote add origin https://github.com/<your-username>/dsc26-cyb-w02.git
git push -u origin main
```

Always run tests with `python -m pytest` from the repository root, the way the grader does. Plain
`pytest` may not put the repository root on the import path, and then `import tmcheck` fails for a
reason that has nothing to do with your code.

## Files

```
tmcheck/__init__.py
tmcheck/core.py          # the checker: fill in every function, keep the names and signatures
tmcheck/__main__.py      # python -m tmcheck MODEL.yaml
models/rawaj_scoring.yaml   # the Sprint 0 model you finish (step 3)
tests/test_public.py     # public tests
AI_USAGE.md              # fill in before you submit (the grader checks the headings)
requirements.txt
```

## What to build

### 1. `tmcheck/core.py`

Use these exact names. The starter has them with `raise NotImplementedError` bodies.

```python
from dataclasses import dataclass

class ModelError(Exception): ...

@dataclass(frozen=True, order=True)
class Issue:
    ref: str          # id of the zone/element/flow/threat the issue is about
    code: str
    message: str = ""

@dataclass(frozen=True, order=True)
class Gap:
    ref: str          # element or flow id
    category: str     # one STRIDE letter

@dataclass(frozen=True)
class RankedThreat:
    id: str
    score: int
    level: str        # "high" | "medium" | "low"

def load_model(path) -> dict: ...
def applicable(kind: str, *, is_log: bool = False) -> set[str]: ...
def validate(model: dict) -> list[Issue]: ...
def crossing_flows(model: dict) -> list[str]: ...
def coverage_gaps(model: dict) -> list[Gap]: ...
def policy_findings(model: dict) -> list[Issue]: ...
def rank(model: dict) -> list[RankedThreat]: ...
```

**The model format.** A mapping with four lists:

- `zones`: `id`, `trust` (integer, higher is more trusted)
- `elements`: `id`, `kind` (`external_entity` | `process` | `data_store`), `zone`, optional
  `holds_pii: true`, optional `is_log: true`
- `flows`: `id`, `source`, `target`, `protocol`, optional `authenticated: true`, optional `data`
- `threats`: `id`, `target` (an element or flow id), `category` (one STRIDE letter), `title`,
  `likelihood` and `impact` (integers 1 to 5), `status` (`open` | `mitigated` | `accepted`), plus
  `mitigation` or `justification` text

**`load_model(path)`** reads the file with `yaml.safe_load` and returns the mapping. Missing or `null`
lists become `[]`. Raise `ModelError` if the file cannot be read, is not valid YAML, uses a tag
`safe_load` refuses, has a top level that is not a mapping, or has a section that is not a list.

**`applicable(kind, is_log=False)`** returns STRIDE per element: `external_entity` → {S, R};
`process` → all six; `data_store` → {T, I, D}, plus R when `is_log`; `data_flow` → {T, I, D}.
Unknown kind: `ValueError`.

**`validate(model)`** returns structural problems as `Issue`s, sorted by `(ref, code, message)`, no
duplicates:

| Code | When |
|---|---|
| `DUPLICATE_ID` | An id is used more than once anywhere in the model (zones, elements, flows and threats share one id space). `ref` is the repeated id |
| `BAD_KIND` | Element kind is not one of the three |
| `UNKNOWN_ZONE` | Element's zone is not a defined zone |
| `UNKNOWN_REF` | A flow's source or target is not an element; a threat's target is neither an element nor a flow |
| `INVALID_FLOW` | Source equals target, or neither end is a process |
| `BAD_CATEGORY` | Category is not exactly one of `S T R I D E` (uppercase, one letter) |
| `INAPPLICABLE_CATEGORY` | Category is valid but does not apply to the target's kind (for example `E` on a data store, `R` on a store that is not a log) |
| `BAD_SCORE` | `likelihood` or `impact` is not an integer from 1 to 5. Booleans are not integers here, and neither is `4.0` |
| `BAD_STATUS` | Status is not one of the three |
| `MISSING_MITIGATION` | `mitigated` with no mitigation text, or text that is only whitespace |
| `MISSING_JUSTIFICATION` | `accepted` with no justification text, or only whitespace |

`ref` is the id of the item the problem is in: the element for `BAD_KIND` and `UNKNOWN_ZONE`, the
flow or threat for `UNKNOWN_REF`, the flow for `INVALID_FLOW`, the threat for the category, score
and status codes.

**`crossing_flows(model)`** returns the ids of flows whose source and target are in different zones,
in file order. Flows with unknown ends are skipped.

**`coverage_gaps(model)`** defines scope as every crossing flow plus both of its end elements. For each
in-scope item and each applicable category, there must be at least one threat with that target and
category, in any status. Return the missing pairs sorted by ref, then in STRIDE order (S, T, R, I, D, E).

**`policy_findings(model)`**, sorted by `(ref, code)`:

- `UNENCRYPTED_CROSSING`: a crossing flow whose protocol, compared case-insensitively, is not one of
  `https`, `tls`, `mtls`, `sftp`, `ssh`. `ref` is the flow.
- `UNAUTHENTICATED_INBOUND`: a crossing flow into a zone with higher `trust` than its source zone,
  where `authenticated` is not `true`. A missing key counts as not authenticated. Flows towards lower
  or equal trust are not flagged. `ref` is the flow.
- `PII_STORE_WITHOUT_I_THREAT`: a data store with `holds_pii: true` and no threat of category `I`
  against it (in any status). `ref` is the store.

**`rank(model)`** returns open threats only (skip threats whose scores are invalid), with
`score = likelihood × impact` and level high (15 or more), medium (8 to 14) or low (7 or less). Order:
score descending, then impact descending, then id in natural order (`T2` before `T10`).

### 2. `tmcheck/__main__.py`

`python -m tmcheck MODEL.yaml` prints a JSON object with the keys `issues`, `gaps`, `policy` and
`ranked`, each a list of objects with the dataclass fields (for example
`{"ref": "f08", "category": "T"}`). Exit code 2 if the file cannot be loaded (including a file that
does not exist), 1 if there are any issues, gaps or policy findings, otherwise 0. If there are
structural issues you may leave `gaps` and `policy` empty.

### 3. `models/rawaj_scoring.yaml`: finish the model

The starter model has five zones, nine elements, eight flows and 26 threats. When your checker works
it reports **11 coverage gaps and 2 policy findings**. Make it pass:

- Add a threat for every gap: a real one about this system, with a title of at least 15 characters.
  No two titles in the file may be the same (compared ignoring upper/lower case and leading or
  trailing spaces).
- Fix the two policy findings the way an engineer would: the flow from the analyst console to the case
  database should not be plaintext, and a store that holds personal data needs an
  information-disclosure threat.
- Do not delete any starter zone, element, flow or threat, and do not make findings disappear by
  editing the design: keep each starter zone's `trust`, each starter element's `kind`, `zone`,
  `holds_pii` and `is_log`, each starter flow's `source` and `target`, and each starter threat's
  `target` and `category` as they are. (You may change a flow's `protocol`, and you may add anything.)

### 4. `AI_USAGE.md`

See "AI tools" below.

## Public tests

`tests/test_public.py` has five tests: STRIDE per element, a store-to-store flow, scope with one
crossing flow, rank ordering, and refusing an unsafe YAML tag. The last one never runs the command in
the file: `safe_load` refuses the tag before anything is constructed, which is the point. If you ever
see "pwned" printed, you used the wrong loader.

The public tests are a smoke test, not the grade. Read the spec line by line and write a test of your
own for every rule in it.

## How grading works

1. Push, then press **Submit for grading** on DSC Hex. The grader pins your latest commit, clones it,
   copies in DSC's hidden tests and runs them with Python 3.12 and the pinned packages, with the
   network off:
   `python -m pytest -q -p no:cacheprovider --timeout=30 tests_hidden/` from the repository root,
   30 seconds per test, 3 minutes in total. If the whole run passes 3 minutes, no test is credited.
2. Before the run the grader deletes any `conftest.py` at the repository root, ignores pytest settings
   in `pytest.ini`, `pyproject.toml`, `tox.ini` and `setup.cfg`, and removes top-level files that
   would shadow a standard-library or test-tool module (for example a `yaml.py` next to `tmcheck/`).
   Keep your code inside `tmcheck/`.
3. If `AI_USAGE.md` is missing or lacks any of the headings `## Tools`, `## What AI got wrong`,
   `## In my own words`, the grader stops and scores 0 with that reason.
4. You get a score from 0 to 100 and, per hidden test, its public name, pass or fail, and a short hint.
   You never see the hidden test code. Each ID is all or nothing: it passes only if every case under
   it passes. A hidden test that cannot import a name from your code fails on its own; the others
   still run.
5. 5 grader runs per task per day. Run the public tests locally first; the grader is a judge, not a
   debugger.
6. Late policy: ×1.0 within 72 hours of the W2 session starting, ×0.6 for the following 7 days, ×0.5
   after that until Thu 3 Dec 23:59. W5 reopens W2 at ×1.0. Your best attempt counts, with the
   multiplier of the window it was submitted in.

### Hidden tests

| ID | Public name | What it checks | Weight |
|---|---|---|---|
| H01 | load: safe loader, sections default to empty | An unsafe tag, a list at top level, invalid YAML, a section that is not a list and a missing file all raise `ModelError`; a file with only `zones` (and a `null` section) gives empty `elements`, `flows`, `threats` | 6 |
| H02 | validate: one id space for the whole model | A flow reusing an element id and a threat reusing a store id are both `DUPLICATE_ID` | 6 |
| H03 | validate: unknown zones and references | Element in an undefined zone, flow to a missing element, threat against a missing target; a clean model gives `[]` | 8 |
| H04 | validate: data-flow diagram rules | Store→store, external→external, external→store, store→external and a self-loop are all `INVALID_FLOW` | 10 |
| H05 | scores: booleans and floats are not scores | `True`, `4.0`, `"4"`, `0`, `6`, `None` give `BAD_SCORE` (as likelihood and as impact); 1 and 5 are fine | 8 |
| H06 | categories: STRIDE per element | `E` on a store, `R` on a non-log store, `T` on an external entity, `S` on a flow are `INAPPLICABLE_CATEGORY`; `R` on a log store is fine; `s` and `ST` are `BAD_CATEGORY` | 8 |
| H07 | decisions need words | Whitespace-only mitigation, missing justification, unknown status; a proper mitigation and justification raise nothing | 6 |
| H08 | scope: crossing flows and their ends | Order of `crossing_flows` (file order, unknown ends skipped); in-scope refs are exactly the crossing flows and their end elements | 8 |
| H09 | coverage: any status counts, sorted output | Accepted, mitigated and open threats all cover a pair; gaps sorted by ref then S, T, R, I, D, E | 8 |
| H10 | policy: encryption and authentication at boundaries | `HTTPS` in capitals passes; `http` fails; missing `authenticated` on an inbound crossing is flagged; an outbound crossing to lower trust is not | 8 |
| H11 | policy: personal data stores need an I threat | Flagged until an `I` threat exists, in any status; a threat of another category does not count | 4 |
| H12 | rank: open only, ties by impact then natural id | Includes `T10` vs `T2`, the 15 / 8 level boundaries, and an open threat with an invalid score (skipped) | 8 |
| H13 | CLI: exit codes and JSON shape | Exit 2 for an unloadable or missing file, 1 for a model with gaps, JSON has the four keys and gap objects have `ref` and `category` | 6 |
| H14 | your model passes the DSC checker | Your `models/rawaj_scoring.yaml` keeps every starter id with its fields as listed in step 3, has unique titles of 15+ characters, and DSC's reference checker finds no issues, gaps or policy findings | 6 |
| | | **Total** | **100** |

**Anti-cheating notes.** The hidden tests build their own models in memory, so special-casing the
Rawaj ids does nothing. H14 runs DSC's checker, not yours, on your model; a checker that always exits
0 does not help it. Copying another intern's threats is easy to see: your Track Mentor reads the eleven
new threats at the design review, and the titles should sound like your squad's thinking.

## AI tools

AI tools are allowed. `AI_USAGE.md` must keep its three headings:

- `## Tools`: what you used, for which parts.
- `## What AI got wrong`: at least one thing you changed and how you noticed (a test, the docs,
  running it).
- `## In my own words`: one or two sentences each, written without AI:
  1. Why does a data store have no Spoofing threats in STRIDE per element, and where does that threat
     go instead?
  2. Which of your eleven new threats would you fix first, and why that one?

The grader does not score the content, but it scores 0 if the file or a heading is missing. Your
Track Mentor reads it, and the W8 defence can ask about it.

Assistants are good at the happy path and weak at exactly the cases this task tests, such as a
boolean that passes `isinstance(x, int)`. Use one for a first draft if you like; the hidden edge cases
decide the score.

## Rules

- Defensive and offline: nothing in this task touches a network or a system you do not own.
- You cannot add packages. The grader has only the versions in `requirements.txt`.
- Never use `yaml.load` with an unsafe loader (`Loader=yaml.Loader`, `FullLoader`, `UnsafeLoader`)
  on files you did not write. Use `yaml.safe_load`.
