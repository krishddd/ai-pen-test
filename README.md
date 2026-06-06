# ai-pen-test

> Penetration-testing framework targeted at LLM-powered applications.
> Runs attack suites against a target endpoint, captures evidence,
> produces structured pentest reports in Markdown / JSON / HTML, and
> exposes the framework as both a CLI and a service.

`ai-pen-test` is a repeatable-engagement framework for LLM security. It
treats each engagement as a structured object — target, scope, attacks,
evidence, verdict — and persists everything in a SQLite database so an
engagement can be paused, resumed, replayed, or compared against a prior
run.

> ⚠️ Use only against systems you are authorised to test.

---

## End-to-end pipeline

```
config.yaml  ← target + scope + attack policy
        │
        ▼
main.py / api.py
        │
        ▼
client.py            ← target adapter (HTTP, auth, rate-limit)
        │
        ▼
scanner.py           ← probe scheduler
        │
        ├──► attacks/  ─►  prompt-injection variants
        │                  jailbreak variants
        │                  semantic exploits
        │                  payload mutation (utils/payloads.py)
        │                  embedding / context tricks (utils/semantic.py)
        │
        ▼
per-probe verdict
        │
        ├──► database.py    →  SQLite (engagement, probe, verdict)
        ├──► api_reports/   →  raw structured responses
        └──► results/       →  per-probe evidence
        │
        ▼
reporter.py
        │
        ├──► pentest_reports/<engagement>.md
        ├──► pentest_reports/<engagement>.json
        ├──► pentest_reports/<engagement>.html
        └──► reports/<engagement>/finding-*.md
        │
        ▼
logs/  ← engagement audit log
```

---

## Engagement lifecycle

Every engagement is a row in `database.py`'s SQLite store:

1. **Create** — `main.py --config config.yaml` creates an engagement with
   a target, scope, attack policy, and rate-limit budget.
2. **Plan** — the scanner selects attacks from `attacks/` per the policy
   and the target's apparent shape.
3. **Probe** — for each attack, the scanner sends one or more requests via
   `client.py`, captures the response in `api_reports/`, and computes a
   per-probe verdict using heuristics and (optionally) a judge LLM.
4. **Persist** — every probe and verdict lands in SQLite with a stable
   probe_id so a re-run can be diffed.
5. **Report** — `reporter.py` aggregates verdicts per category, scores
   posture, and renders Markdown / JSON / HTML under `pentest_reports/`.
   One Markdown per finding lands under `reports/<engagement>/`.
6. **Resume** — `main.py --resume <engagement>` picks up where a pause or
   crash left off; probes already in the DB are skipped.

---

## Attack catalogue

The `attacks/` package ships modular probes:

| Family                 | What it does                                                 |
|------------------------|--------------------------------------------------------------|
| Prompt injection       | Direct + indirect injection, system-prompt extraction        |
| Jailbreak              | Persona-hijack, DAN-style, multi-turn drift                  |
| Semantic exploit       | Homoglyph, encoding, instruction smuggling                   |
| Payload mutation       | Genetic / fuzz mutation over a base payload                  |
| Context / embedding    | Adversarial context inflation, embedding-based exfil         |
| Output filter bypass   | Role smuggling, structured-output injection                  |
| Tool / function abuse  | Argument poisoning, wrong-tool coercion                      |

`utils/payloads.py` provides reusable payload primitives and a small
mutation library; `utils/semantic.py` provides similarity scoring for
fuzz-mutation acceptance criteria.

---

## Reporter formats

`reporter.py` emits three artefact families:

- **Per-engagement summary** — `pentest_reports/<engagement>.md`,
  `.json`, and `.html`. The HTML version is a clickable posture
  dashboard with verdicts grouped by category and severity.
- **Per-finding markdown** — `reports/<engagement>/finding-*.md`. Each
  file is a self-contained writeup with reproduction steps, evidence
  excerpts (redacted), severity, and a suggested remediation.
- **CSV summary** — `pentest_results.csv` accumulates summary rows
  across engagements for trend analysis.

---

## Interactive notebook

`llm_pentest_notebook.ipynb` is a Jupyter notebook for hands-on
exploration. Use it to:

- Build and tune a single payload before pushing it into the attack pack.
- Walk through a target's response to a series of variants.
- Compare two engagements side-by-side.
- Demo the framework to a stakeholder.

---

## API mode

`api.py` exposes the framework over HTTP so engagements can be triggered
from a CI pipeline, a Slack bot, or a downstream dashboard:

```bash
uvicorn api:app --reload --port 8000

# Create an engagement
curl -X POST http://localhost:8000/engagements \
     -H 'Content-Type: application/json' \
     -d '{
       "target": "https://my-llm-app.example.com/chat",
       "scope": ["https://my-llm-app.example.com"],
       "policy": "balanced",
       "rate_rps": 2
     }'

# Poll status
curl http://localhost:8000/engagements/<id>
```

---

## Quickstart

```bash
git clone https://github.com/krishddd/ai-pen-test.git
cd ai-pen-test
pip install -r requirements.txt
cp .env.example .env  # target endpoint, target token, judge LLM keys

# Run an engagement from CLI
python main.py --config config.yaml

# Resume a previous engagement
python main.py --resume <engagement_id>

# Or use the notebook
jupyter lab llm_pentest_notebook.ipynb
```

Open `pentest_reports/<engagement>.html` when done.

---

## Project structure

```
main.py                       CLI engagement driver
api.py                        REST front-end
scanner.py                    Probe scheduler
client.py                     Target HTTP adapter
database.py                   SQLite-backed engagement store
reporter.py                   Markdown / JSON / HTML report builder
attacks/                      Attack modules (prompt injection, jailbreak, ...)
utils/
├── payloads.py               Payload primitives + mutation
└── semantic.py               Semantic similarity helpers
config.yaml                   Engagement config (target + scope + policy)
llm_pentest_notebook.ipynb    Interactive walkthrough
api_reports/                  Raw captured responses (gitignored)
results/                      Per-probe evidence (gitignored)
pentest_reports/              Per-engagement reports
reports/<engagement>/         Per-finding Markdown
pentest_results.csv           Cross-engagement summary
logs/                         Engagement audit log (gitignored)
tests/                        pytest suites
docs/                         Long-form notes
.github/workflows/            CI
```

---

## Configuration

`config.yaml` knobs (excerpt):

```yaml
target:
  base_url: https://my-llm-app.example.com
  auth:
    type: bearer
    token_env: TARGET_TOKEN

scope:
  allow_hosts: [my-llm-app.example.com]
  deny_hosts: []

policy:
  profile: balanced       # stealth | balanced | loud
  rate_rps: 2
  max_total_probes: 500

attacks:
  prompt_injection: { enabled: true, variants: 25 }
  jailbreak: { enabled: true, variants: 15 }
  semantic_exploit: { enabled: true, variants: 10 }
  tool_abuse: { enabled: true }

reporter:
  formats: [markdown, json, html]
  group_by: category
  judge:
    provider: openai
    model: gpt-4o-mini
```

---

## CI

GitHub Actions runs syntax check + pytest on every push.

---

## Status

Personal portfolio. Designed for repeatable engagements with structured
evidence capture and diff-able results.

## License

MIT
