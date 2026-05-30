# ai-pen-test

> Penetration-testing framework targeted at LLM-powered applications.

`ai-pen-test` is a Python framework for security-testing LLM applications and
APIs. It runs attack suites against a target endpoint, captures evidence,
and produces structured pentest reports in Markdown / JSON / HTML.

## Features

- **Attack modules** — prompt injection, jailbreaks, semantic exploits,
  payload mutation.
- **Reporter** — converts findings into Markdown, JSON, and HTML reports
  under `pentest_reports/` and `reports/`.
- **Scanner + client + database** for repeatable engagements (`scanner.py`,
  `client.py`, `database.py`).
- **Interactive notebook** — `llm_pentest_notebook.ipynb` for hands-on
  exploration.
- **API mode** — `api.py` exposes the framework as a service.

## Tech stack

Python · requests · Jupyter · SQLite · YAML configs

## Quickstart

```bash
git clone https://github.com/krishddd/ai-pen-test.git
cd ai-pen-test
pip install -r requirements.txt
cp .env.example .env  # set target endpoint + API keys

# Run an engagement
python main.py --config config.yaml

# Or use the notebook
jupyter lab llm_pentest_notebook.ipynb
```

## Project structure

```
main.py                       Engagement driver
api.py                        REST front-end
scanner.py                    Probe scheduler
client.py                     Target adapter
database.py                   SQLite-backed engagement store
reporter.py                   Report builder
attacks/                      Attack modules (prompt injection, jailbreak, ...)
utils/payloads.py, semantic.py  Payload helpers
config.yaml                   Engagement config
llm_pentest_notebook.ipynb    Interactive walkthrough
```

> ⚠️ Use only against systems you are authorised to test.

## Status

Personal portfolio. Designed for repeatable engagements with structured
evidence capture.

## License

MIT
