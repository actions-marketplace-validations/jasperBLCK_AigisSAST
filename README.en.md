<div align="center">

<img src="https://raw.githubusercontent.com/jasperBLCK/AigisSAST/main/assets/header.svg" width="100%" alt="AigisSAST"/>

<h3>AI writes code fast. AigisSAST makes sure it didn't leave holes.</h3>

<p><i>Security scanner for AI-generated code: finds what vibe coding leaves behind and explains how to fix it.</i></p>

<p><a href="https://github.com/jasperBLCK/AigisSAST/blob/main/README.md">Русский</a> · <b>English</b></p>

<a href="https://github.com/jasperBLCK/AigisSAST/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/jasperBLCK/AigisSAST/ci.yml?branch=main&style=for-the-badge&label=CI&labelColor=000000&color=333333&logo=githubactions&logoColor=white"/></a> <a href="https://pypi.org/project/aigis-sast/"><img src="https://img.shields.io/pypi/v/aigis-sast?style=for-the-badge&labelColor=000000&color=333333&logo=pypi&logoColor=white"/></a> <img src="https://img.shields.io/badge/python-3.9+-000000?style=for-the-badge&logo=python&logoColor=white"/> <img src="https://img.shields.io/badge/dependencies-0-000000?style=for-the-badge"/> <img src="https://img.shields.io/badge/SARIF-2.1.0-000000?style=for-the-badge&logo=github&logoColor=white"/> <img src="https://img.shields.io/badge/license-MIT-000000?style=for-the-badge"/>

</div>

<img src="https://raw.githubusercontent.com/jasperBLCK/AigisSAST/main/assets/divider.svg" width="100%"/>

## Why

Cursor, Copilot and ChatGPT ship a working backend in an evening. Along the way they almost always leave the same things behind:
a bot token right in the code, `f"SELECT ... {user}"`, `allow_origins=["*"]`, `debug=True`, Postgres exposed to the internet.
The code runs, the tests are green, and the service can already be hacked.

AigisSAST catches exactly these mistakes and explains each one **in plain words**: why it is dangerous and how to fix it, with ready code.
No sign-up, no cloud, nothing leaves your machine (unless you turn on `--ai`).

- **Zero dependencies.** Python standard library only, installs in a second.
- **AST, not grep.** Python is parsed into a syntax tree, so there are fewer false positives.
- **Secrets are masked** in reports: `sk-p************`, the key never shows up in CI logs.
- **A link for every finding.** Each finding comes with a clickable link to the file and line on GitHub/GitLab/Bitbucket; `history` links the commit.
- **Fixes, not only complains.** `aigis fix` moves keys into `.env` and rewrites the safe cases itself.
- **Sees the past.** `aigis history` finds keys that were "deleted" but are still in git history.
- **English and Russian.** The whole interface, advice and reports in both languages, picked from your system or `--lang`.
- **CI-ready.** Exit codes, SARIF for GitHub Code Scanning, JSON, Markdown, GitHub Action, pre-commit hook. `aigis init` wires it up in one command.

## Quick start

```bash
pip install aigis-sast
aigis help              # friendly overview of every command
aigis scan              # scan the current folder (or simply: aigis path/to/project)
aigis fix --dry-run     # preview automatic fixes
aigis fix               # apply them
aigis history           # check the whole git history for leaked keys
aigis init              # add the scan to GitHub Actions
```

Try it on a deliberately vulnerable example:

```bash
git clone https://github.com/jasperBLCK/AigisSAST && cd AigisSAST
pip install . && aigis scan examples
```

## What it catches

| ID | Severity | Issue | Where |
|---|---|---|---|
| `AIG001` | CRITICAL | Tokens and API keys: OpenAI, Anthropic, Telegram, GitHub, AWS, Stripe, Slack, Google, Yandex Cloud | everywhere |
| `AIG004` | CRITICAL | Private keys (RSA / EC / OpenSSH / PGP) | everywhere |
| `AIG002` | HIGH | Hardcoded passwords and secrets | Python, JS/TS, YAML, Dockerfile, compose, .ini/.toml |
| `AIG003` | HIGH | Database connection string with a password | everywhere except docs |
| `AIG005` | HIGH | `.env` goes into the repository | git / .gitignore |
| `AIG010` | HIGH | SQL injection: f-string, `%`, `+`, `.format()` in `execute()` / `text()` | Python |
| `AIG011` | HIGH | Shell injection: `shell=True`, `os.system` with a variable | Python |
| `AIG012` | HIGH | `eval` / `exec` on dynamic data | Python |
| `AIG013` | HIGH | `pickle.loads`, `yaml.load` without SafeLoader | Python |
| `AIG017` | HIGH | JWT without signature verification, `algorithms=["none"]` | Python |
| `AIG030` | HIGH | `eval` / `new Function` | JS / TS |
| `AIG014` | MEDIUM | `debug=True`, `DEBUG = True` | Python |
| `AIG015` | MEDIUM → HIGH | CORS `*` (HIGH together with `allow_credentials=True`) | FastAPI, Express |
| `AIG016` | MEDIUM | `verify=False` in requests / httpx | Python |
| `AIG019` | MEDIUM | Tokens and OTP codes from `random` instead of `secrets` | Python |
| `AIG031` | MEDIUM | XSS: `innerHTML`, `dangerouslySetInnerHTML`, `v-html` | JS / TS / Vue |
| `AIG032` | MEDIUM | Secrets in `NEXT_PUBLIC_*` / `VITE_*` / `REACT_APP_*` | frontend |
| `AIG042` | MEDIUM | DB/Redis port published on `0.0.0.0` | docker-compose |
| `AIG018` | LOW | MD5 / SHA-1 | Python |
| `AIG021` | LOW | POST/PUT/PATCH/DELETE without a `Depends(...)` auth dependency | FastAPI |
| `AIG040` | LOW | Container runs as root | Dockerfile |

Any rule in detail: `aigis explain AIG010`, the full list: `aigis rules`.

## Usage

```bash
aigis scan .                              # text report with explanations
aigis scan src api --quiet                # several paths, without the why/fix blocks
aigis scan . --min-severity medium        # hide LOW
aigis scan . --fail-on critical           # fail only on critical
aigis scan . -f sarif -o aigis.sarif      # for GitHub Code Scanning
aigis scan . -f json | jq '.findings[]'   # for your own scripts
aigis scan . -f markdown > SECURITY.md    # report for a PR or a client
```

Every finding looks like this:

```text
▌ app/config.py
   CRITICAL  AIG001  API key or token hardcoded in the code (Telegram bot token)
           app/config.py:12
           ↗ https://github.com/you/bot/blob/3f2c1ab.../app/config.py#L12
           │ BOT_TOKEN = "7312************"
           why it matters: ...
           how to fix: ...
```

The link is built from `git remote` and the current commit, so you jump straight to the line. It is also in JSON (`url`) and Markdown.
Without a remote the links are simply not printed. The report ends with a per-severity summary, a **security score** (0–100),
a grade from `A` to `F` and the finding to fix first.

| Exit code | Meaning |
|---|---|
| `0` | no findings at the `--fail-on` level (default `high`) or above |
| `1` | findings at the `--fail-on` level or above |
| `2` | usage error (bad path, unknown rule) |

### Language

```bash
aigis scan --lang ru      # or --lang en
export AIGIS_LANG=ru      # permanently
```

By default the language comes from your system (`LANG`, or the OS language on Windows): Russian systems get Russian, everyone else English.
It applies to text, JSON, Markdown, SARIF and the AI-mode prompt.

### Ignoring

```python
eval(trusted_expr)  # aigis: ignore
DEBUG = True  # aigis: ignore[AIG014]
```

Exclude files and folders with `.aigisignore` (glob patterns) or `--exclude`.
`node_modules`, `.venv`, `dist` and lock files are skipped automatically, and inside a git repo so is everything in `.gitignore`.

## Auto-fix: `aigis fix`

```bash
aigis fix --dry-run   # only show the diff
aigis fix             # apply
```

It only changes what can be changed without breaking logic:

| Before | After |
|---|---|
| `BOT_TOKEN = "7312845567:AA..."` | `BOT_TOKEN = os.environ["BOT_TOKEN"]` + value in `.env`, key in `.env.example` |
| `connect(password="Pa55word!")` | `connect(password=os.environ["PASSWORD"])` |
| `.env` not in `.gitignore` | `.env` added to `.gitignore` |
| `requests.get(url, verify=False)` | `verify=True` |
| `yaml.load(data)` | `yaml.safe_load(data)` |
| `otp = random.randint(100000, 999999)` | `otp = secrets.randbelow(900000) + 100000` |
| `token = random.choice(alphabet)` | `secrets.choice(alphabet)` |
| `app.run(debug=True)` / `DEBUG = True` | `debug=False` / `DEBUG = os.getenv("DEBUG") == "1"` |
| `- "5432:5432"` in compose | `- "127.0.0.1:5432:5432"` |

Missing `import os` / `import secrets` are added for you. SQL injection, `eval`, `pickle`, JWT and CORS are never touched
automatically: they need an understanding of the app, so they stay on the "manual" list.

## Leaked keys in history: `aigis history`

```text
$ aigis history
aigis history: secrets in git history: 1

  [CRITICAL] AIG001  7312************  (Telegram bot token)
      bot.py  ·  commit 402c92b of 2026-09-14  ·  removed, but still in history
      ↗ https://github.com/you/bot/commit/402c92b...
```

Removing a key in a new commit is not enough: the old file version stays in history and anyone who cloned the repo can see it.
`aigis history` walks every commit and branch, shows where and when the key appeared, whether it is still in the code, and links the commit.
Keys are masked. For CI: `aigis history -f json` (fields `commit_url`, `url`), exit code `1` when something is found.

## README badge

```bash
aigis badge                # writes aigis-badge.svg with the grade, e.g. "aigis | A 100/100"
aigis badge --url          # a shields.io link, no file
```

## AI mode

```bash
export AIGIS_API_KEY=...                         # any OpenAI-compatible API
export AIGIS_BASE_URL=https://api.openai.com/v1  # or your proxy / local LLM
export AIGIS_MODEL=gpt-4o-mini
aigis scan . --ai
```

For each finding the model gets the code around it and returns a fix for your exact code, in your interface language.
**Secret findings (`AIG001`–`AIG005`) are never sent to the model.** Without a key or when the API is down,
the scanner says so and shows the built-in advice.

## GitHub Actions

Quickest, one command:

```bash
aigis init     # creates .github/workflows/aigis.yml and .aigisignore (never overwrites existing files)
```

Or by hand:

```yaml
name: security
on: [push, pull_request]

jobs:
  aigis:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: jasperBLCK/AigisSAST@v0.5.0
        with:
          fail-on: high
          lang: en        # report language: en or ru
```

Findings show up under **Security → Code scanning** and right in the pull request diff.

## pre-commit

```yaml
repos:
  - repo: https://github.com/jasperBLCK/AigisSAST
    rev: v0.5.0
    hooks:
      - id: aigis
```

## How it works

```text
aigis scan
   │
   ├── scanner      git ls-files → filters → .aigisignore → read files
   ├── checks/
   │    ├── python_ast   ast.NodeVisitor: SQL, shell, eval, pickle, JWT, CORS, debug, random, FastAPI auth
   │    └── text         regex: tokens, keys, DSNs, configs, Dockerfile, compose, JS/TS
   ├── ai           (optional) OpenAI-compatible API, secrets filtered out
   ├── gitlink      git remote + HEAD → link to file#line / commit
   └── report       text · json · sarif · markdown  +  score / grade, en / ru

aigis fix       finding AST positions → targeted edits → .env / .env.example / .gitignore
aigis history   git log -p --all → added lines → the same secret detectors
aigis badge     score / grade → SVG or shields.io
aigis init      GitHub Actions workflow + .aigisignore
```

Development:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && pytest -q
```

## Roadmap

- [x] Python AST rules, secrets, configs, Dockerfile, compose, JS/TS
- [x] SARIF, JSON, Markdown, GitHub Action, pre-commit
- [x] AI fixes through an OpenAI-compatible API
- [x] `aigis fix`: automatic fixes for the safe cases (secrets to `.env`)
- [x] `aigis history`: secrets across the whole git history
- [x] `aigis badge`: security grade badge
- [x] Clickable links to the line and the commit right in the output
- [x] English and Russian interface, `aigis help`, `aigis init`
- [ ] Dependency checks for known CVEs and typosquatting
- [ ] Django and Flask rules, Go and PHP
- [ ] VS Code extension

## License

[MIT](https://github.com/jasperBLCK/AigisSAST/blob/main/LICENSE)

<img src="https://raw.githubusercontent.com/jasperBLCK/AigisSAST/main/assets/divider.svg" width="100%"/>

<div align="center"><sub>built by <a href="https://github.com/jasperBLCK">jasperBLCK</a> · ship fast, ship secure</sub></div>
