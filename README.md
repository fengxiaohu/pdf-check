# pdf-check

Static PDF security scanner with:
- LLM instruction/prompt-injection detection (`pdf_check.cli`)
- PDF structural/action/link/hidden-text anomaly analysis (`pdf_sanitizer.py`)

## Threat Model

The scanner targets untrusted PDFs that may contain:
- Hidden/invisible text in content streams
- Dangerous actions (`/OpenAction`, `/JavaScript`, `/Launch`, `/GoToR`, etc.)
- Link spoofing (displayed text vs actual URI mismatch)
- Embedded files and suspicious stream payload indicators
- Obfuscation patterns (very long strings, invisible Unicode controls)
- Structural anomalies (large object counts, incremental-update markers)

This tool performs static analysis only:
- It does not execute JavaScript.
- It does not open external links.
- It does not invoke external system commands from PDF content.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## CLI: PDF Sanitizer

```bash
python pdf_sanitizer.py input.pdf --out report.json --extract output/ --verbose
python pdf_sanitizer.py input.pdf --json
python pdf_sanitizer.py input.pdf --strict
python pdf_sanitizer.py --clean-artifacts --clean-dir .
```

Options:
- `--json`: print machine-readable JSON report
- `--out <path>`: write JSON report to file
- `--extract <dir>`: export suspicious raw objects/metadata to local directory
- `--strict`: lower thresholds, more aggressive detection
- `--verbose`: include finding evidence in console output
- `--clean-artifacts`: delete generated artifacts and exit
- `--clean-dir <path>`: base directory to clean in `--clean-artifacts` mode

Exit code:
- `0`: no high-risk exit-trigger findings
- `1`: high-risk findings detected (`JS`, `Launch`, `OpenAction`, `EmbeddedFiles`)
- `2`: processing error (e.g., dependency/parse failure)

## CLI: LLM Injection Scan

```bash
python -m pdf_check.cli /path/to/file.pdf --json
python -m pdf_check.cli /path/to/file.pdf --llm-strict
python -m pdf_check.cli /path/to/file.pdf --llm-keywords custom_rules.yaml --json
```

## Report Interpretation

Each finding includes:
- `id`
- `severity` / `risk_level` (`low|medium|high`)
- `category`
- `type`
- `page` (if applicable)
- `object_id`
- `description`
- `evidence` (truncated snippet)

Suggested triage:
- `high`: investigate immediately; often indicates active behavior or concealment.
- `medium`: review in context; potential abuse or evasion signals.
- `low`: informational/suspicious context that may need correlation.

## Potential False Positives

- Course/technical PDFs may include words like “debug”, “launch”, or “must”.
- Incremental updates can be legitimate revision history.
- Domain mismatch can trigger on pages with multiple benign URLs.
- Tiny fonts may be used for footnotes or rendering artifacts.

## Tests

Run:

```bash
pytest -q
```

Includes fixture-based tests that lock in:
- LLM severity/confidence behavior
- location/source coverage
- link mismatch heuristics
- structural summary and exit-trigger logic

## Web UI (Upload PDF)

Start local web app:

```bash
python -m pdf_check.web_app
```

Then open:
- `http://127.0.0.1:5000`

The page lets users upload a PDF and run the same static sanitizer scan in-browser.
After scanning, the web UI provides `Download Clean Markdown` and `Download Clean PDF` actions.
