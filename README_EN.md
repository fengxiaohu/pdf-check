**English** | **[简体中文](README.md)**

# pdf-check

`pdf-check` is a static PDF security scanner focused on:
- LLM-targeted instructions / prompt injection
- Hidden text and suspicious links/actions
- Embedded content and structural anomalies

The project also provides a local web UI: users can upload a PDF, run detection, and download cleaned Markdown/PDF.

## Security Boundary

This project performs static analysis only. It does not:
- Execute JavaScript
- Open external links automatically
- Invoke system commands from PDF content

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## CLI Usage

### 1) Sanitizer

```bash
python pdf_sanitizer.py input.pdf --out report.json --extract output/ --verbose
python pdf_sanitizer.py input.pdf --json
python pdf_sanitizer.py input.pdf --strict
python pdf_sanitizer.py --clean-artifacts --clean-dir .
```

Options:
- `--json`: machine-readable JSON output
- `--out <path>`: write JSON report to file
- `--extract <dir>`: export suspicious raw object data
- `--strict`: stricter thresholds
- `--verbose`: print more evidence
- `--clean-artifacts`: remove generated artifacts and exit
- `--clean-dir <path>`: base path for clean mode

Exit code:
- `0`: no high-risk trigger findings
- `1`: high-risk findings detected
- `2`: processing error

### 2) LLM Injection Scan

```bash
python -m pdf_check.cli /path/to/file.pdf --json
python -m pdf_check.cli /path/to/file.pdf --llm-strict
python -m pdf_check.cli /path/to/file.pdf --llm-keywords custom_rules.yaml --json
```

## Web UI

Start:

```bash
python -m pdf_check.web_app
```

Open:
- `http://127.0.0.1:5000`

Features:
- Upload a PDF and run static scanning
- View risk summary and detailed findings
- Download cleaned outputs: `Clean Markdown` / `Clean PDF`

## Tests

```bash
pytest -q
```

## License

This project is licensed under the **MIT License**.
See: `LICENSE`
