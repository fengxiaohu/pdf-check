<a id="readme-top"></a>

**English** | **[简体中文](README.md)**

<br />
<div align="center">
  <h1 align="center">pdf-check</h1>
  <p align="center">
    Static PDF security scanner for hidden text, suspicious links/actions, prompt injection, and cleaned exports.
    <br />
    <a href="https://github.com/fengxiaohu/pdf-check"><strong>View Repository »</strong></a>
    <br />
    <br />
    <a href="https://github.com/fengxiaohu/pdf-check/issues">Report Bug</a>
    ·
    <a href="https://github.com/fengxiaohu/pdf-check/issues">Request Feature</a>
  </p>
</div>

<div align="center">

![CI](https://github.com/fengxiaohu/pdf-check/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/github/license/fengxiaohu/pdf-check)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

</div>

## Table of Contents

- [About The Project](#about-the-project)
  - [Key Features](#key-features)
  - [Built With](#built-with)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
  - [CLI: Sanitizer](#cli-sanitizer)
  - [CLI: LLM Injection Scan](#cli-llm-injection-scan)
  - [Web UI](#web-ui)
- [Threat Model & Boundary](#threat-model--boundary)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)
- [Acknowledgments](#acknowledgments)

## About The Project

`pdf-check` performs **static security analysis** on untrusted PDFs, covering:
- Hidden text (transparent text, tiny/micro fonts, Tr=3, control-character obfuscation)
- Suspicious links and actions (`/OpenAction`, `/JavaScript`, `/URI`, `/Launch`, `/GoToR`, `/SubmitForm`)
- Embedded content (`EmbeddedFiles`, suspicious streams)
- LLM-targeted prompt-injection instructions

### Key Features

- Structure/object scanning + page content-stream analysis
- Severity levels with auditable evidence
- JSON reporting, extraction mode (`--extract`), strict mode (`--strict`)
- Web upload scanning with cleaned export downloads (Markdown/PDF)

### Built With

- Python 3.10+
- `pikepdf`
- `pypdf`
- `Flask`
- `pytest`
- `reportlab`

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Getting Started

### Prerequisites

```bash
python --version
# recommended >= 3.10
```

### Installation

```bash
git clone https://github.com/fengxiaohu/pdf-check.git
cd pdf-check
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Usage

### CLI: Sanitizer

```bash
python pdf_sanitizer.py input.pdf --out report.json --extract output/ --verbose
python pdf_sanitizer.py input.pdf --json
python pdf_sanitizer.py input.pdf --strict
python pdf_sanitizer.py --clean-artifacts --clean-dir .
```

Common options:
- `--json`: machine-readable JSON output
- `--out <path>`: write JSON report file
- `--extract <dir>`: export suspicious raw object data
- `--strict`: stricter thresholds
- `--verbose`: print more evidence
- `--clean-artifacts`: remove generated artifacts and exit

Exit codes:
- `0`: no high-risk trigger findings
- `1`: high-risk findings detected
- `2`: processing error

### CLI: LLM Injection Scan

```bash
python -m pdf_check.cli /path/to/file.pdf --json
python -m pdf_check.cli /path/to/file.pdf --llm-strict
python -m pdf_check.cli /path/to/file.pdf --llm-keywords custom_rules.yaml --json
```

### Web UI

```bash
python -m pdf_check.web_app
```

Open: `http://127.0.0.1:5000`

Features:
- Upload a PDF and run static scanning
- View summary and findings
- Download cleaned outputs: `Clean Markdown` / `Clean PDF`

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Threat Model & Boundary

This tool is static-only. It does not:
- Execute JavaScript
- Open external links automatically
- Execute system commands based on PDF content

This makes it suitable for pre-review, CI checks, and batch screening.

## Roadmap

- [x] Structure/object + content-stream detection
- [x] Web upload scanning UI
- [x] Clean export (Markdown/PDF)
- [x] GitHub Actions automated tests
- [ ] Better visual localization overlays
- [ ] Rule management for custom detection profiles

See issues: <https://github.com/fengxiaohu/pdf-check/issues>

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Contributing

Contributions are welcome:
1. Fork the repository
2. Create a branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -m "feat: ..."`
4. Push branch and open a Pull Request

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE).

## Contact

- GitHub: <https://github.com/fengxiaohu>
- Project: <https://github.com/fengxiaohu/pdf-check>

## Acknowledgments

- [Best-README-Template](https://github.com/othneildrew/Best-README-Template)
- [pikepdf](https://github.com/pikepdf/pikepdf)
- [pypdf](https://github.com/py-pdf/pypdf)
- [Flask](https://flask.palletsprojects.com/)

<p align="right">(<a href="#readme-top">back to top</a>)</p>
