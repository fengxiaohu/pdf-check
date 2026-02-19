from __future__ import annotations

import io
import re
import tempfile
import uuid
from collections import OrderedDict
from pathlib import Path

from flask import Flask, abort, render_template, request, send_file
from pypdf import PdfReader
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from werkzeug.utils import secure_filename

from .sanitizer import AnalyzerConfig, PDFSanitizer

# Keep a small in-memory cache for download actions after scanning.
# token -> {"filename": str, "bytes": bytes}
_DOWNLOAD_CACHE: "OrderedDict[str, dict[str, object]]" = OrderedDict()
_CACHE_LIMIT = 20


def _put_cache(token: str, filename: str, data: bytes) -> None:
    _DOWNLOAD_CACHE[token] = {"filename": filename, "bytes": data}
    _DOWNLOAD_CACHE.move_to_end(token)
    while len(_DOWNLOAD_CACHE) > _CACHE_LIMIT:
        _DOWNLOAD_CACHE.popitem(last=False)


def _get_cached_pdf(token: str) -> tuple[str, bytes] | None:
    item = _DOWNLOAD_CACHE.get(token)
    if not item:
        return None
    filename = str(item["filename"])
    data = item["bytes"]
    if not isinstance(data, (bytes, bytearray)):
        return None
    return filename, bytes(data)


def _should_remove_line(line: str) -> bool:
    low = f" {line.lower()} "
    suspicious_terms = [
        "openaction",
        "javascript",
        " launch ",
        "gotor",
        "submitform",
        "embeddedfiles",
        "filespec",
        "chatgpt",
        "gemini",
        "deepseek",
        "claude",
        "copilot",
        "llm",
        "ai assistant",
        "system prompt",
        "ignore previous instructions",
        "reveal",
        "exfiltrate",
        "do not tell",
        "never tell",
    ]
    if any(term in low for term in suspicious_terms):
        return True
    return bool(re.search(r"https?://\S+", line, flags=re.IGNORECASE))


def _extract_clean_lines(pdf_bytes: bytes) -> list[tuple[int, list[str]]]:
    out: list[tuple[int, list[str]]] = []
    reader = PdfReader(io.BytesIO(pdf_bytes))
    for i, page in enumerate(reader.pages, start=1):
        try:
            text = page.extract_text() or ""
        except Exception:
            text = ""
        kept: list[str] = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            if _should_remove_line(line):
                continue
            kept.append(line)
        out.append((i, kept))
    return out


def _build_clean_markdown(filename: str, pages: list[tuple[int, list[str]]]) -> str:
    lines: list[str] = []
    lines.append("# Cleaned Markdown Export")
    lines.append("")
    lines.append(f"Source file: `{filename}`")
    lines.append("")
    lines.append("Sanitized text-only export (filtered suspicious/prompt-injection/link lines).")
    lines.append("")

    for page_no, page_lines in pages:
        lines.append(f"## Page {page_no}")
        lines.append("")
        if page_lines:
            lines.extend(page_lines)
        else:
            lines.append("_No retained text after sanitization for this page._")
        lines.append("")

    return "\n".join(lines)


def _build_clean_pdf_bytes(filename: str, pages: list[tuple[int, list[str]]]) -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    width, height = letter

    for page_no, page_lines in pages:
        y = height - 48
        c.setFont("Helvetica-Bold", 12)
        c.drawString(36, y, f"Cleaned PDF Export - {filename} - Page {page_no}")
        y -= 24

        c.setFont("Helvetica", 10)
        if not page_lines:
            c.drawString(36, y, "No retained text after sanitization for this page.")
        else:
            for line in page_lines:
                wrapped = _wrap_text(line, max_len=110)
                for chunk in wrapped:
                    if y < 50:
                        c.showPage()
                        y = height - 48
                        c.setFont("Helvetica", 10)
                    c.drawString(36, y, chunk)
                    y -= 13
        c.showPage()

    c.save()
    buf.seek(0)
    return buf.getvalue()


def _wrap_text(text: str, max_len: int) -> list[str]:
    if len(text) <= max_len:
        return [text]
    parts: list[str] = []
    remaining = text
    while len(remaining) > max_len:
        cut = remaining.rfind(" ", 0, max_len)
        if cut <= 0:
            cut = max_len
        parts.append(remaining[:cut])
        remaining = remaining[cut:].lstrip()
    if remaining:
        parts.append(remaining)
    return parts


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB

    @app.get("/")
    def index():
        return render_template("index.html", report=None, error=None)

    @app.post("/scan")
    def scan():
        upload = request.files.get("pdf")
        strict = request.form.get("strict") == "on"
        verbose = request.form.get("verbose") == "on"

        if upload is None or upload.filename == "":
            return render_template("index.html", report=None, error="Please choose a PDF file first.")

        filename = secure_filename(upload.filename)
        if not filename.lower().endswith(".pdf"):
            return render_template("index.html", report=None, error="Only .pdf files are supported.")

        pdf_bytes = upload.read()
        if not pdf_bytes:
            return render_template("index.html", report=None, error="Uploaded file is empty.")

        with tempfile.TemporaryDirectory() as td:
            temp_path = Path(td) / filename
            temp_path.write_bytes(pdf_bytes)

            analyzer = PDFSanitizer(AnalyzerConfig(strict=strict, verbose=verbose))
            try:
                report = analyzer.analyze(str(temp_path))
            except Exception as exc:
                return render_template("index.html", report=None, error=f"Scan failed: {exc}")

        token = uuid.uuid4().hex
        _put_cache(token, filename, pdf_bytes)

        return render_template(
            "index.html",
            report=report,
            error=None,
            scan_options={"strict": strict, "verbose": verbose},
            uploaded_name=filename,
            download_token=token,
        )

    @app.get("/download/clean.md")
    def download_clean_markdown():
        token = request.args.get("token", "")
        cached = _get_cached_pdf(token)
        if cached is None:
            abort(404, "Scan token not found. Please upload and scan again.")
        filename, pdf_bytes = cached
        pages = _extract_clean_lines(pdf_bytes)
        data = _build_clean_markdown(filename, pages).encode("utf-8")
        out_name = f"{Path(filename).stem}.cleaned.md"
        return send_file(io.BytesIO(data), as_attachment=True, download_name=out_name, mimetype="text/markdown")

    @app.get("/download/clean.pdf")
    def download_clean_pdf():
        token = request.args.get("token", "")
        cached = _get_cached_pdf(token)
        if cached is None:
            abort(404, "Scan token not found. Please upload and scan again.")
        filename, pdf_bytes = cached
        pages = _extract_clean_lines(pdf_bytes)
        pdf_data = _build_clean_pdf_bytes(filename, pages)
        out_name = f"{Path(filename).stem}.cleaned.pdf"
        return send_file(io.BytesIO(pdf_data), as_attachment=True, download_name=out_name, mimetype="application/pdf")

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
