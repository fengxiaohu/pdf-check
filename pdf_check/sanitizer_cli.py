from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
import shutil

from .sanitizer import AnalyzerConfig, PDFSanitizer, render_human_report, should_fail_exit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pdf_sanitizer.py",
        description="Static PDF risk scanner (no execution of embedded actions).",
    )
    parser.add_argument("input_pdf", nargs="?", help="Path to input PDF")
    parser.add_argument("--out", help="Write JSON report to path")
    parser.add_argument("--extract", help="Directory to export suspicious raw objects/metadata")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON report")
    parser.add_argument("--strict", action="store_true", help="Aggressive thresholds (more false positives)")
    parser.add_argument("--verbose", action="store_true", help="Show evidence snippets in console output")
    parser.add_argument(
        "--clean-artifacts",
        action="store_true",
        help="Remove generated sanitizer artifacts (output reports/overlays/json files) and exit.",
    )
    parser.add_argument(
        "--clean-dir",
        default=".",
        help="Base directory to clean when --clean-artifacts is used (default: current directory).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.clean_artifacts:
        removed = clean_generated_artifacts(Path(args.clean_dir))
        if args.json:
            print(json.dumps({"cleaned": removed, "count": len(removed)}, ensure_ascii=False, indent=2))
        else:
            print(f"Removed {len(removed)} artifact path(s).")
            for p in removed:
                print(f"- {p}")
        return 0

    if not args.input_pdf:
        parser.error("input_pdf is required unless --clean-artifacts is used")

    config = AnalyzerConfig(strict=args.strict, verbose=args.verbose, extract_dir=args.extract)
    analyzer = PDFSanitizer(config)

    try:
        report = analyzer.analyze(args.input_pdf)
    except Exception as exc:
        err = {"error": str(exc), "file": args.input_pdf}
        if args.json:
            print(json.dumps(err, ensure_ascii=False, indent=2))
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(render_human_report(report, verbose=args.verbose))

    findings = analyzer.findings
    return 1 if should_fail_exit(findings) else 0


def clean_generated_artifacts(base_dir: Path) -> list[str]:
    base = base_dir.resolve()
    removed: list[str] = []

    # Known generated directories/files from this project workflow.
    directories = [
        base / "output",
    ]
    file_patterns = [
        "*.sanitizer.json",
        "*.sanitizer.rerun.json",
        "*.updated.sanitizer.json",
    ]

    for d in directories:
        if d.exists() and d.is_dir():
            shutil.rmtree(d)
            removed.append(str(d))

    for pattern in file_patterns:
        for p in base.glob(pattern):
            if p.is_file():
                p.unlink()
                removed.append(str(p))

    return sorted(removed)


if __name__ == "__main__":
    raise SystemExit(main())
