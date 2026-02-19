from __future__ import annotations

import argparse
import json
import sys

from .llm_detection import default_config, detect_llm_instructions, merge_custom_keywords
from .pdf_scanner import scan_pdf_text_fragments


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pdf-check",
        description="Scan PDFs for LLM/AI-targeted instructions and prompt-injection style content.",
    )
    parser.add_argument("pdf_path", help="Path to the PDF to scan.")
    parser.add_argument(
        "--llm-scan",
        dest="llm_scan",
        action="store_true",
        default=True,
        help="Enable LLM instruction scanning (default: on).",
    )
    parser.add_argument(
        "--no-llm-scan",
        dest="llm_scan",
        action="store_false",
        help="Disable LLM instruction scanning.",
    )
    parser.add_argument(
        "--llm-strict",
        action="store_true",
        help="Enable stricter LLM detection (expanded keywords/patterns and lower effective threshold).",
    )
    parser.add_argument(
        "--llm-keywords",
        help="Path to JSON/YAML file with custom keywords/patterns.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        fragments = scan_pdf_text_fragments(args.pdf_path)
    except Exception as exc:
        _emit_error(f"Failed to scan PDF: {exc}", as_json=args.json)
        return 2

    findings: list[dict[str, object]] = []
    if args.llm_scan:
        try:
            config = default_config(strict=args.llm_strict)
            config = merge_custom_keywords(config, args.llm_keywords)
        except Exception as exc:
            _emit_error(f"Failed to load LLM detection config: {exc}", as_json=args.json)
            return 2
        llm_findings = detect_llm_instructions(fragments, config)
        findings.extend([f.as_dict() for f in llm_findings])

    output = {
        "file": args.pdf_path,
        "findings": findings,
        "counts": {
            "total": len(findings),
            "high": len([f for f in findings if f.get("severity") == "high"]),
            "medium": len([f for f in findings if f.get("severity") == "medium"]),
            "low": len([f for f in findings if f.get("severity") == "low"]),
        },
    }

    if args.json:
        print(json.dumps(output, ensure_ascii=False, indent=2))
    else:
        print(f"File: {output['file']}")
        print(f"Findings: {output['counts']['total']}")
        print(
            f"Severity: high={output['counts']['high']} "
            f"medium={output['counts']['medium']} low={output['counts']['low']}"
        )
        for idx, finding in enumerate(findings, start=1):
            print(
                f"[{idx}] {finding['category']} {finding['severity']} "
                f"loc={finding['location_type']} page={finding['page']} obj={finding['object_id']}"
            )
            print(f"  confidence={finding['confidence']} rules={','.join(finding['matched_rules'])}")
            print(f"  evidence={finding['evidence']}")
    return 0


def _emit_error(message: str, as_json: bool) -> None:
    if as_json:
        print(json.dumps({"error": message}, ensure_ascii=False))
    else:
        print(f"Error: {message}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())

