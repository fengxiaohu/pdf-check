from __future__ import annotations

import json
import re
from collections.abc import Iterable
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

CONTROL_CHARS = {
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\ufeff",  # zero width no-break space
    "\u202a",  # bidi LRE
    "\u202b",  # bidi RLE
    "\u202c",  # bidi PDF
    "\u202d",  # bidi LRO
    "\u202e",  # bidi RLO
    "\u2066",  # LRI
    "\u2067",  # RLI
    "\u2068",  # FSI
    "\u2069",  # PDI
}


@dataclass
class Finding:
    id: str
    severity: str
    category: str
    type: str
    page: int | None
    object_id: int | None
    description: str
    evidence: str
    risk_level: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity,
            "risk_level": self.risk_level,
            "category": self.category,
            "type": self.type,
            "page": self.page,
            "object_id": self.object_id,
            "description": self.description,
            "evidence": self.evidence,
        }


@dataclass
class AnalyzerConfig:
    strict: bool = False
    verbose: bool = False
    extract_dir: str | None = None

    @property
    def tiny_font_threshold(self) -> float:
        return 3.0 if self.strict else 2.0

    @property
    def abnormal_tz_floor(self) -> float:
        return 15.0 if self.strict else 10.0

    @property
    def abnormal_tz_ceil(self) -> float:
        return 250.0 if self.strict else 300.0

    @property
    def long_string_threshold(self) -> int:
        return 4096 if self.strict else 8192

    @property
    def excessive_object_threshold(self) -> int:
        return 7000 if self.strict else 12000


class PDFSanitizer:
    def __init__(self, config: AnalyzerConfig) -> None:
        self.config = config
        self.findings: list[Finding] = []
        self.errors: list[dict[str, str]] = []
        self._finding_counter = 0
        self._page_text_cache: dict[int, str] = {}

    def analyze(self, pdf_path: str) -> dict[str, Any]:
        try:
            import pikepdf  # type: ignore
        except Exception as exc:  # pragma: no cover - validated via tests with monkeypatching
            raise RuntimeError("pikepdf is required. Install dependencies from requirements.txt") from exc

        path = Path(pdf_path)
        with pikepdf.open(str(path)) as pdf:
            self._scan_structure(pdf, path)
            self._scan_page_content(pdf)
            self._scan_links_and_actions(pdf)

        summary = build_summary(self.findings)
        return {
            "file": str(path),
            "summary": summary,
            "findings": [f.as_dict() for f in self.findings],
            "errors": self.errors,
        }

    def _scan_structure(self, pdf: Any, path: Path) -> None:
        try:
            obj_count = len(pdf.objects)
            if obj_count > self.config.excessive_object_threshold:
                self._add_finding(
                    severity="medium",
                    category="structure_anomaly",
                    finding_type="excessive_objects",
                    page=None,
                    object_id=None,
                    description="Excessive number of PDF objects.",
                    evidence=f"object_count={obj_count}",
                )
        except Exception as exc:
            self._log_error("structure", f"unable to count objects: {exc}")

        startxref_hits = 0
        try:
            raw_bytes = path.read_bytes()
            startxref_hits = len(re.findall(rb"startxref", raw_bytes))
            if startxref_hits > 1:
                self._add_finding(
                    severity="medium",
                    category="structure_anomaly",
                    finding_type="incremental_update",
                    page=None,
                    object_id=None,
                    description="Multiple startxref markers detected (incremental updates).",
                    evidence=f"startxref_count={startxref_hits}",
                )
        except Exception as exc:
            self._log_error("structure", f"unable to inspect raw file: {exc}")

        duplicate_fingerprints: Counter[str] = Counter()
        for idx, obj in enumerate(pdf.objects):
            object_id = get_object_id(obj, fallback=idx + 1)
            try:
                fingerprint = object_fingerprint(obj)
                if fingerprint:
                    duplicate_fingerprints[fingerprint] += 1
            except Exception as exc:
                self._log_error("object_scan", f"fingerprint failed for obj={object_id}: {exc}")
            self._scan_single_object(obj, object_id)

        if duplicate_fingerprints:
            repeated = [v for v in duplicate_fingerprints.values() if v > 100]
            if repeated:
                self._add_finding(
                    severity="low",
                    category="structure_anomaly",
                    finding_type="duplicate_objects",
                    page=None,
                    object_id=None,
                    description="Large number of repeated object fingerprints detected.",
                    evidence=f"max_repetition={max(repeated)}",
                )

    def _scan_single_object(self, obj: Any, object_id: int | None) -> None:
        name_map: dict[str, str] = {}
        try:
            _collect_names(obj, name_map)
        except Exception as exc:
            self._log_error("object_walk", f"name collection failed obj={object_id}: {exc}")
            return

        for key in ["/OpenAction", "/AA", "/JavaScript", "/JS", "/XFA"]:
            if key in name_map:
                sev = "high" if key in {"/OpenAction", "/JavaScript", "/JS"} else "medium"
                self._add_finding(
                    severity=sev,
                    category="suspicious_action",
                    finding_type=key.strip("/").lower(),
                    page=None,
                    object_id=object_id,
                    description=f"Suspicious action key present: {key}",
                    evidence=name_map[key],
                )

        for key in ["/URI", "/GoToR", "/Launch", "/SubmitForm"]:
            if key in name_map:
                sev = "high" if key in {"/Launch", "/GoToR"} else "medium"
                self._add_finding(
                    severity=sev,
                    category="suspicious_link_action",
                    finding_type=key.strip("/").lower(),
                    page=None,
                    object_id=object_id,
                    description=f"External link/action key present: {key}",
                    evidence=name_map[key],
                )

        if "/EmbeddedFiles" in name_map or "/Filespec" in name_map or "/Names" in name_map:
            self._add_finding(
                severity="high",
                category="embedded_content",
                finding_type="embedded_files",
                page=None,
                object_id=object_id,
                description="Embedded file structure marker detected.",
                evidence=name_map.get("/EmbeddedFiles", name_map.get("/Filespec", "/Names")),
            )

        long_strings = []
        controls = []
        for text in _collect_strings(obj):
            if len(text) >= self.config.long_string_threshold:
                long_strings.append(text[:160])
            if count_control_chars(text) >= 3:
                controls.append(text[:160])
        if long_strings:
            self._add_finding(
                severity="medium",
                category="obfuscation",
                finding_type="long_string",
                page=None,
                object_id=object_id,
                description="Extremely long string found in object.",
                evidence=truncate_evidence(long_strings[0]),
            )
        if controls:
            self._add_finding(
                severity="medium",
                category="obfuscation",
                finding_type="unicode_controls",
                page=None,
                object_id=object_id,
                description="Invisible Unicode control characters detected.",
                evidence=truncate_evidence(controls[0]),
            )

        if _is_stream_like(obj):
            raw = read_raw_stream_bytes(obj)
            if raw:
                if is_suspicious_stream(raw):
                    self._add_finding(
                        severity="high",
                        category="embedded_content",
                        finding_type="suspicious_stream",
                        page=None,
                        object_id=object_id,
                        description="Suspicious script-like pattern in raw stream bytes.",
                        evidence=truncate_evidence(raw.decode("latin1", errors="ignore")),
                    )
                if self.config.extract_dir:
                    self._extract_raw_object(object_id, "stream", raw)

    def _scan_page_content(self, pdf: Any) -> None:
        for page_idx, page in enumerate(pdf.pages, start=1):
            try:
                page_obj_id = get_object_id(page.obj)
                media = get_page_box(page, "MediaBox")
                crop = get_page_box(page, "CropBox") or media
                self._scan_page_tokens(pdf, page, page_idx, page_obj_id, media, crop)
            except Exception as exc:
                self._log_error("page_scan", f"page={page_idx}: {exc}")

    def _scan_page_tokens(
        self,
        pdf: Any,
        page: Any,
        page_idx: int,
        page_obj_id: int | None,
        media_box: tuple[float, float, float, float] | None,
        crop_box: tuple[float, float, float, float] | None,
    ) -> None:
        try:
            import pikepdf  # type: ignore
        except Exception:
            return

        text_chunks: list[str] = []
        state = {
            "font_size": 12.0,
            "tr": 0,
            "tc": 0.0,
            "tw": 0.0,
            "tz": 100.0,
            "tx": 0.0,
            "ty": 0.0,
            "alpha_zero": False,
            "scale_x": 1.0,
            "scale_y": 1.0,
            "fill_gray": 0.0,
            "stroke_gray": 0.0,
            "fill_rgb": (0.0, 0.0, 0.0),
            "stroke_rgb": (0.0, 0.0, 0.0),
        }
        state_stack: list[dict[str, float | int | bool | tuple[float, float, float]]] = []

        gs_map = {}
        try:
            resources = getattr(page.obj, "Resources", None)
            if resources and "/ExtGState" in resources:
                gs_map = resources["/ExtGState"]
        except Exception:
            gs_map = {}

        try:
            instructions = pikepdf.parse_content_stream(page)
        except Exception as exc:
            self._log_error("page_tokens", f"page={page_idx} parse failed: {exc}")
            return

        for inst in instructions:
            try:
                operands = list(getattr(inst, "operands", []))
                operator = str(getattr(inst, "operator", ""))
            except Exception:
                continue
            if operator == "Tf" and len(operands) >= 2:
                size = safe_float(operands[-1], default=state["font_size"])
                state["font_size"] = size
            elif operator == "Tr" and operands:
                state["tr"] = int(safe_float(operands[0], default=0))
            elif operator == "Tc" and operands:
                state["tc"] = safe_float(operands[0], default=0.0)
            elif operator == "Tw" and operands:
                state["tw"] = safe_float(operands[0], default=0.0)
            elif operator == "Tz" and operands:
                state["tz"] = safe_float(operands[0], default=100.0)
            elif operator == "Tm" and len(operands) >= 6:
                state["tx"] = safe_float(operands[4], default=0.0)
                state["ty"] = safe_float(operands[5], default=0.0)
            elif operator in {"Td", "TD"} and len(operands) >= 2:
                state["tx"] += safe_float(operands[0], default=0.0)
                state["ty"] += safe_float(operands[1], default=0.0)
            elif operator == "T*" and len(operands) == 0:
                state["ty"] -= state["font_size"]
            elif operator == "gs" and operands:
                state["alpha_zero"] = self._graphics_state_alpha_zero(gs_map, operands[0])
            elif operator == "BT":
                state["tx"] = 0.0
                state["ty"] = 0.0
            elif operator == "q":
                state_stack.append(dict(state))
            elif operator == "Q":
                if state_stack:
                    prev = state_stack.pop()
                    state.update(prev)
            elif operator == "cm" and len(operands) >= 6:
                a = safe_float(operands[0], default=1.0)
                b = safe_float(operands[1], default=0.0)
                c = safe_float(operands[2], default=0.0)
                d = safe_float(operands[3], default=1.0)
                sx = max(abs(a), abs(b))
                sy = max(abs(c), abs(d))
                if sx > 0:
                    state["scale_x"] *= sx
                if sy > 0:
                    state["scale_y"] *= sy
            elif operator == "g" and operands:
                gray = safe_float(operands[0], default=0.0)
                state["fill_gray"] = gray
            elif operator == "G" and operands:
                gray = safe_float(operands[0], default=0.0)
                state["stroke_gray"] = gray
            elif operator == "rg" and len(operands) >= 3:
                state["fill_rgb"] = (
                    safe_float(operands[0], default=0.0),
                    safe_float(operands[1], default=0.0),
                    safe_float(operands[2], default=0.0),
                )
            elif operator == "RG" and len(operands) >= 3:
                state["stroke_rgb"] = (
                    safe_float(operands[0], default=0.0),
                    safe_float(operands[1], default=0.0),
                    safe_float(operands[2], default=0.0),
                )

            if operator in {"Tj", "TJ", "'", '"'}:
                shown_text = extract_text_from_operands(operands)
                if shown_text:
                    text_chunks.append(shown_text)
                    self._apply_hidden_text_heuristics(
                        page_idx=page_idx,
                        object_id=page_obj_id,
                        text=shown_text,
                        state=state,
                        media_box=media_box,
                        crop_box=crop_box,
                    )

        page_text = " ".join(t.strip() for t in text_chunks if t.strip())
        if page_text:
            self._page_text_cache[page_idx] = page_text

    def _graphics_state_alpha_zero(self, gs_map: Any, gs_name: Any) -> bool:
        try:
            key = str(gs_name)
            if key not in gs_map:
                return False
            gs = gs_map[key]
            stroke_alpha = safe_float(gs.get("/CA", 1), default=1)
            fill_alpha = safe_float(gs.get("/ca", 1), default=1)
            return stroke_alpha == 0 or fill_alpha == 0
        except Exception:
            return False

    def _apply_hidden_text_heuristics(
        self,
        page_idx: int,
        object_id: int | None,
        text: str,
        state: dict[str, float | int | bool],
        media_box: tuple[float, float, float, float] | None,
        crop_box: tuple[float, float, float, float] | None,
    ) -> None:
        tiny_font = float(state["font_size"]) < self.config.tiny_font_threshold
        effective_font = float(state["font_size"]) * min(float(state["scale_x"]), float(state["scale_y"]))
        micro_effective_font = effective_font < (4.0 if self.config.strict else 3.0)
        invisible_render = int(state["tr"]) == 3
        abnormal_scale = float(state["tz"]) < self.config.abnormal_tz_floor or float(state["tz"]) > self.config.abnormal_tz_ceil
        abnormal_spacing = abs(float(state["tc"])) > 100 or abs(float(state["tw"])) > 200
        alpha_zero = bool(state["alpha_zero"])
        white_fill = float(state["fill_gray"]) >= 0.98 or all(float(v) >= 0.98 for v in state["fill_rgb"])
        white_stroke = float(state["stroke_gray"]) >= 0.98 or all(float(v) >= 0.98 for v in state["stroke_rgb"])
        likely_transparent_or_invisible = alpha_zero or (white_fill and white_stroke and (tiny_font or micro_effective_font))
        # Only evaluate "outside page" in near-identity transform contexts.
        # Complex PDF transform stacks can make raw tx/ty misleading.
        can_check_outside = abs(float(state["scale_x"]) - 1.0) < 0.05 and abs(float(state["scale_y"]) - 1.0) < 0.05
        outside_page = False
        if can_check_outside:
            outside_page = text_position_outside(
                tx=float(state["tx"]),
                ty=float(state["ty"]),
                media_box=media_box,
                crop_box=crop_box,
            )
        controls = count_control_chars(text)

        if tiny_font:
            self._add_finding(
                severity="medium",
                category="hidden_text",
                finding_type="tiny_font",
                page=page_idx,
                object_id=object_id,
                description="Text rendered with extremely small font size.",
                evidence=f"font_size={state['font_size']} text={truncate_evidence(text)}",
            )
        if micro_effective_font:
            self._add_finding(
                severity="medium",
                category="hidden_text",
                finding_type="micro_effective_font",
                page=page_idx,
                object_id=object_id,
                description="Effective font size is extremely small after transforms.",
                evidence=f"effective_font={effective_font:.3f} base_font={state['font_size']} scale=({state['scale_x']:.3f},{state['scale_y']:.3f}) text={truncate_evidence(text)}",
            )
        if invisible_render:
            self._add_finding(
                severity="high",
                category="hidden_text",
                finding_type="invisible_render_mode",
                page=page_idx,
                object_id=object_id,
                description="Text rendering mode Tr=3 (invisible text).",
                evidence=truncate_evidence(text),
            )
        if likely_transparent_or_invisible:
            self._add_finding(
                severity="high",
                category="hidden_text",
                finding_type="transparent_or_white_on_white_text",
                page=page_idx,
                object_id=object_id,
                description="Text appears hidden by transparency or white-on-white microtext.",
                evidence=f"alpha_zero={alpha_zero} fill_gray={state['fill_gray']} stroke_gray={state['stroke_gray']} fill_rgb={state['fill_rgb']} stroke_rgb={state['stroke_rgb']} effective_font={effective_font:.3f} text={truncate_evidence(text)}",
            )
        if abnormal_scale:
            self._add_finding(
                severity="medium",
                category="hidden_text",
                finding_type="abnormal_scaling",
                page=page_idx,
                object_id=object_id,
                description="Abnormal horizontal scaling for text rendering.",
                evidence=f"Tz={state['tz']} text={truncate_evidence(text)}",
            )
        if abnormal_spacing:
            self._add_finding(
                severity="medium",
                category="hidden_text",
                finding_type="abnormal_spacing",
                page=page_idx,
                object_id=object_id,
                description="Abnormal character/word spacing could hide text.",
                evidence=f"Tc={state['tc']} Tw={state['tw']} text={truncate_evidence(text)}",
            )
        if alpha_zero:
            self._add_finding(
                severity="high",
                category="hidden_text",
                finding_type="alpha_zero",
                page=page_idx,
                object_id=object_id,
                description="Graphics state sets alpha to zero while drawing text.",
                evidence=truncate_evidence(text),
            )
        if outside_page:
            self._add_finding(
                severity="medium",
                category="hidden_text",
                finding_type="outside_page_bounds",
                page=page_idx,
                object_id=object_id,
                description="Text matrix position appears outside page bounds.",
                evidence=f"tx={state['tx']} ty={state['ty']} text={truncate_evidence(text)}",
            )
        if controls >= 3:
            self._add_finding(
                severity="medium",
                category="obfuscation",
                finding_type="unicode_controls",
                page=page_idx,
                object_id=object_id,
                description="Large amount of invisible Unicode control characters in page text.",
                evidence=truncate_evidence(text),
            )

    def _scan_links_and_actions(self, pdf: Any) -> None:
        for page_idx, page in enumerate(pdf.pages, start=1):
            try:
                annots = getattr(page.obj, "Annots", None)
                if not annots:
                    continue
                for annot_ref in annots:
                    annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                    self._scan_annotation(page_idx, annot)
            except Exception as exc:
                self._log_error("links", f"page={page_idx}: {exc}")

    def _scan_annotation(self, page_idx: int, annot: Any) -> None:
        object_id = get_object_id(annot)
        try:
            subtype = str(annot.get("/Subtype", ""))
        except Exception:
            subtype = ""
        if subtype != "/Link":
            return

        action = None
        try:
            action = annot.get("/A")
        except Exception:
            action = None
        if action is None:
            return

        uri = safe_to_str(action.get("/URI")) if hasattr(action, "get") else ""
        launch = action.get("/Launch") if hasattr(action, "get") else None
        goto_r = action.get("/GoToR") if hasattr(action, "get") else None
        submit = action.get("/SubmitForm") if hasattr(action, "get") else None

        if uri:
            self._add_finding(
                severity="medium",
                category="suspicious_link_action",
                finding_type="uri",
                page=page_idx,
                object_id=object_id,
                description="External URI link present in annotation.",
                evidence=truncate_evidence(uri),
            )
            mismatch = detect_link_text_mismatch(self._page_text_cache.get(page_idx, ""), uri)
            if mismatch["is_mismatch"]:
                self._add_finding(
                    severity="high",
                    category="link_spoofing",
                    finding_type="display_text_vs_uri",
                    page=page_idx,
                    object_id=object_id,
                    description="Visible page text may not match actual annotation URI.",
                    evidence=truncate_evidence(
                        f"visible_snippet={mismatch['visible_snippet']} actual_uri={uri}"
                    ),
                )
            if self.config.extract_dir:
                self._extract_text_blob(object_id, "uri", uri)

        if launch is not None:
            self._add_finding(
                severity="high",
                category="suspicious_link_action",
                finding_type="launch",
                page=page_idx,
                object_id=object_id,
                description="Launch action detected in annotation.",
                evidence=truncate_evidence(safe_to_str(launch)),
            )
        if goto_r is not None:
            self._add_finding(
                severity="high",
                category="suspicious_link_action",
                finding_type="gotor",
                page=page_idx,
                object_id=object_id,
                description="GoToR action detected in annotation.",
                evidence=truncate_evidence(safe_to_str(goto_r)),
            )
        if submit is not None:
            self._add_finding(
                severity="medium",
                category="suspicious_link_action",
                finding_type="submitform",
                page=page_idx,
                object_id=object_id,
                description="SubmitForm action detected in annotation.",
                evidence=truncate_evidence(safe_to_str(submit)),
            )

    def _extract_text_blob(self, object_id: int | None, kind: str, content: str) -> None:
        if not self.config.extract_dir:
            return
        out_dir = Path(self.config.extract_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        oid = object_id if object_id is not None else "na"
        path = out_dir / f"obj_{oid}_{kind}.txt"
        path.write_text(content, encoding="utf-8", errors="ignore")

    def _extract_raw_object(self, object_id: int | None, kind: str, data: bytes) -> None:
        if not self.config.extract_dir:
            return
        out_dir = Path(self.config.extract_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        oid = object_id if object_id is not None else "na"
        path = out_dir / f"obj_{oid}_{kind}.bin"
        path.write_bytes(data)

    def _add_finding(
        self,
        severity: str,
        category: str,
        finding_type: str,
        page: int | None,
        object_id: int | None,
        description: str,
        evidence: str,
    ) -> None:
        self._finding_counter += 1
        finding = Finding(
            id=f"F-{self._finding_counter:04d}",
            severity=severity,
            risk_level=severity,
            category=category,
            type=finding_type,
            page=page,
            object_id=object_id,
            description=description,
            evidence=truncate_evidence(evidence),
        )
        self.findings.append(finding)

    def _log_error(self, scope: str, message: str) -> None:
        self.errors.append({"scope": scope, "message": message})


def build_summary(findings: list[Finding]) -> dict[str, Any]:
    by_category = Counter(f.category for f in findings)
    by_page: dict[int, int] = defaultdict(int)
    sev = Counter(f.severity for f in findings)
    for finding in findings:
        if finding.page is not None:
            by_page[finding.page] += 1
    top_high = [f.as_dict() for f in findings if f.severity == "high"][:10]
    return {
        "total_risk_count": len(findings),
        "severity": {
            "high": sev.get("high", 0),
            "medium": sev.get("medium", 0),
            "low": sev.get("low", 0),
        },
        "category_breakdown": dict(by_category),
        "per_page": dict(sorted(by_page.items())),
        "top_high_risk_findings": top_high,
    }


def should_fail_exit(findings: list[Finding]) -> bool:
    triggers = {
        ("suspicious_action", "javascript"),
        ("suspicious_action", "js"),
        ("suspicious_action", "openaction"),
        ("suspicious_link_action", "launch"),
        ("embedded_content", "embedded_files"),
    }
    for f in findings:
        if (f.category, f.type) in triggers:
            return True
    return False


def render_human_report(report: dict[str, Any], verbose: bool = False) -> str:
    summary = report["summary"]
    lines = [
        f"File: {report['file']}",
        f"Total risk count: {summary['total_risk_count']}",
        f"Severity: high={summary['severity']['high']} medium={summary['severity']['medium']} low={summary['severity']['low']}",
        "Category breakdown:",
    ]
    for cat, count in sorted(summary["category_breakdown"].items()):
        lines.append(f"  - {cat}: {count}")
    lines.append("Per-page statistics:")
    if summary["per_page"]:
        for page, count in summary["per_page"].items():
            lines.append(f"  - page {page}: {count}")
    else:
        lines.append("  - none")

    if summary["top_high_risk_findings"]:
        lines.append("Top high-risk findings:")
        for item in summary["top_high_risk_findings"]:
            lines.append(
                f"  - {item['id']} [{item['category']}/{item['type']}] page={item['page']} obj={item['object_id']}: {item['description']}"
            )
            if verbose:
                lines.append(f"      evidence: {item['evidence']}")
    else:
        lines.append("Top high-risk findings: none")

    if verbose and report.get("findings"):
        lines.append("All findings:")
        for item in report["findings"]:
            lines.append(
                f"  - {item['id']} [{item['severity']}] {item['category']}/{item['type']} page={item['page']} obj={item['object_id']}"
            )
            lines.append(f"      desc: {item['description']}")
            lines.append(f"      evidence: {item['evidence']}")

    if report.get("errors"):
        lines.append("Errors:")
        for err in report["errors"]:
            lines.append(f"  - [{err['scope']}] {err['message']}")
    return "\n".join(lines)


def detect_link_text_mismatch(page_text: str, uri: str) -> dict[str, Any]:
    uri_domain = extract_domain(uri)
    if not uri_domain:
        return {"is_mismatch": False, "visible_snippet": ""}

    text = (page_text or "").lower()
    if not text.strip():
        return {"is_mismatch": False, "visible_snippet": ""}

    if uri_domain in text:
        return {"is_mismatch": False, "visible_snippet": snippet_around(text, uri_domain)}

    visible_domains = extract_domains_from_text(text)
    if not visible_domains:
        return {"is_mismatch": False, "visible_snippet": snippet_around(text, "", fallback=True)}

    likely_visible = sorted(visible_domains)[0]
    return {
        "is_mismatch": likely_visible != uri_domain,
        "visible_snippet": snippet_around(text, likely_visible),
    }


def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return ""


def extract_domains_from_text(text: str) -> set[str]:
    pattern = re.compile(r"(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})(?:/[^\s]*)?", re.IGNORECASE)
    domains: set[str] = set()
    for match in pattern.finditer(text):
        host = match.group(1).lower()
        if host.startswith("www."):
            host = host[4:]
        domains.add(host)
    return domains


def snippet_around(text: str, needle: str, fallback: bool = False, window: int = 140) -> str:
    if fallback or not needle:
        return truncate_evidence(text[:window])
    idx = text.find(needle)
    if idx < 0:
        return truncate_evidence(text[:window])
    start = max(0, idx - window // 2)
    end = min(len(text), idx + len(needle) + window // 2)
    return truncate_evidence(text[start:end])


def count_control_chars(text: str) -> int:
    return sum(ch in CONTROL_CHARS for ch in text)


def text_position_outside(
    tx: float,
    ty: float,
    media_box: tuple[float, float, float, float] | None,
    crop_box: tuple[float, float, float, float] | None,
) -> bool:
    box = crop_box or media_box
    if box is None:
        return False
    llx, lly, urx, ury = box
    return tx < llx - 5 or tx > urx + 5 or ty < lly - 5 or ty > ury + 5


def truncate_evidence(text: str, limit: int = 260) -> str:
    cleaned = re.sub(r"\s+", " ", str(text)).strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3] + "..."


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def safe_to_str(value: Any) -> str:
    try:
        return str(value)
    except Exception:
        return ""


def extract_text_from_operands(operands: list[Any]) -> str:
    chunks: list[str] = []
    for operand in operands:
        chunks.extend(_extract_text_parts(operand))
    return "".join(chunks)


def _extract_text_parts(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, bytes):
        return [value.decode("latin1", errors="ignore")]
    if isinstance(value, str):
        return [value]
    if isinstance(value, (int, float, bool)):
        return []

    # pikepdf String/Object values stringify to readable text for text operands.
    cls_name = value.__class__.__name__.lower()
    if "string" in cls_name:
        try:
            return [str(value)]
        except Exception:
            return []

    if isinstance(value, Iterable):
        parts: list[str] = []
        try:
            for item in value:
                parts.extend(_extract_text_parts(item))
            return parts
        except Exception:
            parts = []
    try:
        s = str(value)
    except Exception:
        return []
    if not s:
        return []
    return [s]


def get_page_box(page: Any, name: str) -> tuple[float, float, float, float] | None:
    try:
        box = page.obj.get(f"/{name}")
        if not box or len(box) < 4:
            return None
        return (
            safe_float(box[0]),
            safe_float(box[1]),
            safe_float(box[2]),
            safe_float(box[3]),
        )
    except Exception:
        return None


def get_object_id(obj: Any, fallback: int | None = None) -> int | None:
    for attr in ["objgen", "object_id"]:
        if hasattr(obj, attr):
            try:
                value = getattr(obj, attr)
                if attr == "objgen" and isinstance(value, tuple) and value:
                    return int(value[0])
                return int(value)
            except Exception:
                continue
    return fallback


def object_fingerprint(obj: Any) -> str:
    try:
        if hasattr(obj, "to_json"):
            text = obj.to_json()
        else:
            text = str(obj)
        if len(text) > 2000:
            text = text[:2000]
        return json.dumps({"fp": text}, ensure_ascii=False)
    except Exception:
        return ""


def _collect_names(obj: Any, out: dict[str, str], depth: int = 0, max_depth: int = 6) -> None:
    if depth > max_depth or obj is None:
        return
    try:
        if isinstance(obj, dict) or hasattr(obj, "items"):
            for k, v in obj.items():
                ks = str(k)
                out.setdefault(ks, truncate_evidence(str(v)))
                _collect_names(v, out, depth + 1, max_depth)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                _collect_names(item, out, depth + 1, max_depth)
    except Exception:
        return


def _collect_strings(obj: Any, depth: int = 0, max_depth: int = 6) -> list[str]:
    if depth > max_depth or obj is None:
        return []
    texts: list[str] = []
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, bytes):
        return [obj.decode("latin1", errors="ignore")]
    try:
        if isinstance(obj, dict) or hasattr(obj, "items"):
            for k, v in obj.items():
                texts.extend(_collect_strings(k, depth + 1, max_depth))
                texts.extend(_collect_strings(v, depth + 1, max_depth))
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                texts.extend(_collect_strings(item, depth + 1, max_depth))
        elif hasattr(obj, "read_raw_bytes"):
            raw = read_raw_stream_bytes(obj)
            if raw:
                texts.append(raw[:2000].decode("latin1", errors="ignore"))
    except Exception:
        return texts
    return texts


def _is_stream_like(obj: Any) -> bool:
    return hasattr(obj, "read_raw_bytes") or hasattr(obj, "read_bytes")


def read_raw_stream_bytes(obj: Any) -> bytes:
    try:
        if hasattr(obj, "read_raw_bytes"):
            return obj.read_raw_bytes()
        if hasattr(obj, "read_bytes"):
            # Fallback only; may be decoded depending on backend.
            return obj.read_bytes()
    except Exception:
        return b""
    return b""


def is_suspicious_stream(data: bytes) -> bool:
    hay = data[:20000].lower()
    indicators = [b"/javascript", b"eval(", b"function(", b"<script", b"app.alert", b"submitform"]
    return any(ind in hay for ind in indicators)
