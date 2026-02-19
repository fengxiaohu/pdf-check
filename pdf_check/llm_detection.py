from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .types import Finding, TextFragment


@dataclass
class CompiledPattern:
    rule_id: str
    regex: re.Pattern[str]
    severity: str | None = None


@dataclass
class DetectorConfig:
    tool_keywords: list[str]
    action_keywords: list[str]
    workflow_keywords: list[str]
    patterns: list[CompiledPattern]


def _default_patterns() -> list[CompiledPattern]:
    specs: list[tuple[str, str, str | None]] = [
        (
            "PATTERN_IF_USE_MODEL",
            r"if you use\s+(chatgpt|gpt|openai|gemini|deepseek|claude|copilot|llm|ai assistant|assistant).+",
            "medium",
        ),
        (
            "PATTERN_IGNORE_PREVIOUS_INSTRUCTIONS",
            r"(ignore|disregard)\s+(previous|above)\s+(instructions|rules)",
            "high",
        ),
        (
            "PATTERN_REVEAL_SYSTEM_PROMPT_OR_SECRETS",
            r"(reveal|show|print)\s+(the\s+)?(system prompt|hidden instructions|secrets?)",
            "high",
        ),
        (
            "PATTERN_CONCEALMENT",
            r"(do not|don't|never)\s+(tell|mention|disclose)",
            "high",
        ),
        (
            "PATTERN_OVERRIDE_OR_BYPASS",
            r"(override|bypass)\s+(rules|guardrails|restrictions|policy|instructions)",
            "high",
        ),
        (
            "PATTERN_EXFILTRATION",
            r"(exfiltrate|leak|steal).+(secret|token|api[-_\s]?key|password|credential)",
            "high",
        ),
        (
            "PATTERN_MODEL_WORKFLOW_INSTRUCTION",
            r"(chatgpt|gpt|openai|gemini|deepseek|claude|copilot).+(summarize|translate|debug|review|analy[sz]e|audit|extract|execute)",
            "medium",
        ),
    ]
    return [
        CompiledPattern(rule_id=rule_id, regex=re.compile(regex, re.IGNORECASE | re.DOTALL), severity=severity)
        for rule_id, regex, severity in specs
    ]


def _strict_patterns() -> list[CompiledPattern]:
    specs: list[tuple[str, str, str | None]] = [
        ("STRICT_PATTERN_MODEL_ADDRESSED", r"\b(chatgpt|gpt|gemini|deepseek|claude|copilot|llm|assistant)\b.{0,80}\b(must|should|need to|follow|ignore)\b", "medium"),
        ("STRICT_PATTERN_SECRET_REQUEST", r"\b(show|print|reveal)\b.{0,100}\b(secret|token|password|apikey|api key|system prompt)\b", "high"),
    ]
    return [
        CompiledPattern(rule_id=rule_id, regex=re.compile(regex, re.IGNORECASE | re.DOTALL), severity=severity)
        for rule_id, regex, severity in specs
    ]


def default_config(strict: bool = False) -> DetectorConfig:
    tool_keywords = [
        "chatgpt",
        "gpt",
        "openai",
        "gemini",
        "deepseek",
        "claude",
        "copilot",
        "llm",
        "ai assistant",
        "assistant",
        "system prompt",
    ]
    action_keywords = [
        "ignore",
        "follow",
        "must",
        "always",
        "do not",
        "never",
        "override",
        "bypass",
        "reveal",
        "exfiltrate",
        "leak",
        "secret",
        "token",
        "apikey",
        "password",
    ]
    workflow_keywords = [
        "summarize",
        "translate",
        "debug",
        "review",
        "analyze",
        "analyse",
        "audit",
        "extract",
        "execute",
    ]
    patterns = _default_patterns()

    if strict:
        tool_keywords.extend(["model", "ai", "language model", "prompt"])
        action_keywords.extend(["disclose", "print", "show", "disregard"])
        workflow_keywords.extend(["refactor", "fix", "patch"])
        patterns.extend(_strict_patterns())

    return DetectorConfig(
        tool_keywords=_dedupe(tool_keywords),
        action_keywords=_dedupe(action_keywords),
        workflow_keywords=_dedupe(workflow_keywords),
        patterns=patterns,
    )


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        low = item.lower().strip()
        if low and low not in seen:
            seen.add(low)
            out.append(low)
    return out


def merge_custom_keywords(config: DetectorConfig, custom_path: str | None) -> DetectorConfig:
    if not custom_path:
        return config

    payload = _load_keywords_file(custom_path)
    tool = config.tool_keywords[:]
    action = config.action_keywords[:]
    workflow = config.workflow_keywords[:]
    patterns = config.patterns[:]

    for key, dest in [
        ("tool_keywords", tool),
        ("action_keywords", action),
        ("workflow_keywords", workflow),
    ]:
        for value in payload.get(key, []):
            if isinstance(value, str):
                dest.append(value.lower())

    for pat in payload.get("patterns", []):
        if not isinstance(pat, dict):
            continue
        rule_id = str(pat.get("id", "")).strip()
        regex = str(pat.get("regex", "")).strip()
        severity = pat.get("severity")
        if not rule_id or not regex:
            continue
        try:
            compiled = re.compile(regex, re.IGNORECASE | re.DOTALL)
        except re.error:
            continue
        sev = str(severity).lower() if isinstance(severity, str) else None
        if sev not in {"low", "medium", "high"}:
            sev = None
        patterns.append(CompiledPattern(rule_id=rule_id, regex=compiled, severity=sev))

    return DetectorConfig(
        tool_keywords=_dedupe(tool),
        action_keywords=_dedupe(action),
        workflow_keywords=_dedupe(workflow),
        patterns=patterns,
    )


def _load_keywords_file(path: str) -> dict[str, Any]:
    data = Path(path).read_text(encoding="utf-8")
    suffix = Path(path).suffix.lower()
    if suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise RuntimeError("YAML keyword file requires pyyaml installed.") from exc
        parsed = yaml.safe_load(data)
    else:
        parsed = json.loads(data)
    return parsed if isinstance(parsed, dict) else {}


def detect_llm_instructions(fragments: list[TextFragment], config: DetectorConfig) -> list[Finding]:
    findings: list[Finding] = []
    for frag in fragments:
        finding = _classify_fragment(frag, config)
        if finding:
            findings.append(finding)
    return findings


def _classify_fragment(fragment: TextFragment, config: DetectorConfig) -> Finding | None:
    text = _normalize_whitespace(fragment.text)
    if not text:
        return None
    low = text.lower()

    matched_rules: list[str] = []
    explicit_severity: str | None = None
    for pat in config.patterns:
        if pat.regex.search(text):
            matched_rules.append(pat.rule_id)
            if pat.severity == "high":
                explicit_severity = "high"
            elif pat.severity == "medium" and explicit_severity != "high":
                explicit_severity = "medium"
            elif pat.severity == "low" and explicit_severity is None:
                explicit_severity = "low"

    tool_hits = _keyword_hits(low, config.tool_keywords)
    action_hits = _keyword_hits(low, config.action_keywords)
    workflow_hits = _keyword_hits(low, config.workflow_keywords)

    if tool_hits:
        matched_rules.extend([f"KW_TOOL:{k}" for k in tool_hits])
    if action_hits:
        matched_rules.extend([f"KW_ACTION:{k}" for k in action_hits])
    if workflow_hits:
        matched_rules.extend([f"KW_WORKFLOW:{k}" for k in workflow_hits])

    # Required behavior: any instruction addressed to AI tools is reported.
    # We also report benign mentions of AI tools as low severity.
    if not tool_hits and not matched_rules:
        return None

    severity = _determine_severity(explicit_severity, tool_hits, action_hits, workflow_hits, matched_rules)
    confidence = _confidence_score(severity, tool_hits, action_hits, workflow_hits, matched_rules)
    evidence = _truncate_evidence(text)

    return Finding(
        category="llm_instruction",
        severity=severity,
        location_type=fragment.location_type,
        page=fragment.page,
        object_id=fragment.object_id,
        evidence=evidence,
        matched_rules=sorted(set(matched_rules)),
        confidence=confidence,
    )


def _keyword_hits(text: str, keywords: list[str]) -> list[str]:
    hits: list[str] = []
    for kw in keywords:
        if kw and kw in text:
            hits.append(kw)
    return hits


def _determine_severity(
    explicit_severity: str | None,
    tool_hits: list[str],
    action_hits: list[str],
    workflow_hits: list[str],
    matched_rules: list[str],
) -> str:
    high_signals = {
        "PATTERN_IGNORE_PREVIOUS_INSTRUCTIONS",
        "PATTERN_REVEAL_SYSTEM_PROMPT_OR_SECRETS",
        "PATTERN_CONCEALMENT",
        "PATTERN_OVERRIDE_OR_BYPASS",
        "PATTERN_EXFILTRATION",
        "STRICT_PATTERN_SECRET_REQUEST",
    }
    if any(rule in high_signals for rule in matched_rules):
        return "high"
    if explicit_severity == "high":
        return "high"
    if explicit_severity == "medium":
        return "medium"
    if tool_hits and (action_hits or workflow_hits):
        return "medium"
    return "low"


def _confidence_score(
    severity: str,
    tool_hits: list[str],
    action_hits: list[str],
    workflow_hits: list[str],
    matched_rules: list[str],
) -> float:
    score = 0.2
    if tool_hits:
        score += 0.2
    if action_hits:
        score += 0.2
    if workflow_hits:
        score += 0.15

    pattern_count = len([x for x in matched_rules if x.startswith("PATTERN_") or x.startswith("STRICT_PATTERN_")])
    score += min(pattern_count * 0.12, 0.36)

    if severity == "high":
        score = max(score, 0.8)
    elif severity == "medium":
        score = max(score, 0.58)
    else:
        score = max(score, 0.35)

    return round(min(score, 1.0), 3)


def _normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _truncate_evidence(text: str, limit: int = 280) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."

