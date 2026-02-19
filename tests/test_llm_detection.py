from __future__ import annotations

from pdf_check.llm_detection import default_config, detect_llm_instructions


def test_llm_high_severity_injection_pattern(llm_fragments):
    findings = detect_llm_instructions(llm_fragments, default_config(strict=False))
    high = [f for f in findings if f.severity == "high"]
    assert high, "Expected high-severity finding for explicit prompt-injection content"
    rule_ids = set(high[0].matched_rules)
    assert "PATTERN_IGNORE_PREVIOUS_INSTRUCTIONS" in rule_ids


def test_llm_location_type_coverage(llm_fragments):
    findings = detect_llm_instructions(llm_fragments, default_config(strict=False))
    locs = {f.location_type for f in findings}
    assert "content_stream" in locs
    assert "annotation" in locs


def test_llm_confidence_range(llm_fragments):
    findings = detect_llm_instructions(llm_fragments, default_config(strict=True))
    assert findings
    for finding in findings:
        assert 0.0 <= finding.confidence <= 1.0

