from __future__ import annotations

from pdf_check.sanitizer import (
    Finding,
    build_summary,
    count_control_chars,
    detect_link_text_mismatch,
    should_fail_exit,
    text_position_outside,
)


def test_detect_link_text_mismatch_positive():
    text = "Please go to paypal.com for account verification."
    uri = "https://example.com/login"
    result = detect_link_text_mismatch(text, uri)
    assert result["is_mismatch"] is True
    assert "paypal.com" in result["visible_snippet"]


def test_text_position_outside_detection():
    media = (0.0, 0.0, 600.0, 800.0)
    assert text_position_outside(tx=700.0, ty=100.0, media_box=media, crop_box=None) is True
    assert text_position_outside(tx=120.0, ty=300.0, media_box=media, crop_box=None) is False


def test_control_char_count():
    txt = "abc\u200b\u200c\u202ezzz"
    assert count_control_chars(txt) == 3


def test_fail_exit_trigger_for_high_risk_categories():
    findings = [
        Finding(
            id="F-1",
            severity="high",
            risk_level="high",
            category="suspicious_action",
            type="openaction",
            page=None,
            object_id=1,
            description="OpenAction found",
            evidence="/OpenAction",
        )
    ]
    assert should_fail_exit(findings) is True


def test_build_summary_counts():
    findings = [
        Finding(
            id="F-1",
            severity="high",
            risk_level="high",
            category="suspicious_action",
            type="js",
            page=1,
            object_id=2,
            description="JS",
            evidence="x",
        ),
        Finding(
            id="F-2",
            severity="low",
            risk_level="low",
            category="hidden_text",
            type="tiny_font",
            page=1,
            object_id=3,
            description="tiny",
            evidence="y",
        ),
    ]
    summary = build_summary(findings)
    assert summary["total_risk_count"] == 2
    assert summary["severity"]["high"] == 1
    assert summary["per_page"][1] == 2

