"""
PromptWAF Security Regression Test Suite — Payload-based adversarial testing.

Reads adversarial payloads from adversarial_payloads.json and verifies that
the WAF engine detects 100% of them.

This suite tests the WAF engine directly (not through HTTP) for speed and
determinism. For each payload, it:
    1. Wraps the prompt in an OpenAI-compatible payload
    2. Runs the full WAF analysis pipeline (normalization → heuristic → semantic)
    3. Asserts that the verdict is blocked=True

Usage:
    pytest tests/security/test_payloads.py -v --tb=short
"""

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


# ---------------------------------------------------------------------------
# Load adversarial payloads
# ---------------------------------------------------------------------------

PAYLOADS_FILE = Path(__file__).parent / "adversarial_payloads.json"


def _load_payloads() -> list:
    """Load and validate the adversarial payloads JSON file."""
    with open(PAYLOADS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    payloads = data.get("payloads", [])
    assert len(payloads) > 0, "No payloads found in adversarial_payloads.json"
    return payloads


ADVERSARIAL_PAYLOADS = _load_payloads()


def _payload_id(payload: dict) -> str:
    """Generate a human-readable test ID for parametrized tests."""
    return f"{payload['id']}-{payload['category']}"


# ---------------------------------------------------------------------------
# Core Detection Tests — Every payload must be detected
# ---------------------------------------------------------------------------

class TestAdversarialPayloads:
    """
    Regression suite: every adversarial payload MUST be detected by the
    WAF engine. A single miss is a test failure.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize("payload", ADVERSARIAL_PAYLOADS, ids=_payload_id)
    async def test_payload_detected(self, payload: dict):
        """
        Each adversarial payload must produce a WafVerdict with blocked=True.
        """
        from app.services.waf_engine import analyze_prompt

        api_payload = {
            "messages": [
                {"role": "user", "content": payload["prompt"]}
            ]
        }

        verdict = await analyze_prompt(api_payload)

        assert verdict.blocked, (
            f"MISS: Payload {payload['id']} ({payload['category']}) was NOT detected!\n"
            f"  Description: {payload['description']}\n"
            f"  Prompt:      {payload['prompt'][:100]}...\n"
            f"  Verdict:     blocked={verdict.blocked}, layer={verdict.layer}, "
            f"reason={verdict.reason}"
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("payload", ADVERSARIAL_PAYLOADS, ids=_payload_id)
    async def test_payload_layer_attribution(self, payload: dict):
        """
        Verify that the detection layer matches the expected layer
        (when specified in the payload).
        """
        from app.services.waf_engine import analyze_prompt

        expected_layer = payload.get("expected_layer")
        if not expected_layer:
            pytest.skip("No expected_layer specified for this payload")

        api_payload = {
            "messages": [
                {"role": "user", "content": payload["prompt"]}
            ]
        }

        verdict = await analyze_prompt(api_payload)

        assert verdict.blocked, (
            f"Payload {payload['id']} was not blocked at all"
        )
        assert verdict.layer == expected_layer, (
            f"Payload {payload['id']} detected by '{verdict.layer}' "
            f"but expected '{expected_layer}'\n"
            f"  Reason: {verdict.reason}"
        )


# ---------------------------------------------------------------------------
# Aggregate Coverage Report
# ---------------------------------------------------------------------------

class TestCoverageReport:
    """
    Run ALL payloads and produce a summary report.
    This test always runs last and provides a coverage percentage.
    """

    @pytest.mark.asyncio
    async def test_100_percent_detection_rate(self):
        """
        Verify that the WAF achieves 100% detection across all payloads.
        """
        from app.services.waf_engine import analyze_prompt

        total = len(ADVERSARIAL_PAYLOADS)
        detected = 0
        missed = []

        for payload in ADVERSARIAL_PAYLOADS:
            api_payload = {
                "messages": [
                    {"role": "user", "content": payload["prompt"]}
                ]
            }
            verdict = await analyze_prompt(api_payload)

            if verdict.blocked:
                detected += 1
            else:
                missed.append(payload)

        detection_rate = (detected / total) * 100 if total > 0 else 0

        if missed:
            miss_details = "\n".join(
                f"  - {p['id']} ({p['category']}): {p['prompt'][:80]}..."
                for p in missed
            )
            pytest.fail(
                f"Detection rate: {detection_rate:.1f}% ({detected}/{total})\n"
                f"MISSED payloads:\n{miss_details}"
            )

        # This line only reached if 100%
        assert detection_rate == 100.0, (
            f"Detection rate: {detection_rate:.1f}% — must be 100%"
        )


# ---------------------------------------------------------------------------
# Category Breakdown
# ---------------------------------------------------------------------------

class TestCategoryBreakdown:
    """Per-category detection verification."""

    @pytest.mark.asyncio
    async def test_all_categories_covered(self):
        """
        Every category in the payload file has at least one test case,
        and all are detected.
        """
        from app.services.waf_engine import analyze_prompt
        from collections import defaultdict

        categories = defaultdict(lambda: {"total": 0, "detected": 0})

        for payload in ADVERSARIAL_PAYLOADS:
            cat = payload["category"]
            categories[cat]["total"] += 1

            api_payload = {
                "messages": [
                    {"role": "user", "content": payload["prompt"]}
                ]
            }
            verdict = await analyze_prompt(api_payload)
            if verdict.blocked:
                categories[cat]["detected"] += 1

        # Every category must have 100% detection
        for cat, stats in categories.items():
            assert stats["detected"] == stats["total"], (
                f"Category '{cat}': detected {stats['detected']}/{stats['total']}"
            )
