"""
PromptWAF Observability — Prometheus-compatible metrics using prometheus_client.
"""

import time
from typing import Dict
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

REQUESTS_TOTAL = Counter('promptwaf_requests_total', 'Total requests processed')
BLOCKED_TOTAL = Counter('promptwaf_blocked_total', 'Total requests blocked')
MONITORED_TOTAL = Counter('promptwaf_monitored_total', 'Total attacks detected in MONITOR mode')
ALLOWED_TOTAL = Counter('promptwaf_allowed_total', 'Total clean requests forwarded')
ERRORS_TOTAL = Counter('promptwaf_errors_total', 'Total WAF engine errors')
LEAKAGE_TOTAL = Counter('promptwaf_leakage_total', 'Total output leakage detections')
ATTACKS_BY_LAYER = Counter('promptwaf_attacks_by_layer_total', 'Attacks detected per WAF layer', ['layer'])

INSPECTION_LATENCY = Histogram(
    'promptwaf_inspection_latency_ms',
    'WAF inspection latency in milliseconds',
    buckets=(1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000, float('inf'))
)

SEMANTIC_LATENCY = Histogram(
    'promptwaf_semantic_latency_ms',
    'Semantic engine inspection latency in milliseconds',
    buckets=(1, 2, 5, 10, 50, float('inf'))
)

OUTPUT_SCAN_LATENCY = Histogram(
    'promptwaf_output_scan_latency_ms',
    'Output scan latency in milliseconds',
    buckets=(0.1, 0.5, 1, 2, 5, 10, float('inf'))
)

class WafMetrics:
    """
    In-process metrics collector for PromptWAF.
    """

    def record_request(self) -> None:
        REQUESTS_TOTAL.inc()

    def record_blocked(self, layer: str) -> None:
        BLOCKED_TOTAL.inc()
        ATTACKS_BY_LAYER.labels(layer=layer).inc()

    def record_monitored(self, layer: str) -> None:
        MONITORED_TOTAL.inc()
        ATTACKS_BY_LAYER.labels(layer=layer).inc()

    def record_allowed(self) -> None:
        ALLOWED_TOTAL.inc()

    def record_error(self) -> None:
        ERRORS_TOTAL.inc()

    def record_leakage(self) -> None:
        LEAKAGE_TOTAL.inc()

    def record_latency(self, latency_ms: float) -> None:
        INSPECTION_LATENCY.observe(latency_ms)

    def record_semantic_latency(self, latency_ms: float) -> None:
        SEMANTIC_LATENCY.observe(latency_ms)

    def record_output_scan_latency(self, latency_ms: float) -> None:
        OUTPUT_SCAN_LATENCY.observe(latency_ms)

    def get_snapshot(self) -> dict:
        """Legacy JSON snapshot for dashboard compatibility."""
        return {
            "total_requests": REQUESTS_TOTAL._value.get(),
            "total_blocked": BLOCKED_TOTAL._value.get(),
            "total_monitored": MONITORED_TOTAL._value.get(),
            "total_allowed": ALLOWED_TOTAL._value.get(),
            "total_errors": ERRORS_TOTAL._value.get(),
            "total_leakage": LEAKAGE_TOTAL._value.get(),
        }

    def to_prometheus(self) -> bytes:
        return generate_latest()

class LatencyTimer:
    def __init__(self, metrics: WafMetrics):
        self._metrics = metrics
        self._start: float = 0.0
        self.elapsed_ms: float = 0.0

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *args):
        self.elapsed_ms = (time.perf_counter() - self._start) * 1000.0
        self._metrics.record_latency(self.elapsed_ms)

waf_metrics = WafMetrics()
