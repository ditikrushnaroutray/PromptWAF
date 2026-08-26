"""
PromptWAF Observability — Prometheus-compatible metrics.

Exposes counters, histograms, and gauges for WAF operational monitoring.
The /metrics endpoint serves these in Prometheus text exposition format.

Thread-safe: all operations use atomic counters suitable for async contexts.
"""

import threading
import time
from collections import defaultdict
from typing import Dict


class WafMetrics:
    """
    In-process metrics collector for PromptWAF.

    Tracks:
        - Total requests processed
        - Total attacks detected (per layer)
        - Total attacks blocked vs monitored (shadow mode)
        - WAF inspection latency (for average computation)
        - Total leakage detections
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Counters
        self._total_requests: int = 0
        self._total_blocked: int = 0
        self._total_monitored: int = 0  # Detected but not blocked (shadow mode)
        self._total_allowed: int = 0
        self._total_errors: int = 0
        self._total_leakage: int = 0

        # Per-layer attack counters
        self._attacks_by_layer: Dict[str, int] = defaultdict(int)

        # Latency tracking (for average)
        self._total_latency_ms: float = 0.0
        self._latency_count: int = 0
        
        # Semantic Engine Latency Histogram (Buckets: 1ms, 2ms, 5ms, 10ms, 50ms, +Inf)
        self._semantic_latency_buckets = {1: 0, 2: 0, 5: 0, 10: 0, 50: 0, float('inf'): 0}
        self._semantic_latency_sum: float = 0.0
        self._semantic_latency_count: int = 0

    # ----- Recording Methods -----

    def record_request(self) -> None:
        """Increment the total request counter."""
        with self._lock:
            self._total_requests += 1

    def record_blocked(self, layer: str) -> None:
        """Record a blocked attack (BLOCK mode)."""
        with self._lock:
            self._total_blocked += 1
            self._attacks_by_layer[layer] += 1

    def record_monitored(self, layer: str) -> None:
        """Record a detected-but-forwarded attack (MONITOR mode)."""
        with self._lock:
            self._total_monitored += 1
            self._attacks_by_layer[layer] += 1

    def record_allowed(self) -> None:
        """Record a clean request that was forwarded."""
        with self._lock:
            self._total_allowed += 1

    def record_error(self) -> None:
        """Record a WAF engine error."""
        with self._lock:
            self._total_errors += 1

    def record_leakage(self) -> None:
        """Record a leakage detection event."""
        with self._lock:
            self._total_leakage += 1

    def record_latency(self, latency_ms: float) -> None:
        """Record WAF inspection latency in milliseconds."""
        with self._lock:
            self._total_latency_ms += latency_ms
            self._latency_count += 1
            
    def record_semantic_latency(self, latency_ms: float) -> None:
        """Record semantic engine latency into a histogram."""
        with self._lock:
            self._semantic_latency_sum += latency_ms
            self._semantic_latency_count += 1
            for bucket in [1, 2, 5, 10, 50, float('inf')]:
                if latency_ms <= bucket:
                    self._semantic_latency_buckets[bucket] += 1

    # ----- Query Methods -----

    def get_average_latency_ms(self) -> float:
        """Return average WAF inspection latency in ms."""
        with self._lock:
            if self._latency_count == 0:
                return 0.0
            return self._total_latency_ms / self._latency_count

    def get_snapshot(self) -> dict:
        """Return a point-in-time snapshot of all metrics."""
        with self._lock:
            return {
                "total_requests": self._total_requests,
                "total_blocked": self._total_blocked,
                "total_monitored": self._total_monitored,
                "total_allowed": self._total_allowed,
                "total_errors": self._total_errors,
                "total_leakage": self._total_leakage,
                "attacks_by_layer": dict(self._attacks_by_layer),
                "avg_latency_ms": (
                    self._total_latency_ms / self._latency_count
                    if self._latency_count > 0
                    else 0.0
                ),
                "latency_samples": self._latency_count,
                "total_latency_ms": self._total_latency_ms,
                "semantic_latency_buckets": dict(self._semantic_latency_buckets),
                "semantic_latency_sum": self._semantic_latency_sum,
                "semantic_latency_count": self._semantic_latency_count,
            }

    # ----- Prometheus Exposition -----

    def to_prometheus(self) -> str:
        """
        Render metrics in Prometheus text exposition format.
        See: https://prometheus.io/docs/instrumenting/exposition_formats/
        """
        snap = self.get_snapshot()
        lines = []

        # Total requests
        lines.append("# HELP promptwaf_requests_total Total requests processed by PromptWAF.")
        lines.append("# TYPE promptwaf_requests_total counter")
        lines.append(f"promptwaf_requests_total {snap['total_requests']}")

        # Total blocked
        lines.append("# HELP promptwaf_blocked_total Total requests blocked by PromptWAF.")
        lines.append("# TYPE promptwaf_blocked_total counter")
        lines.append(f"promptwaf_blocked_total {snap['total_blocked']}")

        # Total monitored (shadow mode)
        lines.append("# HELP promptwaf_monitored_total Total attacks detected in MONITOR mode (not blocked).")
        lines.append("# TYPE promptwaf_monitored_total counter")
        lines.append(f"promptwaf_monitored_total {snap['total_monitored']}")

        # Total allowed
        lines.append("# HELP promptwaf_allowed_total Total clean requests forwarded.")
        lines.append("# TYPE promptwaf_allowed_total counter")
        lines.append(f"promptwaf_allowed_total {snap['total_allowed']}")

        # Total errors
        lines.append("# HELP promptwaf_errors_total Total WAF engine errors.")
        lines.append("# TYPE promptwaf_errors_total counter")
        lines.append(f"promptwaf_errors_total {snap['total_errors']}")

        # Total leakage
        lines.append("# HELP promptwaf_leakage_total Total output leakage detections.")
        lines.append("# TYPE promptwaf_leakage_total counter")
        lines.append(f"promptwaf_leakage_total {snap['total_leakage']}")

        # Per-layer attack breakdown
        lines.append("# HELP promptwaf_attacks_by_layer_total Attacks detected per WAF layer.")
        lines.append("# TYPE promptwaf_attacks_by_layer_total counter")
        for layer_name in ["heuristic", "semantic", "llm_judge", "length", "leakage"]:
            count = snap["attacks_by_layer"].get(layer_name, 0)
            lines.append(f'promptwaf_attacks_by_layer_total{{layer="{layer_name}"}} {count}')

        # Average latency
        lines.append("# HELP promptwaf_inspection_latency_avg_ms Average WAF inspection latency in milliseconds.")
        lines.append("# TYPE promptwaf_inspection_latency_avg_ms gauge")
        lines.append(f"promptwaf_inspection_latency_avg_ms {snap['avg_latency_ms']:.3f}")

        # Total latency (for deriving averages externally)
        lines.append("# HELP promptwaf_inspection_latency_total_ms Total cumulative WAF inspection latency in milliseconds.")
        lines.append("# TYPE promptwaf_inspection_latency_total_ms counter")
        lines.append(f"promptwaf_inspection_latency_total_ms {snap['total_latency_ms']:.3f}")

        # Latency sample count
        lines.append("# HELP promptwaf_inspection_latency_count Total number of latency samples.")
        lines.append("# TYPE promptwaf_inspection_latency_count counter")
        lines.append(f"promptwaf_inspection_latency_count {snap['latency_samples']}")

        # Semantic latency histogram
        lines.append("# HELP promptwaf_semantic_latency_ms Semantic engine inspection latency in milliseconds.")
        lines.append("# TYPE promptwaf_semantic_latency_ms histogram")
        for bucket in [1, 2, 5, 10, 50]:
            lines.append(f'promptwaf_semantic_latency_ms_bucket{{le="{bucket}"}} {snap["semantic_latency_buckets"][bucket]}')
        lines.append(f'promptwaf_semantic_latency_ms_bucket{{le="+Inf"}} {snap["semantic_latency_buckets"][float("inf")]}')
        lines.append(f"promptwaf_semantic_latency_ms_sum {snap['semantic_latency_sum']:.3f}")
        lines.append(f"promptwaf_semantic_latency_ms_count {snap['semantic_latency_count']}")

        return "\n".join(lines) + "\n"


class LatencyTimer:
    """
    Context manager for measuring WAF inspection latency.

    Usage:
        timer = LatencyTimer(metrics)
        with timer:
            await analyze_prompt(payload)
        # timer.elapsed_ms is now set
    """

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


# ---------------------------------------------------------------------------
# Singleton metrics instance — shared across the application
# ---------------------------------------------------------------------------

waf_metrics = WafMetrics()
