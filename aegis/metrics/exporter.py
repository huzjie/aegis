"""Prometheus text-format exporter over registered metrics."""

from aegis.metrics.counter import Counter
from aegis.metrics.histogram import Histogram


class PrometheusExporter:
    def __init__(self):
        self.metrics = {}

    def register(self, metric) -> None:
        self.metrics[metric.name] = metric

    def render(self) -> str:
        lines = []
        for name, m in self.metrics.items():
            if isinstance(m, Counter):
                for labels, val in m.all().items():
                    lbl = ",".join(labels) if labels else ""
                    label_str = f"{{{lbl}}}" if lbl else ""
                    lines.append(f"{name}{label_str} {val}")
            elif isinstance(m, Histogram):
                snap = m.snapshot()
                for b, c in snap["buckets"].items():
                    lines.append(f'{name}_bucket{{le="{b}"}} {c}')
                lines.append(f"{name}_count {snap['count']}")
                lines.append(f"{name}_sum {snap['sum']}")
        return "\n".join(lines) + ("\n" if lines else "")
