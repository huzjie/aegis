import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

"""示例：使用计数器/直方图并渲染 Prometheus 文本格式。"""
from aegis.metrics.counter import Counter
from aegis.metrics.exporter import PrometheusExporter
from aegis.metrics.histogram import Histogram

exporter = PrometheusExporter()
scans = Counter("aegis_scans_total", "total scans")
hits = Counter("aegis_signature_hits", "signature hits", )
latency = Histogram("aegis_compile_seconds")

scans.inc(("java",))
hits.inc(("log4shell",), 3)
latency.observe(0.012)
latency.observe(0.031)

for m in (scans, hits, latency):
    exporter.register(m)
print(exporter.render())
