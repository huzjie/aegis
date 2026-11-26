import unittest

from aegis.metrics.counter import Counter
from aegis.metrics.exporter import PrometheusExporter
from aegis.metrics.histogram import Histogram


class TestCounter(unittest.TestCase):
    def test_inc_get(self):
        c = Counter("hits")
        c.inc(("a",))
        c.inc(("a",), 2)
        self.assertEqual(c.get(("a",)), 3)
        self.assertEqual(c.get(("b",)), 0)


class TestHistogram(unittest.TestCase):
    def test_observe(self):
        h = Histogram("lat")
        h.observe(0.01)
        h.observe(1.0)
        snap = h.snapshot()
        self.assertEqual(snap["count"], 2)
        self.assertGreater(snap["buckets"]["0.5"], 0)


class TestExporter(unittest.TestCase):
    def test_render(self):
        e = PrometheusExporter()
        c = Counter("aegis_scans")
        c.inc()
        e.register(c)
        h = Histogram("aegis_lat")
        h.observe(0.2)
        e.register(h)
        out = e.render()
        self.assertIn("aegis_scans", out)
        self.assertIn("aegis_lat_bucket", out)
        self.assertIn("aegis_lat_count", out)


if __name__ == "__main__":
    unittest.main()
