"""流量采样与速率计算的单元测试。"""
import os
import tempfile
import unittest

from wgmanager.traffic import (TrafficStore, human_rate, nice_ceiling,
                               nice_rate_ceiling)


class TrafficTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TrafficStore(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()


class TestRecord(TrafficTestCase):
    def test_record_and_read_back(self):
        n = self.store.record("H:22/root", [("PK1", 1000, 500)], ts=1000)
        self.assertEqual(n, 1)
        self.assertEqual(self.store.series("H:22/root", "PK1"),
                         [(1000, 1000, 500)])

    def test_multiple_peers_in_one_call(self):
        self.store.record("H", [("PK1", 10, 1), ("PK2", 20, 2)], ts=100)
        self.assertEqual(len(self.store.series("H", "PK1")), 1)
        self.assertEqual(len(self.store.series("H", "PK2")), 1)

    def test_empty_points_noop(self):
        self.assertEqual(self.store.record("H", []), 0)

    def test_series_ordered_by_time(self):
        for ts in (300, 100, 200):
            self.store.record("H", [("PK1", ts, 0)], ts=ts)
        times = [t for t, _, _ in self.store.series("H", "PK1")]
        self.assertEqual(times, [100, 200, 300])

    def test_series_since_filters(self):
        for ts in (100, 200, 300):
            self.store.record("H", [("PK1", ts, 0)], ts=ts)
        times = [t for t, _, _ in self.store.series("H", "PK1", since=200)]
        self.assertEqual(times, [200, 300])

    def test_hosts_are_isolated(self):
        self.store.record("A", [("PK1", 10, 0)], ts=1)
        self.store.record("B", [("PK1", 20, 0)], ts=1)
        self.assertEqual(self.store.series("A", "PK1"), [(1, 10, 0)])
        self.assertEqual(self.store.series("B", "PK1"), [(1, 20, 0)])

    def test_count(self):
        self.store.record("H", [("PK1", 1, 0), ("PK2", 2, 0)], ts=1)
        self.assertEqual(self.store.count(), 2)


class TestRates(TrafficTestCase):
    def test_simple_rate(self):
        self.store.record("H", [("PK1", 0, 0)], ts=1000)
        self.store.record("H", [("PK1", 6000, 3000)], ts=1060)
        r = self.store.rates("H", "PK1")
        self.assertEqual(len(r), 1)
        ts, down, up = r[0]
        self.assertEqual(ts, 1060)
        self.assertAlmostEqual(down, 100.0)
        self.assertAlmostEqual(up, 50.0)

    def test_single_point_yields_nothing(self):
        self.store.record("H", [("PK1", 100, 100)], ts=1)
        self.assertEqual(self.store.rates("H", "PK1"), [])

    def test_counter_reset_dropped(self):
        # 服务重启后累计值归零，差值会是负数 —— 必须丢掉而不是画成断崖
        self.store.record("H", [("PK1", 900000, 900000)], ts=1000)
        self.store.record("H", [("PK1", 500, 500)], ts=1060)
        self.store.record("H", [("PK1", 1500, 1500)], ts=1120)
        r = self.store.rates("H", "PK1")
        self.assertEqual(len(r), 1, "重置那一对应该被丢掉，只剩重置后的一段")
        self.assertAlmostEqual(r[0][1], 1000 / 60)

    def test_long_gap_dropped(self):
        # 电脑休眠三小时，差值摊到三小时没有意义
        self.store.record("H", [("PK1", 0, 0)], ts=1000)
        self.store.record("H", [("PK1", 10800, 0)], ts=1000 + 3 * 3600)
        self.assertEqual(self.store.rates("H", "PK1"), [])

    def test_custom_max_gap(self):
        self.store.record("H", [("PK1", 0, 0)], ts=1000)
        self.store.record("H", [("PK1", 600, 0)], ts=1060)
        self.assertEqual(len(self.store.rates("H", "PK1", max_gap=30)), 0)
        self.assertEqual(len(self.store.rates("H", "PK1", max_gap=120)), 1)

    def test_duplicate_timestamp_skipped(self):
        self.store.record("H", [("PK1", 0, 0)], ts=1000)
        self.store.record("H", [("PK1", 500, 0)], ts=1000)
        self.assertEqual(self.store.rates("H", "PK1"), [])

    def test_zero_traffic_is_a_valid_point(self):
        self.store.record("H", [("PK1", 100, 100)], ts=1000)
        self.store.record("H", [("PK1", 100, 100)], ts=1060)
        r = self.store.rates("H", "PK1")
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0][1], 0.0)


class TestQueries(TrafficTestCase):
    def test_latest(self):
        self.store.record("H", [("PK1", 10, 1)], ts=100)
        self.store.record("H", [("PK1", 99, 9)], ts=200)
        self.assertEqual(self.store.latest("H", "PK1"), (99, 9))

    def test_latest_missing(self):
        self.assertIsNone(self.store.latest("H", "NOPE"))

    def test_peers(self):
        self.store.record("H", [("PK1", 1, 0), ("PK2", 2, 0)], ts=100)
        self.assertEqual(sorted(self.store.peers("H")), ["PK1", "PK2"])

    def test_peers_isolated_by_host(self):
        self.store.record("A", [("PK1", 1, 0)], ts=1)
        self.store.record("B", [("PK2", 2, 0)], ts=1)
        self.assertEqual(self.store.peers("A"), ["PK1"])

    def test_span(self):
        self.store.record("H", [("PK1", 1, 0)], ts=100)
        self.store.record("H", [("PK1", 2, 0)], ts=900)
        self.assertEqual(self.store.span("H", "PK1"), (100, 900))

    def test_span_missing(self):
        self.assertIsNone(self.store.span("H", "NOPE"))

    def test_prune(self):
        now = 10_000_000
        self.store.record("H", [("PK1", 1, 0)], ts=now - 10 * 86400)
        self.store.record("H", [("PK1", 2, 0)], ts=now - 3600)
        import wgmanager.traffic as tr
        old = tr.time.time
        tr.time.time = lambda: now
        try:
            removed = self.store.prune(keep_days=7)
        finally:
            tr.time.time = old
        self.assertEqual(removed, 1)
        self.assertEqual(self.store.count(), 1)


class TestFormatting(unittest.TestCase):
    def test_human_rate(self):
        self.assertEqual(human_rate(0), "0 B/s")
        self.assertEqual(human_rate(999), "999 B/s")
        self.assertEqual(human_rate(2048), "2.0 KB/s")
        self.assertEqual(human_rate(5 * 1024 * 1024), "5.0 MB/s")

    def test_human_rate_bad_input(self):
        self.assertEqual(human_rate("x"), "-")

    def test_nice_ceiling(self):
        self.assertEqual(nice_ceiling(0), 1.0)
        self.assertEqual(nice_ceiling(7), 8)
        self.assertEqual(nice_ceiling(12), 20)
        self.assertEqual(nice_ceiling(23), 40)
        self.assertEqual(nice_ceiling(40), 40)
        self.assertEqual(nice_ceiling(60), 80)
        self.assertEqual(nice_ceiling(1500), 2000)

    def test_nice_ceiling_always_above(self):
        for v in (1, 3, 9, 11, 99, 101, 777, 1024, 12345):
            self.assertGreaterEqual(nice_ceiling(v), v)

    def test_nice_ceiling_divisible_by_four(self):
        # Y 轴分 4 段，上限除以 4 应该是整数，刻度才不会出现 122.1 这种
        for v in (3, 7, 12, 23, 40, 60, 300, 777, 1500, 12345):
            top = nice_ceiling(v)
            self.assertEqual(top % 4, 0, f"{v} -> {top} 不能被 4 整除")

    def test_nice_rate_ceiling_keeps_unit_round(self):
        # 300 KB/s 应该取整到 400 KB/s，而不是 488.3 KB/s
        self.assertEqual(nice_rate_ceiling(300 * 1024), 400 * 1024)
        self.assertEqual(nice_rate_ceiling(5 * 1024 * 1024), 8 * 1024 * 1024)
        self.assertEqual(nice_rate_ceiling(1), 1)

    def test_nice_rate_ceiling_covers_peak(self):
        for v in (1, 999, 5000, 307200, 9 * 1024 * 1024):
            self.assertGreaterEqual(nice_rate_ceiling(v), v)


class TestPeerViewRawValues(unittest.TestCase):
    def test_peerview_has_rx_tx(self):
        from wgmanager.service import PeerView
        v = PeerView(rx=1234, tx=5678)
        self.assertEqual((v.rx, v.tx), (1234, 5678))

    def test_to_int_handles_junk(self):
        from wgmanager.service import _to_int
        self.assertEqual(_to_int("1234"), 1234)
        self.assertEqual(_to_int("1024.0"), 1024)
        self.assertEqual(_to_int(""), 0)
        self.assertEqual(_to_int(None), 0)
        self.assertEqual(_to_int("abc"), 0)


if __name__ == "__main__":
    unittest.main()
