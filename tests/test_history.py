from dataclasses import replace
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from netdoctor.compare import IncompatibleRuns, compare_runs, profile_mismatches
from netdoctor.history import HISTORY_LIMIT, HistoryError, HistoryStore, Snapshot, encode_snapshot, make_profile
from netdoctor.model import Check, DiagnosticResult, Listener, Proxy, SiteResult
from netdoctor.report import snapshot_report


def snapshot(*, proxy=None, mode="direct", url=None, vpn="未标记", code=200, ms=150,
             ip="1.1.1.1", country="AU"):
    check = Check(code is not None, "测试响应" if code else "连接超时", code, ms)
    address = Check(True, "已从 Cloudflare 取得出口公网 IP", ip=ip, country_code=country)
    dns = Check(True, "DNS 成功")
    tcp = Check(True, "TCP 成功")
    site = SiteResult("GitHub", dns, tcp, check, check if proxy else None)
    result = DiagnosticResult(
        ports=(7890,),
        listeners={7890: [Listener(7890, "127.0.0.1", 123, "core.exe")]},
        settings=("设置状态",),
        sites=[site],
        direct_https=check,
        direct_exit=address,
        proxy_tunnel=tcp if proxy else None,
        proxy_https=check if proxy else None,
        proxy_exit=address if proxy else None,
    )
    return Snapshot.capture(result, url, mode, proxy, vpn, "", "2026-11-11T09:15:20+08:00")


class HistoryTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "history.json"
        self.store = HistoryStore(self.path)

    def test_round_trip_preserves_raw_results_without_credentials(self):
        proxy = Proxy("HTTP", "secret-proxy.example", 7890, "secret-user", "secret-password")
        record = snapshot(proxy=proxy, mode="manual", url="https://example.com/?token=secret-value")
        self.store.save(record)
        self.store.set_baseline(record.id)
        recovered = HistoryStore(self.path)
        self.assertEqual(recovered.baseline, record)
        raw = self.path.read_text(encoding="utf-8")
        for secret in ("secret-proxy.example", "secret-user", "secret-password", "secret-value"):
            self.assertNotIn(secret, raw)
        self.assertIn("1.1.1.1", raw)
        report = snapshot_report(recovered.baseline)
        self.assertIn("2026-11-11T09:15:20+08:00", report)
        self.assertNotIn("1.1.1.1", report)

    def test_released_v130_history_remains_readable_and_comparable(self):
        fixture = Path(__file__).parent / "fixtures" / "history-v1.json"
        original = json.loads(fixture.read_text(encoding="utf-8"))
        recovered = HistoryStore(fixture)
        self.assertFalse(recovered.read_error)
        baseline = recovered.baseline
        self.assertEqual(baseline.id, "legacy-v1-baseline")
        self.assertEqual(baseline.result.sites[0].https.code, 403)
        self.assertEqual(baseline.result.proxy_exit.country_code, "US")
        self.assertEqual(json.loads(json.dumps(encode_snapshot(baseline))), original["records"][0])
        fresh = snapshot(mode="manual", proxy=Proxy("HTTP", "127.0.0.1", 7890))
        changes = {row.metric: row.verdict for row in compare_runs(baseline, fresh)}
        self.assertEqual(changes["GitHub · 直连 HTTPS · HTTP"], "改善")

    def test_auto_baseline_preflight_checks_endpoint_after_discovery(self):
        before = make_profile(None, "auto", Proxy("HTTP", "127.0.0.1", 7890))
        pending = make_profile(None, "auto", None)
        self.assertEqual(profile_mismatches(before, pending, check_proxy=False), [])
        different_target = make_profile("https://example.com/", "auto", None)
        self.assertEqual(profile_mismatches(before, different_target, check_proxy=False), ["检测目标"])
        changed_port = make_profile(None, "auto", Proxy("HTTP", "127.0.0.1", 12450))
        self.assertEqual(profile_mismatches(before, changed_port), ["实际代理端点、协议或认证方式"])

    def test_retention_replace_cancel_and_delete_baseline(self):
        base = snapshot()
        self.store.save(base)
        self.store.set_baseline(base.id)
        for _ in range(HISTORY_LIMIT + 2):
            self.store.save(snapshot())
        self.assertEqual(len(self.store.records), HISTORY_LIMIT)
        self.assertEqual(self.store.baseline, base)
        newest = self.store.records[0]
        self.store.set_baseline(newest.id)
        self.assertEqual(self.store.baseline, newest)
        self.store.set_baseline(None)
        self.assertIsNone(HistoryStore(self.path).baseline)
        self.store.set_baseline(newest.id)
        self.store.delete_many([base.id, newest.id])
        self.assertIsNone(HistoryStore(self.path).baseline)
        self.assertEqual(len(self.store.records), HISTORY_LIMIT - 2)

    def test_corrupt_history_is_not_overwritten(self):
        self.path.write_text("{broken", encoding="utf-8")
        self.store.reload()
        self.assertTrue(self.store.read_error)
        with self.assertRaises(HistoryError):
            self.store.save(snapshot())
        self.assertEqual(self.path.read_text(encoding="utf-8"), "{broken")

    def test_atomic_write_failure_and_multiple_instances(self):
        first, second = snapshot(), snapshot()
        other = HistoryStore(self.path)
        self.store.save(first)
        other.save(second)
        with patch.object(Path, "replace", side_effect=PermissionError):
            with self.assertRaises(HistoryError):
                self.store.delete(first.id)
        self.assertEqual(self.store.records, (second, first))
        self.assertEqual(HistoryStore(self.path).records, (second, first))

    def test_comparison_marks_http_latency_and_exit_changes(self):
        before = snapshot(code=403, vpn="VPN 未连接")
        after = snapshot(vpn="VPN 已连接", ip="8.8.8.8", country="US")
        rows = {row.metric: row for row in compare_runs(before, after)}
        self.assertEqual(rows["GitHub · 直连 HTTPS"].verdict, "无变化")
        self.assertEqual(rows["GitHub · 直连 HTTPS · HTTP"].verdict, "改善")
        self.assertEqual(rows["GitHub · 直连 HTTPS · 耗时"].verdict, "条件不同")
        self.assertEqual(rows["直连 · 出口 IP"].verdict, "已变化")
        self.assertEqual(rows["直连 · 出口国家／地区（估算）"].after, "US")
        slower = compare_runs(after, snapshot(ms=350))
        self.assertIn("恶化", [row.verdict for row in slower])
        failed = compare_runs(after, snapshot(code=None))
        self.assertEqual(next(row for row in failed if row.metric == "GitHub · 直连 HTTPS").verdict,
                         "恶化")

    def test_compare_rejects_target_route_endpoint_and_policy_changes(self):
        first = snapshot()
        manual = snapshot(mode="manual", proxy=Proxy("HTTP", "127.0.0.1", 7890))
        cases = (
            (first, snapshot(url="https://example.com/"), "检测目标"),
            (first, manual, "检测模式"),
            (manual, snapshot(mode="manual", proxy=Proxy("HTTP", "127.0.0.1", 12450)), "代理端点"),
            (first, replace(first, profile=replace(first.profile, policy="different")), "参数版本"),
        )
        for before, after, reason in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(IncompatibleRuns, reason):
                compare_runs(before, after)
