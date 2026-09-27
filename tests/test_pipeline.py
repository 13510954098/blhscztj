from __future__ import annotations

import asyncio
import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import fetch_jcnode  # noqa: E402
import healthcheck_subscriptions as health  # noqa: E402
import merge_subscriptions as merge  # noqa: E402
import mihomo_alive_check as mihomo_check  # noqa: E402


class CandidateOrderTests(unittest.TestCase):
    def test_cached_then_manual_then_remaining_pool_without_duplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            (out_dir / "meta.json").write_text(json.dumps({"code": "1234"}), encoding="utf-8")
            args = SimpleNamespace(code="2345,1234,6789", mode="aabb", out_dir=str(out_dir))

            candidates = fetch_jcnode.build_candidates(args)

            self.assertEqual(candidates[:4], ["1234", "2345", "6789", "0011"])
            self.assertEqual(len(candidates), len(set(candidates)))
            self.assertIn("0099", candidates)

    def test_manual_code_still_falls_back_to_the_selected_pool(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = SimpleNamespace(code="9876", mode="aabb", out_dir=tmp)
            candidates = fetch_jcnode.build_candidates(args)
            self.assertEqual(candidates[:2], ["9876", "0011"])
            self.assertEqual(len(candidates), 91)


class MergeTests(unittest.TestCase):
    def test_clash_uses_daily_template_and_globally_sorts_speed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base_path = root / "old.yaml"
            incoming_path = root / "today.yaml"
            base = {
                "mode": "old-mode",
                "legacy-only": True,
                "proxies": [
                    {"name": "🇺🇸 历史 5MB/s中性", "server": "old-us", "port": 443, "type": "http"},
                    {"name": "🇭🇰 历史未知", "server": "old-hk", "port": 443, "type": "http"},
                    # 与本次低速节点连接参数相同，应该由本次节点覆盖。
                    {"name": "🇺🇸 重复 99MB/s", "server": "today-low", "port": 443, "type": "http"},
                ],
                "proxy-groups": [{"name": "旧结构分组", "type": "select", "proxies": []}],
            }
            incoming = {
                "mode": "rule",
                "today-only": "kept",
                "rules": ["MATCH,☁️ 代理选择"],
                "proxies": [
                    {"name": "🇺🇸 今日低速 1MB/s危险", "server": "today-low", "port": 443, "type": "http"},
                    {"name": "🇭🇰 今日 2MB/s纯净", "server": "today-hk", "port": 443, "type": "http"},
                    {"name": "🇺🇸 今日高速 9MB/s危险", "server": "today-fast", "port": 443, "type": "http"},
                ],
                "proxy-groups": [
                    {"name": "☁️ 代理选择", "type": "select", "proxies": ["🔰 手动选择", "♻️ 自动选择"]},
                    {"name": "🔰 手动选择", "type": "select", "proxies": []},
                    {"name": "♻️ 自动选择", "type": "url-test", "proxies": []},
                    {"name": "🇺🇸 美国自动", "type": "url-test", "proxies": []},
                    {"name": "🇭🇰 香港自动", "type": "url-test", "proxies": []},
                ],
            }
            base_path.write_text(merge.yaml.safe_dump(base, allow_unicode=True), encoding="utf-8")
            incoming_path.write_text(merge.yaml.safe_dump(incoming, allow_unicode=True), encoding="utf-8")

            result, stats = merge.merge_clash(base_path, incoming_path)

            names = [item["name"] for item in result["proxies"]]
            self.assertEqual(
                names,
                ["🇺🇸 今日高速 9MB/s危险", "🇺🇸 历史 5MB/s中性", "🇭🇰 今日 2MB/s纯净", "🇺🇸 今日低速 1MB/s危险", "🇭🇰 历史未知"],
            )
            self.assertEqual(result["mode"], "rule")
            self.assertNotIn("legacy-only", result)
            self.assertNotIn("旧结构分组", [group["name"] for group in result["proxy-groups"]])
            groups = {group["name"]: group["proxies"] for group in result["proxy-groups"]}
            self.assertEqual(groups["🔰 手动选择"], names)
            self.assertEqual(groups["♻️ 自动选择"], names)
            self.assertEqual(groups["🇺🇸 美国自动"], names[:2] + [names[3]])
            self.assertEqual(groups["🇭🇰 香港自动"], [names[2], names[4]])
            self.assertEqual(stats["duplicates_removed"], 1)
            self.assertEqual(stats["template"], "incoming-daily")

    def test_singbox_uses_daily_root_and_speed_sorts_tags(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base_path, incoming_path = root / "old.json", root / "today.json"
            base_path.write_text(
                json.dumps({"log": {"level": "old"}, "old-only": True, "outbounds": [
                    {"type": "http", "tag": "历史 3MB/s", "server": "old", "server_port": 443}
                ]}),
                encoding="utf-8",
            )
            incoming_path.write_text(
                json.dumps({"log": {"level": "warn"}, "today-only": True, "outbounds": [
                    {"type": "http", "tag": "今日 1MB/s危险", "server": "today", "server_port": 443}
                ]}),
                encoding="utf-8",
            )

            result, _ = merge.merge_singbox(base_path, incoming_path)

            self.assertEqual(result["log"], {"level": "warn"})
            self.assertNotIn("old-only", result)
            self.assertEqual([item["tag"] for item in result["outbounds"]], ["历史 3MB/s", "今日 1MB/s危险"])

    def test_v2ray_globally_sorts_decoded_fragments(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base_path, incoming_path = root / "old.txt", root / "today.txt"
            base_path.write_text("https://u:p@history.example:443#历史%203MB%2Fs\n", encoding="utf-8")
            incoming_path.write_text(
                "https://u:p@slow.example:443#今日%201MB%2Fs\n"
                "https://u:p@fast.example:443#今日%209MB%2Fs\n",
                encoding="utf-8",
            )

            result, _ = merge.merge_v2ray(base_path, incoming_path)

            names = [merge.v2ray_name(line) for line in result.splitlines()]
            self.assertEqual(names, ["今日 9MB/s", "历史 3MB/s", "今日 1MB/s"])


class ProbeParsingTests(unittest.TestCase):
    def test_speed_parser_handles_chinese_suffix_and_stable_unknowns(self):
        self.assertEqual(merge.speed_from_name("节点 9.4MB/s危险"), 9.4)
        self.assertIsNone(merge.speed_from_name("节点 测速未知"))
        items = ["unknown-a", "slow 1MB/s", "unknown-b", "fast 3MB/s"]
        self.assertEqual(merge.sort_by_speed(items, str), ["fast 3MB/s", "slow 1MB/s", "unknown-a", "unknown-b"])

    def test_endpoint_canonicalization_and_protocol_statuses(self):
        first = health.make_endpoint("EXAMPLE.COM.", "443", True)
        second = health.make_endpoint("example.com", 443, True, "example.com")
        self.assertEqual(first, second)

        endpoint, hint, _ = health.parse_clash_node(
            {"type": "http", "server": "proxy.example", "port": 443, "tls": True, "sni": "edge.example"}
        )
        self.assertEqual(hint, None)
        self.assertEqual(endpoint.sni, "edge.example")

        endpoint, hint, reason = health.parse_clash_node(
            {"type": "hysteria2", "server": "proxy.example", "port": 443}
        )
        self.assertIsNone(endpoint)
        self.assertEqual((hint, reason), ("unsupported", "udp_or_quic"))

        endpoint, hint, reason = health.parse_clash_node(
            {"type": "vless", "server": "proxy.example", "port": 443, "tls": True,
             "reality-opts": {"public-key": "fixture"}}
        )
        self.assertIsNone(endpoint)
        self.assertEqual((hint, reason), ("unsupported", "reality_requires_special_client"))

    def test_v2ray_vmess_uri_and_unsupported_uri_parsing(self):
        payload = base64.urlsafe_b64encode(
            json.dumps({"add": "vmess.example", "port": "443", "tls": "tls", "net": "ws", "host": "sni.example"}).encode()
        ).decode().rstrip("=")
        endpoint, hint, reason = health.parse_v2ray_line(f"vmess://{payload}#fixture")
        self.assertIsNone(hint)
        self.assertIsNone(reason)
        self.assertEqual((endpoint.host, endpoint.port, endpoint.tls, endpoint.sni),
                         ("vmess.example", 443, True, "sni.example"))

        endpoint, hint, reason = health.parse_v2ray_line(
            "vless://id@proxy.example:443?security=reality&sni=edge.example#fixture"
        )
        self.assertIsNone(endpoint)
        self.assertEqual((hint, reason), ("unsupported", "reality_requires_special_client"))

        endpoint, hint, reason = health.parse_v2ray_line("hy2://id@proxy.example:443#fixture")
        self.assertIsNone(endpoint)
        self.assertEqual((hint, reason), ("unsupported", "udp_or_quic"))

    def test_local_tcp_handshake_only(self):
        async def run_test():
            async def handle(reader, writer):
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            server = await asyncio.start_server(handle, "127.0.0.1", 0)
            try:
                port = server.sockets[0].getsockname()[1]
                endpoint = health.make_endpoint("127.0.0.1", port, False)
                return await health.probe_endpoint(endpoint, timeout=1.0)
            finally:
                server.close()
                await server.wait_closed()

        result = asyncio.run(run_test())
        self.assertEqual(result["status"], "passed")

    def test_persistent_state_retention_and_all_formats(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_dir, output_dir = root / "input", root / "alive"
            input_dir.mkdir()
            clash_doc = {
                "mode": "rule",
                "proxies": [
                    {"name": "🇺🇸 TCP 2MB/s", "type": "http", "server": "clash.example", "port": 443, "tls": True},
                    {"name": "🇸🇬 UDP", "type": "hysteria2", "server": "udp.example", "port": 443},
                    {"name": "🇨🇳 未解析端点", "type": "http", "server": "", "port": "bad"},
                ],
                "proxy-groups": [
                    {"name": "☁️ 代理选择", "type": "select", "proxies": ["🔰 手动选择"]},
                    {"name": "🔰 手动选择", "type": "select", "proxies": ["🇺🇸 TCP 2MB/s", "🇸🇬 UDP"]},
                    {"name": "🇺🇸 美国自动", "type": "url-test", "proxies": ["🇺🇸 TCP 2MB/s"]},
                ],
            }
            singbox_doc = {
                "outbounds": [
                    {"type": "http", "tag": "Sing-box TCP 3MB/s", "server": "sing.example", "server_port": 443,
                     "tls": {"enabled": True}},
                    {"type": "hysteria2", "tag": "Sing-box UDP", "server": "sing-udp.example", "server_port": 443},
                ]
            }
            (input_dir / "clash.yaml").write_text(health.yaml.safe_dump(clash_doc, allow_unicode=True), encoding="utf-8")
            (input_dir / "singbox.json").write_text(json.dumps(singbox_doc), encoding="utf-8")
            (input_dir / "v2ray.txt").write_text(
                "https://u:p@v2ray.example:443#V2Ray%204MB%2Fs\n"
                "hy2://id@v2ray-udp.example:443#V2Ray%20UDP\n",
                encoding="utf-8",
            )

            async def outcomes(endpoints, status):
                return {
                    endpoint.endpoint_id: {
                        "status": status,
                        "latency_ms": 1.0,
                        "error": "TimeoutError" if status == "failed" else "",
                    }
                    for endpoint in endpoints
                }

            async def all_pass(endpoints, timeout, concurrency):
                return await outcomes(endpoints, "passed")

            async def all_fail(endpoints, timeout, concurrency):
                return await outcomes(endpoints, "failed")

            with patch.object(health, "probe_all", new=all_pass):
                first = health.run_healthcheck(input_dir, output_dir, output_dir / "state.json", dry_run=False)
            self.assertEqual(first["node_status_counts"]["clash"]["passed"], 1)
            self.assertEqual(first["node_status_counts"]["clash"]["unsupported"], 1)
            self.assertEqual(first["node_status_counts"]["clash"]["untested"], 1)
            self.assertEqual(first["node_status_counts"]["singbox"]["passed"], 1)
            self.assertEqual(first["node_status_counts"]["v2ray"]["passed"], 1)
            live_clash = health.yaml.safe_load((output_dir / "clash.yaml").read_text(encoding="utf-8"))
            self.assertEqual(len(live_clash["proxies"]), 1)
            self.assertEqual(live_clash["proxy-groups"][1]["proxies"], ["🇺🇸 TCP 2MB/s"])
            self.assertTrue((output_dir / "singbox.json").exists())
            self.assertEqual(len((output_dir / "v2ray.txt").read_text(encoding="utf-8").splitlines()), 1)

            with patch.object(health, "probe_all", new=all_fail):
                retained = health.run_healthcheck(input_dir, output_dir, output_dir / "state.json", retention_hours=24)
            self.assertEqual(retained["node_status_counts"]["clash"]["retained"], 1)
            self.assertEqual(retained["node_status_counts"]["singbox"]["retained"], 1)
            self.assertEqual(retained["node_status_counts"]["v2ray"]["retained"], 1)
            self.assertEqual(len(health.yaml.safe_load((output_dir / "clash.yaml").read_text())["proxies"]), 1)

            with patch.object(health, "probe_all", new=all_fail):
                expired = health.run_healthcheck(input_dir, output_dir, output_dir / "state.json", retention_hours=0)
            self.assertEqual(expired["node_status_counts"]["clash"]["failed"], 1)
            self.assertEqual(len(health.yaml.safe_load((output_dir / "clash.yaml").read_text())["proxies"]), 0)
            state = json.loads((output_dir / "state.json").read_text(encoding="utf-8"))
            self.assertTrue(all("last_success_at" in row and "last_failure_at" in row for row in state["endpoints"].values()))
            self.assertTrue(all("node_names" in row and "formats" in row for row in state["endpoints"].values()))

    def test_first_run_full_then_only_daily_is_probed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            full_dir, daily_dir, output_dir = root / "merged", root / "daily", root / "alive"
            full_dir.mkdir()
            daily_dir.mkdir()
            daily_node = {"name": "🇺🇸 今日节点 2MB/s", "type": "http", "server": "today.example", "port": 443}
            old_node = {"name": "🇯🇵 历史节点 1MB/s", "type": "http", "server": "old.example", "port": 443}

            def write_clash(path, proxies):
                names = [node["name"] for node in proxies]
                doc = {
                    "mode": "rule",
                    "proxies": proxies,
                    "proxy-groups": [
                        {"name": "🔰 手动选择", "type": "select", "proxies": names},
                        {"name": "♻️ 自动选择", "type": "url-test", "proxies": names},
                    ],
                }
                path.write_text(health.yaml.safe_dump(doc, allow_unicode=True), encoding="utf-8")

            write_clash(full_dir / "clash.yaml", [daily_node, old_node])
            write_clash(daily_dir / "clash.yaml", [daily_node])
            calls = []

            async def pass_all(endpoints, timeout, concurrency):
                calls.append([endpoint.endpoint_id for endpoint in endpoints])
                return {
                    endpoint.endpoint_id: {"status": "passed", "latency_ms": 1.0, "error": ""}
                    for endpoint in endpoints
                }

            async def fail_all(endpoints, timeout, concurrency):
                calls.append([endpoint.endpoint_id for endpoint in endpoints])
                return {
                    endpoint.endpoint_id: {"status": "failed", "latency_ms": 1.0, "error": "TimeoutError"}
                    for endpoint in endpoints
                }

            state_path = output_dir / "state.json"
            with patch.object(health, "probe_all", new=pass_all):
                first = health.run_healthcheck(full_dir, output_dir, state_path, daily_dir=daily_dir)
            self.assertEqual(first["probe_scope"], "full_history_bootstrap")
            self.assertEqual(first["unique_tcp_tls_endpoints_tested"], 2)
            self.assertEqual(len(calls[0]), 2)

            with patch.object(health, "probe_all", new=fail_all):
                later = health.run_healthcheck(full_dir, output_dir, state_path, daily_dir=daily_dir)
            self.assertEqual(later["probe_scope"], "daily_only")
            self.assertEqual(later["tested_node_entries"], 1)
            self.assertEqual(later["unique_tcp_tls_endpoints_tested"], 1)
            self.assertEqual(len(calls[1]), 1)
            self.assertNotEqual(calls[0], calls[1])
            self.assertEqual(later["node_status_counts"]["clash"]["retained"], 1)
            self.assertEqual(later["node_status_counts"]["clash"]["stale"], 1)
            live = health.yaml.safe_load((output_dir / "clash.yaml").read_text(encoding="utf-8"))
            self.assertEqual(len(live["proxies"]), 2)


class _FakeMihomoProcess:
    """离线单测用的假 mihomo 内核：可注入启动失败名单、延迟结果与瞬时抖动。"""

    def __init__(self, fail_start_names=(), delay_of=None, flaky_once=(), default_status=408):
        self.fail_start_names = set(fail_start_names)
        self.delay_of = dict(delay_of or {})
        self.flaky_once = set(flaky_once)
        self.default_status = int(default_status)
        self.started = False
        self.stopped = False
        self.loaded_names = []
        self.calls = {}

    def start(self, proxies):
        names = [str(p.get("name")) for p in proxies]
        if self.fail_start_names & set(names):
            return False
        self.started = True
        self.loaded_names = list(names)
        return True

    def is_running(self):
        return self.started and not self.stopped

    def get(self, path, timeout=10.0):
        assert "/proxies/" in path and "/delay" in path, path
        name = unquote(path.split("/proxies/", 1)[1].split("/delay", 1)[0])
        count = self.calls.get(name, 0) + 1
        self.calls[name] = count
        if name in self.flaky_once and count == 1:
            raise OSError("connection refused (fake transient failure)")
        if name in self.delay_of:
            return 200, json.dumps({"delay": self.delay_of[name]}).encode("utf-8")
        return self.default_status, json.dumps({"message": "delay test failed"}).encode("utf-8")

    def stop(self):
        self.stopped = True

    def log_tail(self, lines=15):
        return ""


class MihomoKeyNormalizationTests(unittest.TestCase):
    def test_cross_format_key_normalization(self):
        # clash ss ↔ singbox shadowsocks ↔ v2ray ss://
        candidates, stats = mihomo_check.extract_clash_candidates(
            {"proxies": [{"name": "n", "type": "ss", "server": "Example.COM.", "port": "8388"}]}
        )
        self.assertEqual(stats["invalid"], 0)
        self.assertEqual((candidates[0].host, candidates[0].port, candidates[0].protocol),
                         ("example.com", 8388, "shadowsocks"))
        self.assertEqual(
            mihomo_check.singbox_node_key(
                {"type": "shadowsocks", "server": "example.com", "server_port": 8388}
            ),
            ("example.com", 8388, "shadowsocks"),
        )
        self.assertEqual(
            mihomo_check.v2ray_line_key("ss://YWVzLTI1Ni1nY206cGFzcw@example.com:8388#x"),
            ("example.com", 8388, "shadowsocks"),
        )
        # hy2 / hysteria2 / tuic 等协议名归一
        self.assertEqual(mihomo_check.canon_protocol("hy2"), "hysteria2")
        self.assertEqual(mihomo_check.canon_protocol("socks5"), "socks")
        self.assertEqual(
            mihomo_check.v2ray_line_key("hy2://pw@h.example:443#x"),
            ("h.example", 443, "hysteria2"),
        )
        # v2ray https:// 与 clash http 类型同源
        self.assertEqual(mihomo_check.v2ray_line_key("https://h.example:443#x"),
                         ("h.example", 443, "http"))
        # vmess base64 载荷
        blob = base64.urlsafe_b64encode(
            json.dumps({"add": "vm.example", "port": 443, "ps": "n"}).encode()
        ).decode()
        self.assertEqual(mihomo_check.v2ray_line_key(f"vmess://{blob}"),
                         ("vm.example", 443, "vmess"))
        # 旧式 ss://base64(method:pass@host:port)
        legacy = base64.urlsafe_b64encode(b"aes-256-gcm:pass@old.example:8388").decode()
        self.assertEqual(mihomo_check.v2ray_line_key(f"ss://{legacy}#x"),
                         ("old.example", 8388, "shadowsocks"))
        # 非法输入
        self.assertIsNone(mihomo_check.v2ray_line_key("not-a-uri"))
        self.assertIsNone(mihomo_check.v2ray_line_key("socks5://@:0#x"))

    def test_singbox_aux_types_are_not_nodes(self):
        self.assertTrue(mihomo_check.is_singbox_aux({"type": "direct"}))
        self.assertTrue(mihomo_check.is_singbox_aux({"type": "selector", "tag": "sel"}))
        self.assertIsNone(mihomo_check.singbox_node_key({"type": "urltest", "tag": "auto"}))

    def test_candidate_extraction_marks_udp_and_dedups(self):
        doc = {
            "proxies": [
                {"name": "A", "type": "vmess", "server": "a.example", "port": 1},
                {"name": "A", "type": "vmess", "server": "dup.example", "port": 2},
                {"name": "U", "type": "hysteria2", "server": "u.example", "port": 3},
                {"name": "Q", "type": "vless", "server": "q.example", "port": 4, "network": "quic"},
                {"name": "bad", "type": "http", "server": "", "port": "x"},
                "not-a-dict",
            ]
        }
        candidates, stats = mihomo_check.extract_clash_candidates(doc)
        self.assertEqual([c.name for c in candidates], ["A", "U", "Q"])
        self.assertFalse(candidates[0].udp)
        self.assertTrue(candidates[1].udp)
        self.assertTrue(candidates[2].udp)
        self.assertEqual(stats["invalid"], 2)
        self.assertEqual(stats["duplicate_name"], 1)


class MihomoConfigAndQueryTests(unittest.TestCase):
    def test_mihomo_test_config_contains_only_proxies_and_controller(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = mihomo_check.MihomoProcess(
                "/nonexistent", Path(tmp), api_port=19099, secret="s3cret"
            )
            proc.write_config([{"name": "n1", "type": "http", "server": "a", "port": 80}])
            doc = health.yaml.safe_load(proc.config_path.read_text(encoding="utf-8"))
            self.assertEqual(doc["external-controller"], "127.0.0.1:19099")
            self.assertEqual(doc["secret"], "s3cret")
            self.assertEqual(doc["mode"], "direct")
            self.assertEqual(len(doc["proxies"]), 1)
            self.assertNotIn("rules", doc)
            self.assertNotIn("proxy-groups", doc)

    def test_query_delay_success_and_error_paths(self):
        fake = _FakeMihomoProcess(delay_of={"ok": 123})
        good = mihomo_check.query_delay(fake, "ok", "http://x/generate_204", 3000)
        self.assertTrue(good["ok"])
        self.assertEqual(good["delay_ms"], 123)
        dead = mihomo_check.query_delay(fake, "dead", "http://x/generate_204", 3000)
        self.assertFalse(dead["ok"])
        self.assertEqual(dead["error"], "HTTP 408")

    def test_delay_tests_retry_transient_failures(self):
        def make(name, host):
            endpoint = health.make_endpoint(host, 443, False)
            return mihomo_check.Candidate(
                name=name, protocol="http", host=endpoint.host, port=endpoint.port,
                endpoint_id=endpoint.endpoint_id,
                proxy={"name": name, "type": "http", "server": host, "port": 443},
                udp=False,
            )

        candidates = [make("flaky", "flaky.example"), make("solid", "solid.example")]
        retry_fake = _FakeMihomoProcess(delay_of={"flaky": 90, "solid": 80}, flaky_once={"flaky"})
        retry_fake.started = True
        with_retry = mihomo_check.run_delay_tests(
            retry_fake, candidates, "http://x/generate_204", 3000, concurrency=2, retries=1,
        )
        self.assertTrue(with_retry["flaky"]["ok"])
        self.assertEqual(with_retry["flaky"]["attempts"], 2)
        self.assertEqual(with_retry["solid"]["attempts"], 1)

        no_retry_fake = _FakeMihomoProcess(delay_of={"flaky": 90, "solid": 80}, flaky_once={"flaky"})
        no_retry_fake.started = True
        no_retry = mihomo_check.run_delay_tests(
            no_retry_fake, candidates, "http://x/generate_204", 3000, concurrency=2, retries=0,
        )
        self.assertFalse(no_retry["flaky"]["ok"])
        self.assertTrue(no_retry["solid"]["ok"])

    def test_bisect_isolates_proxies_that_break_mihomo_startup(self):
        def make(name, host):
            endpoint = health.make_endpoint(host, 443, False)
            return mihomo_check.Candidate(
                name=name, protocol="http", host=endpoint.host, port=endpoint.port,
                endpoint_id=endpoint.endpoint_id,
                proxy={"name": name, "type": "http", "server": host, "port": 443},
                udp=False,
            )

        bad_name = "🇺🇸 坏节点"
        candidates = [make(f"n{i}", f"h{i}.example") for i in range(8)]
        candidates.insert(4, make(bad_name, "bad.example"))
        good_delays = {c.name: 100 for c in candidates if c.name != bad_name}
        created = []

        def factory():
            fake = _FakeMihomoProcess(fail_start_names={bad_name}, delay_of=good_delays)
            created.append(fake)
            return fake

        results, bad_list = mihomo_check.run_real_test(
            factory, candidates, "http://x/generate_204", 3000, concurrency=4, retries=0
        )
        self.assertEqual([c.name for c in bad_list], [bad_name])
        self.assertEqual(len(results), 8)
        self.assertTrue(all(r["ok"] for r in results.values()))
        self.assertTrue(all(fake.stopped for fake in created))


class MihomoPipelineTests(unittest.TestCase):
    @staticmethod
    def _write_input(root: Path):
        input_dir = root / "merged"
        input_dir.mkdir(parents=True, exist_ok=True)
        clash_doc = {
            "mode": "rule",
            "proxies": [
                {"name": "🇺🇸 存活HTTP 2MB/s", "type": "http", "server": "alive.example",
                 "port": 8080, "tls": True},
                {"name": "🇸🇬 存活UDP", "type": "hysteria2", "server": "alive-udp.example", "port": 443},
                {"name": "🇯🇵 死节点", "type": "trojan", "server": "dead.example",
                 "port": 443, "password": "x"},
            ],
            "proxy-groups": [
                {"name": "🔰 手动选择", "type": "select",
                 "proxies": ["🇺🇸 存活HTTP 2MB/s", "🇸🇬 存活UDP", "🇯🇵 死节点"]},
                {"name": "🇺🇸 美国自动", "type": "url-test", "proxies": ["🇺🇸 存活HTTP 2MB/s"]},
            ],
        }
        singbox_doc = {
            "outbounds": [
                {"type": "http", "tag": "sb-alive", "server": "alive.example", "server_port": 8080},
                {"type": "hysteria2", "tag": "sb-alive-udp", "server": "alive-udp.example",
                 "server_port": 443},
                {"type": "trojan", "tag": "sb-dead", "server": "dead.example", "server_port": 443},
                {"type": "direct", "tag": "direct"},
            ]
        }
        v2ray_text = (
            "https://alive.example:8080#alive-http\n"
            "hy2://pw@alive-udp.example:443?sni=x#alive-udp\n"
            "trojan://pw@dead.example:443?sni=y#dead\n"
        )
        (input_dir / "clash.yaml").write_text(json.dumps(clash_doc, ensure_ascii=False), encoding="utf-8")
        (input_dir / "singbox.json").write_text(json.dumps(singbox_doc, ensure_ascii=False), encoding="utf-8")
        (input_dir / "v2ray.txt").write_text(v2ray_text, encoding="utf-8")
        return input_dir

    def test_full_pipeline_aggregates_alive_across_formats(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_dir = self._write_input(root)
            output_dir = root / "alive"
            state_path = output_dir / "state.json"

            meta = mihomo_check.run_alive_check(
                input_dir, output_dir, state_path, "/nonexistent-mihomo",
                prefilter_timeout=0, proc_factory=lambda: _FakeMihomoProcess(
                    delay_of={"🇺🇸 存活HTTP 2MB/s": 120, "🇸🇬 存活UDP": 250},
                ),
            )
            self.assertEqual(meta["node_status_counts"]["clash"]["kept"], 2)
            self.assertEqual(meta["node_status_counts"]["clash"]["failed"], 1)
            self.assertEqual(meta["alive_unique_keys"], 2)
            self.assertEqual(meta["alive_delay_ms"]["min"], 120)

            live_clash = health.yaml.safe_load((output_dir / "clash.yaml").read_text(encoding="utf-8"))
            self.assertEqual(
                sorted(p["name"] for p in live_clash["proxies"]),
                sorted(["🇺🇸 存活HTTP 2MB/s", "🇸🇬 存活UDP"]),
            )
            self.assertEqual(live_clash["proxy-groups"][0]["proxies"],
                             ["🇺🇸 存活HTTP 2MB/s", "🇸🇬 存活UDP"])
            self.assertEqual(live_clash["proxy-groups"][1]["proxies"], ["🇺🇸 存活HTTP 2MB/s"])

            live_singbox = json.loads((output_dir / "singbox.json").read_text(encoding="utf-8"))
            self.assertEqual([o["tag"] for o in live_singbox["outbounds"]],
                             ["sb-alive", "sb-alive-udp", "direct"])

            live_v2ray = (output_dir / "v2ray.txt").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(live_v2ray), 2)
            self.assertTrue(all("dead.example" not in line for line in live_v2ray))

            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["version"], 2)
            self.assertEqual(len(state["nodes"]), 3)
            dead_record = state["nodes"]["dead.example|443|trojan"]
            self.assertEqual(dead_record["last_status"], "failed")
            self.assertEqual(dead_record["failure_count"], 1)
            alive_record = state["nodes"]["alive.example|8080|http"]
            self.assertEqual(alive_record["last_status"], "passed")
            self.assertEqual(alive_record["last_delay_ms"], 120)

            # 第二轮：原本存活的 HTTP 节点失联 → 严格判活，立即从聚合中移除
            meta2 = mihomo_check.run_alive_check(
                input_dir, output_dir, state_path, "/nonexistent-mihomo",
                prefilter_timeout=0, proc_factory=lambda: _FakeMihomoProcess(
                    delay_of={"🇸🇬 存活UDP": 260},
                ),
            )
            self.assertEqual(meta2["node_status_counts"]["clash"]["kept"], 1)
            live_clash2 = health.yaml.safe_load((output_dir / "clash.yaml").read_text(encoding="utf-8"))
            self.assertEqual([p["name"] for p in live_clash2["proxies"]], ["🇸🇬 存活UDP"])
            state2 = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state2["nodes"]["alive.example|8080|http"]["failure_count"], 1)
            self.assertEqual(state2["nodes"]["alive.example|8080|http"]["success_count"], 1)
            self.assertEqual(state2["nodes"]["alive.example|8080|http"]["best_delay_ms"], 120)

    def test_state_v1_is_reset_to_v2(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_dir = self._write_input(root)
            output_dir = root / "alive"
            state_path = output_dir / "state.json"
            output_dir.mkdir(parents=True, exist_ok=True)
            state_path.write_text(json.dumps({
                "version": 1,
                "endpoints": {"abc": {"host": "old.example", "last_status": "passed"}},
            }), encoding="utf-8")

            meta = mihomo_check.run_alive_check(
                input_dir, output_dir, state_path, "/nonexistent-mihomo",
                prefilter_timeout=0, proc_factory=lambda: _FakeMihomoProcess(
                    delay_of={"🇺🇸 存活HTTP 2MB/s": 120, "🇸🇬 存活UDP": 250},
                ),
            )
            self.assertEqual(meta["node_status_counts"]["clash"]["kept"], 2)
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["version"], 2)
            self.assertIn("nodes", state)
            self.assertNotIn("endpoints", state)

    def test_tcp_prefilter_gates_candidates_before_mihomo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_dir = root / "merged"
            input_dir.mkdir(parents=True)
            clash_doc = {
                "proxies": [
                    {"name": "A", "type": "http", "server": "alive.example", "port": 80},
                    {"name": "B", "type": "http", "server": "alive.example", "port": 80},
                    {"name": "C", "type": "http", "server": "dead.example", "port": 81},
                    {"name": "U", "type": "hysteria2", "server": "udp.example", "port": 443},
                ]
            }
            (input_dir / "clash.yaml").write_text(json.dumps(clash_doc, ensure_ascii=False), encoding="utf-8")

            async def pass_alive_only(endpoints, timeout, concurrency):
                return {
                    ep.endpoint_id: {
                        "status": "passed" if ep.host == "alive.example" else "failed",
                        "latency_ms": 1.0, "error": "",
                    }
                    for ep in endpoints
                }

            fake = _FakeMihomoProcess(delay_of={"A": 50, "B": 60, "U": 70})
            with patch.object(mihomo_check, "probe_all", new=pass_alive_only):
                meta = mihomo_check.run_alive_check(
                    input_dir, root / "alive", root / "alive" / "state.json",
                    "/nonexistent-mihomo",
                    prefilter_timeout=1, proc_factory=lambda: fake,
                )
            # UDP 节点与 TCP 可达候选进入实测；C 被预筛剔除
            self.assertEqual(sorted(fake.loaded_names), ["A", "B", "U"])
            self.assertEqual(meta["node_status_counts"]["clash"]["kept"], 3)
            self.assertEqual(meta["node_status_counts"]["clash"]["prefilter_dropped"], 1)
            self.assertEqual(meta["prefilter"]["endpoints_passed"], 1)
            self.assertEqual(meta["prefilter"]["endpoints_failed"], 1)

    def test_scope_daily_limits_candidates_to_daily_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_dir = root / "merged"
            daily_dir = root / "daily"
            input_dir.mkdir(parents=True)
            daily_dir.mkdir(parents=True)
            merged_doc = {
                "proxies": [
                    {"name": "🇺🇸 今日", "type": "http", "server": "today.example", "port": 80},
                    {"name": "🇯🇵 历史", "type": "http", "server": "old.example", "port": 81},
                ]
            }
            daily_doc = {"proxies": [{"name": "🇺🇸 今日", "type": "http",
                                      "server": "today.example", "port": 80}]}
            (input_dir / "clash.yaml").write_text(json.dumps(merged_doc, ensure_ascii=False), encoding="utf-8")
            (daily_dir / "clash.yaml").write_text(json.dumps(daily_doc, ensure_ascii=False), encoding="utf-8")

            fake = _FakeMihomoProcess(delay_of={"🇺🇸 今日": 40, "🇯🇵 历史": 41})
            meta = mihomo_check.run_alive_check(
                input_dir, root / "alive", root / "alive" / "state.json",
                "/nonexistent-mihomo", daily_dir=daily_dir, scope="daily",
                prefilter_timeout=0, proc_factory=lambda: fake,
            )
            self.assertEqual(fake.loaded_names, ["🇺🇸 今日"])
            self.assertEqual(meta["clash_candidates"]["scope_filtered_out"], 1)
            live = health.yaml.safe_load((root / "alive" / "clash.yaml").read_text(encoding="utf-8"))
            self.assertEqual([p["name"] for p in live["proxies"]], ["🇺🇸 今日"])

    def test_step_summary_written_when_github_env_set(self):
        """回归测试：GITHUB_STEP_SUMMARY 只在 Actions 上存在，本地没有——
        曾经导致 summary 分支从未被单测覆盖，clash 格式 KeyError 'dropped' 只在 runner 上爆。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_dir = self._write_input(root)
            output_dir = root / "alive"
            summary_path = root / "step_summary.md"

            with patch.dict(mihomo_check.os.environ, {"GITHUB_STEP_SUMMARY": str(summary_path)}):
                mihomo_check.run_alive_check(
                    input_dir, output_dir, output_dir / "state.json", "/nonexistent-mihomo",
                    prefilter_timeout=0, proc_factory=lambda: _FakeMihomoProcess(
                        delay_of={"🇺🇸 存活HTTP 2MB/s": 120, "🇸🇬 存活UDP": 250},
                    ),
                )

            text = summary_path.read_text(encoding="utf-8")
            for fmt in ("clash", "singbox", "v2ray"):
                self.assertIn(f"**{fmt}**", text, f"summary 缺少 {fmt} 行：\n{text}")
            # clash：3 候选 - 2 存活 = 剔除 1（预筛 0 + 实测失败 1 + 加载失败 0）
            self.assertIn("- **clash**：保留 `2` / 剔除 `1`", text)
            self.assertIn("- **singbox**：保留 `2` / 配置骨架 `1` / 剔除 `1`", text)
            self.assertIn("- **v2ray**：保留 `2` / 剔除 `1`", text)


class YamlAmbiguityQuotingTests(unittest.TestCase):
    """go-yaml（mihomo 的解析器）会把未加引号的数字样式字符串解析成数字，
    一个 `short-id: 71150e37` 就能让整个配置被拒载。防御：写出时强制加引号。"""

    def test_needs_go_quote_detection(self):
        poison = [
            "71150e37", "681e6419", "7294", "76394756",  # 真实数据样本
            "1e5", ".5", "+123", "-42", "0x1F", "0o17", "1_000",
            "true", "on", "yes", "null", "~", "2026-09-27",
        ]
        for value in poison:
            self.assertTrue(mihomo_check._needs_go_quote(value), value)
        safe = [
            "aOfVRBN3tfHAXKY4-8SdNb0hsxY2LhaiIyTfkPXLiks",  # reality public-key
            "chrome", "0c", "0c30407d", "71150e3z", "ws", "aes-256-gcm", "h2", "US001 节点",
            "202d6dd6-77af-45ee-99db-82ea75758340", "k0g3h.biliimg.com",
        ]
        for value in safe:
            self.assertFalse(mihomo_check._needs_go_quote(value), value)

    def test_mihomo_config_quotes_ambiguous_scalars(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = mihomo_check.MihomoProcess("/nonexistent", Path(tmp), api_port=19099, secret="s")
            proc.write_config([{
                "name": "n", "type": "vless", "server": "a.example", "port": 443,
                "reality-opts": {"public-key": "pubKEY123", "short-id": "71150e37"},
                "password": "666",
            }])
            text = proc.config_path.read_text(encoding="utf-8")
            self.assertIn("short-id: '71150e37'", text)
            self.assertIn("password: '666'", text)
            self.assertIn("server: a.example", text)  # 普通字符串保持不加引号

    def test_alive_and_merge_outputs_quote_ambiguous_scalars(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_dir = root / "merged"
            input_dir.mkdir(parents=True)
            clash_doc = {"proxies": [{
                "name": "🇭🇰 HK 毒short-id", "type": "vless", "server": "hk.example", "port": 443,
                "uuid": "u", "tls": True,
                "reality-opts": {"public-key": "p", "short-id": "71150e37"},
            }]}
            (input_dir / "clash.yaml").write_text(
                json.dumps(clash_doc, ensure_ascii=False), encoding="utf-8")
            meta = mihomo_check.run_alive_check(
                input_dir, root / "alive", root / "alive" / "state.json", "/nonexistent-mihomo",
                prefilter_timeout=0,
                proc_factory=lambda: _FakeMihomoProcess(delay_of={"🇭🇰 HK 毒short-id": 88}),
            )
            self.assertEqual(meta["node_status_counts"]["clash"]["kept"], 1)
            alive_text = (root / "alive" / "clash.yaml").read_text(encoding="utf-8")
            self.assertIn("short-id: '71150e37'", alive_text)

        # merge 输出同样必须可被 go-yaml 加载
        out = health.yaml.dump(
            clash_doc, Dumper=merge.ClashSafeDumper, allow_unicode=True,
            sort_keys=False, default_flow_style=False, width=4096,
        )
        self.assertIn("short-id: '71150e37'", out)

    def test_merge_normalizes_http_opts_headers(self):
        doc = {"proxies": [
            {"name": "a", "type": "vmess", "server": "s", "port": 1, "network": "http",
             "http-opts": {"path": ["/"], "headers": {"Host": "https://x.com"}}},
            {"name": "b", "type": "vmess", "server": "s2", "port": 2, "network": "http",
             "http-opts": {"headers": {"Host": ["ok.com"], "X-Null": None}}},
        ]}
        merge.normalize_clash_http_opts(doc)
        self.assertEqual(doc["proxies"][0]["http-opts"]["headers"],
                         {"Host": ["https://x.com"]})
        self.assertEqual(doc["proxies"][1]["http-opts"]["headers"],
                         {"Host": ["ok.com"]})


class CircuitBreakerTests(unittest.TestCase):
    @staticmethod
    def _make(name, host):
        endpoint = health.make_endpoint(host, 443, False)
        return mihomo_check.Candidate(
            name=name, protocol="http", host=endpoint.host, port=endpoint.port,
            endpoint_id=endpoint.endpoint_id,
            proxy={"name": name, "type": "http", "server": host, "port": 443},
            udp=False,
        )

    def test_dead_kernel_aborts_with_runtime_error(self):
        class DeadKernel:
            def __init__(self):
                self.stopped = False

            def start(self, proxies):
                return False

            def stop(self):
                self.stopped = True

            def log_tail(self, lines=15):
                return ""

        candidates = [self._make(f"n{i}", f"h{i}.example") for i in range(8)]
        with self.assertRaises(RuntimeError):
            mihomo_check.run_real_test(
                lambda: DeadKernel(), candidates, "http://x/generate_204", 3000, 4, 0,
            )

    def test_many_bad_nodes_are_isolated_without_tripping_breaker(self):
        # 10 个坏节点散布在 90 个好节点中：全部定位剔除，不触发熔断（旧版累计计数会误杀）
        bad_positions = {3, 13, 23, 33, 43, 53, 63, 73, 83, 93}
        candidates, bad_names, good_names = [], set(), set()
        b = 0
        for i in range(100):
            if i in bad_positions:
                name = f"bad{b}"
                b += 1
                bad_names.add(name)
            else:
                name = f"good{i}"
                good_names.add(name)
            candidates.append(self._make(name, f"h{i}.example"))
        results, bad = mihomo_check.run_real_test(
            lambda: _FakeMihomoProcess(
                fail_start_names=bad_names,
                delay_of={n: 50 for n in good_names},
            ),
            candidates, "http://x/generate_204", 3000, 4, 0,
        )
        self.assertEqual(len(bad), 10)
        self.assertEqual({c.name for c in bad}, bad_names)
        self.assertEqual(len(results), 90)
        self.assertTrue(all(r["ok"] for r in results.values()))


if __name__ == "__main__":
    unittest.main()
