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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import fetch_jcnode  # noqa: E402
import healthcheck_subscriptions as health  # noqa: E402
import merge_subscriptions as merge  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
