#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""全量 TCP/TLS 握手检测，并生成只含近期通过节点的存活订阅。

注意：这里只建立 TCP 连接或完成 TLS ClientHello/握手，不发送代理认证信息，
也不发起完整代理请求。Hysteria、TUIC、QUIC、Reality 等不能由此方式验证，
会单独标为 unsupported，绝不误记为通过。
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import ssl
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

try:
    import yaml
except ImportError as exc:  # pragma: no cover - Actions 会安装 PyYAML
    raise SystemExit("缺少 PyYAML，请先运行：python -m pip install PyYAML") from exc

try:
    from merge_subscriptions import (
        NoAliasDumper,
        SPECIAL_PROXY_REFS,
        atomic_write,
        leading_country_flag,
        proxy_name,
    )
except ImportError as exc:  # pragma: no cover
    raise SystemExit("请从仓库根目录运行，或确保 scripts/ 在 Python 搜索路径中") from exc


FORMATS = ("clash", "singbox", "v2ray")
STATUS_NAMES = ("passed", "retained", "stale", "failed", "untested", "unsupported")
UDP_PROTOCOLS = {
    "hysteria",
    "hysteria2",
    "hy2",
    "tuic",
    "wireguard",
    "wireguard-go",
    "wg",
}
UDP_NETWORKS = {"udp", "quic", "quic-go"}
CLASH_TCP_PROTOCOLS = {
    "http", "https", "socks", "socks4", "socks5", "ss", "shadowsocks",
    "shadowsocksr", "ssr", "vmess", "vless", "trojan", "anytls", "ssh",
    "mieru", "snell", "shadowtls",
}
SINGBOX_TCP_PROTOCOLS = {
    "http", "socks", "shadowsocks", "shadowsocksr", "vmess", "vless",
    "trojan", "anytls", "ssh", "mieru", "shadowtls", "ssr",
}
V2RAY_TCP_SCHEMES = {
    "http", "https", "socks", "socks4", "socks5", "ss", "shadowsocks",
    "shadowsocksr", "ssr", "vmess", "vmess1", "vless", "trojan", "anytls",
}
SINGBOX_AUX_TYPES = {"direct", "block", "dns", "selector", "urltest", "url-test", "reject"}


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    tls: bool
    sni: str = ""

    @property
    def endpoint_id(self) -> str:
        payload = json.dumps(
            [self.host, self.port, self.tls, self.sni],
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class NodeRef:
    format: str
    index: int
    name: str
    endpoint: Endpoint | None
    hint: str | None = None
    reason: str | None = None
    keep_without_probe: bool = False


def _truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().lower() in {"true", "yes", "1", "tls", "enabled"}


def _normal_host(value) -> str | None:
    if value is None:
        return None
    host = str(value).strip()
    if len(host) >= 2 and host[0] == "[" and host[-1] == "]":
        host = host[1:-1]
    host = host.rstrip(".")
    if not host or any(ch.isspace() for ch in host) or "/" in host:
        return None
    if ":" not in host:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    return host.lower()


def _normal_sni(value) -> str:
    if value is None or not str(value).strip():
        return ""
    sni = str(value).strip().rstrip(".")
    if ":" not in sni:
        try:
            sni = sni.encode("idna").decode("ascii")
        except UnicodeError:
            return ""
    return sni.lower()


def make_endpoint(host, port, tls: bool, sni=None) -> Endpoint | None:
    normalized_host = _normal_host(host)
    try:
        normalized_port = int(port)
    except (TypeError, ValueError):
        return None
    if normalized_host is None or not 1 <= normalized_port <= 65535:
        return None

    normalized_sni = _normal_sni(sni) if tls else ""
    if tls and not normalized_sni:
        try:
            ipaddress.ip_address(normalized_host.split("%", 1)[0])
        except ValueError:
            normalized_sni = normalized_host
    return Endpoint(normalized_host, normalized_port, bool(tls), normalized_sni)


def _is_reality(value) -> bool:
    if not isinstance(value, dict):
        return False
    reality = value.get("reality")
    return _truthy(reality.get("enabled")) if isinstance(reality, dict) else _truthy(reality)


def _unsupported(reason: str) -> tuple[None, str, str]:
    return None, "unsupported", reason


def _untested(reason: str) -> tuple[None, str, str]:
    return None, "untested", reason


def parse_clash_node(node) -> tuple[Endpoint | None, str | None, str | None]:
    if not isinstance(node, dict):
        return _untested("invalid_node")
    protocol = str(node.get("type", "")).strip().lower()
    network = str(node.get("network", "")).strip().lower()
    if protocol in UDP_PROTOCOLS or network in UDP_NETWORKS:
        return _unsupported("udp_or_quic")
    if protocol not in CLASH_TCP_PROTOCOLS:
        return _unsupported("unsupported_protocol")

    tls_options = node.get("tls")
    if node.get("reality-opts") or _is_reality(tls_options):
        return _unsupported("reality_requires_special_client")
    tls_enabled = protocol in {"trojan", "anytls", "shadowtls"} or _truthy(tls_options)
    endpoint = make_endpoint(
        node.get("server"),
        node.get("port"),
        tls_enabled,
        node.get("sni") or node.get("servername"),
    )
    if endpoint is None:
        return _untested("invalid_endpoint")
    return endpoint, None, None


def parse_singbox_node(node) -> tuple[Endpoint | None, str | None, str | None, bool]:
    if not isinstance(node, dict):
        endpoint, hint, reason = _untested("invalid_node")
        return endpoint, hint, reason, False
    protocol = str(node.get("type", "")).strip().lower()
    if protocol in SINGBOX_AUX_TYPES:
        endpoint, hint, reason = _untested("non_proxy_outbound")
        return endpoint, hint, reason, True

    transport = node.get("transport") if isinstance(node.get("transport"), dict) else {}
    network = str(transport.get("type", node.get("network", ""))).strip().lower()
    if protocol in UDP_PROTOCOLS or network in UDP_NETWORKS:
        endpoint, hint, reason = _unsupported("udp_or_quic")
        return endpoint, hint, reason, False
    if protocol not in SINGBOX_TCP_PROTOCOLS:
        endpoint, hint, reason = _unsupported("unsupported_protocol")
        return endpoint, hint, reason, False

    tls_options = node.get("tls") if isinstance(node.get("tls"), dict) else {}
    if _is_reality(tls_options):
        endpoint, hint, reason = _unsupported("reality_requires_special_client")
        return endpoint, hint, reason, False
    tls_enabled = protocol in {"trojan", "anytls", "shadowtls"} or _truthy(tls_options.get("enabled"))
    endpoint = make_endpoint(
        node.get("server"),
        node.get("server_port", node.get("port")),
        tls_enabled,
        tls_options.get("server_name") or tls_options.get("serverName"),
    )
    if endpoint is None:
        endpoint, hint, reason = _untested("invalid_endpoint")
        return endpoint, hint, reason, False
    return endpoint, None, None, False


def _decode_base64_text(value: str) -> str | None:
    clean = str(value).strip()
    clean += "=" * (-len(clean) % 4)
    try:
        return base64.urlsafe_b64decode(clean.encode("ascii")).decode("utf-8", "strict")
    except (ValueError, UnicodeError, base64.binascii.Error):
        return None


def _query_first(query: dict[str, list[str]], *keys: str) -> str:
    for key in keys:
        values = query.get(key) or query.get(key.lower())
        if values and values[0]:
            return str(values[0])
    return ""


def _parse_vmess(parsed) -> tuple[Endpoint | None, str | None, str | None]:
    blob = parsed.netloc or parsed.path
    payload = _decode_base64_text(blob)
    if payload is None:
        return _untested("invalid_vmess_payload")
    try:
        node = json.loads(payload)
    except json.JSONDecodeError:
        return _untested("invalid_vmess_payload")
    if not isinstance(node, dict):
        return _untested("invalid_vmess_payload")

    network = str(node.get("net", node.get("network", ""))).strip().lower()
    if network in UDP_NETWORKS:
        return _unsupported("udp_or_quic")
    security = str(node.get("security", "")).strip().lower()
    if security == "reality" or _truthy(node.get("reality")):
        return _unsupported("reality_requires_special_client")
    tls_enabled = str(node.get("tls", "")).strip().lower() in {"tls", "true", "1", "yes"}
    endpoint = make_endpoint(
        node.get("add", node.get("addr")),
        node.get("port"),
        tls_enabled,
        node.get("sni") or node.get("serverName") or (node.get("host") if tls_enabled else None),
    )
    if endpoint is None:
        return _untested("invalid_endpoint")
    return endpoint, None, None


def _parse_ss_base64(parsed) -> tuple[str | None, int | None]:
    """解析旧式 ss://base64(method:password@host:port) 链接的服务端地址。"""
    blob = parsed.netloc or parsed.path
    decoded = _decode_base64_text(blob)
    if not decoded or "@" not in decoded:
        return None, None
    address = decoded.rsplit("@", 1)[1]
    try:
        address_url = urlsplit("ss://" + address)
        return address_url.hostname, address_url.port
    except ValueError:
        return None, None


def parse_v2ray_line(line: str) -> tuple[Endpoint | None, str | None, str | None]:
    value = line.strip()
    if "://" not in value:
        return _untested("invalid_uri")
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
    except ValueError:
        return _untested("invalid_uri")

    if scheme in UDP_PROTOCOLS:
        return _unsupported("udp_or_quic")
    if scheme in {"vmess", "vmess1"}:
        return _parse_vmess(parsed)
    if scheme not in V2RAY_TCP_SCHEMES:
        return _unsupported("unsupported_protocol")

    try:
        host, port = parsed.hostname, parsed.port
    except ValueError:
        return _untested("invalid_endpoint")
    if scheme in {"ss", "shadowsocks"} and (not host or port is None):
        host, port = _parse_ss_base64(parsed)

    query = parse_qs(parsed.query, keep_blank_values=True)
    security = _query_first(query, "security", "tls").strip().lower()
    network = _query_first(query, "type", "network", "net").strip().lower()
    if network in UDP_NETWORKS:
        return _unsupported("udp_or_quic")
    if security == "reality":
        return _unsupported("reality_requires_special_client")

    tls_enabled = scheme in {"https", "trojan", "anytls"} or security in {"tls", "true", "1"}
    sni = _query_first(query, "sni", "peer", "servername", "serverName", "tlsHost")
    endpoint = make_endpoint(host, port, tls_enabled, sni)
    if endpoint is None:
        return _untested("invalid_endpoint")
    return endpoint, None, None


def _entry_name(fmt: str, item, index: int) -> str:
    if fmt == "clash" and isinstance(item, dict):
        return proxy_name(item)
    if fmt == "singbox" and isinstance(item, dict):
        return str(item.get("tag") or f"outbound-{index + 1}")
    if fmt == "v2ray":
        try:
            return unquote(urlsplit(str(item)).fragment) or f"v2ray-{index + 1}"
        except ValueError:
            return f"v2ray-{index + 1}"
    return f"{fmt}-{index + 1}"


def load_subscriptions(input_dir: Path) -> tuple[dict, list[NodeRef]]:
    docs: dict[str, object] = {}
    entries: list[NodeRef] = []

    clash_path = input_dir / "clash.yaml"
    if clash_path.exists():
        doc = yaml.safe_load(clash_path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            raise ValueError(f"{clash_path} 不是 YAML 对象")
        docs["clash"] = doc
        proxies = doc.get("proxies") or []
        if not isinstance(proxies, list):
            raise ValueError(f"{clash_path} 的 proxies 必须是列表")
        for index, item in enumerate(proxies):
            endpoint, hint, reason = parse_clash_node(item)
            entries.append(NodeRef("clash", index, _entry_name("clash", item, index), endpoint, hint, reason))

    singbox_path = input_dir / "singbox.json"
    if singbox_path.exists():
        doc = json.loads(singbox_path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            raise ValueError(f"{singbox_path} 不是 JSON 对象")
        docs["singbox"] = doc
        outbounds = doc.get("outbounds") or []
        if not isinstance(outbounds, list):
            raise ValueError(f"{singbox_path} 的 outbounds 必须是列表")
        for index, item in enumerate(outbounds):
            endpoint, hint, reason, keep = parse_singbox_node(item)
            entries.append(
                NodeRef("singbox", index, _entry_name("singbox", item, index), endpoint, hint, reason, keep)
            )

    v2ray_path = input_dir / "v2ray.txt"
    if v2ray_path.exists():
        lines = [line.strip() for line in v2ray_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        docs["v2ray"] = lines
        for index, line in enumerate(lines):
            endpoint, hint, reason = parse_v2ray_line(line)
            entries.append(NodeRef("v2ray", index, _entry_name("v2ray", line, index), endpoint, hint, reason))

    if not docs:
        raise ValueError(f"{input_dir} 中没有 clash.yaml、singbox.json 或 v2ray.txt")
    return docs, entries


async def probe_endpoint(endpoint: Endpoint, timeout: float) -> dict:
    """只连 TCP 或完成 TLS 握手，不发送任何代理协议/认证数据。"""
    started = time.monotonic()
    writer = None
    try:
        ssl_context = None
        server_hostname = None
        if endpoint.tls:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            server_hostname = endpoint.sni or None
            if server_hostname:
                try:
                    ipaddress.ip_address(server_hostname.split("%", 1)[0])
                    server_hostname = None
                except ValueError:
                    pass

        kwargs = {}
        if ssl_context is not None:
            kwargs.update(
                ssl=ssl_context,
                server_hostname=server_hostname,
                ssl_handshake_timeout=timeout,
            )
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(endpoint.host, endpoint.port, **kwargs),
            timeout=timeout,
        )
        latency_ms = round((time.monotonic() - started) * 1000, 1)
        return {
            "status": "passed",
            "latency_ms": latency_ms,
            "error": "",
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        return {
            "status": "failed",
            "latency_ms": round((time.monotonic() - started) * 1000, 1),
            "error": type(exc).__name__,
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.25)
            except Exception:
                pass


async def probe_all(endpoints: list[Endpoint], timeout: float, concurrency: int) -> dict[str, dict]:
    semaphore = asyncio.Semaphore(concurrency)

    async def one(endpoint: Endpoint):
        async with semaphore:
            return endpoint.endpoint_id, await probe_endpoint(endpoint, timeout)

    results: dict[str, dict] = {}
    batch_size = max(concurrency * 8, concurrency)
    for start in range(0, len(endpoints), batch_size):
        batch = endpoints[start : start + batch_size]
        batch_results = await asyncio.gather(*(one(endpoint) for endpoint in batch))
        results.update(batch_results)
        completed = min(start + len(batch), len(endpoints))
        print(f"  TCP/TLS 进度：{completed}/{len(endpoints)}")
    return results


def _load_state(path: Path) -> dict:
    if not path.exists() or path.stat().st_size == 0:
        return {"version": 1, "endpoints": {}}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("endpoints"), dict):
        raise ValueError(f"存活状态库格式无效：{path}；为避免覆盖，已停止")
    return value


def _parse_timestamp(value) -> datetime | None:
    if not value:
        return None
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)
        return result.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _recent_success(record: dict, now: datetime, retention_hours: float) -> bool:
    last_success = _parse_timestamp(record.get("last_success_at"))
    if last_success is None or retention_hours <= 0:
        return False
    return now - last_success <= timedelta(hours=retention_hours)


def _update_state(
    state: dict,
    endpoints: list[Endpoint],
    results: dict[str, dict],
    now: datetime,
    labels_by_endpoint: dict[str, dict] | None = None,
) -> None:
    records = state.setdefault("endpoints", {})
    stamp = now.isoformat(timespec="seconds")
    for endpoint in endpoints:
        endpoint_id = endpoint.endpoint_id
        result = results[endpoint_id]
        checked_at = result.get("checked_at") or stamp
        record = records.setdefault(endpoint_id, {})
        record.update(
            {
                "host": endpoint.host,
                "port": endpoint.port,
                "tls": endpoint.tls,
                "sni": endpoint.sni,
                "first_seen_at": record.get("first_seen_at", checked_at),
                "last_seen_at": checked_at,
                "last_test_at": checked_at,
                "last_status": result["status"],
                "last_latency_ms": result.get("latency_ms"),
                "last_error": result.get("error", ""),
            }
        )
        labels = (labels_by_endpoint or {}).get(endpoint_id)
        if labels:
            names = sorted(labels.get("names", set()))
            record["formats"] = sorted(labels.get("formats", set()))
            record["node_name_count"] = len(names)
            record["node_names"] = names[:50]
        if result["status"] == "passed":
            record["last_success_at"] = checked_at
            record["success_count"] = int(record.get("success_count", 0)) + 1
            record["consecutive_failures"] = 0
        else:
            record["last_failure_at"] = checked_at
            record["failure_count"] = int(record.get("failure_count", 0)) + 1
            record["consecutive_failures"] = int(record.get("consecutive_failures", 0)) + 1
    state["version"] = 1
    state["updated_at"] = stamp
    state["probe_method"] = "TCP connect / TLS handshake only; no proxy authentication or traffic"


def _filter_clash_groups(doc: dict, live_proxies: list[dict]) -> None:
    groups = doc.get("proxy-groups")
    if not isinstance(groups, list):
        return
    names = [proxy_name(node) for node in live_proxies if isinstance(node, dict)]
    name_set = set(names)
    group_names = {
        str(group.get("name"))
        for group in groups
        if isinstance(group, dict) and group.get("name") is not None
    }
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("proxies"), list):
            continue
        group_name = str(group.get("name", ""))
        refs = group["proxies"]
        if "手动选择" in group_name or "自动选择" in group_name:
            group["proxies"] = list(names)
            continue
        flag = leading_country_flag(group_name)
        if flag:
            regional = [name for name in names if leading_country_flag(name) == flag]
            group["proxies"] = regional or [str(ref) for ref in refs if str(ref) in SPECIAL_PROXY_REFS]
            continue
        kept: list[str] = []
        for ref in refs:
            value = str(ref)
            if value in name_set or value in group_names or value in SPECIAL_PROXY_REFS:
                if value not in kept:
                    kept.append(value)
        group["proxies"] = kept


def _node_status(
    entry: NodeRef,
    state: dict,
    results: dict[str, dict],
    now: datetime,
    retention_hours: float,
) -> str:
    if entry.hint:
        return entry.hint
    assert entry.endpoint is not None
    endpoint_id = entry.endpoint.endpoint_id
    record = state.get("endpoints", {}).get(endpoint_id, {})

    if endpoint_id in results:
        result = results[endpoint_id]
        if result["status"] == "passed":
            return "passed"
        return "retained" if _recent_success(record, now, retention_hours) else "failed"

    # 非当日节点本轮不会被探测。其上次通过状态标为 stale 而非本次通过；
    # 若上次记录是失败，则仅在最近成功仍处于保留窗口时继续保留。
    if not record:
        return "untested"
    last_status = record.get("last_status")
    if last_status == "passed":
        return "stale"
    if last_status == "failed":
        return "retained" if _recent_success(record, now, retention_hours) else "failed"
    if record.get("last_success_at"):
        return "stale"
    return "untested"


def run_healthcheck(
    input_dir: Path,
    output_dir: Path,
    state_path: Path,
    timeout: float = 3.0,
    concurrency: int = 64,
    retention_hours: float = 24.0,
    dry_run: bool = False,
    daily_dir: Path | None = None,
) -> dict:
    if timeout <= 0:
        raise ValueError("--timeout 必须大于 0")
    if concurrency < 1 or concurrency > 512:
        raise ValueError("--concurrency 必须在 1 到 512 之间")
    if retention_hours < 0:
        raise ValueError("--retention-hours 不能小于 0")

    all_docs, all_entries = load_subscriptions(input_dir)
    daily_dir = Path(daily_dir) if daily_dir is not None else input_dir
    if daily_dir.resolve() == input_dir.resolve():
        daily_entries = all_entries
    else:
        _, daily_entries = load_subscriptions(daily_dir)

    state = _load_state(state_path)
    bootstrap_completed = bool(state.get("bootstrap_full_completed"))
    probe_scope = "daily_only" if bootstrap_completed else "full_history_bootstrap"
    probe_entries = daily_entries if bootstrap_completed else all_entries

    endpoints_by_id: dict[str, Endpoint] = {}
    all_format_total = {fmt: 0 for fmt in FORMATS}
    probe_format_total = {fmt: 0 for fmt in FORMATS}
    format_supported = {fmt: 0 for fmt in FORMATS}
    for entry in all_entries:
        all_format_total[entry.format] += 1
    for entry in probe_entries:
        probe_format_total[entry.format] += 1
        if entry.endpoint is not None and entry.hint is None:
            format_supported[entry.format] += 1
            endpoints_by_id.setdefault(entry.endpoint.endpoint_id, entry.endpoint)

    endpoints = list(endpoints_by_id.values())
    scope_label = "全历史首次检测" if probe_scope == "full_history_bootstrap" else "仅当日数据"
    print(
        f"检测范围：{scope_label}；全库条目 {len(all_entries)} 条；"
        f"本次候选 {len(probe_entries)} 条；唯一 TCP/TLS 端点 {len(endpoints)} 个；"
        f"timeout={timeout:g}s concurrency={concurrency}"
    )
    if dry_run:
        hint_counts = {fmt: {"unsupported": 0, "untested": 0} for fmt in FORMATS}
        for entry in probe_entries:
            if entry.hint in hint_counts[entry.format]:
                hint_counts[entry.format][entry.hint] += 1
        print("Dry-run：未发起任何网络连接。")
        for fmt in FORMATS:
            print(
                f"  {fmt}: 本次条目 {probe_format_total[fmt]}，全库 {all_format_total[fmt]}，"
                f"可探测 {format_supported[fmt]}，未测试 {hint_counts[fmt]['untested']}，"
                f"不支持 {hint_counts[fmt]['unsupported']}"
            )
        return {
            "dry_run": True,
            "probe_scope": probe_scope,
            "all_nodes": all_format_total,
            "probe_nodes": probe_format_total,
            "unique_endpoints": len(endpoints),
        }

    labels_by_endpoint: dict[str, dict[str, set[str]]] = {}
    for entry in probe_entries:
        if entry.endpoint is None or entry.hint is not None:
            continue
        labels = labels_by_endpoint.setdefault(
            entry.endpoint.endpoint_id, {"formats": set(), "names": set()}
        )
        labels["formats"].add(entry.format)
        labels["names"].add(entry.name)

    results = asyncio.run(probe_all(endpoints, timeout, concurrency))
    now = datetime.now(timezone.utc)
    _update_state(state, endpoints, results, now, labels_by_endpoint)
    if not bootstrap_completed:
        state["bootstrap_full_completed"] = True
        state["bootstrap_full_completed_at"] = now.isoformat(timespec="seconds")
    state["last_probe_scope"] = probe_scope
    state["last_probe_at"] = now.isoformat(timespec="seconds")

    counts = {fmt: {status: 0 for status in STATUS_NAMES} for fmt in FORMATS}
    reason_counts = {fmt: {"untested": {}, "unsupported": {}} for fmt in FORMATS}
    live_indices = {fmt: set() for fmt in FORMATS}
    for entry in all_entries:
        status = _node_status(entry, state, results, now, retention_hours)
        counts[entry.format][status] += 1
        if entry.hint in reason_counts[entry.format] and entry.reason:
            bucket = reason_counts[entry.format][entry.hint]
            bucket[entry.reason] = bucket.get(entry.reason, 0) + 1
        if status in {"passed", "retained", "stale"} or entry.keep_without_probe:
            live_indices[entry.format].add(entry.index)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_files: dict[str, Path] = {}

    if "clash" in all_docs:
        doc = all_docs["clash"]
        original = doc.get("proxies") or []
        live_proxies = [node for i, node in enumerate(original) if i in live_indices["clash"]]
        doc["proxies"] = live_proxies
        _filter_clash_groups(doc, live_proxies)
        output_path = output_dir / "clash.yaml"
        content = yaml.dump(
            doc,
            Dumper=NoAliasDumper,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
            width=4096,
        ).encode("utf-8")
        atomic_write(output_path, content)
        output_files["clash"] = output_path

    if "singbox" in all_docs:
        doc = all_docs["singbox"]
        original = doc.get("outbounds") or []
        doc["outbounds"] = [
            node for i, node in enumerate(original)
            if i in live_indices["singbox"]
        ]
        output_path = output_dir / "singbox.json"
        content = (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        atomic_write(output_path, content)
        output_files["singbox"] = output_path

    if "v2ray" in all_docs:
        lines = all_docs["v2ray"]
        live_lines = [line for i, line in enumerate(lines) if i in live_indices["v2ray"]]
        output_path = output_dir / "v2ray.txt"
        atomic_write(output_path, ("\n".join(live_lines) + ("\n" if live_lines else "")).encode("utf-8"))
        output_files["v2ray"] = output_path

    probe_outcomes = {"passed": 0, "failed": 0}
    for result in results.values():
        probe_outcomes[result["status"]] += 1
    bootstrap_completed_at = state.get("bootstrap_full_completed_at")
    meta = {
        "generated_at": now.isoformat(timespec="seconds"),
        "source_dir": str(input_dir),
        "daily_dir": str(daily_dir),
        "probe_scope": probe_scope,
        "bootstrap_full_completed": bool(state.get("bootstrap_full_completed")),
        "bootstrap_full_completed_at": bootstrap_completed_at,
        "probe_method": "TCP connect / TLS handshake only; no proxy authentication or traffic",
        "retention_hours": retention_hours,
        "total_node_entries": len(all_entries),
        "tested_node_entries": len(probe_entries),
        "unique_tcp_tls_endpoints_tested": len(endpoints),
        "unique_probe_outcomes": probe_outcomes,
        "node_status_counts": counts,
        "node_reason_counts": reason_counts,
        "node_status_meaning": {
            "passed": "本次 TCP 连接或 TLS 握手成功",
            "retained": "本次失败或未复测，但最近一次成功仍在保留期内",
            "stale": "本次未复测；状态库最近记录为通过，作为上次已知可达节点保留，不代表本次通过",
            "failed": "最近一次实际探测失败且没有保留期内的成功记录",
            "untested": "节点信息无法解析，或没有可用的探测结果",
            "unsupported": "UDP/QUIC、Reality 或未知协议，未执行 TCP/TLS 探测",
        },
        "files": {},
    }
    for fmt, path in output_files.items():
        meta["files"][path.name] = {
            "nodes": counts[fmt]["passed"] + counts[fmt]["retained"] + counts[fmt]["stale"],
            "sha256_16": hashlib.sha256(path.read_bytes()).hexdigest()[:16],
        }

    meta_path = output_dir / "meta.json"
    atomic_write(meta_path, (json.dumps(meta, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    atomic_write(state_path, (json.dumps(state, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))

    passed_endpoints = probe_outcomes["passed"]
    failed_endpoints = probe_outcomes["failed"]
    print(
        f"完成：范围={scope_label}；端点本次通过 {passed_endpoints}、失败 {failed_endpoints}；"
        f"最近成功保留 {retention_hours:g} 小时。存活订阅写入 {output_dir}"
    )
    for fmt in FORMATS:
        if all_format_total[fmt]:
            print(f"  {fmt}: " + " / ".join(f"{key}={counts[fmt][key]}" for key in STATUS_NAMES))

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(
                "## JCNode TCP/TLS 存活检测\n\n"
                "仅检测 TCP 连接或 TLS 握手，不验证代理认证与转发；UDP/QUIC、Reality/未知协议不会标记为通过。\n\n"
                f"- 本次范围：`{scope_label}`；全库条目：`{len(all_entries)}`；本次检测条目：`{len(probe_entries)}`\n"
                f"- 唯一端点：`{len(endpoints)}`；本次通过：`{passed_endpoints}`；失败：`{failed_endpoints}`\n"
                f"- 最近成功保留：`{retention_hours:g}` 小时\n"
            )
            for fmt in FORMATS:
                if all_format_total[fmt]:
                    c = counts[fmt]
                    fh.write(
                        f"- **{fmt}**：通过 `{c['passed']}` / 保留 `{c['retained']}` / "
                        f"未复测保留 `{c['stale']}` / 失败 `{c['failed']}` / "
                        f"未测试 `{c['untested']}` / 不支持 `{c['unsupported']}`\n"
                    )
            fh.write("\n")
    return meta


def main() -> int:
    parser = argparse.ArgumentParser(description="首次全历史初始化，之后只检测当日订阅并生成存活版")
    parser.add_argument("--input", default="sub/merged", help="全历史订阅目录；用于生成全历史存活版")
    parser.add_argument("--daily", default="sub", help="当日订阅目录；全历史初始化后仅检测此目录")
    parser.add_argument("--out", default="sub/alive", help="存活订阅输出目录")
    parser.add_argument("--state", default="", help="持久状态库；默认 <out>/state.json")
    parser.add_argument("--timeout", type=float, default=3.0, help="单端点 TCP/TLS 总超时秒数")
    parser.add_argument("--concurrency", type=int, default=64, help="并发探测数，范围 1-512")
    parser.add_argument("--retention-hours", type=float, default=24.0,
                        help="当前失败时仍保留最近成功节点的小时数，默认 24")
    parser.add_argument("--dry-run", action="store_true", help="只解析并统计，不建立任何网络连接或写文件")
    args = parser.parse_args()

    output_dir = Path(args.out)
    state_path = Path(args.state) if args.state else output_dir / "state.json"
    try:
        run_healthcheck(
            Path(args.input),
            output_dir,
            state_path,
            timeout=args.timeout,
            concurrency=args.concurrency,
            retention_hours=args.retention_hours,
            dry_run=args.dry_run,
            daily_dir=Path(args.daily),
        )
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"❌ 存活检测失败：{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
