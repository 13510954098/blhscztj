#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mihomo 内核实测活：在临时机上运行 mihomo 内核，对每个候选节点发起真实代理
请求（generate_204 延迟测试），把真正能建立代理连接的节点聚合为存活订阅。

流程：
1. 读取 sub/merged 全库（Clash / Sing-box / V2Ray 三格式），以 Clash 节点作为
   实测载体（mihomo 原生格式；经数据验证 Sing-box/V2Ray 节点的 host:port+协议
   与 Clash 完全对齐，不存在没有载体的情况）；
2. TCP 预筛：TCP 类协议先做端口握手探测，快速剔除死端点；UDP/QUIC 类协议
   （hysteria/hysteria2/tuic/wireguard 等）跳过预筛，直接交给 mihomo 实测；
3. 生成临时 mihomo 配置（仅 proxies + external-controller，不带规则和分组），
   启动内核并等待 RESTful API 就绪；若个别节点导致内核无法启动，自动二分
   定位并剔除坏节点后继续，保证整轮测活可以跑完；
4. 通过 API 并发对每个节点做真实代理延迟测试（默认重试 1 次）；
5. 聚合本轮真实通过的节点：Clash 按节点名过滤，Sing-box/V2Ray 按
   (host, port, 归一化协议) 键对齐过滤，输出 sub/alive 三格式 + state + meta。

严格判活：只有本轮实测通过的节点才会进入存活订阅，没有保留宽限；
state.json 升级为 v2（按 host|port|协议 记录历史），检测方法与旧的
TCP/TLS 握手版完全不同，首次运行会自动重置旧状态库。
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import os
import random
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

import urllib.error
import urllib.request

try:
    import yaml
except ImportError as exc:  # pragma: no cover - Actions 会安装 PyYAML
    raise SystemExit("缺少 PyYAML，请先运行：python -m pip install PyYAML") from exc

try:
    from merge_subscriptions import SPECIAL_PROXY_REFS, NoAliasDumper, atomic_write, proxy_name
    from healthcheck_subscriptions import (
        Endpoint,
        _decode_base64_text,
        _filter_clash_groups,
        _parse_ss_base64,
        make_endpoint,
        probe_all,
    )
except ImportError as exc:  # pragma: no cover
    raise SystemExit("请从仓库根目录运行，或确保 scripts/ 在 Python 搜索路径中") from exc


FORMATS = ("clash", "singbox", "v2ray")

# ---------------------------------------------------------------------------
# go-yaml 类型歧义防御
#
# mihomo 用 go-yaml 解析配置：未加引号的 `71150e37` 会被当成科学计数法浮点数、
# `7294` 会被当成整数，进而触发 "invalid REALITY short ID" 之类的加载失败——
# 一个节点即可让整个配置被拒载。PyYAML 认为这类字符串不是数字，写出时不加引号，
# 因此必须在 dump 时主动识别并强制加引号。
# ---------------------------------------------------------------------------

_GO_YAML_NUMBER = re.compile(
    r"""^[-+]?(?:
        [0-9][0-9_]*(?:\.[0-9_]*)?(?:[eE][-+]?[0-9]+)?   # 整数 / 浮点 / 科学计数法
      | \.[0-9][0-9_]*(?:[eE][-+]?[0-9]+)?               # .5 / .5e3
      | 0[xX][0-9a-fA-F_]+                                # 0x 十六进制
      | 0[oO][0-7_]+                                      # 0o 八进制
    )$""",
    re.VERBOSE,
)
_GO_YAML_SPECIAL = {
    "", "~", "null", "Null", "NULL",
    "true", "True", "TRUE", "false", "False", "FALSE",
    "yes", "Yes", "YES", "no", "No", "NO",
    "on", "On", "ON", "off", "Off", "OFF",
    "y", "Y", "n", "N",
}
_GO_YAML_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}([Tt ].+)?$")


def _needs_go_quote(value: str) -> bool:
    """该字符串是否需要强制加引号，避免 go-yaml 把它解析成数字/布尔/时间戳。"""
    if value in _GO_YAML_SPECIAL:
        return True
    return bool(_GO_YAML_NUMBER.match(value) or _GO_YAML_TIMESTAMP.match(value))


class ClashSafeDumper(NoAliasDumper):
    """给 go-yaml 会误判类型的字符串标量强制加引号的 dumper。"""

    def represent_str(self, data):
        if _needs_go_quote(data):
            return self.represent_scalar("tag:yaml.org,2002:str", data, style="'")
        return super().represent_str(data)


ClashSafeDumper.add_representer(str, ClashSafeDumper.represent_str)

DEFAULT_TEST_URL = "http://www.gstatic.com/generate_204"
DEFAULT_MIHOMO_FALLBACK_VERSION = "v1.19.31"

# 不能用 TCP 握手预筛的协议（纯 UDP/QUIC），必须交给 mihomo 真实探测。
UDP_CLASH_TYPES = {
    "hysteria", "hysteria2", "hy2", "tuic",
    "wireguard", "wireguard-go", "wg",
}
UDP_NETWORKS = {"udp", "quic", "quic-go"}

# Sing-box 配置里的非代理出站（配置骨架），不参与测活也不计入节点数。
SINGBOX_AUX_TYPES = {"direct", "block", "dns", "selector", "urltest", "url-test", "reject"}

# 三种格式的协议名归一化：clash type / singbox type / v2ray scheme → 统一名。
PROTO_CANON = {
    "ss": "shadowsocks",
    "shadowsocks": "shadowsocks",
    "ssr": "shadowsocksr",
    "shadowsocksr": "shadowsocksr",
    "socks5": "socks",
    "socks": "socks",
    "socks4": "socks4",
    "hy2": "hysteria2",
    "hysteria2": "hysteria2",
    "hysteria": "hysteria",
    "tuic": "tuic",
    "vmess": "vmess",
    "vless": "vless",
    "trojan": "trojan",
    "http": "http",
    "https": "http",  # v2ray 的 https:// 与 clash 的 http+tls 同源
    "anytls": "anytls",
    "mieru": "mieru",
    "ssh": "ssh",
    "wireguard": "wireguard",
    "wg": "wireguard",
    "wireguard-go": "wireguard",
}

STATE_VERSION = 2
STATE_PRUNE_DAYS = 30  # state 中超过该天数未出现的节点记录会被清理


def canon_protocol(value) -> str:
    raw = str(value or "").strip().lower()
    return PROTO_CANON.get(raw, raw)


@dataclass
class Candidate:
    """一个待实测的 Clash 节点（mihomo 测试载体）。"""

    name: str  # clash 节点名，同时也是 mihomo API 里的代理名
    protocol: str  # 归一化协议名
    host: str
    port: int
    endpoint_id: str  # 与 healthcheck.Endpoint 一致算法的端点 ID（预筛用）
    proxy: dict  # 原始 clash 节点配置
    udp: bool  # True = UDP/QUIC 类，跳过 TCP 预筛


def _clash_is_udp(proxy: dict) -> bool:
    proto = str(proxy.get("type", "")).strip().lower()
    network = str(proxy.get("network", "")).strip().lower()
    return proto in UDP_CLASH_TYPES or network in UDP_NETWORKS


def extract_clash_candidates(doc: dict) -> tuple[list[Candidate], dict]:
    """从 merged Clash 文档提取实测候选；重名节点只保留第一个。"""
    proxies = doc.get("proxies") or []
    if not isinstance(proxies, list):
        raise ValueError("Clash proxies 必须是列表")
    candidates: list[Candidate] = []
    seen_names: set[str] = set()
    stats = {"total": 0, "invalid": 0, "duplicate_name": 0}
    for item in proxies:
        if not isinstance(item, dict):
            stats["invalid"] += 1
            continue
        stats["total"] += 1
        name = proxy_name(item)
        if name in seen_names:
            stats["duplicate_name"] += 1
            continue
        try:
            name.encode("utf-8")
        except UnicodeEncodeError:
            # 病态节点名（如孤立代理字符）无法进入 mihomo API 路由，直接剔除
            stats["invalid"] += 1
            continue
        endpoint = make_endpoint(item.get("server"), item.get("port"), False)
        if endpoint is None:
            stats["invalid"] += 1
            continue
        seen_names.add(name)
        candidates.append(
            Candidate(
                name=name,
                protocol=canon_protocol(item.get("type")),
                host=endpoint.host,
                port=endpoint.port,
                endpoint_id=endpoint.endpoint_id,
                proxy=item,
                udp=_clash_is_udp(item),
            )
        )
    return candidates, stats


def is_singbox_aux(node) -> bool:
    if not isinstance(node, dict):
        return False
    return str(node.get("type", "")).strip().lower() in SINGBOX_AUX_TYPES


def singbox_node_key(node) -> tuple[str, int, str] | None:
    """Sing-box 出站 → (host, port, 归一化协议) 匹配键；非代理/非法返回 None。"""
    if not isinstance(node, dict) or is_singbox_aux(node):
        return None
    endpoint = make_endpoint(
        node.get("server"), node.get("server_port", node.get("port")), False
    )
    if endpoint is None:
        return None
    return (endpoint.host, endpoint.port, canon_protocol(node.get("type")))


def v2ray_line_key(line: str) -> tuple[str, int, str] | None:
    """V2Ray 分享链接 → (host, port, 归一化协议) 匹配键；无法解析返回 None。"""
    value = str(line).strip()
    if "://" not in value:
        return None
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
    except ValueError:
        return None
    host, port, protocol = None, None, canon_protocol(scheme)

    if scheme in {"vmess", "vmess1"}:
        payload = _decode_base64_text(parsed.netloc or parsed.path)
        if payload:
            try:
                obj = json.loads(payload)
            except json.JSONDecodeError:
                obj = None
            if isinstance(obj, dict):
                host = obj.get("add") or obj.get("addr")
                port = obj.get("port")
                protocol = "vmess"
    else:
        try:
            host, port = parsed.hostname, parsed.port
        except ValueError:
            host, port = None, None
        if scheme in {"ss", "shadowsocks"} and (not host or port is None):
            host, port = _parse_ss_base64(parsed)

    if host is None or port is None:
        return None
    endpoint = make_endpoint(host, port, False)
    if endpoint is None:
        return None
    return (endpoint.host, endpoint.port, protocol)


# ---------------------------------------------------------------------------
# mihomo 进程管理
# ---------------------------------------------------------------------------


class MihomoProcess:
    """一个 mihomo 内核实例：写配置、启动、等 API 就绪、查询、停止。

    测试里可以用同接口的假对象替换（见 tests/test_pipeline.py）。
    """

    def __init__(
        self,
        binary: str,
        workdir: Path,
        api_port: int | None = None,
        secret: str | None = None,
        ready_timeout: float = 60.0,
    ):
        self.binary = str(Path(binary).resolve())
        self.workdir = Path(workdir)
        self.api_port = int(api_port or random.randint(21000, 59999))
        self.secret = str(secret or secrets.token_hex(16))
        self.ready_timeout = float(ready_timeout)
        self.process: subprocess.Popen | None = None
        self.last_failure = ""
        self.log_path = self.workdir / "mihomo.log"
        self.config_path = self.workdir / "config.yaml"

    @property
    def api_base(self) -> str:
        return f"http://127.0.0.1:{self.api_port}"

    def write_config(self, proxies: list[dict]) -> None:
        """生成测活专用配置：只有 proxies 与 API，不带规则和分组。"""
        doc = {
            "mode": "direct",
            "log-level": "warning",
            "allow-lan": False,
            "external-controller": f"127.0.0.1:{self.api_port}",
            "secret": self.secret,
            "unified-delay": True,
            "tcp-concurrent": True,
            "profile": {"store-selected": False, "store-fake-ip": False},
            "proxies": copy.deepcopy(proxies),
        }
        self.workdir.mkdir(parents=True, exist_ok=True)
        atomic_write(
            self.config_path,
            yaml.dump(
                doc,
                Dumper=ClashSafeDumper,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
                width=4096,
            ).encode("utf-8"),
        )

    def start(self, proxies: list[dict]) -> bool:
        """写入配置并启动内核；API 就绪返回 True，启动失败/超时返回 False。

        失败原因记入 self.last_failure（区分进程即退 / API 超时 / 无法拉起），
        配合 log_tail() 可在熔断时给出可定位的诊断信息。
        """
        self.write_config(proxies)
        self.last_failure = ""
        with self.log_path.open("ab") as log_fh:
            try:
                self.process = subprocess.Popen(
                    [self.binary, "-d", str(self.workdir), "-f", str(self.config_path)],
                    stdout=log_fh,
                    stderr=subprocess.STDOUT,
                    cwd=str(self.workdir),
                )
            except OSError as exc:
                self.last_failure = f"无法拉起进程：{exc}"
                return False
        deadline = time.monotonic() + self.ready_timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.last_failure = (
                    f"进程启动后即退出（退出码 {self.process.returncode}，"
                    "详见下方内核日志）"
                )
                return False
            try:
                status, _ = self.get("/version", timeout=2.0)
                if status == 200:
                    return True
            except Exception:
                pass
            time.sleep(0.25)
        self.last_failure = f"API 在 {self.ready_timeout:g}s 内未就绪（进程未退出）"
        return False

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def get(self, path: str, timeout: float = 10.0) -> tuple[int, bytes]:
        request = urllib.request.Request(
            self.api_base + path,
            headers={"Authorization": f"Bearer {self.secret}"},
        )
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return resp.status, resp.read()

    def log_tail(self, lines: int = 15) -> str:
        try:
            data = self.log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return ""
        return "\n".join(data[-lines:])

    def stop(self) -> None:
        process, self.process = self.process, None
        if process is None:
            return
        for sig in (signal.SIGTERM, signal.SIGKILL):
            if process.poll() is not None:
                return
            try:
                process.send_signal(sig)
            except ProcessLookupError:
                return
            try:
                process.wait(timeout=5)
                return
            except subprocess.TimeoutExpired:
                continue


def query_delay(proc: MihomoProcess, name: str, test_url: str, timeout_ms: int) -> dict:
    """对单个节点发起真实代理延迟测试。返回 {ok, delay_ms, error}。"""
    path = (
        f"/proxies/{quote(name, safe='')}/delay"
        f"?timeout={int(timeout_ms)}&url={quote(test_url, safe='')}"
    )
    try:
        status, body = proc.get(path, timeout=timeout_ms / 1000.0 + 10.0)
    except urllib.error.HTTPError as exc:
        return {"ok": False, "delay_ms": None, "error": f"HTTP {exc.code}"}
    except Exception as exc:  # 连接失败/超时等
        return {"ok": False, "delay_ms": None, "error": type(exc).__name__}

    if status == 200:
        try:
            payload = json.loads(body.decode("utf-8"))
            delay = payload.get("delay")
            if isinstance(delay, (int, float)) and delay >= 0:
                return {"ok": True, "delay_ms": round(float(delay), 1), "error": ""}
        except (ValueError, UnicodeDecodeError):
            pass
        return {"ok": False, "delay_ms": None, "error": "bad_response"}
    return {"ok": False, "delay_ms": None, "error": f"HTTP {status}"}


def run_delay_tests(
    proc: MihomoProcess,
    candidates: list[Candidate],
    test_url: str,
    timeout_ms: int,
    concurrency: int,
    retries: int,
) -> dict[str, dict]:
    """并发跑完一批节点的真实延迟测试（含重试）。"""
    results: dict[str, dict] = {}
    total = len(candidates)
    done = 0
    done_lock = threading.Lock()

    def work(candidate: Candidate) -> tuple[str, dict]:
        if not proc.is_running():
            raise RuntimeError("mihomo 进程意外退出，中止本轮测试")
        outcome = query_delay(proc, candidate.name, test_url, timeout_ms)
        attempt = 0
        while not outcome["ok"] and attempt < retries:
            attempt += 1
            time.sleep(0.3)
            outcome = query_delay(proc, candidate.name, test_url, timeout_ms)
        outcome["attempts"] = attempt + 1
        return candidate.name, outcome

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = [pool.submit(work, candidate) for candidate in candidates]
        for future in as_completed(futures):
            name, outcome = future.result()
            results[name] = outcome
            with done_lock:
                done += 1
                if done % 200 == 0 or done == total:
                    print(f"  实测进度：{done}/{total}")
    return results


def _test_batch(
    proc_factory,
    candidates: list[Candidate],
    test_url: str,
    timeout_ms: int,
    concurrency: int,
    retries: int,
) -> dict[str, dict] | None:
    """启动一个 mihomo 实例测试一批节点；内核无法启动时返回 None。"""
    proc = proc_factory()
    try:
        if not proc.start([candidate.proxy for candidate in candidates]):
            return None
        return run_delay_tests(proc, candidates, test_url, timeout_ms, concurrency, retries)
    finally:
        proc.stop()


def run_real_test(
    proc_factory,
    candidates: list[Candidate],
    test_url: str,
    timeout_ms: int,
    concurrency: int,
    retries: int,
    max_startup_failures: int = 60,
) -> tuple[dict[str, dict], list[Candidate]]:
    """真实测活入口；整批无法启动时二分定位坏节点并剔除后继续。

    熔断按"连续无进展失败"计：成功启动一批、或定位剔除一个坏节点，计数都会清零；
    只有连续 60 次批量启动失败且毫无进展，才判定内核/环境异常并中止。
    单节点启动失败时会先用最小探针配置验证内核本身是否还活着，
    避免内核损坏时把好节点逐个误判为坏节点。
    """
    results: dict[str, dict] = {}
    bad: list[Candidate] = []
    consecutive_failures = 0

    def recurse(chunk: list[Candidate]) -> None:
        nonlocal consecutive_failures
        if not chunk:
            return
        outcome = _test_batch(proc_factory, chunk, test_url, timeout_ms, concurrency, retries)
        if outcome is not None:
            results.update(outcome)
            consecutive_failures = 0  # 成功启动 = 有进展
            return
        if len(chunk) == 1:
            alive, probe_detail = _kernel_still_alive(proc_factory)
            if not alive:
                raise RuntimeError(
                    "mihomo 连最小探针配置都无法加载，内核本身不可用"
                    "（下载损坏或运行环境异常），已中止。"
                    f"诊断：{probe_detail}"
                )
            bad.append(chunk[0])
            print(f"  ⚠️ 剔除导致 mihomo 无法加载的节点：{chunk[0].name}")
            consecutive_failures = 0  # 定位到一个坏节点 = 有进展
            return
        consecutive_failures += 1
        if consecutive_failures > max_startup_failures:
            raise RuntimeError(
                f"mihomo 批量启动连续失败 {max_startup_failures} 次且无任何进展，"
                "疑似内核或运行环境异常，已中止"
            )
        middle = len(chunk) // 2
        recurse(chunk[:middle])
        recurse(chunk[middle:])

    recurse(candidates)
    return results, bad


_HEALTH_PROBE_PROXY = {
    "name": "__mihomo_health_check__",
    "type": "http",
    "server": "127.0.0.1",
    "port": 9,
}


def _kernel_still_alive(proc_factory) -> tuple[bool, str]:
    """用最小配置探针验证内核能否启动（区分"坏节点"与"坏内核"）。

    返回 (是否存活, 诊断信息)；诊断信息仅在失败时有内容，
    包含内核版本、失败模式与内核日志尾部，便于在 CI 日志中直接定位。
    对测试注入的假内核（无 binary/last_failure 属性）做 getattr 防御。
    """
    proc = proc_factory()
    try:
        ok = proc.start([copy.deepcopy(_HEALTH_PROBE_PROXY)])
        detail = ""
        if not ok:
            version = detect_mihomo_version(getattr(proc, "binary", "")) or "未知"
            reason = getattr(proc, "last_failure", "") or "未提供失败详情"
            tail = getattr(proc, "log_tail", lambda lines=15: "")(20).strip()
            detail = f"内核版本 {version}；失败模式：{reason}"
            if tail:
                detail += f"；内核日志尾部：\n{tail}"
        return ok, detail
    finally:
        proc.stop()


# ---------------------------------------------------------------------------
# 预筛与聚合
# ---------------------------------------------------------------------------


def run_config_test(binary, config_path, workdir) -> tuple[bool, str]:
    """运行 mihomo -t 校验配置能否被内核加载；返回 (是否通过, 输出尾部)。"""
    try:
        proc = subprocess.run(
            [str(binary), "-t", "-d", str(workdir), "-f", str(config_path)],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, "mihomo -t 超时（180s）"
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, output.strip()


def _clash_probe_doc(doc: dict) -> dict:
    """存活 clash 配置的深拷贝探针：剥离 rules/rule-providers。

    mihomo -t 遇到 rules 会触发 geodata 下载（CI 环境不确定可用）；
    剥离后仍能完整校验 proxies 解析与 proxy-groups 引用关系——
    客户端加载失败几乎都发生在这两层。
    """
    probe = copy.deepcopy(doc)
    probe.pop("rules", None)
    probe.pop("rule-providers", None)
    return probe


def _ensure_groups_nonempty(doc: dict) -> list[str]:
    """给过滤后 proxies 为空的分组填入 DIRECT，避免空分组让客户端拒载。

    分组过滤剔除死节点后，某地区分组可能被清空（如本轮没有该国存活节点）；
    mihomo/clash 要求每个分组必须有非空 proxies 或 use，空列表会拒载整个配置
    （"'use' or 'proxies' missing"）。填内置 DIRECT 可保持 rules 引用有效。
    返回被填充的分组名列表。
    """
    filled: list[str] = []
    groups = doc.get("proxy-groups")
    if not isinstance(groups, list):
        return filled
    for group in groups:
        if not isinstance(group, dict):
            continue
        proxies = group.get("proxies")
        if isinstance(proxies, list) and not proxies and not group.get("use"):
            group["proxies"] = ["DIRECT"]
            name = str(group.get("name") or "")
            if name:
                filled.append(name)
    return filled


def ensure_clash_output_loadable(mihomo_binary, doc: dict, runner=None) -> None:
    """写出前用 mihomo -t 预校验存活 clash 配置，保证客户端一定能加载。

    内核拒绝配置（如字段类型不规范）时抛 RuntimeError，
    不合格的存活文件不会写盘替换上一版；
    -t 无法执行（二进制消失等 OSError）则告警跳过，不阻断。
    """
    if runner is None:
        runner = run_config_test
    probe = _clash_probe_doc(doc)
    with tempfile.TemporaryDirectory(prefix="mihomo-validate-") as tmp:
        probe_path = Path(tmp) / "probe.yaml"
        atomic_write(
            probe_path,
            yaml.dump(
                probe,
                Dumper=ClashSafeDumper,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
                width=4096,
            ).encode("utf-8"),
        )
        try:
            ok, output = runner(mihomo_binary, probe_path, Path(tmp))
        except OSError as exc:
            print(f"⚠️ 无法运行 mihomo -t 做输出自检，跳过：{exc}")
            return
        if not ok:
            tail = "\n".join(output.splitlines()[-8:])
            raise RuntimeError(
                "存活 clash.yaml 未能通过 mihomo -t 预校验，"
                "已阻止写出（上一版存活文件保留），内核报错：\n" + tail
            )


def prefilter_tcp(candidates: list[Candidate], timeout: float, concurrency: int) -> tuple[set[str], dict]:
    """对 TCP 类候选的唯一端点做握手预筛，返回通过的 endpoint_id 集合。"""
    tcp_candidates = [c for c in candidates if not c.udp]
    endpoints: dict[str, Endpoint] = {}
    for candidate in tcp_candidates:
        endpoints.setdefault(candidate.endpoint_id, Endpoint(candidate.host, candidate.port, False, ""))
    stats = {
        "method": "TCP/TLS handshake",
        "timeout_s": timeout,
        "tcp_candidates": len(tcp_candidates),
        "udp_direct_candidates": len(candidates) - len(tcp_candidates),
        "unique_endpoints": len(endpoints),
    }
    if not endpoints:
        stats["endpoints_passed"] = 0
        stats["endpoints_failed"] = 0
        return set(), stats
    results = asyncio.run(probe_all(list(endpoints.values()), timeout, concurrency))
    passed = {eid for eid, result in results.items() if result.get("status") == "passed"}
    stats["endpoints_passed"] = len(passed)
    stats["endpoints_failed"] = len(endpoints) - len(passed)
    return passed, stats


def detect_mihomo_version(binary: str) -> str:
    """运行 mihomo -v 提取版本号；失败时返回空字符串。"""
    try:
        output = subprocess.run(
            [str(binary), "-v"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""
    match = re.search(r"v\d+\.\d+\.\d+\S*", output)
    return match.group(0) if match else ""


def _load_state(path: Path) -> dict:
    if not path.exists() or path.stat().st_size == 0:
        return {"version": STATE_VERSION, "nodes": {}}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("nodes"), dict):
        # 旧版（TCP 时代）或损坏的状态库：语义完全不同，直接重置。
        print("  ℹ️ 旧状态库与 mihomo 实测语义不同，已重置为全新 v2 状态库")
        return {"version": STATE_VERSION, "nodes": {}}
    return value


def _update_state(
    state: dict,
    candidates: list[Candidate],
    results: dict[str, dict],
    now: datetime,
) -> None:
    """按 host|port|协议 合并本轮实测结果进状态库，并清理长期未出现的节点。"""
    records = state.setdefault("nodes", {})
    stamp = now.isoformat(timespec="seconds")
    seen_keys: set[str] = set()
    for candidate in candidates:
        key = f"{candidate.host}|{candidate.port}|{candidate.protocol}"
        seen_keys.add(key)
        outcome = results.get(candidate.name, {})
        record = records.get(key)
        if record is None:
            record = {
                "host": candidate.host,
                "port": candidate.port,
                "protocol": candidate.protocol,
                "first_seen_at": stamp,
                "success_count": 0,
                "failure_count": 0,
            }
            records[key] = record
        record["last_seen_at"] = stamp
        record["last_test_at"] = stamp
        ok = bool(outcome.get("ok"))
        record["last_status"] = "passed" if ok else "failed"
        record["last_delay_ms"] = outcome.get("delay_ms")
        record["last_error"] = outcome.get("error", "")
        names = set(record.get("representative_names") or [])
        names.add(candidate.name)
        record["representative_names"] = sorted(names)[:5]
        if ok:
            record["last_success_at"] = stamp
            delay = outcome.get("delay_ms")
            best = record.get("best_delay_ms")
            if delay is not None and (best is None or delay < best):
                record["best_delay_ms"] = delay
            record["success_count"] = int(record.get("success_count", 0)) + 1
        else:
            record["failure_count"] = int(record.get("failure_count", 0)) + 1

    # 清理超过 STATE_PRUNE_DAYS 天没再出现的节点记录，避免无限增长。
    horizon = now - timedelta(days=STATE_PRUNE_DAYS)
    for key in list(records):
        last_seen = str(records[key].get("last_seen_at") or "")
        try:
            seen_time = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        except ValueError:
            seen_time = None
        if seen_time is None or seen_time < horizon:
            if key not in seen_keys:
                records.pop(key, None)

    state["version"] = STATE_VERSION
    state["updated_at"] = stamp
    state["probe_method"] = "mihomo real proxy delay test"


def _load_input_docs(input_dir: Path) -> dict:
    docs: dict[str, object] = {}
    clash_path = input_dir / "clash.yaml"
    if clash_path.exists():
        doc = yaml.safe_load(clash_path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            raise ValueError(f"{clash_path} 不是 Clash YAML 对象")
        docs["clash"] = doc
    singbox_path = input_dir / "singbox.json"
    if singbox_path.exists():
        doc = json.loads(singbox_path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            raise ValueError(f"{singbox_path} 不是 JSON 对象")
        docs["singbox"] = doc
    v2ray_path = input_dir / "v2ray.txt"
    if v2ray_path.exists():
        docs["v2ray"] = [
            line.strip()
            for line in v2ray_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    if not docs:
        raise ValueError(f"{input_dir} 中没有 clash.yaml、singbox.json 或 v2ray.txt")
    return docs


def _daily_allowed_keys(daily_dir: Path) -> set[tuple[str, int, str]] | None:
    """scope=daily 时：只测当日订阅里出现过的 (host, port, 协议) 键。"""
    clash_path = daily_dir / "clash.yaml"
    if not clash_path.exists():
        return None
    doc = yaml.safe_load(clash_path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        return None
    keys: set[tuple[str, int, str]] = set()
    for item in doc.get("proxies") or []:
        if not isinstance(item, dict):
            continue
        endpoint = make_endpoint(item.get("server"), item.get("port"), False)
        if endpoint is None:
            continue
        keys.add((endpoint.host, endpoint.port, canon_protocol(item.get("type"))))
    return keys or None


def run_alive_check(
    input_dir: Path,
    output_dir: Path,
    state_path: Path,
    mihomo_binary: str,
    daily_dir: Path | None = None,
    scope: str = "full",
    test_url: str = DEFAULT_TEST_URL,
    timeout: float = 5.0,
    concurrency: int = 128,
    retries: int = 1,
    prefilter_timeout: float = 3.0,
    limit: int = 0,
    workdir: Path | None = None,
    proc_factory=None,
) -> dict:
    """完整测活流程；返回写出的 meta（也便于单测断言）。"""
    if scope not in {"full", "daily"}:
        raise ValueError("--scope 只支持 full 或 daily")
    if timeout <= 0:
        raise ValueError("--timeout 必须大于 0")
    if concurrency < 1 or concurrency > 512:
        raise ValueError("--concurrency 必须在 1 到 512 之间")
    if retries < 0:
        raise ValueError("--retries 不能小于 0")

    docs = _load_input_docs(input_dir)
    if "clash" not in docs:
        raise ValueError(f"{input_dir} 缺少 clash.yaml，无法构造 mihomo 测试载体")

    candidates, clash_stats = extract_clash_candidates(docs["clash"])

    if scope == "daily" and daily_dir is not None:
        allowed = _daily_allowed_keys(daily_dir)
        if allowed is None:
            print("  ⚠️ 未找到当日 Clash 订阅，scope=daily 无法圈定范围，退回全库实测")
        else:
            before = len(candidates)
            candidates = [c for c in candidates if (c.host, c.port, c.protocol) in allowed]
            clash_stats["scope_filtered_out"] = before - len(candidates)
    if limit and limit > 0:
        candidates = candidates[:limit]

    print(
        f"候选载体：{len(candidates)} 个 Clash 节点"
        f"（全库 {clash_stats['total']}，无效 {clash_stats['invalid']}，"
        f"重名跳过 {clash_stats['duplicate_name']}）；scope={scope}"
    )

    # ---- 第一级：TCP 预筛（UDP/QUIC 协议跳过，直接进实测） ----
    if prefilter_timeout > 0:
        print(f"TCP 预筛：timeout={prefilter_timeout:g}s concurrency={concurrency}")
        passed_endpoints, prefilter_stats = prefilter_tcp(candidates, prefilter_timeout, concurrency)
        real_set = [c for c in candidates if c.udp or c.endpoint_id in passed_endpoints]
        prefilter_stats["candidates_dropped"] = len(candidates) - len(real_set)
        print(
            f"  唯一端点 {prefilter_stats['unique_endpoints']} 个，"
            f"通过 {prefilter_stats['endpoints_passed']} 个，"
            f"剔除 TCP 不通候选 {prefilter_stats['candidates_dropped']} 个；"
            f"UDP 直测 {prefilter_stats['udp_direct_candidates']} 个"
        )
    else:
        passed_endpoints = set()
        real_set = list(candidates)
        prefilter_stats = {"method": "disabled"}

    if not real_set:
        print("❌ 没有任何可实测的候选节点")
        real_set = []

    # ---- 第二级：mihomo 内核真实测活 ----
    timeout_ms = int(timeout * 1000)
    own_workdir = workdir is None
    if workdir is None:
        workdir = Path(tempfile.mkdtemp(prefix="mihomo-alive-"))
    else:
        workdir = Path(workdir)
        workdir.mkdir(parents=True, exist_ok=True)

    if proc_factory is None:
        real_kernel = True

        def proc_factory():
            return MihomoProcess(mihomo_binary, workdir)
    else:
        real_kernel = False  # 离线单测注入假内核，不做真实 -t 自检

    try:
        print(
            f"mihomo 实测：{len(real_set)} 个候选，test_url={test_url}，"
            f"timeout={timeout:g}s，concurrency={concurrency}，retries={retries}"
        )
        attempts = 0
        while True:
            attempts += 1
            try:
                results, bad_proxies = run_real_test(
                    proc_factory, real_set, test_url, timeout_ms, concurrency, retries
                )
                break
            except RuntimeError as exc:
                # 偶发异常（runner 上内核崩溃/进程被杀）重试一次；
                # 重试仍失败则正常抛出，交由 workflow 门禁暴露
                if attempts >= 2:
                    raise
                print(f"⚠️ 实测阶段异常（{exc}），重置内核重试（第 2 次尝试）")
    finally:
        if own_workdir:
            shutil.rmtree(workdir, ignore_errors=True)

    alive_candidates = [c for c in real_set if results.get(c.name, {}).get("ok")]
    alive_names = {c.name for c in alive_candidates}
    alive_keys: set[tuple[str, int, str]] = set()
    delay_by_key: dict[tuple[str, int, str], float] = {}
    for candidate in alive_candidates:
        key = (candidate.host, candidate.port, candidate.protocol)
        alive_keys.add(key)
        delay = results[candidate.name].get("delay_ms")
        if delay is not None:
            delay_by_key[key] = min(delay, delay_by_key.get(key, delay))

    bad_names = {c.name for c in bad_proxies}
    print(
        f"实测完成：真实可用 {len(alive_candidates)} / {len(real_set)}"
        f"（剔除无法加载节点 {len(bad_proxies)} 个，唯一可用键 {len(alive_keys)} 个）"
    )
    if real_set and not alive_candidates:
        print("⚠️ 本轮没有任何节点实测通过，存活订阅将为空（严格判活，无保留宽限）")

    # ---- 聚合输出三格式 ----
    output_dir.mkdir(parents=True, exist_ok=True)
    output_files: dict[str, Path] = {}
    output_validated = False
    counts = {
        "clash": {"kept": 0, "failed": 0, "prefilter_dropped": 0, "load_error": 0, "invalid": 0, "duplicate_name": 0},
        "singbox": {"kept": 0, "aux_kept": 0, "dropped": 0},
        "v2ray": {"kept": 0, "dropped": 0},
    }
    counts["clash"]["invalid"] = clash_stats["invalid"]
    counts["clash"]["duplicate_name"] = clash_stats["duplicate_name"]
    counts["clash"]["prefilter_dropped"] = len(candidates) - len(real_set)
    counts["clash"]["load_error"] = len(bad_proxies)
    counts["clash"]["failed"] = len(real_set) - len(alive_candidates) - len(bad_proxies)
    counts["clash"]["kept"] = len(alive_candidates)

    if "clash" in docs:
        doc = docs["clash"]
        original = doc.get("proxies") or []
        alive_proxies = [node for node in original if proxy_name(node) in alive_names]
        doc["proxies"] = alive_proxies
        _filter_clash_groups(doc, alive_proxies)
        filled = _ensure_groups_nonempty(doc)
        if filled:
            print(f"  ⚠️ 本轮无存活节点，地区分组已填 DIRECT 防空分组拒载：{'、'.join(filled)}")
        if real_kernel:
            # 写盘前用真实内核预校验：客户端加载不了的存活文件一律阻止写出
            ensure_clash_output_loadable(mihomo_binary, doc)
            output_validated = True
            print("  ✅ 存活 clash.yaml 已通过 mihomo -t 预校验")
        output_path = output_dir / "clash.yaml"
        atomic_write(
            output_path,
            yaml.dump(
                doc,
                Dumper=ClashSafeDumper,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
                width=4096,
            ).encode("utf-8"),
        )
        output_files["clash"] = output_path

    if "singbox" in docs:
        doc = docs["singbox"]
        outbounds = doc.get("outbounds") or []
        kept, aux, dropped = [], 0, 0
        for node in outbounds:
            if is_singbox_aux(node):
                kept.append(node)
                aux += 1
                continue
            key = singbox_node_key(node)
            if key is not None and key in alive_keys:
                kept.append(node)
            else:
                dropped += 1
        doc["outbounds"] = kept
        counts["singbox"] = {"kept": len(kept) - aux, "aux_kept": aux, "dropped": dropped}
        output_path = output_dir / "singbox.json"
        atomic_write(
            output_path,
            (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
        )
        output_files["singbox"] = output_path

    if "v2ray" in docs:
        lines = docs["v2ray"]
        kept = [line for line in lines if v2ray_line_key(line) in alive_keys]
        counts["v2ray"] = {"kept": len(kept), "dropped": len(lines) - len(kept)}
        output_path = output_dir / "v2ray.txt"
        atomic_write(
            output_path,
            ("\n".join(kept) + ("\n" if kept else "")).encode("utf-8"),
        )
        output_files["v2ray"] = output_path

    # ---- 状态库与 meta ----
    state = _load_state(state_path)
    _update_state(state, real_set, results, datetime.now(timezone.utc))
    atomic_write(
        state_path,
        (json.dumps(state, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )

    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    alive_delay_list = sorted(d for d in delay_by_key.values())
    meta = {
        "generated_at": now_iso,
        "source_dir": str(input_dir),
        "daily_dir": str(daily_dir) if daily_dir else "",
        "scope": scope,
        "probe_method": "mihomo real proxy delay test",
        "test_url": test_url,
        "timeout_s": timeout,
        "concurrency": concurrency,
        "retries": retries,
        "mihomo_version": detect_mihomo_version(mihomo_binary),
        "output_validated": output_validated,
        "prefilter": prefilter_stats,
        "clash_candidates": clash_stats,
        "alive_unique_keys": len(alive_keys),
        "alive_delay_ms": {
            "min": alive_delay_list[0] if alive_delay_list else None,
            "median": alive_delay_list[len(alive_delay_list) // 2] if alive_delay_list else None,
            "max": alive_delay_list[-1] if alive_delay_list else None,
        },
        "node_status_counts": counts,
        "files": {},
    }
    for fmt, path in output_files.items():
        meta["files"][path.name] = {
            "nodes": counts[fmt]["kept"],
            "sha256_16": hashlib.sha256(path.read_bytes()).hexdigest()[:16],
        }
    meta_path = output_dir / "meta.json"
    atomic_write(
        meta_path,
        (json.dumps(meta, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )

    print(f"✅ 存活聚合完成，写入 {output_dir}")
    for fmt in FORMATS:
        if fmt in output_files:
            detail = counts[fmt]
            print(f"  {fmt}: " + " / ".join(f"{k}={v}" for k, v in detail.items()))

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write("## mihomo 内核实测活\n\n")
            fh.write(
                "每次运行在临时机上全新下载 mihomo 内核，对节点发起真实代理请求"
                f"（`{test_url}`），只聚合本轮真实连通的节点；无保留宽限。\n\n"
                f"- 内核版本：`{meta['mihomo_version'] or '未知'}`；scope：`{scope}`\n"
                f"- Clash 候选：`{clash_stats['total']}` → 实测 `{len(real_set)}` → 真实可用 "
                f"`{len(alive_candidates)}`（预筛剔除 `{counts['clash']['prefilter_dropped']}`，"
                f"加载失败 `{len(bad_proxies)}`，实测失败 `{counts['clash']['failed']}`）\n"
                f"- 唯一可用键（host|port|协议）：`{len(alive_keys)}`\n"
            )
            delays = meta["alive_delay_ms"]
            if delays["min"] is not None:
                fh.write(
                    f"- 实测延迟：min `{delays['min']}ms` / 中位 `{delays['median']}ms` / "
                    f"max `{delays['max']}ms`\n"
                )
            for fmt in FORMATS:
                if fmt in output_files:
                    detail = counts[fmt]
                    if fmt == "clash":
                        # clash 计数字典没有 dropped 键，剔除 = 预筛 + 实测失败 + 加载失败
                        dropped = (
                            detail["prefilter_dropped"]
                            + detail["failed"]
                            + detail["load_error"]
                        )
                    else:
                        dropped = detail["dropped"]
                    fh.write(
                        f"- **{fmt}**：保留 `{detail['kept']}`"
                        + (f" / 配置骨架 `{detail['aux_kept']}`" if fmt == "singbox" else "")
                        + f" / 剔除 `{dropped}`\n"
                    )
            fh.write("\n")
    return meta


def main() -> int:
    parser = argparse.ArgumentParser(
        description="mihomo 内核实测活：真实代理延迟测试 + 聚合能连上的节点"
    )
    parser.add_argument("--input", default="sub/merged", help="全历史订阅目录（三格式）")
    parser.add_argument("--daily", default="sub", help="当日订阅目录；--scope daily 时用于圈定范围")
    parser.add_argument("--out", default="sub/alive", help="存活订阅输出目录")
    parser.add_argument("--state", default="", help="持久状态库；默认 <out>/state.json")
    parser.add_argument("--mihomo", required=True, help="mihomo 内核可执行文件路径")
    parser.add_argument("--scope", choices=["full", "daily"], default="full",
                        help="full=全库实测（默认）；daily=只测当日订阅覆盖的节点")
    parser.add_argument("--test-url", default=DEFAULT_TEST_URL, help="真实测活 URL")
    parser.add_argument("--timeout", type=float, default=5.0, help="单节点延迟测试超时秒数")
    parser.add_argument("--concurrency", type=int, default=128, help="并发数，范围 1-512")
    parser.add_argument("--retries", type=int, default=1, help="失败重试次数，默认 1")
    parser.add_argument("--prefilter-timeout", type=float, default=3.0,
                        help="TCP 预筛超时秒数，0 = 关闭预筛（全部直接实测）")
    parser.add_argument("--limit", type=int, default=0, help="调试用：最多实测 N 个候选，0 = 不限")
    args = parser.parse_args()

    output_dir = Path(args.out)
    state_path = Path(args.state) if args.state else output_dir / "state.json"
    daily_dir = Path(args.daily) if args.daily else None

    try:
        run_alive_check(
            Path(args.input),
            output_dir,
            state_path,
            args.mihomo,
            daily_dir=daily_dir,
            scope=args.scope,
            test_url=args.test_url,
            timeout=args.timeout,
            concurrency=args.concurrency,
            retries=args.retries,
            prefilter_timeout=args.prefilter_timeout,
            limit=args.limit,
        )
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError, RuntimeError) as exc:
        print(f"❌ mihomo 实测活失败：{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    # CI 管道下 stdout 是块缓冲，会导致日志乱序（错误先于进度出现）；改行缓冲
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(line_buffering=True)
        except (AttributeError, ValueError):
            pass
    raise SystemExit(main())
