#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动获取 JCNode 每日免费节点订阅（Clash yaml / Sing-box json / V2Ray txt）

原理：
  https://jcnode.com/posts/free-nodes/ 页面的口令是 AABB 型四位数字，
  校验走 POST https://jcnode.com/api/verify，服务端直接返回订阅链接。
  AABB 型（d1=d2, d3=d4 且 A≠B）总共只有 10×9 = 90 种，逐个试即可。

用法：
  python scripts/fetch_jcnode.py                     # 默认：AABB 90 种，命中即停
  python scripts/fetch_jcnode.py --code 7788         # 已知口令，跳过枚举
  python scripts/fetch_jcnode.py --mode full         # 兜底：0000-9999 全量扫描（慢，慎用）
  python scripts/fetch_jcnode.py --out-dir sub       # 输出目录（默认 sub）

只依赖 Python 标准库。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import itertools
import json
import os
import random
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

VERIFY_URL = "https://jcnode.com/api/verify"
PAGE_URL = "https://jcnode.com/posts/free-nodes/"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)
CST = timezone(timedelta(hours=8))

# 订阅文件的落盘名：键名 -> (文件名, 说明)
FILES = {
    "clash": ("clash.yaml", "Clash / Mihomo"),
    "singbox": ("singbox.json", "Sing-box / Karing"),
    "v2ray": ("v2ray.txt", "V2Ray / v2rayN / Shadowrocket"),
}


def log(msg: str) -> None:
    print(f"[{datetime.now(CST):%Y-%m-%d %H:%M:%S} CST] {msg}", flush=True)


def _request(url: str, data: bytes | None = None, timeout: int = 25, headers: dict | None = None) -> bytes:
    h = {
        "User-Agent": UA,
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Referer": PAGE_URL,
    }
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def post_json(code: str, timeout: int) -> dict:
    body = json.dumps({"code": code}).encode("utf-8")
    raw = _request(
        VERIFY_URL,
        data=body,
        timeout=timeout,
        headers={"Content-Type": "application/json", "Origin": "https://jcnode.com"},
    )
    return json.loads(raw.decode("utf-8"))


def download(url: str, timeout: int) -> bytes:
    return _request(url, timeout=timeout)


# ---------------------------------------------------------------- 口令候选

def aabb_candidates() -> list[str]:
    """AABB 型：d1=d2, d3=d4，且 A≠B（A=B 时退化成 AAAA，不属于 AABB）。"""
    return [f"{a}{a}{b}{b}" for a, b in itertools.permutations("0123456789", 2)]


def full_candidates() -> list[str]:
    return [f"{i:04d}" for i in range(10000)]


def build_candidates(args) -> list[str]:
    if args.code:
        return [c.strip() for c in args.code.split(",") if c.strip()]

    pool = aabb_candidates() if args.mode == "aabb" else full_candidates()

    # 先用上次命中的口令试（口令有可能多日不变），能省掉几十次请求
    cached = read_cached_code(args.out_dir)
    codes: list[str] = []
    if cached and cached in pool:
        codes.append(cached)
    codes += [c for c in pool if c not in codes]
    return codes


def read_cached_code(out_dir: str) -> str | None:
    meta = os.path.join(out_dir, "meta.json")
    try:
        with open(meta, encoding="utf-8") as f:
            code = str(json.load(f).get("code", "")).strip()
        return code if re.fullmatch(r"\d{4}", code) else None
    except Exception:
        return None


# ---------------------------------------------------------------- 抓取

def find_code(candidates: list[str], args) -> tuple[str, dict]:
    """逐个试口令，返回 (code, api_json)。"""
    total = len(candidates)
    last_err: str | None = None
    for i, code in enumerate(candidates, 1):
        for attempt in range(1, args.retries + 1):
            try:
                data = post_json(code, args.timeout)
                break
            except urllib.error.HTTPError as e:
                last_err = f"HTTP {e.code}"
                if e.code in (429, 403, 503):  # 被限流/挡了，退避后重试
                    wait = 5 * attempt
                    log(f"{code} -> {last_err}，{wait}s 后重试（{attempt}/{args.retries}）")
                    time.sleep(wait)
                    continue
                log(f"{code} -> {last_err}")
                break
            except Exception as e:  # 网络抖动
                last_err = f"{type(e).__name__}: {e}"
                if attempt < args.retries:
                    time.sleep(2 * attempt)
                    continue
                log(f"{code} -> {last_err}")
                break
        else:
            raise SystemExit(f"连续失败，放弃。最后一次错误：{last_err}")

        if data.get("success"):
            log(f"✅ 第 {i}/{total} 次命中口令：{code}")
            return code, data

        # 每 20 次报一次进度，日志不至于太长
        if i % 20 == 0:
            log(f"进度 {i}/{total} …")

        time.sleep(max(0.0, args.sleep + random.uniform(-0.1, 0.2)))

    raise SystemExit(f"未在 {total} 个候选中找到有效口令（最后错误：{last_err}）")


def pick_links(data: dict) -> tuple[dict[str, str], str]:
    """优先用 direct，坏掉时退回 proxy。返回 (urls, tier)。"""
    links = data.get("links") or {}
    direct = {k: (links.get("direct", {}).get(k) or "").strip() for k in FILES}
    proxy = {k: (links.get("proxy", {}).get(k) or "").strip() for k in FILES}

    def usable(d):
        return all(re.match(r"^https?://", v) for v in d.values())

    if usable(direct):
        return direct, "direct"
    if usable(proxy):
        return proxy, "proxy"
    # 混合兜底：逐个补
    merged = {k: (direct[k] or proxy[k]) for k in FILES}
    if usable(merged):
        return merged, "mixed"
    raise SystemExit(f"接口未返回可用链接：{json.dumps(links, ensure_ascii=False)}")


# ---------------------------------------------------------------- 校验

def count_clash(text: str) -> int:
    """只统计 proxies: 段里的节点，避免把 proxy-groups 的策略组也算进去。"""
    m = re.search(r"^proxies:\s*$(.*?)(?=^[A-Za-z_]|\Z)", text, re.M | re.S)
    block = m.group(1) if m else text
    return len(re.findall(r"^\s*-\s+name:", block, re.M))


def count_singbox(text: str) -> int:
    obj = json.loads(text)
    return len(obj.get("outbounds") or [])


def count_v2ray(text: str) -> int:
    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) == 1 and re.fullmatch(r"[A-Za-z0-9+/=_-]{200,}", lines[0].strip()):
        blob = lines[0].strip().replace("-", "+").replace("_", "/")
        blob += "=" * (-len(blob) % 4)
        try:
            lines = base64.b64decode(blob).decode("utf-8", "ignore").splitlines()
        except Exception:
            pass
    return len([l for l in lines if l.strip() and not l.strip().startswith("#")])


COUNTERS = {"clash": count_clash, "singbox": count_singbox, "v2ray": count_v2ray}


def write_atomic(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)  # 原子替换，避免 Actions 中断留下半个文件
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


# ---------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description="自动获取 JCNode 每日订阅")
    ap.add_argument("--out-dir", default="sub", help="输出目录，默认 sub")
    ap.add_argument("--mode", choices=["aabb", "full"], default="aabb",
                    help="aabb=90 种（默认，温和）；full=0000-9999 全量扫描（慢，仅 AABB 失效时用）")
    ap.add_argument("--code", default="", help="已知口令，多个用逗号分隔；填了就跳过枚举")
    ap.add_argument("--min-nodes", type=int, default=50, help="节点数下限，低于此值视为失败")
    ap.add_argument("--sleep", type=float, default=0.4, help="每次尝试之间的间隔秒数")
    ap.add_argument("--timeout", type=int, default=25, help="单次请求超时秒数")
    ap.add_argument("--retries", type=int, default=3, help="单次请求重试次数")
    ap.add_argument("--history", default="history/codes.log", help="口令变更记录文件")
    args = ap.parse_args()

    candidates = build_candidates(args)
    log(f"候选口令 {len(candidates)} 个（mode={args.mode}），开始尝试…")

    code, data = find_code(candidates, args)
    urls, tier = pick_links(data)
    log(f"使用 {tier} 链接：{urls['clash']}")

    counts: dict[str, int] = {}
    sha: dict[str, str] = {}
    for key, (filename, label) in FILES.items():
        raw = download(urls[key], args.timeout)
        text = raw.decode("utf-8", "ignore")
        n = COUNTERS[key](text)
        if n < args.min_nodes:
            raise SystemExit(f"❌ {filename} 只解析出 {n} 个节点（< {args.min_nodes}），判定抓取失败：{urls[key]}")
        write_atomic(os.path.join(args.out_dir, filename), raw)
        counts[key] = n
        sha[key] = hashlib.sha256(raw).hexdigest()[:16]
        log(f"  {filename:12s} {len(raw):>8d} bytes  节点 {n:<4d}  {label}")

    now = datetime.now(CST)
    meta = {
        "code": code,
        "updated_at": now.isoformat(timespec="seconds"),
        "updated_at_utc": now.astimezone(timezone.utc).isoformat(timespec="seconds"),
        "date": now.strftime("%Y-%m-%d"),
        "source_page": PAGE_URL,
        "link_tier": tier,
        "links": urls,
        "nodes": counts,
        "sha256_16": sha,
    }
    write_atomic(
        os.path.join(args.out_dir, "meta.json"),
        json.dumps(meta, ensure_ascii=False, indent=2).encode("utf-8"),
    )

    # 口令变更记录（只在变化时追加一行，方便回溯）
    hist_path = args.history
    last_line = ""
    if os.path.exists(hist_path):
        with open(hist_path, encoding="utf-8") as f:
            lines_txt = [l for l in f if l.strip()]
        last_line = lines_txt[-1] if lines_txt else ""
    entry = f"{now:%Y-%m-%d}  code={code}  nodes={counts['clash']}  tier={tier}"
    if not last_line.endswith(f"code={code}  nodes={counts['clash']}  tier={tier}"):
        os.makedirs(os.path.dirname(hist_path) or ".", exist_ok=True)
        with open(hist_path, "a", encoding="utf-8") as f:
            f.write(entry + "\n")

    log(f"完成 ✅ 口令 {code}｜{now:%Y-%m-%d %H:%M} CST｜Clash {counts['clash']} / Sing-box {counts['singbox']} / V2Ray {counts['v2ray']} 个节点")

    # GitHub Actions 的任务摘要
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write(
                f"## JCNode 订阅更新 {meta['date']}\n\n"
                f"- 口令：`{code}`（{tier} 链接）\n"
                f"- 节点数：Clash {counts['clash']} / Sing-box {counts['singbox']} / V2Ray {counts['v2ray']}\n"
                f"- 时间：{meta['updated_at']}\n"
                f"- 文件：`sub/clash.yaml` `sub/singbox.json` `sub/v2ray.txt`\n"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
