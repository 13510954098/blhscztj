#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把本次抓取到的订阅和仓库里上一次的订阅合并，按连接参数去重。

用法：
  python scripts/merge_subscriptions.py \
      --base sub/merged \
      --out sub/merged \
      --incoming .incoming-sub \
      --history history/codes.log

说明：
- incoming（本次抓取）优先，旧文件只补充本次没有的节点；
- Clash/Sing-box 的输出结构取自 JC 当日订阅，历史文件只贡献节点数据；
- Clash 去掉 name、测速 delay、sub_tag 后按连接参数去重，Sing-box 去掉 tag 去重，V2Ray 去掉节点名去重；
- 所有格式按节点名中的 MB/s 标注全局降序；无速度标记稳定地排在末尾；
- 不生成 archive，不删除历史节点；当天订阅和综合订阅分开保存。
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

try:
    import yaml
except ImportError as exc:  # pragma: no cover - 给 Actions/用户清晰提示
    raise SystemExit(
        "缺少 PyYAML，请先运行：python -m pip install PyYAML"
    ) from exc


VOLATILE_CLASH_KEYS = {"name", "delay", "sub_tag"}
SPEED_RE = re.compile(r"(?<![0-9.])([0-9]+(?:\.[0-9]+)?)\s*MB/s(?=$|[^A-Za-z])", re.IGNORECASE)
SPECIAL_PROXY_REFS = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"}


def speed_from_name(name: str) -> float | None:
    """读取节点名里的 MB/s 标注；没有标注时返回 None。"""
    match = SPEED_RE.search(str(name))
    return float(match.group(1)) if match else None


def sort_by_speed(items: list, name_getter) -> list:
    """按节点名标注速度全局降序；同速和无标注项保持原有稳定顺序。"""
    return sorted(
        items,
        key=lambda item: (
            speed_from_name(name_getter(item)) is None,
            -(speed_from_name(name_getter(item)) or 0.0),
        ),
    )


def leading_country_flag(name: str) -> str | None:
    """返回名称开头的双区域指示符旗帜（如 🇺🇸），否则返回 None。"""
    value = str(name)
    if len(value) >= 2 and all(0x1F1E6 <= ord(ch) <= 0x1F1FF for ch in value[:2]):
        return value[:2]
    return None


class NoAliasDumper(yaml.SafeDumper):
    """避免 PyYAML 为重复的嵌套对象写出 YAML 锚点，客户端兼容性更好。"""

    def ignore_aliases(self, data):  # noqa: D401
        return True


def freeze(value, ignored: set[str] | None = None):
    """把嵌套 YAML/JSON 值变成可哈希结构。"""
    ignored = ignored or set()
    if isinstance(value, dict):
        return tuple(
            (str(k), freeze(v, ignored))
            for k, v in sorted(value.items(), key=lambda item: str(item[0]))
            if str(k) not in ignored
        )
    if isinstance(value, (list, tuple)):
        return tuple(freeze(v, ignored) for v in value)
    return value


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        value = json.load(fh)
    if not isinstance(value, dict):
        raise ValueError(f"{path} 不是 JSON 对象")
    return value


def proxy_name(proxy: dict) -> str:
    value = proxy.get("name")
    if value is not None and str(value):
        return str(value)
    server = proxy.get("server", "")
    port = proxy.get("port", "")
    return f"{proxy.get('type', 'proxy')} {server}:{port}"


def unique_name(name: str, used: set[str]) -> str:
    if name not in used:
        return name
    n = 2
    while f"{name} #{n}" in used:
        n += 1
    return f"{name} #{n}"


def clash_key(proxy: dict):
    return freeze(proxy, VOLATILE_CLASH_KEYS)


def merge_clash(base_path: Path, incoming_path: Path) -> tuple[dict, dict]:
    """合并 Clash 节点，但始终以本次 JC 配置作为结构模板。"""
    incoming = yaml.safe_load(incoming_path.read_text(encoding="utf-8"))
    if not isinstance(incoming, dict):
        raise ValueError(f"{incoming_path} 不是 Clash YAML 对象")
    base = None
    if base_path.exists() and base_path.stat().st_size:
        base = yaml.safe_load(base_path.read_text(encoding="utf-8"))
        if not isinstance(base, dict):
            raise ValueError(f"{base_path} 不是 Clash YAML 对象")

    incoming_proxies = incoming.get("proxies") or []
    base_proxies = (base or {}).get("proxies") or []
    if not isinstance(incoming_proxies, list) or not isinstance(base_proxies, list):
        raise ValueError("Clash proxies 必须是列表")

    # 本次节点优先，历史节点补充；按完整连接参数去重。
    selected: list[dict] = []
    seen: dict[object, dict] = {}
    aliases: dict[str, str] = {}
    used_names: set[str] = set()
    incoming_count = len(incoming_proxies)
    duplicate_count = 0
    added_from_incoming = 0

    for source_index, proxy in enumerate([*incoming_proxies, *base_proxies]):
        if not isinstance(proxy, dict):
            continue
        key = clash_key(proxy)
        if key in seen:
            duplicate_count += 1
            old_name = proxy_name(proxy)
            chosen_name = proxy_name(seen[key])
            if old_name != chosen_name:
                aliases.setdefault(old_name, chosen_name)
            continue

        item = copy.deepcopy(proxy)
        original_name = proxy_name(item)
        final_name = unique_name(original_name, used_names)
        item["name"] = final_name
        used_names.add(final_name)
        seen[key] = item
        selected.append(item)
        if source_index < incoming_count:
            added_from_incoming += 1

    # 使用名称中标注的 MB/s 全局降序；sort 是稳定排序，同速或无速度项沿用
    # “本次在前、历史在后”的顺序。
    selected = sort_by_speed(selected, proxy_name)

    # 配置端口、规则、分组名称和其他选项一律来自 JC 当日文件，避免旧历史
    # 文件成为过期骨架；只把聚合后的节点列表回填到当日结构。
    output = copy.deepcopy(incoming)
    output["proxies"] = selected
    groups = copy.deepcopy(incoming.get("proxy-groups") or [])
    if not isinstance(groups, list):
        raise ValueError("Clash proxy-groups 必须是列表")

    selected_names = [proxy_name(proxy) for proxy in selected]
    selected_name_set = set(selected_names)
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

        # 当日模板中的全局手动/自动组承载全部历史节点，并与 proxies 保持同序。
        if "手动选择" in group_name or "自动选择" in group_name:
            group["proxies"] = list(selected_names)
            continue

        # 当日已有的国家组按旗帜从全量节点中重建，因此组内也全局按速度有序。
        flag = leading_country_flag(group_name)
        if flag:
            regional = [name for name in selected_names if leading_country_flag(name) == flag]
            if regional:
                group["proxies"] = regional
            else:
                group["proxies"] = [
                    str(ref) for ref in refs if str(ref) in SPECIAL_PROXY_REFS
                ]
            continue

        # 服务分组和顶层入口等非节点组沿用当日规则，只修正重复节点别名并
        # 丢弃不再存在的节点引用；分组引用与 DIRECT/REJECT 等内置项保留。
        replaced: list[str] = []
        for ref in refs:
            ref_s = aliases.get(str(ref), str(ref))
            if ref_s in selected_name_set or ref_s in group_names or ref_s in SPECIAL_PROXY_REFS:
                if ref_s not in replaced:
                    replaced.append(ref_s)
        group["proxies"] = replaced

    output["proxy-groups"] = groups
    stats = {
        "incoming": incoming_count,
        "base": len(base_proxies),
        "final": len(selected),
        "added": added_from_incoming,
        "duplicates_removed": duplicate_count,
        "sort": "name-mb-s-desc-stable",
        "template": "incoming-daily",
    }
    return output, stats


def outbound_key(outbound: dict):
    return freeze(outbound, {"tag"})


def merge_singbox(base_path: Path, incoming_path: Path) -> tuple[dict, dict]:
    incoming = load_json(incoming_path)
    base = load_json(base_path) if base_path.exists() and base_path.stat().st_size else None
    incoming_items = incoming.get("outbounds") or []
    base_items = (base or {}).get("outbounds") or []
    selected: list[dict] = []
    seen = set()
    used_tags: set[str] = set()
    duplicates = 0
    added = 0

    for source_index, item in enumerate([*incoming_items, *base_items]):
        if not isinstance(item, dict):
            continue
        key = outbound_key(item)
        if key in seen:
            duplicates += 1
            continue
        item = copy.deepcopy(item)
        tag = str(item.get("tag") or f"{item.get('type', 'outbound')} {item.get('server', '')}:{item.get('server_port', '')}")
        final_tag = unique_name(tag, used_tags)
        item["tag"] = final_tag
        used_tags.add(final_tag)
        seen.add(key)
        selected.append(item)
        if source_index < len(incoming_items):
            added += 1

    selected = sort_by_speed(selected, lambda outbound: str(outbound.get("tag", "")))
    # Sing-box 的顶层选项也采用当日文件作为模板，历史合并只扩展 outbounds。
    output = copy.deepcopy(incoming)
    output["outbounds"] = selected
    return output, {
        "incoming": len(incoming_items),
        "base": len(base_items),
        "final": len(selected),
        "added": added,
        "duplicates_removed": duplicates,
    }


def v2ray_key(line: str):
    """尽量按连接参数而不是 fragment（节点名）去重。"""
    line = line.strip()
    if "://" not in line:
        return ("raw", line)
    try:
        parsed = urlsplit(line)
        scheme = parsed.scheme.lower()
        # vmess:// 有时是 base64 JSON；去掉 ps（节点名）后作为连接键。
        if scheme in {"vmess", "vmess1"}:
            import base64

            blob = parsed.netloc or parsed.path
            blob += "=" * (-len(blob) % 4)
            decoded = base64.urlsafe_b64decode(blob).decode("utf-8", "ignore")
            obj = json.loads(decoded)
            if isinstance(obj, dict):
                obj = {k: v for k, v in obj.items() if k not in {"ps", "name", "remark"}}
                return (scheme, freeze(obj))
        query = tuple(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
        return (
            scheme,
            (parsed.hostname or "").lower(),
            parsed.port,
            unquote(parsed.username or ""),
            unquote(parsed.password or ""),
            parsed.path,
            query,
        )
    except Exception:
        return ("raw", line)


def v2ray_name(line: str) -> str:
    try:
        return unquote(urlsplit(line).fragment)
    except Exception:
        return ""


def merge_v2ray(base_path: Path, incoming_path: Path) -> tuple[str, dict]:
    incoming_lines = [line.strip() for line in read_text(incoming_path).splitlines() if line.strip()]
    base_lines = [line.strip() for line in read_text(base_path).splitlines() if line.strip()] if base_path.exists() else []
    selected: list[str] = []
    seen = set()
    duplicates = 0
    added = 0
    for source_index, line in enumerate([*incoming_lines, *base_lines]):
        key = v2ray_key(line)
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        selected.append(line)
        if source_index < len(incoming_lines):
            added += 1
    selected = sort_by_speed(selected, v2ray_name)
    return "\n".join(selected) + ("\n" if selected else ""), {
        "incoming": len(incoming_lines),
        "base": len(base_lines),
        "final": len(selected),
        "added": added,
        "duplicates_removed": duplicates,
    }


def file_sha16(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def update_history(path: Path, meta: dict, clash_count: int) -> None:
    code = str(meta.get("code", ""))
    tier = str(meta.get("link_tier", ""))
    date = str(meta.get("date", "")) or datetime.now().strftime("%Y-%m-%d")
    entry = f"{date}  code={code}  nodes={clash_count}  tier={tier}"
    old = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    if not old or old[-1].strip() != entry:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(entry + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="把本次订阅和旧的综合订阅去重合并")
    ap.add_argument("--base", default="sub/merged", help="旧的综合订阅目录，默认 sub/merged")
    ap.add_argument("--out", default="", help="新的综合订阅目录，默认与 --base 相同")
    ap.add_argument("--incoming", required=True, help="本次抓取的临时目录")
    ap.add_argument("--history", default="history/codes.log", help="合并后的历史记录")
    args = ap.parse_args()

    base = Path(args.base)
    out = Path(args.out or args.base)
    incoming = Path(args.incoming)
    out.mkdir(parents=True, exist_ok=True)

    clash_stats = {}
    if (incoming / "clash.yaml").exists():
        clash, clash_stats = merge_clash(base / "clash.yaml", incoming / "clash.yaml")
        clash_bytes = yaml.dump(
            clash,
            Dumper=NoAliasDumper,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
            width=4096,
        ).encode("utf-8")
        atomic_write(out / "clash.yaml", clash_bytes)

    singbox_stats = {}
    if (incoming / "singbox.json").exists():
        singbox, singbox_stats = merge_singbox(base / "singbox.json", incoming / "singbox.json")
        atomic_write(
            out / "singbox.json",
            (json.dumps(singbox, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
        )

    v2ray_stats = {}
    if (incoming / "v2ray.txt").exists():
        v2ray_text, v2ray_stats = merge_v2ray(base / "v2ray.txt", incoming / "v2ray.txt")
        atomic_write(out / "v2ray.txt", v2ray_text.encode("utf-8"))

    meta = {}
    if (incoming / "meta.json").exists():
        meta = load_json(incoming / "meta.json")
    meta["merge"] = {
        "enabled": True,
        "policy": "current-incoming-template+speed-desc-stable-deduplicate",
        "ordering": {"field": "node-name MB/s", "direction": "descending", "missing": "stable-last"},
        "updated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "clash": clash_stats,
        "singbox": singbox_stats,
        "v2ray": v2ray_stats,
    }
    meta["nodes"] = {
        "clash": clash_stats.get("final", 0),
        "singbox": singbox_stats.get("final", 0),
        "v2ray": v2ray_stats.get("final", 0),
    }
    meta["fresh_nodes"] = {
        "clash": clash_stats.get("incoming", 0),
        "singbox": singbox_stats.get("incoming", 0),
        "v2ray": v2ray_stats.get("incoming", 0),
    }
    meta["sha256_16"] = {
        name: file_sha16(out / name)
        for name in ("clash.yaml", "singbox.json", "v2ray.txt")
        if (out / name).exists()
    }
    atomic_write(
        out / "meta.json",
        (json.dumps(meta, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )
    update_history(Path(args.history), meta, clash_stats.get("final", 0))

    print(f"✅ 去重合并完成（综合订阅写入 {out}；本次数据优先，不生成 archive）")
    for label, stats in (("Clash", clash_stats), ("Sing-box", singbox_stats), ("V2Ray", v2ray_stats)):
        if stats:
            print(
                f"  {label}: 本次 {stats['incoming']} + 旧 {stats['base']} "
                f"→ 合并后 {stats['final']}，本轮重复 {stats['duplicates_removed']}，新增 {stats['added']}"
            )
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write("## JCNode 去重合并\n\n")
            for label, stats in (("Clash", clash_stats), ("Sing-box", singbox_stats), ("V2Ray", v2ray_stats)):
                if stats:
                    fh.write(
                        f"- **{label}**：本次 `{stats['incoming']}` + 旧 `{stats['base']}` "
                        f"→ 合并后 `{stats['final']}`；新增 `{stats['added']}`\n"
                    )
            fh.write(f"- 综合订阅目录：`{out}`\n- 策略：本次数据优先，按连接参数去重，不生成 archive。\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
