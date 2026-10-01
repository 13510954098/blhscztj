#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate generated Clash profiles with FlClash's bundled core via its IPC API.

This exercises the same FlClashCore methods used by the desktop client:
validateConfig, then (for the selected runtime profile) initClash/setupConfig/getProxies
and a small asyncTestDelay smoke sample. It is intentionally not a GUI automation test.
"""
from __future__ import annotations

import argparse
import json
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

MAX_FRAME_SIZE = 64 * 1024 * 1024
DEFAULT_TEST_URL = "https://www.gstatic.com/generate_204"


def encode_frame(payload: bytes) -> bytes:
    if len(payload) > MAX_FRAME_SIZE:
        raise ValueError(f"IPC frame exceeds {MAX_FRAME_SIZE} bytes")
    return struct.pack("<I", len(payload)) + payload


def _read_exact(conn: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = conn.recv(remaining)
        if not chunk:
            raise EOFError("FlClashCore closed its IPC connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(conn: socket.socket) -> bytes:
    size = struct.unpack("<I", _read_exact(conn, 4))[0]
    if size > MAX_FRAME_SIZE:
        raise ValueError(f"IPC frame exceeds {MAX_FRAME_SIZE} bytes")
    return _read_exact(conn, size)


class FlClashCoreRPC:
    """Minimal host side for the length-prefixed JSON IPC used by FlClashCore."""

    def __init__(self, binary: Path, timeout: float = 180.0):
        self.binary = Path(binary).resolve()
        self.timeout = timeout
        self._tmp = None
        self._server = None
        self._conn = None
        self._process = None
        self._log = None
        self._request_id = 0

    def __enter__(self):
        if not self.binary.is_file():
            raise FileNotFoundError(f"FlClashCore binary not found: {self.binary}")
        self._tmp = tempfile.TemporaryDirectory(prefix="fc-ipc-")
        root = Path(self._tmp.name)
        address = str(root / "core.sock")
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(address)
        self._server.listen(1)
        self._server.settimeout(30.0)
        self._log = (root / "core.log").open("wb")
        try:
            self._process = subprocess.Popen(
                [str(self.binary), address],
                stdin=subprocess.DEVNULL,
                stdout=self._log,
                stderr=subprocess.STDOUT,
                close_fds=True,
            )
            self._conn, _ = self._server.accept()
            self._conn.settimeout(self.timeout)
        except Exception:
            self.close()
            raise
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def _log_tail(self, max_lines: int = 30) -> str:
        if self._tmp is None:
            return ""
        try:
            path = Path(self._tmp.name) / "core.log"
            return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-max_lines:])
        except OSError:
            return ""

    def call(self, method: str, arguments=None):
        if self._conn is None:
            raise RuntimeError("FlClashCore IPC is not connected")
        self._request_id += 1
        request_id = f"arena-{self._request_id}"
        payload = json.dumps(
            {"id": request_id, "method": method, "arguments": arguments},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        self._conn.sendall(encode_frame(payload))
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                message = json.loads(read_frame(self._conn).decode("utf-8"))
            except (OSError, EOFError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError(
                    f"FlClashCore IPC failed during {method}: {exc}\n{self._log_tail()}"
                ) from exc
            if message.get("id") == request_id:
                if message.get("error"):
                    err = message["error"]
                    raise RuntimeError(
                        f"FlClashCore {method} failed: {err.get('message', err)}"
                    )
                return message.get("result")
            # Unsolicited log/provider events are part of the same IPC stream.
        raise TimeoutError(f"FlClashCore {method} timed out after {self.timeout:g}s\n{self._log_tail()}")

    def close(self):
        if self._conn is not None:
            try:
                self._conn.close()
            except OSError:
                pass
            self._conn = None
        if self._process is not None:
            if self._process.poll() is None:
                self._process.terminate()
                try:
                    self._process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait(timeout=5)
            self._process = None
        if self._server is not None:
            self._server.close()
            self._server = None
        if self._log is not None:
            self._log.close()
            self._log = None
        if self._tmp is not None:
            self._tmp.cleanup()
            self._tmp = None


def _profile_proxy_names(path: Path) -> list[str]:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Cannot parse {path}: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("proxies"), list):
        raise ValueError(f"{path}: expected a Clash document with a proxies list")
    names = [p.get("name") for p in doc["proxies"] if isinstance(p, dict)]
    if any(not isinstance(name, str) or not name for name in names):
        raise ValueError(f"{path}: at least one proxy has no non-empty name")
    if len(names) != len(set(names)):
        raise ValueError(f"{path}: duplicate proxy names prevent reliable FlClash lookup")
    return names


def _copy_flclash_assets(assets_dir: Path, home_dir: Path) -> None:
    if not assets_dir.is_dir():
        raise FileNotFoundError(f"FlClash resource directory not found: {assets_dir}")
    for item in assets_dir.iterdir():
        if item.is_file():
            shutil.copy2(item, home_dir / item.name)


def validate_with_flclash_core(
    core_binary: Path,
    config_paths: list[Path],
    runtime_config: Path | None = None,
    assets_dir: Path | None = None,
    test_url: str = DEFAULT_TEST_URL,
    timeout_ms: int = 8000,
    delay_samples: int = 3,
) -> dict:
    """Use the packaged FlClash core to validate profiles and load/test alive output."""
    paths = [Path(p).resolve() for p in config_paths]
    if not paths:
        raise ValueError("At least one Clash config path is required")
    for path in paths:
        if not path.is_file() or path.stat().st_size == 0:
            raise FileNotFoundError(f"Clash config missing or empty: {path}")

    runtime_path = Path(runtime_config).resolve() if runtime_config else None
    expected_names = _profile_proxy_names(runtime_path) if runtime_path else []
    if runtime_path and runtime_path not in paths:
        paths.append(runtime_path)
    if runtime_path and assets_dir is None:
        raise ValueError("--assets is required when --runtime-config is used")

    report = {"validated": [], "runtime_loaded": 0, "delay_samples": []}
    with FlClashCoreRPC(core_binary) as core:
        for path in paths:
            result = core.call("validateConfig", str(path))
            if result not in ("", None):
                raise RuntimeError(f"FlClashCore rejected {path}: {result}")
            print(f"FlClashCore validateConfig: OK — {path}")
            report["validated"].append(str(path))

        if runtime_path is None:
            return report

        with tempfile.TemporaryDirectory(prefix="flclash-home-") as home_tmp:
            home = Path(home_tmp)
            shutil.copy2(runtime_path, home / "config.yaml")
            _copy_flclash_assets(Path(assets_dir).resolve(), home)

            initialized = core.call(
                "initClash", {"home-dir": str(home), "version": 0}
            )
            if initialized is not True:
                raise RuntimeError(f"FlClashCore initClash failed: {initialized!r}")
            setup_result = core.call(
                "setupConfig", {"selected-map": {}, "test-url": test_url}
            )
            if setup_result not in ("", None):
                raise RuntimeError(f"FlClashCore setupConfig failed: {setup_result}")

            proxies_data = core.call("getProxies")
            loaded = set((proxies_data or {}).get("proxies", {}))
            missing = sorted(set(expected_names) - loaded)
            if missing:
                raise RuntimeError(
                    f"FlClashCore loaded only {len(expected_names) - len(missing)} / "
                    f"{len(expected_names)} profile proxies; missing examples: {missing[:5]}"
                )
            report["runtime_loaded"] = len(expected_names)
            print(
                f"FlClashCore setupConfig/getProxies: loaded all "
                f"{len(expected_names)} profile proxies"
            )

            sample_names = expected_names[:max(0, delay_samples)]
            if sample_names:
                successful = 0
                for name in sample_names:
                    last_result = None
                    for attempt in range(2):
                        last_result = core.call(
                            "asyncTestDelay",
                            {
                                "proxy-name": name,
                                "test-url": test_url,
                                "timeout": int(timeout_ms),
                            },
                        )
                        delay = (last_result or {}).get("value", -1)
                        if isinstance(delay, (int, float)) and delay >= 0:
                            successful += 1
                            print(f"FlClashCore asyncTestDelay: OK — {name}: {delay} ms")
                            break
                        if attempt == 0:
                            print(f"FlClashCore asyncTestDelay retry: {name}")
                    else:
                        print(f"⚠️ FlClashCore asyncTestDelay timed out: {name}: {last_result}")
                    report["delay_samples"].append(
                        {"name": name, "result": last_result}
                    )
                if successful == 0:
                    raise RuntimeError(
                        f"FlClashCore loaded the profile but none of {len(sample_names)} "
                        "sample proxies passed its built-in delay test"
                    )
                report["delay_samples_passed"] = successful
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate Clash profiles using the FlClash bundled core IPC"
    )
    parser.add_argument("--core", required=True, type=Path, help="Extracted FlClashCore binary")
    parser.add_argument("--assets", type=Path, help="FlClash bundled data directory (required for runtime load)")
    parser.add_argument("--runtime-config", type=Path, help="Profile to apply/load and test with FlClashCore")
    parser.add_argument("--test-url", default=DEFAULT_TEST_URL)
    parser.add_argument("--timeout-ms", type=int, default=8000)
    parser.add_argument("--delay-samples", type=int, default=3)
    parser.add_argument("configs", nargs="+", type=Path, help="Clash YAML files to validate")
    args = parser.parse_args()
    try:
        validate_with_flclash_core(
            args.core,
            args.configs,
            runtime_config=args.runtime_config,
            assets_dir=args.assets,
            test_url=args.test_url,
            timeout_ms=args.timeout_ms,
            delay_samples=args.delay_samples,
        )
    except (OSError, ValueError, RuntimeError, TimeoutError) as exc:
        print(f"❌ FlClashCore compatibility check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
