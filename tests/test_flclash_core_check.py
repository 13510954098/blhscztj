import socket
import tempfile
import unittest
from pathlib import Path

import yaml

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import flclash_core_check as flcheck


class FlClashIPCFrameTests(unittest.TestCase):
    def test_length_prefixed_frame_round_trip(self):
        left, right = socket.socketpair()
        try:
            payload = b'{"id":"test","method":"validateConfig"}'
            left.sendall(flcheck.encode_frame(payload))
            self.assertEqual(flcheck.read_frame(right), payload)
        finally:
            left.close()
            right.close()

    def test_oversized_frame_is_rejected(self):
        original = flcheck.MAX_FRAME_SIZE
        try:
            flcheck.MAX_FRAME_SIZE = 3
            with self.assertRaises(ValueError):
                flcheck.encode_frame(b"four")
        finally:
            flcheck.MAX_FRAME_SIZE = original

    def test_extracts_proxy_names_for_runtime_core_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profile.yaml"
            path.write_text(yaml.safe_dump({"proxies": [
                {"name": "node-a", "type": "http", "server": "a.example", "port": 443},
                {"name": "🇶🇦 卡塔尔", "type": "vless", "server": "b.example", "port": 443},
            ]}, allow_unicode=True), encoding="utf-8")
            self.assertEqual(flcheck._profile_proxy_names(path), ["node-a", "🇶🇦 卡塔尔"])

    def test_duplicate_proxy_names_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profile.yaml"
            path.write_text(yaml.safe_dump({"proxies": [
                {"name": "duplicate", "type": "http", "server": "a.example", "port": 443},
                {"name": "duplicate", "type": "http", "server": "b.example", "port": 443},
            ]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate proxy names"):
                flcheck._profile_proxy_names(path)


if __name__ == "__main__":
    unittest.main()
