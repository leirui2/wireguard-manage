"""分发卡片（card.py）的测试：Endpoint 解析、图片尺寸、异常输入。"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "vendor")):
    if path not in sys.path:
        sys.path.insert(0, path)

from wgmanager.card import endpoint_of, render_card  # noqa: E402

CONF = """[Interface]
PrivateKey = aBcD1234fakeKeyForTestingOnly=
Address = 10.8.0.5/32
DNS = 1.1.1.1

[Peer]
PublicKey = ServerPubKeyExample=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 111.38.183.123:51820
"""


class EndpointParse(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(endpoint_of(CONF), "111.38.183.123:51820")

    def test_ipv6_bracket(self):
        text = "Endpoint = [fd08::1]:51820\n"
        self.assertEqual(endpoint_of(text), "[fd08::1]:51820")

    def test_extra_spaces(self):
        self.assertEqual(endpoint_of("Endpoint    =   1.2.3.4:1234  \n"),
                         "1.2.3.4:1234")

    def test_missing(self):
        self.assertEqual(endpoint_of("[Interface]\nAddress = 10.0.0.1/32\n"), "")
        self.assertEqual(endpoint_of(""), "")

    def test_case_insensitive_key(self):
        self.assertEqual(endpoint_of("endpoint = 9.9.9.9:1"), "9.9.9.9:1")


@unittest.skipUnless(
    __import__("importlib").util.find_spec("PIL") is not None, "需要 Pillow"
)
class RenderCard(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="wgm-card-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_render_to_file(self):
        from PIL import Image

        path = os.path.join(self.dir, "card.png")
        out = render_card(CONF, name="张三-手机", note="研发部", out_path=path)
        self.assertEqual(out, path)
        self.assertTrue(os.path.isfile(path))
        with Image.open(path) as img:
            self.assertEqual(img.format, "PNG")
            width, height = img.size
        self.assertEqual(width, 600)
        self.assertGreater(height, 600)
        self.assertLess(height, 1200)

    def test_render_without_name_and_note(self):
        from PIL import Image

        path = os.path.join(self.dir, "bare.png")
        render_card(CONF, out_path=path)
        with Image.open(path) as img:
            self.assertLess(img.size[1], 900, "没有名称/备注时卡片不该那么高")

    def test_render_returns_base64_when_no_path(self):
        import base64

        blob = render_card(CONF, name="x")
        raw = base64.b64decode(blob)
        self.assertEqual(raw[:8], b"\x89PNG\r\n\x1a\n")

    def test_empty_conf_raises(self):
        with self.assertRaises(ValueError):
            render_card("")
        with self.assertRaises(ValueError):
            render_card("   \n  ")

    def test_long_note_does_not_crash(self):
        path = os.path.join(self.dir, "long.png")
        render_card(CONF, name="一个特别特别长的密钥名称用来测试排版",
                    note="备注" * 40, out_path=path)
        self.assertTrue(os.path.isfile(path))


if __name__ == "__main__":
    unittest.main()
