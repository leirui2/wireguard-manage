"""界面偏好、托盘图标、开机自启的单元测试。

注意：这里不真的启动托盘、也不真的写注册表 ——
测试跑在开发机上，不该污染用户环境。
"""
import json
import os
import sys
import tempfile
import unittest

from wgmanager import autostart, tray
from wgmanager.settings import DEFAULTS, Settings


class SettingsTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()


class TestSettings(SettingsTestCase):
    def test_defaults_when_no_file(self):
        s = Settings(self.tmp.name)
        self.assertEqual(s.get("minimize_to_tray"), True)
        self.assertEqual(s.get("monitor_interval"), 60)
        self.assertFalse(os.path.exists(s.path))

    def test_set_persists(self):
        s = Settings(self.tmp.name)
        s.set("monitor_interval", 120)
        again = Settings(self.tmp.name)
        self.assertEqual(again.get("monitor_interval"), 120)

    def test_set_writes_valid_json(self):
        s = Settings(self.tmp.name)
        s.set("autostart", True)
        with open(s.path, encoding="utf-8") as f:
            raw = json.load(f)
        self.assertIs(raw["autostart"], True)

    def test_unknown_keys_ignored(self):
        path = os.path.join(self.tmp.name, "settings.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"未来版本加的键": 1, "monitor_interval": 30}, f)
        s = Settings(self.tmp.name)
        self.assertEqual(s.get("monitor_interval"), 30)
        self.assertNotIn("未来版本加的键", s.data)

    def test_corrupt_file_falls_back(self):
        path = os.path.join(self.tmp.name, "settings.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write("{这不是 JSON")
        s = Settings(self.tmp.name)
        self.assertEqual(s.get("monitor_interval"), 60)

    def test_partial_file_uses_defaults(self):
        path = os.path.join(self.tmp.name, "settings.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"minimize_to_tray": False}, f)
        s = Settings(self.tmp.name)
        self.assertFalse(s.get("minimize_to_tray"))
        self.assertEqual(s.get("monitor_interval"), 60)

    def test_get_default_argument(self):
        s = Settings(self.tmp.name)
        self.assertEqual(s.get("不存在的键", "兜底"), "兜底")

    def test_all_defaults_present(self):
        s = Settings(self.tmp.name)
        for key in DEFAULTS:
            self.assertIsNotNone(s.data.get(key))


class TestTrayIcon(unittest.TestCase):
    def test_available(self):
        # vendor 里装了 pystray 和 Pillow，应该可用
        self.assertTrue(tray.available())

    def test_icon_size_and_mode(self):
        img = tray._icon_image()
        self.assertEqual(img.size, (64, 64))
        self.assertEqual(img.mode, "RGBA")

    def test_icon_has_transparent_corner(self):
        img = tray._icon_image()
        corner = img.getpixel((0, 0))
        self.assertEqual(corner[3], 0, "四个角应该是透明的（圆底）")

    def test_icon_center_is_opaque(self):
        img = tray._icon_image()
        center = img.getpixel((32, 32))
        self.assertEqual(center[3], 255)

    def test_colors_differ(self):
        ok = tray._icon_image(tray.COLOR_OK)
        alert = tray._icon_image(tray.COLOR_ALERT)
        self.assertNotEqual(ok.getpixel((6, 32)), alert.getpixel((6, 32)))


class TestAutostart(unittest.TestCase):
    def test_available_on_windows(self):
        self.assertEqual(autostart.available(), sys.platform == "win32")

    def test_source_mode_not_supported(self):
        # 测试跑在源码里，不该声称支持 —— 写进去会是 python.exe
        ok, reason = autostart.supported()
        self.assertFalse(ok)
        self.assertIn("exe", reason)

    def test_enable_refuses_in_source_mode(self):
        ok, msg = autostart.enable()
        self.assertFalse(ok)
        self.assertTrue(msg)

    def test_is_enabled_does_not_raise(self):
        self.assertIsInstance(autostart.is_enabled(), bool)

    def test_current_target_does_not_raise(self):
        self.assertIsInstance(autostart.current_target(), str)

    def test_app_name_is_ascii(self):
        # 注册表值名用中文在某些系统区域设置下会出怪问题
        self.assertTrue(autostart.APP_NAME.isascii())


if __name__ == "__main__":
    unittest.main()
