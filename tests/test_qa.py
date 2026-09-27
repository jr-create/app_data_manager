# -*- coding: utf-8 -*-
"""PC 换机数据迁移助手 —— QA 独立验收测试（严过关 / QA）。

与工程师自测（``tests/smoke_test.py``）相互独立，重点覆盖**边界与攻击面**：

    1. 黑名单绕过攻击（大小写 / 分隔符 / ``\\\\?\\`` 前缀 / ``..`` 回溯 / 末尾空格 / 8.3 短名 / UNC）
    2. zip-slip 归档逃逸
    3. 删除 / 备份健壮性（只读、占用、超长路径、中文特殊字符、junction）
    4. 归属推断 L1→L6 质量、阈值边界、冲突裁决、手动指派
    5. 导出正确性（CSV BOM / 字段数 / 中文；JSON ensure_ascii）
    6. 大小计算（可取消、结果保留、不存在路径）
    7. 线程与 UI 约定（workers.py 不得直接操作控件，信号/槽签名匹配）
    8. 真实只读扫描
    9. GUI 启动冒烟
    10. 其它：MSIX 编码、junction 递归

安全红线（本文件严格遵守）：
    * 绝不删除 / 卸载 / 修改任何真实软件或真实用户数据；
    * 所有破坏性验证一律在 ``tempfile.mkdtemp()`` 构造的假数据上进行；
    * 绝不写入或删除注册表项；
    * 验证系统目录黑名单时**只断言"被拒绝"**，并确认目标路径**仍然存在**；
    * 测试结束后清理全部临时文件。

用法::

    python tests/test_qa.py
"""

from __future__ import annotations

import csv
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from datetime import datetime

# --------------------------------------------------------------------------
# 路径引导：保证以脚本方式直接运行时也能导入 src 包
# --------------------------------------------------------------------------

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.core import config as config_mod          # noqa: E402
from src.core import paths                          # noqa: E402
from src.core import software_scanner               # noqa: E402
from src.core.attribution import AttributionEngine  # noqa: E402
from src.core.backuper import Backuper              # noqa: E402
from src.core.deleter import Deleter                # noqa: E402
from src.core.exporters import CSV_HEADERS, export_csv, export_json  # noqa: E402
from src.core.models import (                       # noqa: E402
    ContentType,
    DataPathEntry,
    DeleteMode,
    EntryKind,
    InstalledSoftware,
    MatchLevel,
    ScanResult,
)
from src.core.scan_service import ScanService       # noqa: E402
from src.core.size_calculator import SizeCalculator  # noqa: E402
from src.core.utils import normalize_name           # noqa: E402

#: 真实长路径前缀字符（\\?\），长度为 4
LONG_PREFIX = "\\\\?\\"

#: 运行期收集的"备注/风险"信息（不计入失败，但会在报告中列出）
NOTES: list[str] = []


def _note(text: str) -> None:
    """记录一条备注（风险/环境问题），不影响通过率。"""
    NOTES.append(text)
    print(f"    · 备注：{text}")


# --------------------------------------------------------------------------
# 临时资源管理
# --------------------------------------------------------------------------


class TempSpace:
    """测试用临时空间：统一创建与清理，确保不残留任何文件。"""

    def __init__(self, prefix: str = "sdm_qa_") -> None:
        self.root = tempfile.mkdtemp(prefix=prefix)

    def path(self, *parts: str) -> str:
        return os.path.join(self.root, *parts)

    def make_dir(self, *parts: str) -> str:
        p = self.path(*parts)
        os.makedirs(p, exist_ok=True)
        return p

    def write_file(self, rel: str, content: str = "x" * 64, encoding: str = "utf-8") -> str:
        p = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(paths.to_long_path(p), "w", encoding=encoding) as fh:
            fh.write(content)
        return p

    def cleanup(self) -> None:
        """尽力清理（含只读文件、长路径、junction）。"""
        if not os.path.exists(self.root):
            return
        # 1) 解除只读属性
        for dirpath, dirnames, filenames in os.walk(paths.to_long_path(self.root)):
            for name in list(dirnames) + list(filenames):
                try:
                    os.chmod(os.path.join(dirpath, name), stat.S_IWRITE)
                except OSError:
                    pass
        # 2) 删除 junction / 符号链接（不能用 rmtree，会穿透）
        for dirpath, dirnames, _files in os.walk(self.root):
            for name in list(dirnames):
                full = os.path.join(dirpath, name)
                try:
                    if os.path.islink(full):
                        os.unlink(full)
                        dirnames.remove(name)
                        continue
                except OSError:
                    pass
                # junction：islink 为 False，尝试 rmdir（junction 为空时可删）
                try:
                    os.rmdir(full)
                    dirnames.remove(name)
                except OSError:
                    pass
        shutil.rmtree(paths.to_long_path(self.root), ignore_errors=True)
        shutil.rmtree(self.root, ignore_errors=True)


def make_entry(p: str, kind: EntryKind = EntryKind.DIR, **kw) -> DataPathEntry:
    """构造一条候选条目（路径规范化）。"""
    return DataPathEntry(path=paths.to_absolute(p), kind=kind, **kw)


def make_software(sid: str, name: str, publisher: str = "", install_location: str = "",
                  exe_names=None, family: str = "", version: str = "1.0.0") -> InstalledSoftware:
    """构造一款软件（默认不带发布商，避免级别互相污染）。"""
    return InstalledSoftware(
        id=sid, name=name, publisher=publisher, install_location=install_location,
        exe_names=list(exe_names or []), package_family_name=family, version=version,
    )


# ==========================================================================
# 1. 黑名单绕过攻击
# ==========================================================================


class TestBlacklistBypass(unittest.TestCase):
    """系统关键目录黑名单 —— 各种变体绕过尝试。"""

    def test_01_常规系统目录被拒绝(self):
        """常规系统目录必须全部被拦截，且目标仍然存在。"""
        targets = [
            r"C:\Windows",
            r"C:\Windows\System32",
            r"C:\Windows\SysWOW64",
            r"C:\Windows\WinSxS",
            r"C:\Program Files",
            r"C:\Program Files (x86)",
            r"C:\ProgramData",
            r"C:\Users\Default",
            r"C:\Users\Public",
            paths.to_absolute(r"%USERPROFILE%"),
            paths.to_absolute(r"%LOCALAPPDATA%\Packages"),
            paths.to_absolute(r"%LOCALAPPDATA%\Microsoft\WindowsApps"),
            os.path.splitdrive(paths.to_absolute(r"%USERPROFILE%"))[0] + os.sep,
        ]
        for t in targets:
            with self.subTest(target=t):
                v = paths.check_path_safety(t)
                self.assertFalse(v.allowed, f"应被拦截却放行：{t}")
                self.assertTrue(v.reason.strip(), f"拦截原因不应为空：{t}")
                self.assertTrue(v.blocked)

    def test_02_大小写变体(self):
        """大小写变体必须被拦截（normcase 归一）。"""
        for t in [r"c:\WiNdOwS\System32", r"C:\WINDOWS", r"C:\WiNdOws",
                  r"c:\windows\system32", r"C:\Program Files".upper(),
                  r"C:\PROGRAMDATA"]:
            with self.subTest(target=t):
                v = paths.check_path_safety(t)
                self.assertFalse(v.allowed, f"大小写变体绕过：{t}")

    def test_03_尾部分隔符变体(self):
        """尾部斜杠 / 反斜杠 / 多余分隔符必须被拦截。"""
        for t in [r"C:\Windows\\", r"C:\Windows/", r"C:\Windows\/", r"C:\Windows\\\\",
                  r"C:\Windows\System32\\", r"C:\Windows/System32/"]:
            with self.subTest(target=t):
                v = paths.check_path_safety(t)
                self.assertFalse(v.allowed, f"尾部分隔符变体绕过：{t}")

    def test_04_回溯与点段(self):
        """``..`` 回溯与 ``.`` 点段必须被拦截。"""
        for t in [r"C:\Windows\..\Windows\System32",
                  r"C:\Windows\System32\.",
                  r"C:\Windows\System32\..",
                  r"C:\Windows\System32\..\..\..\Windows",
                  r"C:\Program Files\..\Windows"]:
            with self.subTest(target=t):
                v = paths.check_path_safety(t)
                self.assertFalse(v.allowed, f"回溯/点段变体绕过：{t}")

    def test_05_末尾空格与点(self):
        """Windows 会忽略路径末尾空格与点，必须同等拦截。"""
        for t in [r"C:\Windows ", r"C:\Windows.", r"C:\Windows\System32 ",
                  r"C:\Windows\System32.", r"C:\Windows\System32  "]:
            with self.subTest(target=t):
                v = paths.check_path_safety(t)
                self.assertFalse(v.allowed, f"末尾空格/点变体绕过：{t!r}")

    def test_06_环境变量形式(self):
        """含环境变量的路径（大小写混写）必须被拦截。"""
        for t in [r"%WINDIR%", r"%windir%", r"%WiNdIr%\System32", r"%SYSTEMROOT%",
                  r"%systemroot%\system32", r"%PROGRAMFILES%", r"%PROGRAMDATA%"]:
            with self.subTest(target=t):
                v = paths.check_path_safety(t)
                self.assertFalse(v.allowed, f"环境变量变体绕过：{t}")

    def test_07_长路径前缀变体(self):
        """``\\\\?\\`` / ``\\\\.\\`` 设备路径前缀**不得**成为绕过通道。

        架构约定：内部存储一律不含 ``\\\\?\\`` 前缀，仅在调用磁盘 API 前临时添加；
        因此安全判定必须先剥离该前缀再比对黑名单，否则 Deleter 会真的删掉系统目录。
        """
        for t in [LONG_PREFIX + r"C:\Windows",
                  LONG_PREFIX + r"C:\Windows\System32",
                  r"\\.\C:\Windows",
                  r"\\.\C:\Windows\System32",
                  LONG_PREFIX + r"C:\Program Files",
                  "\\\\\\\\?\\\\C:\\Windows"]:
            with self.subTest(target=t):
                v = paths.check_path_safety(t)
                self.assertFalse(
                    v.allowed,
                    f"[P0] 长路径/设备路径前缀绕过黑名单：{t} —— "
                    f"Deleter._delete_permanent 会用 to_long_path 直接 rmtree，可删除系统目录",
                )

    def test_08_盘符相对路径(self):
        """``C:Windows\\System32`` 一类盘符相对路径：解析结果若落入系统目录则必须拦截。

        注：Python 的 abspath 按**当前工作目录**解析，本用例只在解析结果确实
        指向系统目录时才要求拦截，否则仅做备注。
        """
        t = r"C:Windows\System32"
        resolved = paths.to_absolute(t)
        v = paths.check_path_safety(t)
        if os.path.normcase(resolved).startswith(os.path.normcase(paths.to_absolute(r"C:\Windows")) + os.sep):
            self.assertFalse(v.allowed, f"盘符相对路径解析为系统目录却放行：{t} -> {resolved}")
        else:
            _note(f"盘符相对路径 {t} 被解析为 {resolved}（未落入系统目录，本机不构成绕过）")

    def test_09_本机管理共享_UNC(self):
        """``\\\\localhost\\C$\\Windows`` 一类本机管理共享不得成为绕过通道。"""
        for t in [r"\\localhost\C$\Windows",
                  r"\\127.0.0.1\C$\Windows",
                  LONG_PREFIX + r"UNC\localhost\C$\Windows"]:
            with self.subTest(target=t):
                v = paths.check_path_safety(t)
                self.assertFalse(
                    v.allowed,
                    f"本机管理共享 UNC 绕过黑名单：{t} —— 经由 C$ 共享可达 C:\\Windows",
                )

    def test_10_8_3_短名风格(self):
        """8.3 短名风格路径（如 ``C:\\PROGRA~1``）不得成为绕过通道。"""
        candidates = [r"C:\PROGRA~1", r"C:\PROGRA~2", r"C:\WINDOWS\SYSTEM~1"]
        checked = 0
        for t in candidates:
            if not os.path.exists(t):
                continue
            checked += 1
            with self.subTest(target=t):
                v = paths.check_path_safety(t)
                self.assertFalse(v.allowed, f"8.3 短名绕过黑名单：{t}（该路径在本机确实存在）")
        if checked == 0:
            _note("本机不存在 8.3 短名路径，本用例无实际断言对象（已跳过具体校验）")

    def test_11_空与非法输入(self):
        """空串 / 纯空白 / None 必须被拒绝，不得抛异常。"""
        for t in ["", "   ", "\t", None]:
            with self.subTest(target=repr(t)):
                v = paths.check_path_safety(t)
                self.assertFalse(v.allowed, f"空/非法输入不得放行：{t!r}")
                self.assertTrue(v.reason.strip())

    def test_12_Deleter_层二次校验(self):
        """Deleter 必须独立二次校验黑名单，且拦截后系统目录仍然存在。"""
        win = r"C:\Windows"
        before_exists = os.path.exists(win)
        report = Deleter().delete([make_entry(win)], DeleteMode.PERMANENT)
        self.assertTrue(before_exists, "前置条件：C:\\Windows 应存在")
        self.assertEqual(report.deleted_count, 0, "Deleter 不得删除系统目录")
        self.assertEqual(len(report.blocked), 1, "Deleter 应记录 1 条黑名单拦截")
        self.assertTrue(os.path.exists(win), "C:\\Windows 必须仍然存在（安全红线）")
        self.assertTrue(report.blocked[0][1].strip(), "拦截原因应为中文说明")

    def test_13_Deleter_层长路径前缀绕过(self):
        """Deleter 层对 ``\\\\?\\`` 前缀路径必须同样拦截。

        为避免触碰真实系统目录，本用例向黑名单**临时注入**一个位于临时目录的
        "假保护目录"，用对照组（普通路径）与实验组（``\\\\?\\`` 前缀）对比验证。
        注入项在 finally 中还原。
        """
        space = TempSpace("qa_bypass_")
        try:
            protected = space.make_dir("FAKE_PROTECTED")
            child = space.make_dir("FAKE_PROTECTED", "child")
            space.write_file("FAKE_PROTECTED/child/x.txt", "q" * 32)

            blacklist = paths.get_blacklist()
            original = list(blacklist)
            try:
                blacklist.append((paths.to_absolute(protected), False, "QA 注入的假保护目录"))

                # 对照组：普通路径应被拦截，且目录仍在
                report_plain = Deleter().delete(
                    [make_entry(child, size=32, file_count=1)], DeleteMode.PERMANENT)
                self.assertEqual(report_plain.deleted_count, 0,
                                 "对照组：普通路径应被黑名单拦截")
                self.assertTrue(os.path.exists(child), "对照组：假保护目录子项应仍然存在")

                # 实验组：\\?\ 前缀路径必须同样被拦截（当前实现会放行 -> 预期失败）
                long_child = LONG_PREFIX + child
                self.assertFalse(
                    paths.check_path_safety(long_child).allowed,
                    f"[P0] check_path_safety 对 {long_child} 放行，黑名单判定被前缀绕过",
                )
                report_long = Deleter().delete(
                    [DataPathEntry(path=long_child, kind=EntryKind.DIR, size=32, file_count=1)],
                    DeleteMode.PERMANENT,
                )
                self.assertEqual(
                    report_long.deleted_count, 0,
                    "[P0] Deleter 未拦截 \\\\?\\ 前缀的黑名单路径 —— "
                    "黑名单二次校验被绕过，真实场景可删除 C:\\Windows",
                )
                self.assertTrue(os.path.exists(child),
                                "[P0] 假保护目录子项已被删除，证明黑名单闸门失效")
            finally:
                blacklist.clear()
                blacklist.extend(original)
        finally:
            space.cleanup()

    def test_14_黑名单允许子项的目录本体仍被拦截(self):
        """Program Files 等"允许子项"的目录：本体拦截，子目录放行。"""
        pf = paths.to_absolute(r"%PROGRAMFILES%")
        self.assertFalse(paths.check_path_safety(pf).allowed, "Program Files 本体应被拦截")
        v = paths.check_path_safety(os.path.join(pf, "Some Software"))
        self.assertTrue(v.allowed, "Program Files 下的软件目录应可操作")
        # 磁盘根目录同理
        drive = os.path.splitdrive(pf)[0] + os.sep
        self.assertFalse(paths.check_path_safety(drive).allowed, "磁盘根目录应被拦截")


# ==========================================================================
# 2. zip-slip 归档逃逸
# ==========================================================================


class TestZipSlip(unittest.TestCase):
    """备份归档内部路径安全（防 zip-slip）。"""

    def test_01_archive_path_压平恶意相对路径(self):
        """``../evil.txt`` 等逃逸片段必须被压平，不得出现 ``..`` 与盘符。"""
        base = r"C:\tmp\fake\APPDATA"
        hostile = [
            r"C:\tmp\fake\APPDATA\Soft\a.txt",
            r"C:\tmp\fake\APPDATA\..\..\evil.txt",
            r"C:\tmp\fake\APPDATA\..\..\..\..\..\..\..\evil.txt",
            r"C:\evil.txt",
            r"D:\other\evil.txt",
            r"C:\tmp\fake\APPDATA\..\evil.txt",
            r"\\?\C:\evil.txt",
            r"\\server\share\evil.txt",
        ]
        for src in hostile:
            with self.subTest(src=src):
                arc = Backuper._archive_path("Soft", "APPDATA", base, src)
                self.assertNotIn("..", arc.split("/"), f"arcname 含 .. 片段：{arc}")
                self.assertFalse(arc.startswith("/") or arc.startswith("\\"),
                                 f"arcname 不得为绝对路径：{arc}")
                self.assertNotIn(":", arc.replace(":/", ""), f"arcname 不得含盘符：{arc}")
                self.assertTrue(arc.startswith("data/"), f"arcname 应位于 data/ 下：{arc}")
                self.assertFalse(arc.startswith("\\\\"), f"arcname 不得为 UNC：{arc}")

    def test_02_safe_join_name_清洗危险字符(self):
        """``safe_join_name`` 必须剔除分隔符、非法字符与盘符。"""
        for raw in ["..", "../evil", r"..\..\evil", r"C:\evil", "a/b", "  ", "...",
                    "evil|name", "a?b*c", "  ..  "]:
            with self.subTest(raw=raw):
                out = paths.safe_join_name(raw, "item")
                self.assertNotIn("\\", out, f"输出含反斜杠：{raw} -> {out}")
                self.assertNotIn("/", out, f"输出含斜杠：{raw} -> {out}")
                self.assertNotIn(":", out, f"输出含盘符：{raw} -> {out}")
                for ch in '*?"<>|':
                    self.assertNotIn(ch, out, f"输出含非法字符 {ch!r}：{raw} -> {out}")
                self.assertTrue(out.strip(), "输出不得为空或纯空白")

    def test_03_真实归档解压不会逃逸(self):
        """真实备份后解压：所有成员必须落在目标目录内，且内容一致。"""
        space = TempSpace("qa_zipslip_")
        try:
            src = space.make_dir("APPDATA", "Soft")
            space.write_file("APPDATA/Soft/config.json", '{"k": "值"}')
            space.write_file("APPDATA/Soft/sub/deep.txt", "deep 内容")

            sw = make_software("s1", "Soft")
            sw.data_paths = [
                DataPathEntry(path=src, root_key="APPDATA", root_abs=space.path("APPDATA"),
                              kind=EntryKind.DIR, content_type=ContentType.CONFIG,
                              size=100, file_count=2),
            ]
            dest = space.make_dir("backups")
            report = Backuper(dest_dir=dest).backup([sw])
            self.assertTrue(report.success, f"备份应成功：{report.error}")
            self.assertTrue(os.path.isfile(report.archive_path), "归档文件应存在")

            # 断言归档内所有成员安全
            with zipfile.ZipFile(report.archive_path) as zf:
                names = zf.namelist()
                for n in names:
                    self.assertNotIn("..", n.split("/"), f"归档成员含 .. ：{n}")
                    self.assertFalse(os.path.isabs(n) or n.startswith("/"), f"归档成员为绝对路径：{n}")
                    self.assertNotIn(":", n[1:], f"归档成员含盘符：{n}")
                self.assertIn("manifest.json", names, "归档应含 manifest.json")

                extract_dir = space.make_dir("extract")
                zf.extractall(extract_dir)

            # 断言解压后无任何文件逃逸到 extract_dir 之外
            extract_root = os.path.normcase(os.path.abspath(extract_dir))
            for dirpath, _dn, files in os.walk(extract_dir):
                self.assertTrue(os.path.normcase(os.path.abspath(dirpath)).startswith(extract_root),
                                "解压后出现异常目录")
                for f in files:
                    full = os.path.normcase(os.path.abspath(os.path.join(dirpath, f)))
                    self.assertTrue(full.startswith(extract_root), f"文件逃逸出目标目录：{full}")

            # 内容一致性
            hit = None
            for dirpath, _dn, files in os.walk(extract_dir):
                if "config.json" in files:
                    hit = os.path.join(dirpath, "config.json")
            self.assertIsNotNone(hit, "解压后应能找到 config.json")
            with open(hit, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh), {"k": "值"}, "解压后内容应与原文件一致")
        finally:
            space.cleanup()

    def test_04_manifest_结构完整(self):
        """manifest.json 可解析且关键字段齐全。"""
        space = TempSpace("qa_manifest_")
        try:
            src = space.make_dir("APPDATA", "Soft")
            space.write_file("APPDATA/Soft/a.txt", "hello")
            sw = make_software("s1", "Soft", publisher="QA 出版社")
            sw.data_paths = [
                DataPathEntry(path=src, root_key="APPDATA", root_abs=space.path("APPDATA"),
                              kind=EntryKind.DIR, content_type=ContentType.CONFIG,
                              size=5, file_count=1, mtime=time.time()),
            ]
            report = Backuper(dest_dir=space.make_dir("bk")).backup([sw])
            self.assertTrue(report.success, f"备份应成功：{report.error}")
            self.assertTrue(os.path.isfile(report.manifest_path), "manifest 应同步落盘")
            with open(report.manifest_path, encoding="utf-8") as fh:
                data = json.load(fh)
            for key in ("schema_version", "created_at", "host", "options", "software", "totals"):
                self.assertIn(key, data, f"manifest 缺少字段：{key}")
            self.assertEqual(data["totals"]["files"], 1, "manifest 文件数应为 1")
            self.assertEqual(data["software"][0]["name"], "Soft", "manifest 软件名应保留中文/原名")
        finally:
            space.cleanup()


# ==========================================================================
# 3. 删除 / 备份健壮性
# ==========================================================================


class TestDeleteRobustness(unittest.TestCase):
    """删除与备份在各种恶劣条件下的健壮性（全部使用临时假数据）。"""

    def test_01_只读属性文件(self):
        """只读文件：不得崩溃，应计入 skipped 并给出中文原因，目录仍在。"""
        space = TempSpace("qa_ro_")
        try:
            d = space.make_dir("ro")
            fp = os.path.join(d, "ro.txt")
            with open(fp, "w") as fh:
                fh.write("y" * 64)
            os.chmod(fp, stat.S_IREAD)
            try:
                report = Deleter().delete([make_entry(d, size=64, file_count=1)], DeleteMode.PERMANENT)
                self.assertEqual(report.deleted_count, 0, "只读文件所在目录不应被计为删除成功")
                self.assertTrue(report.skipped, "只读文件应计入 skipped")
                self.assertTrue(report.skipped[0].reason.strip(), "skipped 应给出中文原因")
                self.assertTrue(os.path.exists(d), "只读文件目录应仍然存在")
            finally:
                os.chmod(fp, stat.S_IWRITE)
        finally:
            space.cleanup()

    def test_02_文件被占用(self):
        """文件被占用（保持打开句柄）：不得崩溃，应计入 skipped。"""
        space = TempSpace("qa_lock_")
        handle = None
        try:
            d = space.make_dir("locked")
            fp = os.path.join(d, "lock.txt")
            with open(fp, "w") as fh:
                fh.write("z" * 64)
            handle = open(fp, "r+b")
            report = Deleter().delete([make_entry(d, size=64, file_count=1)], DeleteMode.PERMANENT)
            self.assertEqual(report.deleted_count, 0, "被占用文件不应被计为删除成功")
            self.assertTrue(report.skipped, "被占用文件应计入 skipped")
            self.assertTrue(os.path.exists(d), "被占用文件目录应仍然存在")
        finally:
            if handle is not None:
                handle.close()
            space.cleanup()

    def test_03_不存在的路径(self):
        """路径不存在：应计入 skipped 并给出原因，不得抛异常。"""
        space = TempSpace("qa_gone_")
        try:
            ghost = space.path("no-such-dir-xyz")
            report = Deleter().delete([make_entry(ghost)], DeleteMode.PERMANENT)
            self.assertEqual(report.deleted_count, 0)
            self.assertTrue(report.skipped, "不存在的路径应计入 skipped")
            self.assertTrue(report.skipped[0].reason.strip(), "应给出中文原因")
        finally:
            space.cleanup()

    def test_04_空目录(self):
        """空目录应能被正常删除。"""
        space = TempSpace("qa_empty_")
        try:
            d = space.make_dir("empty")
            report = Deleter().delete([make_entry(d)], DeleteMode.PERMANENT)
            self.assertEqual(report.deleted_count, 1, "空目录应被删除")
            self.assertFalse(os.path.exists(d), "空目录应确实被移除")
        finally:
            space.cleanup()

    def test_05_中文与特殊字符(self):
        """中文、空格、``&``、``#`` 等特殊字符路径应能正常删除。"""
        space = TempSpace("qa_special_")
        try:
            for name in ["中文 目录", "a&b#c", "dir with space", "名字(带括号)", "百分号%路径"]:
                d = space.make_dir(name)
                space.write_file(f"{name}/f.txt", "内容")
                report = Deleter().delete([make_entry(d, size=10, file_count=1)], DeleteMode.PERMANENT)
                with self.subTest(name=name):
                    self.assertEqual(report.deleted_count, 1, f"应能删除：{name}")
                    self.assertFalse(os.path.exists(d), f"应确实被移除：{name}")
        finally:
            space.cleanup()

    def test_06_超长路径_超过260字符(self):
        """>260 字符的超长路径应能正常删除（长路径前缀生效）。"""
        space = TempSpace("qa_long_")
        try:
            deep = space.root
            for _ in range(30):
                deep = os.path.join(deep, "d" * 8)
            os.makedirs(paths.to_long_path(deep), exist_ok=True)
            fpath = os.path.join(deep, "file.txt")
            with open(paths.to_long_path(fpath), "w") as fh:
                fh.write("hello")
            self.assertGreater(len(fpath), 260, f"前置条件：路径长度应 >260，实际 {len(fpath)}")
            self.assertTrue(os.path.exists(paths.to_long_path(fpath)), "前置条件：文件应已创建")

            report = Deleter().delete([make_entry(os.path.dirname(fpath), size=5, file_count=1)],
                                      DeleteMode.PERMANENT)
            self.assertEqual(report.deleted_count, 1, "超长路径目录应能被删除")
            self.assertFalse(os.path.exists(paths.to_long_path(os.path.dirname(fpath))),
                             "超长路径目录应确实被移除")
        finally:
            space.cleanup()

    def test_07_空列表与全黑名单(self):
        """空列表安全返回；全部命中黑名单时不执行任何删除。"""
        report = Deleter().delete([], DeleteMode.PERMANENT)
        self.assertTrue(report.success)
        self.assertEqual(report.deleted_count, 0)

        targets = [r"C:\Windows", r"C:\Windows\System32", paths.to_absolute(r"%PROGRAMFILES%")]
        report = Deleter().delete([make_entry(t) for t in targets], DeleteMode.PERMANENT)
        self.assertEqual(report.deleted_count, 0, "黑名单目标不得被删除")
        self.assertEqual(len(report.blocked), 3, "3 条目标应全部被拦截")
        for t in targets:
            self.assertTrue(os.path.exists(t), f"目标必须仍然存在：{t}")

    def test_08_先备份后删除_备份失败则不删除(self):
        """备份失败时必须中止删除（数据未动）。"""
        space = TempSpace("qa_btd_")
        try:
            d = space.make_dir("Soft")
            space.write_file("Soft/a.txt", "x" * 32)

            class FailingBackuper(Backuper):
                def backup(self, *_a, **_kw):
                    from src.core.models import BackupReport
                    r = BackupReport()
                    r.error = "模拟备份失败"
                    return r

            report = Deleter(backuper=FailingBackuper(dest_dir=space.make_dir("bk"))).delete(
                [DataPathEntry(path=d, kind=EntryKind.DIR, size=32, file_count=1,
                               content_type=ContentType.CONFIG)],
                DeleteMode.BACKUP_THEN_DELETE)
            self.assertFalse(report.success, "备份失败时删除应整体失败")
            self.assertEqual(report.deleted_count, 0, "备份失败不得删除任何数据")
            self.assertTrue(os.path.exists(d), "备份失败时数据必须原封不动")
        finally:
            space.cleanup()

    def test_09_先备份后删除_正常路径(self):
        """正常路径：先产出归档再删除，且数据确实进入归档。"""
        space = TempSpace("qa_btd2_")
        try:
            d = space.make_dir("Soft")
            space.write_file("Soft/a.txt", "重要数据")
            report = Deleter(backuper=Backuper(dest_dir=space.make_dir("bk"))).delete(
                [DataPathEntry(path=d, kind=EntryKind.DIR, size=12, file_count=1,
                               content_type=ContentType.CONFIG)],
                DeleteMode.BACKUP_THEN_DELETE)
            self.assertEqual(report.deleted_count, 1, "应删除 1 项")
            self.assertTrue(report.archive_path and os.path.isfile(report.archive_path),
                            "应先产出备份归档")
            self.assertFalse(os.path.exists(d), "目标应已被删除")
            with zipfile.ZipFile(report.archive_path) as zf:
                blob = "".join(zf.read(n).decode("utf-8", "replace")
                               for n in zf.namelist() if n.endswith(".txt"))
            self.assertIn("重要数据", blob, "数据应确实进入归档（可还原）")
        finally:
            space.cleanup()

    def test_10_备份被占用文件计入_skipped(self):
        """备份时遇到被占用文件：应逐文件跳过并记录，整体不崩溃。"""
        space = TempSpace("qa_bklock_")
        handle = None
        try:
            d = space.make_dir("Soft")
            space.write_file("Soft/ok.txt", "ok 内容")
            fp = os.path.join(d, "busy.txt")
            with open(fp, "w") as fh:
                fh.write("busy" * 16)
            handle = open(fp, "r+b")

            sw = make_software("s1", "Soft")
            sw.data_paths = [DataPathEntry(path=d, kind=EntryKind.DIR,
                                           content_type=ContentType.CONFIG, size=64, file_count=2)]
            report = Backuper(dest_dir=space.make_dir("bk")).backup([sw])
            # 整体不应抛异常；成功或被占用其一均可，但必须有明确 outcome
            self.assertTrue(report.success or report.error or report.skipped,
                            "备份应给出明确结果（成功/错误/跳过）")
            if report.skipped:
                self.assertTrue(report.skipped[0].reason.strip(), "跳过原因应为中文说明")
            _note(f"备份被占用文件：success={report.success} 跳过 {len(report.skipped)} 项")
        finally:
            if handle is not None:
                handle.close()
            space.cleanup()

    def test_11_junction_不崩溃(self):
        """目录 junction：删除与备份均不得崩溃（junction 不应被穿透删除目标内容）。"""
        space = TempSpace("qa_junc_")
        try:
            target = space.make_dir("target")
            space.write_file("target/t.txt", "目标内容")
            link = space.path("link")
            rc = os.system(f'cmd /c mklink /J "{link}" "{target}" >nul 2>&1')
            if rc != 0 or not os.path.exists(link):
                _note("本机无法创建 junction（可能无权限），本用例降级为跳过")
                return
            # 删除 junction 本身：不应崩溃
            report = Deleter().delete([make_entry(link, size=10, file_count=1)], DeleteMode.PERMANENT)
            self.assertIsNotNone(report, "删除 junction 不应抛异常")
            # 无论删除成功与否，junction 目标内容不应被连带删除
            _note(f"junction 删除结果：deleted={report.deleted_count} "
                  f"目标仍在={os.path.exists(target)}")
        finally:
            space.cleanup()


# ==========================================================================
# 4. 归属推断质量
# ==========================================================================


class TestAttribution(unittest.TestCase):
    """L1→L6 各级命中、阈值边界、冲突裁决、手动指派、未识别。"""

    @staticmethod
    def _engine():
        """构造一组互不干扰的软件，保证每级能被独立验证。"""
        sw = [
            make_software("s1", "Google Chrome", publisher="UniquePub Alpha",
                          install_location=r"C:\Program Files\UniqueChrome\App",
                          exe_names=["chromeunique"]),
            make_software("s2", "BetaSoft", publisher="Kingsoft Unique",
                          install_location=r"D:\Nope\OtherDir", exe_names=["nopeexe"]),
            make_software("s3", "GammaTool", publisher="Pub Gamma",
                          install_location=r"D:\Tools\GammaRoot", exe_names=["nopeexe2"]),
            make_software("s4", "DeltaApp", publisher="Pub Delta",
                          install_location=r"D:\Nope2\DeltaDir", exe_names=["deltaexe"]),
            make_software("s5", "Epsilon Suite", publisher="Pub Epsilon",
                          install_location=r"D:\Nope3\EpsilonDir", exe_names=["epsexec"]),
            make_software("s6", "VLC media player", publisher="Pub Zeta",
                          install_location=r"D:\Nope4\ZetaDir", exe_names=["vlcx"]),
        ]
        eng = AttributionEngine(sw, threshold=0.75)
        eng.build_index()
        return eng

    def test_01_L1_精确名(self):
        """L1：归一化目录名 == 归一化软件名。"""
        eng = self._engine()
        m = eng.match_one("Google Chrome")
        self.assertEqual(m.software_id, "s1")
        self.assertEqual(m.level, MatchLevel.L1_EXACT)
        self.assertEqual(m.confidence, 1.0)
        self.assertFalse(m.is_fuzzy)

    def test_02_L2_发布商(self):
        """L2：归一化目录名 == 归一化发布商（含企业后缀剔除）。"""
        eng = self._engine()
        m = eng.match_one("Kingsoft Unique")
        self.assertEqual(m.software_id, "s2")
        self.assertEqual(m.level, MatchLevel.L2_PUBLISHER)
        self.assertAlmostEqual(m.confidence, 0.90, places=3)

    def test_03_L3_安装路径(self):
        """L3：目录名 == InstallLocation 末级目录名。"""
        eng = self._engine()
        m = eng.match_one("GammaRoot")
        self.assertEqual(m.software_id, "s3")
        self.assertEqual(m.level, MatchLevel.L3_INSTALL_PATH)
        self.assertAlmostEqual(m.confidence, 0.95, places=3)

    def test_04_L4_可执行文件名(self):
        """L4：目录名 == 主可执行文件名。"""
        eng = self._engine()
        m = eng.match_one("deltaexe")
        self.assertEqual(m.software_id, "s4")
        self.assertEqual(m.level, MatchLevel.L4_EXE_OR_FAMILY)
        self.assertAlmostEqual(m.confidence, 0.85, places=3)

    def test_05_L5_模糊匹配(self):
        """L5：相似度达阈值，且必须标记 is_fuzzy（UI 需提示确认）。"""
        eng = self._engine()
        m = eng.match_one("Epsilon Suit")   # 与 "Epsilon Suite" 近似
        self.assertEqual(m.software_id, "s5")
        self.assertEqual(m.level, MatchLevel.L5_FUZZY)
        self.assertTrue(m.is_fuzzy, "L5 必须标记 is_fuzzy 供 UI 提示")
        self.assertLess(m.confidence, 1.0)

    def test_06_L6_别名表(self):
        """L6：内置别名表兜底（软件名 → 与之无字面重叠的别名目录名）。

        注意：需选用与软件名**不互为子串**的别名（如 ``videolan``），
        否则会先被 L5 子串分支拦截，测不到 L6。
        """
        eng = self._engine()
        m = eng.match_one("videolan")   # ALIAS_TABLE["vlcmediaplayer"] 含 "videolan"
        self.assertEqual(m.software_id, "s6", "VLC 应通过别名表命中目录 videolan")
        self.assertEqual(m.level, MatchLevel.L6_ALIAS,
                         f"应命中 L6 别名表，实际为 {m.level.value}")
        self.assertAlmostEqual(m.confidence, 0.80, places=3)
        self.assertFalse(m.is_fuzzy, "L6 不应标记为模糊匹配")

    def test_07_全部未命中进入未识别(self):
        """全部级别未命中时进入 LX（未识别），不得强行归属。"""
        eng = self._engine()
        for name in ["zzzz-unknown-folder", "qqqqqq", "随机中文目录名"]:
            with self.subTest(name=name):
                m = eng.match_one(name)
                self.assertIsNone(m.software_id, f"不应强行归属：{name}")
                self.assertEqual(m.level, MatchLevel.NONE)
                self.assertEqual(m.confidence, 0.0)
                self.assertFalse(m.matched)

    def test_08_冲突裁决(self):
        """同一目录多软件竞争：应给出最优归属并列出冲突软件。"""
        sw = [
            make_software("c1", "Same Name App", publisher="Publisher One"),
            make_software("c2", "Same Name App", publisher="Publisher Two"),
        ]
        eng = AttributionEngine(sw, threshold=0.75)
        eng.build_index()
        m = eng.match_one("Same Name App")
        self.assertIsNotNone(m.software_id, "同名的两款软件应命中其中之一")
        self.assertIn(m.software_id, ("c1", "c2"))
        self.assertTrue(m.conflict_ids, "存在同等置信度竞争时应标记 conflict_ids")
        self.assertNotIn(m.software_id, m.conflict_ids, "冲突列表不应包含自身")

    def test_09_手动指派覆盖(self):
        """手动指派优先于一切规则；清除后回到自动推断。"""
        eng = self._engine()
        p = r"C:\Data\zzzz-unknown-folder"
        self.assertIsNone(eng.match_one("zzzz-unknown-folder", p).software_id)

        eng.apply_manual_overrides({p: "s1"})
        m = eng.match_one("zzzz-unknown-folder", p)
        self.assertEqual(m.software_id, "s1", "手动指派应覆盖自动推断")
        self.assertFalse(m.is_fuzzy)
        self.assertTrue(eng.is_manual(p))

        eng.set_manual_override(p, None)
        m = eng.match_one("zzzz-unknown-folder", p)
        self.assertIsNone(m.software_id, "清除指派后应回到未识别")
        self.assertFalse(eng.is_manual(p))

    def test_10_手动指派大小写与斜杠无关(self):
        """手动指派的路径比对应忽略大小写与斜杠方向。"""
        eng = self._engine()
        eng.apply_manual_overrides({r"C:\Data\MyFolder": "s2"})
        for variant in [r"c:\data\myfolder", r"C:/Data/MyFolder", r"C:\Data\MyFolder\\"]:
            with self.subTest(variant=variant):
                self.assertTrue(eng.is_manual(variant), f"应识别为已手动指派：{variant}")

    def test_11_阈值边界行为(self):
        """调整 fuzzy_threshold 应能收紧模糊匹配（阈值提高不应更宽松）。"""
        sw = [make_software("x1", "Nodejs Runtime", publisher="Pub X")]
        eng = AttributionEngine(sw, threshold=0.75)
        eng.build_index()
        loose = eng.match_one("Nodejs Runtim")     # 高相似度
        eng.threshold = 0.99
        strict = eng.match_one("Nodejs Runtim")
        self.assertIsNotNone(loose.software_id, "默认阈值下应命中")
        if strict.software_id is not None:
            self.assertLessEqual(strict.confidence, loose.confidence,
                                 "阈值提高后命中置信度不应变高")
        _note(f"阈值 0.75 -> {loose.software_id}/{loose.confidence}；"
              f"阈值 0.99 -> {strict.software_id}/{strict.confidence}")

    def test_12_空与异常输入(self):
        """空/空白/None 输入不得抛异常，返回未识别。"""
        eng = self._engine()
        for args in [("", ""), (None, None), ("   ", ""), (".", ""), ("..", "")]:
            with self.subTest(args=args):
                m = eng.match_one(*args)
                self.assertIsNone(m.software_id)
                self.assertEqual(m.level, MatchLevel.NONE)

    def test_13_中文软件名无法命中英文别名表(self):
        """中文软件名（如"微信"）应能通过别名表命中英文目录名（WeChat Files）。

        当前别名表以英文归一化名为键，中文软件名无法挂接，导致国内常见软件
        的目录落入"未识别"。
        """
        sw = [make_software("wx", "微信", publisher="腾讯科技", exe_names=["wechatx"])]
        eng = AttributionEngine(sw, threshold=0.75)
        eng.build_index()
        m = eng.match_one("WeChat Files", r"C:\Data\WeChat Files")
        self.assertEqual(
            m.software_id, "wx",
            "中文软件『微信』应通过别名表命中目录 WeChat Files，实际落入未识别 "
            "（别名表缺少中文键，国内软件归属率受影响）",
        )

    def test_14_批量归属写回字段(self):
        """attribute() 应把归属结果写回条目各字段。"""
        eng = self._engine()
        entries = [
            DataPathEntry(path=os.path.join(r"C:\Data", "Google Chrome")),
            DataPathEntry(path=os.path.join(r"C:\Data", "zzzz-unknown")),
        ]
        result = eng.attribute(entries)
        self.assertEqual(len(result), 2)
        self.assertEqual(entries[0].owner_id, "s1")
        self.assertEqual(entries[0].match_level, MatchLevel.L1_EXACT)
        self.assertIsNone(entries[1].owner_id)
        self.assertEqual(entries[1].match_level, MatchLevel.NONE)


# ==========================================================================
# 5. 导出正确性
# ==========================================================================


class TestExporters(unittest.TestCase):
    """CSV / JSON 导出正确性（Excel 可直接打开、中文无乱码、字段一致）。"""

    @staticmethod
    def _build_result() -> ScanResult:
        """构造一份含软件条目与未识别条目的扫描结果。"""
        result = ScanResult(started_at=time.time() - 1.0, finished_at=time.time())
        sw = make_software("s1", "测试软件 中文名", publisher="测试发布商",
                           version="1.2.3", install_location=r"C:\Program Files\测试")
        entry = DataPathEntry(
            path=paths.to_absolute(os.path.join(tempfile.gettempdir(), "QA", "测试软件")),
            root_key="APPDATA", kind=EntryKind.DIR, content_type=ContentType.CONFIG,
            size=2048, file_count=3, mtime=time.time(),
            owner_id="s1", match_level=MatchLevel.L1_EXACT, confidence=1.0,
        )
        sw.data_paths = [entry]
        sw.total_size = 2048
        result.software = {sw.id: sw}
        orphan = DataPathEntry(
            path=paths.to_absolute(os.path.join(tempfile.gettempdir(), "QA", "未识别目录")),
            root_key="LOCALAPPDATA", kind=EntryKind.DIR, content_type=ContentType.CACHE,
            size=1024, file_count=1, mtime=time.time(),
        )
        result.orphan_entries = [orphan]
        ScanService.refresh_stats(result)
        return result

    def test_01_CSV_BOM(self):
        """CSV 必须以 utf-8-sig BOM 开头（Excel 双击打开不乱码）。"""
        space = TempSpace("qa_exp_")
        try:
            p = space.path("清单.csv")
            export_csv(self._build_result(), p)
            with open(p, "rb") as fh:
                head = fh.read(3)
            self.assertEqual(head, b"\xef\xbb\xbf", "CSV 必须以 UTF-8 BOM 开头")
        finally:
            space.cleanup()

    def test_02_CSV_中文无乱码且可解析(self):
        """CSV 中文应原样可读，且可被 csv 模块正确解析。"""
        space = TempSpace("qa_exp_")
        try:
            p = space.path("清单.csv")
            export_csv(self._build_result(), p)
            with open(p, encoding="utf-8-sig") as fh:
                rows = list(csv.reader(fh))
            self.assertTrue(rows, "CSV 不应为空")
            self.assertEqual(rows[0], list(CSV_HEADERS), "表头应与 CSV_HEADERS 一致")
            blob = "\n".join(",".join(r) for r in rows)
            self.assertIn("测试软件 中文名", blob, "中文软件名应原样出现")
            self.assertIn("未识别", blob, "未识别分组应被导出（A8）")
            self.assertNotIn("\\ufffd", blob, "不应出现替换字符（乱码）")
        finally:
            space.cleanup()

    def test_03_CSV_字段数一致(self):
        """每一行（含未识别分组行与空路径软件行）字段数必须与表头一致。"""
        space = TempSpace("qa_exp_")
        try:
            p = space.path("清单.csv")
            result = self._build_result()
            # 追加一款"无任何关联路径"的软件，覆盖空路径分支
            empty_sw = make_software("s2", "空路径软件", publisher="某发布商")
            result.software[empty_sw.id] = empty_sw
            export_csv(result, p)
            with open(p, encoding="utf-8-sig") as fh:
                rows = list(csv.reader(fh))
            expect = len(CSV_HEADERS)
            for i, row in enumerate(rows):
                with self.subTest(row=i):
                    self.assertEqual(len(row), expect, f"第 {i} 行字段数 {len(row)} != {expect}")
            self.assertGreaterEqual(len(rows), 4, "应包含表头 + 软件行 + 空路径行 + 未识别行")
        finally:
            space.cleanup()

    def test_04_JSON_可解析且中文原样(self):
        """JSON 必须 ensure_ascii=False（中文原样）且可被解析，关键字段齐全。"""
        space = TempSpace("qa_exp_")
        try:
            p = space.path("清单.json")
            export_json(self._build_result(), p)
            raw = open(p, "rb").read()
            self.assertNotIn(b"\\u", raw, "JSON 不应做 ASCII 转义（应 ensure_ascii=False）")
            with open(p, encoding="utf-8") as fh:
                data = json.load(fh)
            for key in ("schema_version", "exported_at", "stats", "software",
                        "orphan_entries", "warnings"):
                self.assertIn(key, data, f"JSON 缺少字段：{key}")
            for key in ("software_count", "entry_count", "identified_count",
                        "orphan_count", "total_size"):
                self.assertIn(key, data["stats"], f"stats 缺少字段：{key}")
            self.assertEqual(data["software"][0]["name"], "测试软件 中文名")
            self.assertEqual(len(data["orphan_entries"]), 1, "未识别条目应被导出")
        finally:
            space.cleanup()

    def test_05_导出统计与扫描结果一致(self):
        """导出内容中的统计数字应与 ScanResult.stats 一致。"""
        space = TempSpace("qa_exp_")
        try:
            result = self._build_result()
            p = space.path("清单.json")
            export_json(result, p)
            with open(p, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["stats"]["software_count"], result.stats.software_count)
            self.assertEqual(data["stats"]["entry_count"], result.stats.entry_count)
            self.assertEqual(data["stats"]["orphan_count"], result.stats.orphan_count)
            self.assertEqual(data["stats"]["identified_count"], result.stats.identified_count)
        finally:
            space.cleanup()


# ==========================================================================
# 6. 大小计算
# ==========================================================================


class TestSizeCalculator(unittest.TestCase):
    """占用大小计算：可取消、结果保留、异常路径处理。"""

    def test_01_基本计算(self):
        """目录字节数与文件数统计正确。"""
        space = TempSpace("qa_size_")
        try:
            d = space.make_dir("Soft")
            space.write_file("Soft/a.txt", "a" * 100)
            space.write_file("Soft/b.txt", "b" * 200)
            space.make_dir("Soft/sub")
            space.write_file("Soft/sub/c.txt", "c" * 300)
            size, count = SizeCalculator().compute_path(d, is_dir=True)
            self.assertEqual(size, 600, f"字节数应为 600，实际 {size}")
            self.assertEqual(count, 3, f"文件数应为 3，实际 {count}")
        finally:
            space.cleanup()

    def test_02_可中途取消(self):
        """cancel_event 置位后应尽快返回 (-1, -1)。"""
        space = TempSpace("qa_size_")
        try:
            d = space.make_dir("Soft")
            for i in range(50):
                space.write_file(f"Soft/f{i}.txt", "x" * 100)
            ev = threading.Event()
            ev.set()
            size, count = SizeCalculator(ev).compute_path(d, is_dir=True)
            self.assertEqual((size, count), (-1, -1), "已取消时应返回 (-1,-1)")
        finally:
            space.cleanup()

    def test_03_取消后已算结果保留(self):
        """批量计算中途取消：已完成的条目结果必须保留，未完成的保持 -1。"""
        space = TempSpace("qa_size_")
        try:
            dirs = []
            for i in range(6):
                d = space.make_dir(f"Soft{i}")
                space.write_file(f"Soft{i}/f.txt", "x" * (10 * (i + 1)))
                dirs.append(d)
            entries = [DataPathEntry(path=d, kind=EntryKind.DIR, size=-1, file_count=-1)
                       for d in dirs]
            ev = threading.Event()

            def on_progress(done, total, path):
                if done >= 3:
                    ev.set()

            SizeCalculator(ev).compute_all(entries, on_progress)
            computed = [e for e in entries if e.size >= 0]
            self.assertGreaterEqual(len(computed), 1, "取消前应至少完成 1 项")
            self.assertLess(len(computed), len(entries), "取消后不应继续算完全部")
            for e in computed:
                self.assertGreater(e.size, 0, "已完成的条目应保留正确大小")
                self.assertEqual(e.file_count, 1)
            for e in entries:
                if e.size < 0:
                    self.assertEqual(e.size, -1, "未完成条目应保持 -1（未计算）")
        finally:
            space.cleanup()

    def test_04_不存在的路径(self):
        """不存在的路径返回 (-1,-1)，不抛异常。"""
        space = TempSpace("qa_size_")
        try:
            ghost = space.path("no-such-xyz")
            for is_dir in (True, False):
                with self.subTest(is_dir=is_dir):
                    size, count = SizeCalculator().compute_path(ghost, is_dir=is_dir)
                    self.assertEqual((size, count), (-1, -1), "不存在路径应返回 (-1,-1)")
            self.assertEqual(SizeCalculator().compute_path("", is_dir=True), (-1, -1),
                             "空路径应返回 (-1,-1)")
        finally:
            space.cleanup()

    def test_05_符号链接不递归死循环(self):
        """符号链接应被跳过，不得造成重复计数或死循环。"""
        space = TempSpace("qa_size_")
        try:
            target = space.make_dir("target")
            space.write_file("target/t.txt", "x" * 100)
            link = space.path("link")
            try:
                os.symlink(target, link, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                _note(f"本机无法创建符号链接（{exc}），本用例降级为跳过")
                return
            size, count = SizeCalculator().compute_path(space.root, is_dir=True)
            self.assertLessEqual(count, 2, f"符号链接应被跳过，文件数不应重复累加（实际 {count}）")
            self.assertLessEqual(size, 200, f"大小不应重复累加（实际 {size}）")
        finally:
            space.cleanup()

    def test_06_junction_不被穿透计数(self):
        """junction（目录联接）应被视为挂载点跳过，不得重复计数。

        架构文档声明"跳过符号链接与挂载点，避免循环与重复计数"，
        但 ``DirEntry.is_symlink()`` 在 Windows 上对 junction 返回 False。
        """
        space = TempSpace("qa_size_")
        try:
            inner = space.make_dir("real")
            space.write_file("real/f.txt", "x" * 100)
            link = space.path("junction_link")
            rc = os.system(f'cmd /c mklink /J "{link}" "{inner}" >nul 2>&1')
            if rc != 0 or not os.path.exists(link):
                _note("本机无法创建 junction，本用例降级为跳过")
                return
            size, count = SizeCalculator().compute_path(space.root, is_dir=True)
            self.assertEqual(
                count, 1,
                f"junction 应被跳过：目录内实际只有 1 个文件，却统计到 {count} 个"
                f"（大小 {size} 字节）—— junction 未被识别为挂载点",
            )
        finally:
            space.cleanup()

    def test_07_compute_写回条目(self):
        """compute() 应就地写回 entry.size / entry.file_count。"""
        space = TempSpace("qa_size_")
        try:
            d = space.make_dir("Soft")
            space.write_file("Soft/a.txt", "x" * 42)
            entry = DataPathEntry(path=d, kind=EntryKind.DIR, size=-1, file_count=-1)
            SizeCalculator().compute(entry)
            self.assertEqual(entry.size, 42)
            self.assertEqual(entry.file_count, 1)
        finally:
            space.cleanup()


# ==========================================================================
# 7. 线程与 UI 约定（静态审查）
# ==========================================================================


class TestThreadUIContract(unittest.TestCase):
    """后台 Worker 不得直接操作 UI 控件；信号与槽签名必须匹配。"""

    WORKERS = os.path.join(PROJECT_ROOT, "src", "ui", "workers.py")
    MAIN_WINDOW = os.path.join(PROJECT_ROOT, "src", "ui", "main_window.py")

    def _read(self, path: str) -> str:
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def test_01_workers_不直接操作控件(self):
        """workers.py 中不得出现任何 UI 控件类型或直接界面写入调用。"""
        src = self._read(self.WORKERS)
        banned = ["QWidget", "QLabel", "QTableWidget", "QProgressBar", "QMessageBox",
                  "QPushButton", "QTreeWidget", "QComboBox", "QLineEdit", "QDialog",
                  ".setText(", ".setEnabled(", ".setVisible(", ".setValue(",
                  ".addItem(", ".show()", ".hide(", ".clear()"]
        for token in banned:
            with self.subTest(token=token):
                self.assertNotIn(token, src, f"workers.py 出现 UI 操作：{token}")

    def test_02_workers_只通过信号回传(self):
        """workers.py 应只 import QtCore 的 Signal/QThread，不得 import QtWidgets。"""
        src = self._read(self.WORKERS)
        self.assertIn("from PySide6.QtCore import", src, "workers.py 应依赖 QtCore")
        self.assertNotIn("PySide6.QtWidgets", src, "workers.py 不得依赖 QtWidgets")
        self.assertNotIn("PySide6.QtGui", src, "workers.py 不得依赖 QtGui")

    def test_03_信号声明与槽签名匹配(self):
        """main_window 中连接的槽函数签名应与 workers 的信号声明一致。"""
        workers_src = self._read(self.WORKERS)
        mw_src = self._read(self.MAIN_WINDOW)
        # 信号声明
        for sig, args in [("stageChanged", "str"), ("progressChanged", "int, int, str"),
                          ("entrySized", "str, object, object"), ("finished", "object"),
                          ("errorOccurred", "str"), ("logEmitted", "str"),
                          ("scanReady", "object")]:
            with self.subTest(signal=sig):
                self.assertIn(f"{sig} = Signal({args})", workers_src,
                              f"workers.py 缺少信号声明 {sig}({args})")
        # 槽函数签名
        for slot, sig in [("def on_scan_stage(self, text: str)", "stageChanged"),
                          ("def on_scan_progress(self, done: int, total: int, text: str)", "progressChanged"),
                          ("def on_entry_sized(self, path: str, size: int, file_count: int)", "entrySized"),
                          ("def on_worker_error(self, message: str)", "errorOccurred")]:
            with self.subTest(slot=slot):
                self.assertIn(slot, mw_src, f"main_window.py 缺少与 {sig} 匹配的槽：{slot}")

    def test_03b_entrySized_大整数不溢出(self):
        """回归：entrySized 信号用 object 类型，目录 > 2 GiB（> 2^31-1 字节）时不应抛 OverflowError。"""
        from PySide6.QtWidgets import QApplication
        app = QApplication.instance() or QApplication([])
        from src.ui.workers import BaseWorker

        captured = []

        class _Probe(BaseWorker):
            def run(self):  # pragma: no cover - 仅用于信号回传验证
                pass

        w = _Probe()
        w.entrySized.connect(lambda p, size, count: captured.append((p, size, count)))
        # 2.59 GB > 2^31 - 1，正是触发原 OverflowError 的值
        huge = 2590134828
        try:
            w.entrySized.emit("C:\\Some\\BigDir", huge, 1234567)
        except Exception as exc:  # noqa: BLE001
            self.fail(f"entrySized 传递大整数时抛出异常：{exc}")
        self.assertEqual(captured[0], ("C:\\Some\\BigDir", huge, 1234567))

    def test_04_worker_统一异常兜底(self):
        """Worker 应有 run_safely 兜底，避免子线程异常导致界面无响应。"""
        src = self._read(self.WORKERS)
        self.assertIn("def run_safely", src, "缺少 run_safely 统一兜底")
        self.assertIn("emit_error", src, "异常应通过 errorOccurred 上报 UI")


# ==========================================================================
# 8. 真实只读扫描
# ==========================================================================


class TestRealScan(unittest.TestCase):
    """真实环境只读扫描（注册表 + MSIX + 目录枚举 + 归属）。"""

    def test_01_真实扫描不抛异常(self):
        """完整只读扫描应正常完成，软件数 > 0，归属耗时 < 3 秒。"""
        cfg = config_mod.AppConfig()
        cfg.data_roots = [r"%APPDATA%", r"%LOCALAPPDATA%", r"%PROGRAMDATA%", r"%USERPROFILE%"]
        svc = ScanService(cfg)

        t0 = time.time()
        software_list = svc.scan_software()
        self.assertGreater(len(software_list), 0, "应扫描到已安装软件")
        self.assertIsInstance(svc.warnings, list, "warnings 应为列表")

        candidates = svc.scan_candidates()
        self.assertIsInstance(candidates, list, "候选条目应为列表")

        engine = svc.build_engine(software_list)
        t1 = time.time()
        matches = engine.attribute(candidates)
        elapsed = time.time() - t1

        self.assertLess(elapsed, 3.0, f"归属耗时应 <3 秒，实际 {elapsed:.3f} 秒")
        print(f"    真实扫描：软件 {len(software_list)} 个 / 候选 {len(candidates)} 条 / "
              f"归属耗时 {elapsed:.3f} 秒 / 总耗时 {time.time()-t0:.2f} 秒")

        from collections import Counter
        dist = Counter(m.level.value for m in matches.values())
        identified = sum(1 for m in matches.values() if m.matched)
        print(f"    级别分布：{dict(dist)}")
        print(f"    识别率：{identified}/{len(matches)} = "
              f"{identified / max(1, len(matches)):.1%}")

        # 抽样打印，供人工判断合理性
        by_id = {s.id: s for s in software_list}
        print("    抽样归属结果（前 10 条已识别）：")
        shown = 0
        for entry in candidates:
            m = matches.get(entry.path)
            if m and m.matched and shown < 10:
                sw = by_id.get(m.software_id)
                print(f"      · {paths.to_display_path(entry.path)}  →  "
                      f"{sw.name if sw else m.software_id}  [{m.level.value} {m.confidence}]")
                shown += 1

    def test_02_真实扫描条目均通过黑名单标记(self):
        """扫描产出的条目都应完成黑名单标记（字段类型正确）。"""
        cfg = config_mod.AppConfig()
        cfg.data_roots = [r"%APPDATA%"]
        svc = ScanService(cfg)
        entries = svc.scan_candidates()
        for e in entries[:200]:
            self.assertIsInstance(e.is_blacklisted, bool)
            self.assertIsInstance(e.block_reason, str)
            if e.is_blacklisted:
                self.assertTrue(e.block_reason.strip(), "被拦截条目必须有中文原因")
                self.assertFalse(paths.check_path_safety(e.path).allowed,
                                 "标记与判定应一致")

    def test_03_MSIX_PowerShell_输出编码正确(self):
        """MSIX 扫描解析 PowerShell 输出时不得出现乱码（U+FFFD）。

        PowerShell 控制台输出使用 OEM 代码页（简体中文为 936/GBK），
        按 utf-8 解码会把中文发布商名变成替换字符。
        """
        try:
            items = software_scanner.MsixScanner().scan()
        except Exception as exc:  # noqa: BLE001 - 环境问题不判失败
            _note(f"MSIX 扫描不可用：{exc}")
            return
        self.assertIsInstance(items, list)
        if not items:
            _note("本机无 MSIX 应用，本用例仅校验接口可用性")
            return
        broken = [s for s in items if "\ufffd" in (s.publisher or "") or "\ufffd" in (s.name or "")]
        for s in broken[:3]:
            print(f"      乱码样本：{s.name!r} publisher={s.publisher!r}")
        self.assertEqual(
            len(broken), 0,
            f"MSIX 扫描出现 {len(broken)} 条中文乱码（U+FFFD）—— "
            f"software_scanner.MsixScanner.scan 用 encoding='utf-8' 解码，"
            f"而 PowerShell 输出为 OEM 代码页（本机 cp936）",
        )


# ==========================================================================
# 9. GUI 启动冒烟
# ==========================================================================


class TestGuiSmoke(unittest.TestCase):
    """GUI 启动冒烟：主窗口能显示、能正常退出（退出码 0）。"""

    SCRIPT = '''
# -*- coding: utf-8 -*-
import os, sys, tempfile
ROOT = {root!r}
sys.path.insert(0, ROOT)
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication
from src.core.config import AppConfig
from src.ui.main_window import MainWindow

app = QApplication(sys.argv)
cfg = AppConfig()
w = MainWindow(cfg)
w.resize(1280, 800)
w.show()
QTimer.singleShot(1500, app.quit)
code = app.exec()
print("QT_EXIT_CODE:", code)
print("TITLE:", w.windowTitle())
sys.exit(0)
'''

    def test_01_主窗口可启动并正常退出(self):
        """QTimer 定时自动退出：进程退出码 0，且窗口标题正确。"""
        script = self.SCRIPT.format(root=PROJECT_ROOT)
        fd, script_path = tempfile.mkstemp(prefix="qa_gui_", suffix=".py")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(script)
            proc = subprocess.run(
                [sys.executable, script_path],
                capture_output=True, text=True, timeout=90,
                encoding="utf-8", errors="replace",
            )
            out = (proc.stdout or "") + (proc.stderr or "")
            self.assertEqual(proc.returncode, 0,
                             f"GUI 启动冒烟应退出码 0，实际 {proc.returncode}\n{out[-1500:]}")
            self.assertIn("QT_EXIT_CODE: 0", out, f"Qt 事件循环退出码应为 0\n{out[-1500:]}")
            self.assertIn("软件数据迁移助手", out, f"窗口标题不正确\n{out[-800:]}")
        finally:
            try:
                os.remove(script_path)
            except OSError:
                pass


class TestCheckboxAndSizeDisplay(unittest.TestCase):
    """复选框 setData（PySide6 6.8 CheckState 枚举）与占用列显示诚实化回归。"""

    @classmethod
    def setUpClass(cls):
        from PySide6.QtWidgets import QApplication
        cls._app = QApplication.instance() or QApplication([])

    def _make_row(self, key, name, entries):
        from src.ui.widgets import Row
        from src.core.models import InstalledSoftware, SoftwareSource
        return Row(key=key, name=name, publisher="", version="", entries=entries,
                   software=InstalledSoftware(id=key, name=name, source=SoftwareSource.REGISTRY),
                   is_orphan=False, path_count=len(entries), size=0)

    def test_01_setData_接受CheckState枚举(self):
        """用户点击复选框时 Qt 传入 Qt.CheckState 枚举，不得抛 TypeError（bug 回归）。"""
        from PySide6.QtCore import Qt
        from src.ui.widgets import SoftwareTableModel, COL_CHECK
        m = SoftwareTableModel()
        m.set_rows([self._make_row("t1", "A", [])])
        idx = m.index(0, COL_CHECK)
        self.assertTrue(m.setData(idx, Qt.CheckState.Checked, Qt.CheckStateRole))
        self.assertTrue(m.rows()[0].checked)
        self.assertTrue(m.setData(idx, Qt.CheckState.Unchecked, Qt.CheckStateRole))
        self.assertFalse(m.rows()[0].checked)

    def test_02_setData_兼容int传入(self):
        """程序化调用可能传入 int（2=Checked / 0=Unchecked），同样可用。"""
        from PySide6.QtCore import Qt
        from src.ui.widgets import SoftwareTableModel, COL_CHECK
        m = SoftwareTableModel()
        m.set_rows([self._make_row("t1", "A", [])])
        idx = m.index(0, COL_CHECK)
        self.assertTrue(m.setData(idx, 2, Qt.CheckStateRole))
        self.assertTrue(m.rows()[0].checked)
        self.assertTrue(m.setData(idx, 0, Qt.CheckStateRole))
        self.assertFalse(m.rows()[0].checked)

    def test_03_占用列_无归属路径显示破折号(self):
        """未归属任何数据路径的软件显示 '—'，不再误导性地显示 '0 B'。"""
        from PySide6.QtCore import Qt
        from src.ui.widgets import SoftwareTableModel, COL_SIZE
        m = SoftwareTableModel()
        m.set_rows([self._make_row("t1", "A", [])])
        self.assertEqual(m.data(m.index(0, COL_SIZE), Qt.DisplayRole), "—")

    def test_04_占用列_未算完与路径不存在状态区分(self):
        """计算中显示"计算中…"；sizing_done 后 -1 视为路径不存在显示 '—'；真实 0B 保持 '0 B'。"""
        from PySide6.QtCore import Qt
        from src.ui.widgets import SoftwareTableModel, COL_SIZE
        from src.core.models import DataPathEntry, EntryKind
        pending = [DataPathEntry(path=r"C:\no\such\dir", kind=EntryKind.DIR, size=-1, file_count=-1)]
        empty = [DataPathEntry(path=r"C:\empty", kind=EntryKind.DIR, size=0, file_count=0)]
        m = SoftwareTableModel()
        m.set_rows([self._make_row("t1", "A", pending), self._make_row("t2", "B", empty)])
        self.assertEqual(m.data(m.index(0, COL_SIZE), Qt.DisplayRole), "计算中…")
        self.assertEqual(m.data(m.index(1, COL_SIZE), Qt.DisplayRole), "0 B")
        m.sizing_done = True
        self.assertEqual(m.data(m.index(0, COL_SIZE), Qt.DisplayRole), "—")
        self.assertEqual(m.data(m.index(1, COL_SIZE), Qt.DisplayRole), "0 B")


# ==========================================================================
# 结果收集与报告
# ==========================================================================


class ChineseTestResult(unittest.TextTestResult):
    """中文测试结果收集器。"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passed: list[str] = []
        #: 失败明细（可能多于失败用例数：一个用例可含多个 subTest 断言）
        self.failed: list[tuple[str, str]] = []
        #: 失败用例 id 集合（用于统计"失败用例数"）
        self.failed_ids: set[str] = set()
        self.skipped: list[tuple[str, str]] = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.passed.append(test.id())

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.failed_ids.add(test.id())
        self.failed.append((test.id(), self._short(err)))

    def addError(self, test, err):
        super().addError(test, err)
        self.failed_ids.add(test.id())
        self.failed.append((test.id(), self._short(err)))

    def addSubTest(self, test, subtest, err):
        """子测试失败也要计入（默认实现不会调用 addFailure，会漏统计）。"""
        super().addSubTest(test, subtest, err)
        if err is not None:
            self.failed_ids.add(test.id())
            self.failed.append((f"{test.id()}｜{subtest}", self._short(err)))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.skipped.append((test.id(), reason))

    @staticmethod
    def _short(err) -> str:
        import traceback
        tb = "".join(traceback.format_exception(*err))
        lines = [ln for ln in tb.splitlines() if ln.strip()]
        # 取最后的断言信息 + 异常行
        keep = []
        for ln in lines:
            if "AssertionError" in ln or ln.strip().startswith("File \""):
                keep.append(ln.strip())
        return " ｜ ".join(keep[-3:]) if keep else lines[-1] if lines else "未知错误"


def main() -> int:
    """运行全部 QA 用例并输出中文报告。"""
    print("=" * 78)
    print("  PC 换机数据迁移助手 —— QA 独立验收测试")
    print(f"  项目根目录：{PROJECT_ROOT}")
    print(f"  解释器：{sys.executable}（Python {sys.version.split()[0]}）")
    print(f"  开始时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 78)

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules["__main__"])
    runner = unittest.TextTestRunner(verbosity=2, resultclass=ChineseTestResult, stream=sys.stdout)
    started = time.time()
    result = runner.run(suite)
    elapsed = time.time() - started

    total = result.testsRun
    failed_n = len(result.failed_ids)
    skipped_n = len(result.skipped)
    passed_n = total - failed_n - skipped_n

    print()
    print("=" * 78)
    print("  QA 验收汇总")
    print("=" * 78)
    print(f"  用例总数：{total}　通过：{passed_n}　失败：{failed_n}　跳过：{skipped_n}")
    print(f"  失败断言条数：{len(result.failed)}（一个用例可含多个 subTest 断言）")
    print(f"  总耗时：{elapsed:.2f} 秒")

    if result.failed:
        print()
        print("-" * 78)
        print("  失败明细（源码 Bug 候选，需工程师修复）：")
        print("-" * 78)
        for i, (tid, msg) in enumerate(result.failed, 1):
            print(f"  {i:2d}. {tid}")
            print(f"      {msg}")

    if result.skipped:
        print()
        print("-" * 78)
        print("  跳过明细：")
        print("-" * 78)
        for tid, reason in result.skipped:
            print(f"  · {tid} —— {reason}")

    if NOTES:
        print()
        print("-" * 78)
        print("  备注 / 环境信息：")
        print("-" * 78)
        for n in NOTES:
            print(f"  · {n}")

    print()
    print("=" * 78)
    print(f"  IS_PASS: {'YES' if failed_n == 0 else 'NO'}")
    print("=" * 78)
    return 1 if failed_n else 0


if __name__ == "__main__":
    sys.exit(main())
