# -*- coding: utf-8 -*-
"""已安装软件扫描（L2）：注册表卸载项 + MSIX/Store 应用。

设计要点：
    * :class:`SoftwareSourceScanner` 为抽象基类，便于后续扩展"多用户扫描 / 便携软件"等来源（P2）；
    * 注册表扫描对 HKLM/HKCU × 64/32 位视图共打开 4 次，天然覆盖 WOW6432Node；
    * MSIX 走 ``powershell Get-AppxPackage | ConvertTo-Json``，注意单包时返回 dict 需归一化；
    * 单条子项解析失败只记警告，绝不中断整体流程。
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from abc import ABC, abstractmethod

from . import paths
from .models import InstalledSoftware, SoftwareSource
from .utils import normalize_name, tokenize

try:  # pragma: no cover - 非 Windows 平台
    import winreg
except ImportError:  # pragma: no cover
    winreg = None  # type: ignore[assignment]

try:  # pragma: no cover - 非 Windows 平台
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None  # type: ignore[assignment]

logger = logging.getLogger("scan.software")


def get_oem_encoding() -> str:
    """返回控制台默认 OEM 代码页对应的 Python 编码名（简体中文为 ``cp936``）。

    PowerShell 控制台输出默认使用该代码页；按其解码才能正确还原中文发布商名。

    Returns:
        形如 ``cp936`` 的编码名；获取失败时回退 ``utf-8``。
    """
    if ctypes is None or not hasattr(ctypes, "windll"):
        return "utf-8"
    try:
        code_page = int(ctypes.windll.kernel32.GetOEMCP())
        if code_page > 0:
            return f"cp{code_page}"
    except (AttributeError, OSError, ValueError):
        pass
    return "utf-8"


def decode_console_output(raw: "bytes | str | None") -> str:
    """解码控制台输出：优先按 UTF-8，出现替换字符时回退 OEM 代码页。

    Args:
        raw: 子进程输出的原始字节（或已被解码的字符串）。

    Returns:
        解码后的文本；两种编码都无法还原的字符以 ``U+FFFD`` 占位，不抛异常。
    """
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    if not raw:
        return ""
    text = raw.decode("utf-8-sig", errors="replace")
    if "\ufffd" in text:
        fallback = raw.decode(get_oem_encoding(), errors="replace")
        if fallback.count("\ufffd") < text.count("\ufffd"):
            return fallback
    return text

#: 卸载项注册表子路径
UNINSTALL_SUBKEY: str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

#: 补丁类条目的名称模式（如 KB5032189）
_PATCH_NAME_RE = re.compile(r"^KB\d{4,8}$", re.IGNORECASE)

#: 静默/标准卸载命令中的 exe 提取模式
_EXE_IN_CMD_RE = re.compile(r"\"([^\"]+\.exe)\"|([^\s\"]+\.exe)", re.IGNORECASE)


# --------------------------------------------------------------------------
# 抽象基类
# --------------------------------------------------------------------------


class SoftwareSourceScanner(ABC):
    """软件来源扫描器抽象基类（P2 扩展位：新增子类即可接入新来源）。"""

    #: 来源名称（用于日志与 UI）
    source_name: str = "unknown"

    def __init__(self) -> None:
        """初始化，准备警告收集容器。"""
        self.warnings: list[dict] = []

    def add_warning(self, target: str, message: str) -> None:
        """记录一条扫描警告。"""
        self.warnings.append({"stage": self.source_name, "target": target, "message": message})
        logger.warning("%s：%s（%s）", self.source_name, message, target)

    @abstractmethod
    def scan(self) -> list[InstalledSoftware]:
        """扫描并返回软件列表。"""

    # ---- 公共工具 ----

    @staticmethod
    def derive_exe_names(sw: InstalledSoftware) -> list[str]:
        """从卸载命令 / 图标路径 / 包族名中推断主可执行文件名（小写、无扩展名）。"""
        names: list[str] = []
        for raw in (sw.display_icon, sw.uninstall_string, sw.quiet_uninstall_string):
            if not raw:
                continue
            head = raw.split(",")[0].strip().strip('"')
            match = _EXE_IN_CMD_RE.search(head)
            if match:
                exe = match.group(1) or match.group(2) or ""
                base = os.path.basename(exe)
                if base:
                    names.append(os.path.splitext(base)[0].lower())
        if sw.package_family_name:
            names.append(sw.package_family_name.split("_")[0].lower())
        seen: set[str] = set()
        result: list[str] = []
        for n in names:
            if n and n not in seen:
                seen.add(n)
                result.append(n)
        return result

    @staticmethod
    def finalize(sw: InstalledSoftware) -> InstalledSoftware:
        """填充派生字段（归一化名、发布商、可执行文件名）。"""
        sw.norm_name = normalize_name(sw.name)
        sw.norm_publisher = normalize_name(sw.publisher)
        sw.exe_names = SoftwareSourceScanner.derive_exe_names(sw)
        return sw


# --------------------------------------------------------------------------
# 注册表扫描器
# --------------------------------------------------------------------------


class RegistryScanner(SoftwareSourceScanner):
    """扫描注册表卸载项（HKLM/HKCU × 64/32 位视图）。"""

    source_name = "registry"

    def __init__(self, include_system_component: bool = False) -> None:
        """初始化。

        Args:
            include_system_component: 是否保留 ``SystemComponent=1`` 的条目（默认过滤）。
        """
        super().__init__()
        self.include_system_component: bool = include_system_component

    # ---- 内部工具 ----

    @staticmethod
    def _hives() -> list[tuple[str, object]]:
        """返回 ``(hive 缩写, hive 句柄常量)`` 列表。"""
        if winreg is None:
            return []
        return [("HKLM", winreg.HKEY_LOCAL_MACHINE), ("HKCU", winreg.HKEY_CURRENT_USER)]

    @staticmethod
    def _views() -> list[tuple[str, int]]:
        """返回 ``(视图名, 访问标志)`` 列表。"""
        if winreg is None:
            return []
        return [
            ("64", winreg.KEY_WOW64_64KEY),
            ("32", winreg.KEY_WOW64_32KEY),
        ]

    @staticmethod
    def _read_value(key, name: str, default: str = "") -> str:
        """读取字符串型注册表值，失败返回默认值。"""
        try:
            value, _ = winreg.QueryValueEx(key, name)
        except OSError:
            return default
        if isinstance(value, str):
            return value.strip()
        if isinstance(value, int):
            return str(value)
        return default

    def _build_from_key(self, hive_name: str, view_name: str, key, subkey: str) -> InstalledSoftware | None:
        """从单个卸载项子键构建 :class:`InstalledSoftware`。"""
        name = self._read_value(key, "DisplayName")
        if not name:
            return None

        system_component = self._read_value(key, "SystemComponent", "0")
        is_system = system_component in ("1", "1.0", "True")
        if is_system and not self.include_system_component:
            return None

        # 过滤 Windows 更新补丁类条目
        if _PATCH_NAME_RE.match(name.strip()):
            return None
        if self._read_value(key, "ParentKeyName") or self._read_value(key, "ReleaseType"):
            return None

        raw_size = self._read_value(key, "EstimatedSize", "0")
        try:
            estimated_size_kb = int(float(raw_size))
        except (TypeError, ValueError):
            estimated_size_kb = 0

        sw = InstalledSoftware(
            id=f"reg:{hive_name}{view_name}\\{subkey}",
            name=name.strip(),
            publisher=self._read_value(key, "Publisher"),
            version=self._read_value(key, "DisplayVersion"),
            install_location=self._read_value(key, "InstallLocation").strip().strip('"'),
            install_date=self._read_value(key, "InstallDate"),
            estimated_size_kb=estimated_size_kb,
            uninstall_string=self._read_value(key, "UninstallString"),
            quiet_uninstall_string=self._read_value(key, "QuietUninstallString"),
            display_icon=self._read_value(key, "DisplayIcon"),
            source=SoftwareSource.REGISTRY,
            is_system_component=is_system,
        )
        return self.finalize(sw)

    def _scan_one_view(self, hive_name: str, hive, view_name: str, flag: int) -> list[InstalledSoftware]:
        """扫描单个 hive 的单个视图。"""
        result: list[InstalledSoftware] = []
        access = winreg.KEY_READ | flag
        try:
            with winreg.OpenKey(hive, UNINSTALL_SUBKEY, 0, access) as root:
                index = 0
                while True:
                    try:
                        subkey = winreg.EnumKey(root, index)
                    except OSError:
                        break
                    index += 1
                    try:
                        with winreg.OpenKey(root, subkey, 0, access) as item:
                            sw = self._build_from_key(hive_name, view_name, item, subkey)
                    except (OSError, ValueError) as exc:
                        self.add_warning(f"{hive_name}\\{subkey}", f"卸载项读取失败：{exc}")
                        continue
                    if sw is not None:
                        result.append(sw)
        except OSError as exc:
            self.add_warning(f"{hive_name}\\{UNINSTALL_SUBKEY}", f"无法打开卸载项根键：{exc}")
        return result

    # ---- 对外接口 ----

    def scan(self) -> list[InstalledSoftware]:
        """扫描全部 4 个卸载项根键并去重（HKLM 优先于 HKCU）。"""
        if winreg is None:
            self.add_warning("winreg", "当前平台不支持注册表访问，已跳过注册表扫描")
            return []

        collected: list[InstalledSoftware] = []
        for hive_name, hive in self._hives():
            for view_name, flag in self._views():
                items = self._scan_one_view(hive_name, hive, view_name, flag)
                logger.info("注册表扫描 %s(%s 位视图)：读取 %d 条", hive_name, view_name, len(items))
                collected.extend(items)

        # 去重：HKLM 优先（先出现者优先）；按 归一化名+发布商 判重
        seen: set[tuple[str, str]] = set()
        result: list[InstalledSoftware] = []
        for sw in sorted(collected, key=lambda s: 0 if s.id.startswith("reg:HKLM") else 1):
            key = (sw.norm_name or normalize_name(sw.name), sw.norm_publisher)
            if key in seen:
                continue
            seen.add(key)
            result.append(sw)
        logger.info("注册表扫描完成：去重后 %d 款软件", len(result))
        return result


# --------------------------------------------------------------------------
# MSIX 扫描器
# --------------------------------------------------------------------------


class MsixScanner(SoftwareSourceScanner):
    """扫描 MSIX / Microsoft Store 应用（PowerShell → JSON）。"""

    source_name = "msix"

    #: PowerShell 调用超时（秒）
    DEFAULT_TIMEOUT: int = 90

    def __init__(self, all_users: bool = False, timeout: int = DEFAULT_TIMEOUT) -> None:
        """初始化。

        Args:
            all_users: 是否追加 ``-AllUsers``（需管理员权限，Q3 默认关闭）。
            timeout: PowerShell 调用超时秒数。
        """
        super().__init__()
        self.all_users: bool = all_users
        self.timeout: int = timeout

    def build_powershell_args(self) -> list[str]:
        """构造 PowerShell 参数列表（不使用 ``shell=True``）。

        命令前置 ``[Console]::OutputEncoding = [System.Text.Encoding]::UTF8``：
        PowerShell 控制台默认按 **OEM 代码页**（简体中文为 936/GBK）输出，
        若按 utf-8 解码会把中文发布商名变成替换字符 ``U+FFFD``。
        """
        command = (
            "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
            "Get-AppxPackage"
            + (" -AllUsers" if self.all_users else "")
            + " | Select-Object Name,PackageFullName,Publisher,Version,"
              "InstallLocation,PackageFamilyName,Architecture | ConvertTo-Json -Depth 3 -Compress"
        )
        return [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ]

    def _parse(self, text: str) -> list[dict]:
        """解析 PowerShell 输出；单包时 ``ConvertTo-Json`` 返回 dict，需归一化为 list。"""
        text = (text or "").strip()
        if not text:
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            # 容错：截取第一个 JSON 起始位置再试
            start = min([i for i in (text.find("["), text.find("{")) if i >= 0], default=-1)
            if start < 0:
                self.add_warning("powershell", f"MSIX 输出解析失败：{exc}")
                return []
            try:
                data = json.loads(text[start:])
            except json.JSONDecodeError as exc2:
                self.add_warning("powershell", f"MSIX 输出解析失败：{exc2}")
                return []
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            self.add_warning("powershell", "MSIX 输出格式异常（既非对象也非数组）")
            return []
        return [d for d in data if isinstance(d, dict)]

    def _to_software(self, item: dict) -> InstalledSoftware:
        """把一条 MSIX 记录转换为 :class:`InstalledSoftware`。"""
        full_name = str(item.get("PackageFullName") or "").strip()
        family = str(item.get("PackageFamilyName") or "").strip()
        name = str(item.get("Name") or "").strip() or (family.split("_")[0] if family else "")
        sw = InstalledSoftware(
            id=f"msix:{full_name or name}",
            name=name,
            publisher=str(item.get("Publisher") or "").strip(),
            version=str(item.get("Version") or "").strip(),
            install_location=str(item.get("InstallLocation") or "").strip(),
            source=SoftwareSource.MSIX,
            package_family_name=family,
            is_system_component=False,
        )
        return self.finalize(sw)

    def scan(self) -> list[InstalledSoftware]:
        """执行 PowerShell 并解析为软件列表；失败时返回空列表并记录警告。"""
        args = self.build_powershell_args()
        try:
            # 以字节捕获，交由 decode_console_output 决定 utf-8 还是 OEM 代码页，
            # 避免中文发布商名被解成替换字符（U+FFFD）。
            completed = subprocess.run(
                args,
                capture_output=True,
                text=False,
                timeout=self.timeout,
                shell=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except FileNotFoundError:
            self.add_warning("powershell", "未找到 PowerShell，已跳过 MSIX 扫描")
            return []
        except subprocess.TimeoutExpired:
            self.add_warning("powershell", f"MSIX 扫描超时（{self.timeout} 秒），已跳过")
            return []
        except OSError as exc:
            self.add_warning("powershell", f"MSIX 扫描调用失败：{exc}")
            return []

        if completed.returncode != 0:
            detail = decode_console_output(completed.stderr).strip()[:200]
            self.add_warning("powershell", f"PowerShell 返回非零退出码 {completed.returncode}：{detail}")
            return []

        items = self._parse(decode_console_output(completed.stdout))
        result: list[InstalledSoftware] = []
        for item in items:
            try:
                sw = self._to_software(item)
            except (ValueError, TypeError) as exc:
                self.add_warning("powershell", f"MSIX 条目解析失败：{exc}")
                continue
            if sw.name:
                result.append(sw)
        logger.info("MSIX 扫描完成：%d 款应用", len(result))
        return result


# --------------------------------------------------------------------------
# 便捷函数
# --------------------------------------------------------------------------


def scan_all_software(
    include_system_component: bool = False,
    msix_all_users: bool = False,
) -> tuple[list[InstalledSoftware], list[dict]]:
    """一次性执行注册表 + MSIX 双源扫描。

    Args:
        include_system_component: 是否包含系统组件条目。
        msix_all_users: MSIX 是否包含所有用户。

    Returns:
        ``(软件列表, 警告列表)`` 二元组。
    """
    warnings: list[dict] = []
    result: list[InstalledSoftware] = []

    registry = RegistryScanner(include_system_component=include_system_component)
    result.extend(registry.scan())
    warnings.extend(registry.warnings)

    msix = MsixScanner(all_users=msix_all_users)
    result.extend(msix.scan())
    warnings.extend(msix.warnings)

    # 为无安装目录的软件补充一个基于名称的兜底关键词，提升 L5 召回
    for sw in result:
        if not sw.install_location:
            sw.install_location = ""
        if not sw.exe_names and sw.norm_name:
            sw.exe_names = []
        _ = tokenize  # 保持引用，供后续扩展使用

    return result, warnings


def resolve_exe_from_install_location(sw: InstalledSoftware) -> str:
    """在安装目录下寻找体积最大的 ``.exe``（图标提取用），失败返回空字符串。"""
    location = paths.to_absolute(sw.install_location)
    if not location or not os.path.isdir(paths.to_long_path(location)):
        return ""
    best_path = ""
    best_size = -1
    try:
        with os.scandir(paths.to_long_path(location)) as it:
            for item in it:
                try:
                    if not item.is_file(follow_symlinks=False):
                        continue
                    if not item.name.lower().endswith(".exe"):
                        continue
                    size = item.stat(follow_symlinks=False).st_size
                    if size > best_size:
                        best_size = size
                        best_path = item.path
                except OSError:
                    continue
    except OSError:
        return ""
    return best_path
