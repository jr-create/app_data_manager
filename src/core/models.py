# -*- coding: utf-8 -*-
"""数据模型定义（L1 基础设施层）。

包含全部枚举与数据类：软件来源、内容类型、归属匹配级别、条目类型、删除模式，
以及 ``InstalledSoftware`` / ``DataPathEntry`` / ``ScanResult`` 等核心载体。
本模块只依赖同层的 ``paths``，不依赖任何上层模块，也**禁止导入 PySide6**。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum

from . import paths

# --------------------------------------------------------------------------
# 枚举定义
# --------------------------------------------------------------------------

#: 软件来源（用于 UI 展示的中文标签）
SOURCE_LABELS: dict[str, str] = {
    "registry": "注册表",
    "msix": "应用商店",
}

#: 内容类型（用于 UI 展示的中文标签）
CONTENT_TYPE_LABELS: dict[str, str] = {
    "config": "配置",
    "cache": "缓存",
    "log": "日志",
    "data": "数据",
    "plugin": "插件",
    "other": "其他",
}

#: 归属匹配级别（用于 UI 展示的中文标签）
MATCH_LEVEL_LABELS: dict[str, str] = {
    "L1": "L1 精确名",
    "L2": "L2 发布商",
    "L3": "L3 安装路径",
    "L4": "L4 可执行文件名",
    "L5": "L5 模糊匹配",
    "L6": "L6 别名表",
    "LX": "未识别",
}

#: 条目类型（用于 UI 展示的中文标签）
ENTRY_KIND_LABELS: dict[str, str] = {
    "dir": "目录",
    "file": "文件",
}

#: 删除模式（用于 UI 展示的中文标签）
DELETE_MODE_LABELS: dict[str, str] = {
    "backup_then_delete": "先备份后删除",
    "recycle_bin": "移入回收站",
    "permanent": "永久删除",
}


class SoftwareSource(str, Enum):
    """已安装软件的来源。"""

    REGISTRY = "registry"   # Win32 卸载项（注册表）
    MSIX = "msix"           # Microsoft Store / Appx 包

    @property
    def label(self) -> str:
        """返回用于界面展示的中文标签。"""
        return SOURCE_LABELS.get(self.value, self.value)


class ContentType(str, Enum):
    """数据路径的内容类型。"""

    CONFIG = "config"
    CACHE = "cache"
    LOG = "log"
    DATA = "data"
    PLUGIN = "plugin"
    OTHER = "other"

    @property
    def label(self) -> str:
        """返回用于界面展示的中文标签。"""
        return CONTENT_TYPE_LABELS.get(self.value, self.value)


class MatchLevel(str, Enum):
    """路径 → 软件 的归属匹配级别（L1 最强，LX 未识别）。"""

    L1_EXACT = "L1"
    L2_PUBLISHER = "L2"
    L3_INSTALL_PATH = "L3"
    L4_EXE_OR_FAMILY = "L4"
    L5_FUZZY = "L5"
    L6_ALIAS = "L6"
    NONE = "LX"

    @property
    def label(self) -> str:
        """返回用于界面展示的中文标签。"""
        return MATCH_LEVEL_LABELS.get(self.value, self.value)


class EntryKind(str, Enum):
    """候选条目类型：目录或文件。"""

    DIR = "dir"
    FILE = "file"

    @property
    def label(self) -> str:
        """返回用于界面展示的中文标签。"""
        return ENTRY_KIND_LABELS.get(self.value, self.value)


class DeleteMode(str, Enum):
    """删除策略（默认"先备份后删除"，符合换机场景）。"""

    BACKUP_THEN_DELETE = "backup_then_delete"
    RECYCLE_BIN = "recycle_bin"
    PERMANENT = "permanent"

    @property
    def label(self) -> str:
        """返回用于界面展示的中文标签。"""
        return DELETE_MODE_LABELS.get(self.value, self.value)


# --------------------------------------------------------------------------
# 核心数据类
# --------------------------------------------------------------------------


@dataclass
class InstalledSoftware:
    """一款已安装软件。

    Attributes:
        id: 稳定唯一标识，形如 ``reg:HKLM\\...\\Google Chrome`` 或 ``msix:{包全名}``。
        name: 显示名称（DisplayName / MSIX Name）。
        publisher: 发布商。
        version: 版本字符串。
        install_location: 安装目录。
        install_date: 安装日期，保留注册表原样 ``YYYYMMDD``。
        estimated_size_kb: 注册表登记的预估体积（KB）。
        uninstall_string: 标准卸载命令。
        quiet_uninstall_string: 静默卸载命令。
        display_icon: 图标路径，形如 ``C:\\...\\app.exe,0``。
        source: 软件来源。
        is_system_component: 是否为系统组件（默认不展示）。
        package_family_name: MSIX 包族名（仅 MSIX）。
        norm_name: 归一化后的名称（归属推断用，扫描后填充）。
        norm_publisher: 归一化后的发布商。
        exe_names: 主可执行文件名列表（L4 用，不含扩展名，小写）。
        data_paths: 归属于本软件的数据路径条目。
        total_size: 全部数据路径字节数合计。
    """

    id: str
    name: str = ""
    publisher: str = ""
    version: str = ""
    install_location: str = ""
    install_date: str = ""
    estimated_size_kb: int = 0
    uninstall_string: str = ""
    quiet_uninstall_string: str = ""
    display_icon: str = ""
    source: SoftwareSource = SoftwareSource.REGISTRY
    is_system_component: bool = False
    package_family_name: str = ""
    # ---- 派生字段（扫描后填充，不导出为冗余列）----
    norm_name: str = ""
    norm_publisher: str = ""
    exe_names: list[str] = field(default_factory=list)
    data_paths: list["DataPathEntry"] = field(default_factory=list)
    total_size: int = 0

    def install_root_name(self) -> str:
        """返回安装目录的末级目录名（小写），用于 L3 归属推断。

        Returns:
            末级目录名小写字符串；无安装目录时返回空字符串。
        """
        loc = (self.install_location or "").strip().strip('"').rstrip("\\/")
        if not loc:
            return ""
        return os.path.basename(loc).lower()

    def has_uninstall_cmd(self) -> bool:
        """是否存在可用的卸载命令（含 MSIX 的 Remove-AppxPackage）。"""
        return bool(
            (self.uninstall_string or "").strip()
            or (self.quiet_uninstall_string or "").strip()
            or (self.package_family_name or "").strip()
        )

    def to_dict(self) -> dict:
        """转换为可序列化字典（导出 JSON 用）。"""
        return {
            "id": self.id,
            "name": self.name,
            "publisher": self.publisher,
            "version": self.version,
            "install_location": self.install_location,
            "install_date": self.install_date,
            "estimated_size_kb": self.estimated_size_kb,
            "uninstall_string": self.uninstall_string,
            "quiet_uninstall_string": self.quiet_uninstall_string,
            "display_icon": self.display_icon,
            "source": self.source.value,
            "is_system_component": self.is_system_component,
            "package_family_name": self.package_family_name,
            "total_size": self.total_size,
            "path_count": len(self.data_paths),
        }


@dataclass
class DataPathEntry:
    """一条候选数据路径（目录或文件）。

    Attributes:
        path: 规范化后的绝对路径（不含 ``\\\\?\\`` 前缀），展示与逻辑统一使用此字段。
        root_key: 所属数据根目录标识，如 ``APPDATA`` / ``LOCALAPPDATA``。
        root_abs: 该根目录的绝对路径（备份/还原映射用）。
        kind: 目录或文件。
        content_type: 内容类型标签。
        size: 字节数；``-1`` 表示"未计算"。
        file_count: 文件数；``-1`` 表示"未计算"。
        mtime: 最后修改时间（UNIX 时间戳）。
        owner_id: 归属软件 id；``None`` 表示未识别。
        match_level: 命中级别。
        confidence: 置信度 0.0~1.0。
        is_fuzzy: 是否为模糊匹配（L5），UI 需标注"模糊匹配，请确认"。
        is_blacklisted: 是否命中系统关键目录黑名单。
        block_reason: 被拦截的中文原因。
        is_manual: 是否为用户手动指派（P1-4）。
        conflict_ids: 存在冲突的其它软件 id 列表。
        exists: 该路径当前是否仍存在。
    """

    path: str
    root_key: str = ""
    root_abs: str = ""
    kind: EntryKind = EntryKind.DIR
    content_type: ContentType = ContentType.OTHER
    size: int = -1
    file_count: int = -1
    mtime: float = 0.0
    owner_id: str | None = None
    match_level: MatchLevel = MatchLevel.NONE
    confidence: float = 0.0
    is_fuzzy: bool = False
    is_blacklisted: bool = False
    block_reason: str = ""
    is_manual: bool = False
    conflict_ids: list[str] = field(default_factory=list)
    exists: bool = True

    def display_path(self) -> str:
        """返回折叠为 ``%APPDATA%\\...`` 形式的展示路径。"""
        return paths.to_display_path(self.path)

    def to_dict(self) -> dict:
        """转换为可序列化字典（manifest / 导出 JSON 用）。"""
        return {
            "source_path": self.path,
            "display_path": self.display_path(),
            "root_key": self.root_key,
            "kind": self.kind.value,
            "content_type": self.content_type.value,
            "size": self.size,
            "file_count": self.file_count,
            "mtime": self.mtime,
            "owner_id": self.owner_id,
            "match_level": self.match_level.value,
            "confidence": round(self.confidence, 3),
            "is_fuzzy": self.is_fuzzy,
            "is_blacklisted": self.is_blacklisted,
            "block_reason": self.block_reason,
            "is_manual": self.is_manual,
            "conflict_ids": list(self.conflict_ids),
            "exists": self.exists,
        }


@dataclass
class ScanStats:
    """一次扫描的统计信息。"""

    software_count: int = 0
    entry_count: int = 0
    identified_count: int = 0
    orphan_count: int = 0
    blacklisted_count: int = 0
    total_size: int = 0
    elapsed_sec: float = 0.0


@dataclass
class ScanResult:
    """扫描结果总载体。

    Attributes:
        started_at: 扫描开始时间戳（time.time()）。
        finished_at: 扫描结束时间戳。
        software: ``软件 id -> InstalledSoftware`` 映射。
        orphan_entries: 未识别（Orphan）分组的条目列表。
        warnings: 警告列表，元素形如 ``{"stage","target","message"}``。
        stats: 统计信息。
    """

    started_at: float = 0.0
    finished_at: float = 0.0
    software: dict[str, InstalledSoftware] = field(default_factory=dict)
    orphan_entries: list[DataPathEntry] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)

    def all_entries(self) -> list[DataPathEntry]:
        """返回全部条目（已归属 + 未识别）。"""
        entries: list[DataPathEntry] = []
        for sw in self.software.values():
            entries.extend(sw.data_paths)
        entries.extend(self.orphan_entries)
        return entries

    def get(self, sw_id: str) -> InstalledSoftware | None:
        """按 id 取软件对象，不存在时返回 ``None``。"""
        return self.software.get(sw_id)

    def add_warning(self, stage: str, target: str, message: str) -> None:
        """追加一条扫描警告。"""
        self.warnings.append({"stage": stage, "target": target, "message": message})


@dataclass
class SkippedItem:
    """被跳过的条目（被占用 / 无权限 / 路径异常）。"""

    path: str = ""
    reason: str = ""

    def to_dict(self) -> dict:
        """转换为字典。"""
        return {"path": self.path, "reason": self.reason}


@dataclass
class BackupReport:
    """备份结果报告。"""

    success: bool = False
    archive_path: str = ""
    manifest_path: str = ""
    file_count: int = 0
    total_bytes: int = 0
    skipped: list[SkippedItem] = field(default_factory=list)
    error: str = ""

    def summary(self) -> str:
        """返回中文摘要（供对话框展示）。"""
        if not self.success:
            return f"备份失败：{self.error or '未知原因'}"
        text = f"备份完成：归档 {self.archive_path}（{self.file_count} 个文件）"
        if self.skipped:
            text += f"，跳过 {len(self.skipped)} 项"
        return text


@dataclass
class DeleteReport:
    """删除结果报告。"""

    success: bool = False
    deleted_count: int = 0
    deleted_bytes: int = 0
    skipped: list[SkippedItem] = field(default_factory=list)
    blocked: list[tuple[str, str]] = field(default_factory=list)
    mode: str = ""
    archive_path: str = ""

    def summary(self) -> str:
        """返回中文摘要（供对话框展示）。"""
        parts: list[str] = [f"已删除 {self.deleted_count} 项"]
        if self.blocked:
            parts.append(f"黑名单拦截 {len(self.blocked)} 项")
        if self.skipped:
            parts.append(f"失败/跳过 {len(self.skipped)} 项")
        if self.archive_path:
            parts.append(f"已先备份至 {self.archive_path}")
        return "，".join(parts)


@dataclass
class UninstallReport:
    """卸载结果报告。"""

    success: bool = False
    exit_code: int = -1
    command: str = ""
    elapsed_sec: float = 0.0
    error: str = ""
    stdout: str = ""
    stderr: str = ""

    def summary(self) -> str:
        """返回中文摘要（供对话框展示）。"""
        if self.success:
            return f"卸载完成（退出码 {self.exit_code}，用时 {self.elapsed_sec:.1f} 秒）"
        return f"卸载未成功：{self.error or '未知原因'}（退出码 {self.exit_code}）"


class AppError(Exception):
    """应用级异常：可预期的业务错误统一抛此类型，由 UI 层捕获并弹窗。"""

    def __init__(self, code: str, message: str, detail: str = "") -> None:
        """初始化。

        Args:
            code: 错误码，如 ``E_BACKUP_SPACE``。
            message: 面向用户的中文提示。
            detail: 调试用详细信息（可为空）。
        """
        super().__init__(message)
        self.code: str = code
        self.message: str = message
        self.detail: str = detail

    def __str__(self) -> str:
        if self.detail:
            return f"[{self.code}] {self.message}｜{self.detail}"
        return f"[{self.code}] {self.message}"
