# -*- coding: utf-8 -*-
"""用户数据目录扫描（L2）：枚举根目录第一层子项并判定内容类型。

仅枚举**第一层直接子项**作为候选（避免全盘深遍历导致的性能与误判），
深度占用大小由 :mod:`size_calculator` 按需异步计算。
"""

from __future__ import annotations

import logging
import os

from . import paths
from .models import ContentType, DataPathEntry, EntryKind

logger = logging.getLogger("scan.dir")

# --------------------------------------------------------------------------
# 内容类型判定规则（PRD 3.3，顺序匹配，命中即停）
# --------------------------------------------------------------------------

#: 缓存类关键词
CACHE_WORDS: frozenset[str] = frozenset({
    "cache", "caches", "cachestorage", "gpucache", "codecache", "code cache",
    "temp", "tmp", "tempdir", "shadercache", " crashpad", "blob_storage",
})

#: 日志类关键词
LOG_WORDS: frozenset[str] = frozenset({"log", "logs", "logging", "crashlogs", "crashreports"})

#: 日志类扩展名
LOG_EXTS: frozenset[str] = frozenset({".log", ".etl", ".evtx"})

#: 插件类关键词
PLUGIN_WORDS: frozenset[str] = frozenset({"plugins", "plugin", "extensions", "extension", "addons", "add-ins"})

#: 配置类关键词
CONFIG_WORDS: frozenset[str] = frozenset({
    "config", "configs", "configuration", "settings", "setting", "preferences", "prefs",
})

#: 配置类扩展名（仅在 %APPDATA% 下生效）
CONFIG_EXTS: frozenset[str] = frozenset({".json", ".ini", ".xml", ".cfg", ".toml", ".yaml", ".yml", ".conf"})

#: 数据类关键词
DATA_WORDS: frozenset[str] = frozenset({
    "data", "databases", "database", "db", "storage", "local storage", "session storage",
    "user data", "indexeddb", "leveldb", "session", "state",
})

#: 用户主目录下与软件无关的知名目录/文件（直接忽略，不进入候选）
IGNORE_NAMES: frozenset[str] = frozenset({
    "desktop", "documents", "downloads", "music", "pictures", "videos", "links",
    "contacts", "favorites", "saved games", "searches", "3d objects", "onedrive",
    "appdata", "application data", "cookies", "recent", "templates", "libraries",
    "桌面", "文档", "下载", "音乐", "图片", "视频", "收藏夹", "库",
})

#: 需要忽略的文件名前缀（系统文件）
IGNORE_FILE_PREFIXES: tuple[str, ...] = ("ntuser", "usrclass", "desktop.ini", "thumbs.db")


def _split_segments(p: str) -> list[str]:
    """把路径切成小写的段列表。"""
    return [s.lower() for s in p.replace("/", "\\").split("\\") if s]


class DirScanner:
    """用户数据根目录扫描器。

    Attributes:
        roots: ``(根标识, 绝对路径)`` 列表。
        warnings: 扫描过程中产生的警告列表。
    """

    def __init__(self, roots: list[tuple[str, str]] | None = None) -> None:
        """初始化。

        Args:
            roots: 数据根目录列表；为 ``None`` 时使用 :data:`paths.DEFAULT_DATA_ROOTS` 的解析结果。
        """
        if roots is None:
            roots = [(key, paths.to_absolute(tpl)) for key, tpl in paths.DEFAULT_DATA_ROOTS]
        self.roots: list[tuple[str, str]] = [(k, v) for k, v in roots if v]
        self.warnings: list[dict] = []

    # ---- 内容类型判定 ----

    def classify_content_type(self, path: str, root_key: str = "") -> ContentType:
        """按 PRD 3.3 规则判定内容类型（顺序匹配，命中即停）。

        Args:
            path: 绝对路径。
            root_key: 所属根目录标识（``APPDATA`` 等），用于扩展名规则。

        Returns:
            :class:`ContentType` 枚举值。
        """
        if not path:
            return ContentType.OTHER
        ap = paths.to_absolute(path)
        segments = _split_segments(ap)
        lower = ap.lower()
        ext = os.path.splitext(ap)[1].lower()
        name = os.path.basename(ap)
        root_key_upper = (root_key or "").upper()

        # 1) 缓存
        if any(word in segments for word in CACHE_WORDS):
            return ContentType.CACHE

        # 2) 日志
        if any(word in segments for word in LOG_WORDS) or ext in LOG_EXTS:
            return ContentType.LOG

        # 3) 插件
        if any(word in segments for word in PLUGIN_WORDS):
            return ContentType.PLUGIN

        # 4) 配置
        if any(word in segments for word in CONFIG_WORDS):
            return ContentType.CONFIG
        if root_key_upper == "APPDATA" and ext in CONFIG_EXTS:
            return ContentType.CONFIG
        if root_key_upper == "USERPROFILE" and name.startswith(".") and not name.startswith(".."):
            return ContentType.CONFIG

        # 5) 数据
        if any(word in segments for word in DATA_WORDS):
            return ContentType.DATA
        profile_docs = paths.to_absolute(os.path.join(paths.expand_env(r"%USERPROFILE%"), "Documents"))
        public_docs = paths.to_absolute(paths.expand_env(r"%PUBLIC%\Documents"))
        if paths.is_subpath(ap, profile_docs) or paths.is_subpath(ap, public_docs):
            return ContentType.DATA

        return ContentType.OTHER

    # ---- 目录枚举 ----

    def _should_ignore(self, name: str, is_dir: bool) -> bool:
        """判断是否应忽略该子项。"""
        lower = name.lower()
        if not is_dir:
            if lower.startswith(IGNORE_FILE_PREFIXES):
                return True
            if lower in IGNORE_NAMES:
                return True
        else:
            if lower in IGNORE_NAMES:
                return True
        return False

    def _scan_root(self, root_key: str, root_abs: str) -> list[DataPathEntry]:
        """枚举单个根目录的第一层子项。"""
        entries: list[DataPathEntry] = []
        long_root = paths.to_long_path(root_abs)
        try:
            items = list(os.scandir(long_root))
        except OSError as exc:
            self.warnings.append({
                "stage": "dir",
                "target": root_abs,
                "message": f"数据根目录无法访问：{exc}",
            })
            logger.warning("数据根目录无法访问：%s（%s）", root_abs, exc)
            return entries

        for item in items:
            try:
                # 跳过符号链接与 junction/挂载点（Windows 下 junction 的 is_symlink() 为 False，
                # 需额外判断 FILE_ATTRIBUTE_REPARSE_POINT），避免循环与重复计数
                if item.is_symlink() or paths.is_reparse_point(item):
                    continue
                is_dir = item.is_dir(follow_symlinks=False)
            except OSError:
                continue
            name = item.name
            if self._should_ignore(name, is_dir):
                continue
            # 还原为规范化普通路径（去掉 \\?\ 前缀）
            normal_path = paths.to_absolute(paths.strip_long_prefix(item.path))
            entry = DataPathEntry(
                path=normal_path,
                root_key=root_key,
                root_abs=root_abs,
                kind=EntryKind.DIR if is_dir else EntryKind.FILE,
                content_type=self.classify_content_type(normal_path, root_key),
            )
            try:
                stat_result = item.stat(follow_symlinks=False)
                entry.mtime = float(stat_result.st_mtime)
                if not is_dir:
                    entry.size = int(stat_result.st_size)
                    entry.file_count = 1
            except OSError:
                entry.mtime = 0.0
            self._mark_safety(entry)
            entries.append(entry)
        return entries

    @staticmethod
    def _mark_safety(entry: DataPathEntry) -> None:
        """按黑名单标记条目的可删除性。"""
        allowed, reason = paths.mark_entry_safety(entry.path)
        entry.is_blacklisted = not allowed
        entry.block_reason = reason

    # ---- 对外接口 ----

    def scan(self) -> list[DataPathEntry]:
        """枚举全部数据根目录的第一层子项。

        Returns:
            去重后的候选条目列表（``size`` 仍为 ``-1``，等待渐进式计算）。
        """
        collected: list[DataPathEntry] = []
        for root_key, root_abs in self.roots:
            items = self._scan_root(root_key, root_abs)
            logger.info("数据根目录 %s（%s）：%d 个候选条目", root_key, root_abs, len(items))
            collected.extend(items)

        # 按路径去重（同一目录可能同时被两个根命中，如 LOCALAPPDATA 与其 Programs 子目录）
        seen: set[str] = set()
        result: list[DataPathEntry] = []
        for entry in collected:
            key = os.path.normcase(paths.to_absolute(entry.path))
            if key in seen:
                continue
            seen.add(key)
            result.append(entry)
        logger.info("候选条目合计（去重后）：%d", len(result))
        return result

    def scan_paths(self) -> list[str]:
        """仅返回候选路径字符串列表（供残留扫描等场景复用）。"""
        return [entry.path for entry in self.scan()]


def build_entry(path: str, root_key: str = "", root_abs: str = "") -> DataPathEntry:
    """根据给定路径构造一条候选条目（含类型判定与黑名单标记）。"""
    ap = paths.to_absolute(path)
    is_dir = os.path.isdir(paths.to_long_path(ap))
    entry = DataPathEntry(
        path=ap,
        root_key=root_key,
        root_abs=root_abs or os.path.dirname(ap),
        kind=EntryKind.DIR if is_dir else EntryKind.FILE,
    )
    entry.content_type = DirScanner().classify_content_type(ap, root_key)
    try:
        stat_result = os.stat(paths.to_long_path(ap), follow_symlinks=False)
        entry.mtime = float(stat_result.st_mtime)
        if not is_dir:
            entry.size = int(stat_result.st_size)
            entry.file_count = 1
    except OSError:
        entry.exists = False
    allowed, reason = paths.mark_entry_safety(ap)
    entry.is_blacklisted = not allowed
    entry.block_reason = reason
    return entry


def dedupe_entries(entries: list[DataPathEntry]) -> list[DataPathEntry]:
    """按路径去重条目列表。"""
    seen: set[str] = set()
    result: list[DataPathEntry] = []
    for entry in entries:
        key = os.path.normcase(paths.to_absolute(entry.path))
        if key in seen:
            continue
        seen.add(key)
        result.append(entry)
    return result


def filter_existing(entries: list[DataPathEntry]) -> list[DataPathEntry]:
    """保留仍然存在的条目。"""
    result: list[DataPathEntry] = []
    for entry in entries:
        long_path = paths.to_long_path(entry.path)
        entry.exists = os.path.exists(long_path)
        if entry.exists:
            result.append(entry)
    return result


__all__ = [
    "DirScanner",
    "build_entry",
    "dedupe_entries",
    "filter_existing",
    "ContentType",
]
