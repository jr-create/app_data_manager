# -*- coding: utf-8 -*-
"""备份打包（L3）：把软件关联数据目录打包为 zip 归档 + manifest.json。

安全约束：
    * ``archive_path`` 一律为**正斜杠相对路径**、剥离盘符与 ``..``（防 zip-slip）；
    * 备份前校验目标磁盘剩余空间（P1-3），不足时直接失败并给出中文原因；
    * 被占用/无权限文件逐文件 ``try/except``，写入 ``skipped`` 清单（不静默失败）。
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import threading
import zipfile
from datetime import datetime
from typing import Callable, Iterator

from . import config as config_mod
from . import paths
from .models import (
    BackupReport,
    ContentType,
    DataPathEntry,
    EntryKind,
    InstalledSoftware,
    SkippedItem,
)
from .utils import Throttler, human_size, now_iso, stamp

logger = logging.getLogger("backup")

#: 归档文件名前缀（A2 裁决：SDM_backup_<YYYYMMDD>_<HHMMSS>.zip）
ARCHIVE_PREFIX: str = "SDM_backup"

#: manifest 结构版本
MANIFEST_SCHEMA_VERSION: int = 1

#: 默认排除的内容类型（Q2 裁决）
EXCLUDED_TYPES: frozenset[ContentType] = frozenset({ContentType.CACHE, ContentType.LOG})


class Backuper:
    """备份打包器。"""

    def __init__(
        self,
        dest_dir: str = "",
        exclude_cache_log: bool = True,
        include_types: set[ContentType] | None = None,
    ) -> None:
        """初始化。

        Args:
            dest_dir: 归档输出目录；为空时使用配置中的默认目录。
            exclude_cache_log: 是否排除缓存与日志类路径（默认排除）。
            include_types: 显式指定要包含的内容类型；为 ``None`` 时不按类型额外过滤。
        """
        self.dest_dir: str = dest_dir or config_mod.get_default_backup_dir()
        self.exclude_cache_log: bool = exclude_cache_log
        self.include_types: set[ContentType] | None = include_types

    # ---- 过滤规则 ----

    def _entry_included(self, entry: DataPathEntry) -> bool:
        """判断条目是否纳入本次备份。"""
        if self.exclude_cache_log and entry.content_type in EXCLUDED_TYPES:
            return False
        if self.include_types is not None and entry.content_type not in self.include_types:
            return False
        return True

    # ---- 文件遍历 ----

    @staticmethod
    def _iter_files(entry: DataPathEntry) -> Iterator[str]:
        """遍历条目下的全部文件（跳过符号链接与 junction/挂载点），产出规范化普通路径。"""
        if entry.kind == EntryKind.FILE:
            yield entry.path
            return
        stack: list[str] = [paths.to_long_path(entry.path)]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as iterator:
                    for item in iterator:
                        try:
                            # 跳过符号链接与 junction/挂载点，避免重复打包与意外穿透
                            if item.is_symlink() or paths.is_reparse_point(item):
                                continue
                            if item.is_dir(follow_symlinks=False):
                                stack.append(item.path)
                            else:
                                yield paths.strip_long_prefix(item.path)
                        except OSError:
                            continue
            except OSError:
                continue

    @staticmethod
    def _archive_path(sw_name: str, root_key: str, base_dir: str, file_path: str) -> str:
        """生成 zip 内部安全相对路径（正斜杠、无盘符、无 ``..``）。"""
        try:
            rel = os.path.relpath(file_path, base_dir)
        except ValueError:
            rel = os.path.basename(file_path)
        rel = rel.replace("\\", "/")
        segments: list[str] = []
        for part in rel.split("/"):
            if part in ("", ".", ".."):
                continue
            segments.append(paths.safe_join_name(part, "item"))
        if not segments:
            segments = [paths.safe_join_name(os.path.basename(file_path), "item")]
        head = paths.safe_join_name(sw_name, "软件")
        root = paths.safe_join_name(root_key, "ROOT")
        return "/".join(["data", head, root, *segments])

    # ---- 空间预估 ----

    def estimate_size(self, software_list: list[InstalledSoftware]) -> int:
        """估算本次备份需要的字节数（已知大小的条目求和）。"""
        total = 0
        for sw in software_list:
            for entry in sw.data_paths:
                if self._entry_included(entry) and entry.size > 0:
                    total += entry.size
        return total

    def free_space(self) -> int:
        """返回目标目录所在磁盘的可用字节数。"""
        target = self.dest_dir
        probe = target if os.path.isdir(target) else os.path.dirname(target) or "."
        while probe and not os.path.isdir(probe):
            parent = os.path.dirname(probe)
            if parent == probe:
                break
            probe = parent
        try:
            return shutil.disk_usage(probe).free
        except OSError:
            return -1

    # ---- 主流程 ----

    def backup(
        self,
        software_list: list[InstalledSoftware],
        on_progress: Callable[[int, int, str], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> BackupReport:
        """执行备份。

        Args:
            software_list: 待备份的软件列表（取其 ``data_paths``）。
            on_progress: 进度回调 ``(已完成文件数, 总文件数, 当前文件)``。
            cancel_event: 取消事件；置位后在下一个文件检查点退出。

        Returns:
            :class:`BackupReport`。
        """
        report = BackupReport()
        if not software_list:
            report.error = "未选择任何软件，备份已取消"
            return report

        # 1) 汇总待备份条目
        planned: list[tuple[InstalledSoftware, DataPathEntry]] = []
        for sw in software_list:
            for entry in sw.data_paths:
                if not self._entry_included(entry):
                    continue
                if not os.path.exists(paths.to_long_path(entry.path)):
                    report.skipped.append(SkippedItem(entry.path, "路径已不存在，已跳过"))
                    continue
                planned.append((sw, entry))
        if not planned:
            report.error = "没有可备份的路径（可能全部被排除或已不存在）"
            return report

        # 2) 目标目录与磁盘空间校验（P1-3）
        try:
            os.makedirs(self.dest_dir, exist_ok=True)
        except OSError as exc:
            report.error = f"备份目录无法创建：{exc}"
            logger.error("备份目录无法创建：%s", exc)
            return report

        estimated = self.estimate_size(software_list)
        free = self.free_space()
        if free >= 0 and estimated > 0 and free < estimated:
            report.error = (
                f"磁盘空间不足：预计需要 {human_size(estimated)}，可用 {human_size(free)}"
            )
            logger.error("磁盘空间不足：需要 %s，可用 %s", human_size(estimated), human_size(free))
            return report

        # 3) 打包
        archive_name = f"{ARCHIVE_PREFIX}_{stamp()}.zip"
        archive_path = os.path.join(self.dest_dir, archive_name)
        file_total = sum(e.file_count for _, e in planned if e.file_count > 0)
        done = 0
        written = 0
        total_bytes = 0
        throttler = Throttler(100)
        manifest_software: list[dict] = []
        #: 已写入的归档内部路径，用于去重（同一文件可能被多个条目重复覆盖）
        written_arcnames: set[str] = set()

        try:
            with zipfile.ZipFile(
                archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True
            ) as zf:
                for sw, entry in planned:
                    if cancel_event is not None and cancel_event.is_set():
                        report.error = "备份已被用户取消"
                        break
                    base_dir = entry.root_abs or os.path.dirname(entry.path)
                    entry_files = 0
                    entry_bytes = 0
                    entry_skipped: list[dict] = []
                    if cancel_event is not None and cancel_event.is_set():
                        report.error = "备份已被用户取消"
                        break
                    for file_path in self._iter_files(entry):
                        if cancel_event is not None and cancel_event.is_set():
                            report.error = "备份已被用户取消"
                            break
                        arcname = self._archive_path(sw.name or "未命名软件", entry.root_key or "ROOT", base_dir, file_path)
                        if arcname in written_arcnames:
                            continue  # 同一文件被多个条目覆盖时只写入一次，避免重复条目
                        written_arcnames.add(arcname)
                        try:
                            zf.write(paths.to_long_path(file_path), arcname=arcname)
                            entry_files += 1
                            entry_bytes += os.path.getsize(paths.to_long_path(file_path))
                        except (OSError, PermissionError, ValueError) as exc:
                            reason = f"文件被占用或无权限：{exc}"
                            entry_skipped.append({"source_path": file_path, "reason": reason})
                            report.skipped.append(SkippedItem(file_path, reason))
                            continue
                        done += 1
                        if on_progress is not None and throttler.allow():
                            on_progress(done, max(file_total, done), file_path)
                    written += entry_files
                    total_bytes += entry_bytes
                    manifest_software.append({
                        "id": sw.id,
                        "name": sw.name,
                        "publisher": sw.publisher,
                        "version": sw.version,
                        "source": sw.source.value,
                        "install_location": sw.install_location,
                        "entries": [{
                            "source_path": entry.path,
                            "root_key": entry.root_key,
                            "archive_path": f"data/{paths.safe_join_name(sw.name or '未命名软件', '软件')}/"
                                            f"{paths.safe_join_name(entry.root_key or 'ROOT', 'ROOT')}",
                            "content_type": entry.content_type.value,
                            "size": entry.size,
                            "file_count": entry_files,
                            "bytes": entry_bytes,
                            "mtime": datetime.fromtimestamp(entry.mtime).isoformat(timespec="seconds") if entry.mtime else "",
                            "skipped": entry_skipped,
                        }],
                        "total_size": entry_bytes,
                    })
                    if cancel_event is not None and cancel_event.is_set():
                        break

                # 4) manifest.json（写入归档内部）
                manifest = self._build_manifest(manifest_software, written, total_bytes, report)
                zf.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            report.error = f"归档写入失败：{exc}"
            logger.exception("归档写入失败")
            return report

        if report.error:
            report.success = False
            report.archive_path = archive_path
            return report

        # 5) 同步写一份 manifest 到归档旁边，便于用户直接查看
        manifest_path = os.path.splitext(archive_path)[0] + ".manifest.json"
        try:
            with open(manifest_path, "w", encoding="utf-8") as fp:
                json.dump(self._build_manifest(manifest_software, written, total_bytes, report),
                          fp, ensure_ascii=False, indent=2)
        except OSError:
            manifest_path = ""

        report.success = True
        report.archive_path = archive_path
        report.manifest_path = manifest_path
        report.file_count = written
        report.total_bytes = total_bytes
        if on_progress is not None:
            on_progress(done, max(file_total, done), "备份完成")
        logger.info("备份完成：%s（%d 个文件，%s，跳过 %d 项）",
                    archive_path, written, human_size(total_bytes), len(report.skipped))
        return report

    # ---- manifest ----

    def _build_manifest(
        self,
        software_items: list[dict],
        file_count: int,
        total_bytes: int,
        report: BackupReport,
    ) -> dict:
        """构造 manifest.json 内容（schema 见架构 3.5 节）。"""
        import getpass
        import platform

        return {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "tool_version": "0.1.0",
            "created_at": now_iso(),
            "host": {"user": getpass.getuser(), "machine": platform.node()},
            "options": {
                "exclude_cache_log": self.exclude_cache_log,
                "compression": "deflate",
                "include_types": sorted(t.value for t in self.include_types) if self.include_types else None,
            },
            "software": software_items,
            "totals": {
                "software": len(software_items),
                "entries": sum(len(s.get("entries", [])) for s in software_items),
                "files": file_count,
                "bytes": total_bytes,
                "skipped": len(report.skipped),
            },
        }

    # ---- 还原（P1-2 预留）----

    def restore(self, archive_path: str, target_map: dict[str, str] | None = None) -> None:
        """从归档还原数据（P1-2）。

        Raises:
            NotImplementedError: MVP 阶段仅预留接口，不做实现。
        """
        raise NotImplementedError("P1-2 还原功能：接口预留，MVP 不实现")
