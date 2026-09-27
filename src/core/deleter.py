# -*- coding: utf-8 -*-
"""数据删除（L3）：三种策略 + 黑名单二次校验 + 回收站支持。

安全红线：
    * **执行前再次调用** ``paths.check_path_safety()``（不依赖 UI 置灰，防绕过）；
    * 默认策略为"先备份后删除"，备份失败则**不删除任何数据**；
    * 回收站删除走 ``SHFileOperationW`` + ``FOF_ALLOWUNDO``（可恢复，自实现 ctypes，不引入 send2trash）。
"""

from __future__ import annotations

import ctypes
import logging
import os
import shutil
import sys
from typing import Callable

from . import config as config_mod
from . import paths
from .backuper import Backuper
from .models import (
    DataPathEntry,
    DeleteMode,
    DeleteReport,
    EntryKind,
    InstalledSoftware,
    SkippedItem,
)
from .utils import human_size

logger = logging.getLogger("delete")

# --------------------------------------------------------------------------
# 回收站删除（ctypes 自实现，Windows only）
# --------------------------------------------------------------------------

#: Shell 操作类型：删除
FO_DELETE: int = 3
#: 允许撤销（即移入回收站）
FOF_ALLOWUNDO: int = 0x0040
#: 不弹出确认框
FOF_NOCONFIRMATION: int = 0x0010
#: 静默模式
FOF_SILENT: int = 0x0004
#: 不显示错误 UI
FOF_NOERRORUI: int = 0x0400
#: 不确认新建目录
FOF_NOCONFIRMMKDIR: int = 0x0200

#: 单次提交给 SHFileOperationW 的最大路径条数
RECYCLE_BATCH_SIZE: int = 100

_IS_WINDOWS: bool = sys.platform.startswith("win")


if _IS_WINDOWS:  # pragma: no cover - 非 Windows 平台不定义结构
    from ctypes import wintypes

    class SHFILEOPSTRUCTW(ctypes.Structure):
        """``SHFILEOPSTRUCTW`` 结构体（用于 SHFileOperationW）。"""

        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("wFunc", wintypes.UINT),
            ("pFrom", wintypes.LPCWSTR),
            ("pTo", wintypes.LPCWSTR),
            ("fFlags", ctypes.c_uint16),
            ("fAnyOperationsAborted", wintypes.BOOL),
            ("hNameMappings", ctypes.c_void_p),
            ("lpszProgressTitle", wintypes.LPCWSTR),
        ]

else:  # pragma: no cover
    SHFILEOPSTRUCTW = None  # type: ignore[assignment,misc]


def send_to_recycle_bin(path_list: list[str]) -> tuple[list[str], list[tuple[str, str]]]:
    """把路径列表移入回收站（``FOF_ALLOWUNDO`` 可恢复）。

    Args:
        path_list: 普通绝对路径列表（**不能**带 ``\\\\?\\`` 前缀，也不能是相对路径）。

    Returns:
        ``(成功列表, 失败列表)``，失败元素为 ``(路径, 中文原因)``。
    """
    if not path_list:
        return [], []
    if not _IS_WINDOWS:
        return [], [(p, "当前平台不支持回收站删除") for p in path_list]

    ok: list[str] = []
    failed: list[tuple[str, str]] = []
    for start in range(0, len(path_list), RECYCLE_BATCH_SIZE):
        batch = path_list[start:start + RECYCLE_BATCH_SIZE]
        buffer = "\0".join(batch) + "\0\0"
        try:
            op = SHFILEOPSTRUCTW()
            op.hwnd = None
            op.wFunc = FO_DELETE
            op.pFrom = buffer
            op.pTo = None
            op.fFlags = (
                FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI | FOF_NOCONFIRMMKDIR
            )
            op.fAnyOperationsAborted = False
            op.hNameMappings = None
            op.lpszProgressTitle = None
            result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
        except (OSError, AttributeError, ctypes.ArgumentError) as exc:
            failed.extend((p, f"调用系统删除接口失败：{exc}") for p in batch)
            continue
        if result != 0 or bool(op.fAnyOperationsAborted):
            # 实测在部分 Windows 11 环境下 SHFileOperationW 会返回非零码（如 2），
            # 但目标确实已被移入回收站；因此以"路径是否仍然存在"作为最终判定依据。
            detail = ctypes.FormatError(result) if result else "操作被中止"
            for p in batch:
                if os.path.exists(p):
                    failed.append((p, f"移入回收站失败：{detail}"))
                else:
                    ok.append(p)
            continue
        ok.extend(batch)
    return ok, failed


def is_admin() -> bool:
    """判断当前进程是否拥有管理员权限。"""
    if not _IS_WINDOWS:
        return True
    try:
        shell32 = ctypes.windll.shell32
        shell32.IsUserAnAdmin.restype = ctypes.c_bool
        shell32.IsUserAnAdmin.argtypes = []
        return bool(shell32.IsUserAnAdmin())
    except (OSError, AttributeError):
        return False


# --------------------------------------------------------------------------
# 删除器
# --------------------------------------------------------------------------


class Deleter:
    """数据删除执行器。"""

    def __init__(self, backuper: Backuper | None = None) -> None:
        """初始化。

        Args:
            backuper: "先备份后删除"策略使用的备份器；为 ``None`` 时按需用默认目录构造。
        """
        self._backuper: Backuper | None = backuper

    @property
    def backuper(self) -> Backuper:
        """返回备份器（懒构造）。"""
        if self._backuper is None:
            self._backuper = Backuper(dest_dir=config_mod.get_default_backup_dir())
        return self._backuper

    # ---- 内部：按条目构造备份用的伪软件 ----

    @staticmethod
    def _build_pseudo_software(entries: list[DataPathEntry]) -> list[InstalledSoftware]:
        """按归属分组，把条目包装成"伪软件"以便复用备份逻辑。"""
        grouped: dict[str, list[DataPathEntry]] = {}
        for entry in entries:
            key = entry.owner_id or "__orphan__"
            grouped.setdefault(key, []).append(entry)
        result: list[InstalledSoftware] = []
        for key, items in grouped.items():
            name = items[0].owner_id or "未识别分组"
            result.append(InstalledSoftware(id=key, name=name, data_paths=items))
        return result

    # ---- 主流程 ----

    def delete(
        self,
        entries: list[DataPathEntry],
        mode: DeleteMode = DeleteMode.BACKUP_THEN_DELETE,
        on_progress: Callable[[int, int, str], None] | None = None,
    ) -> DeleteReport:
        """执行删除。

        Args:
            entries: 待删除条目（**未过滤黑名单**，本方法内部会二次校验）。
            mode: 删除策略。
            on_progress: 进度回调 ``(已完成, 总数, 当前路径)``。

        Returns:
            :class:`DeleteReport`。
        """
        report = DeleteReport(mode=mode.value if isinstance(mode, DeleteMode) else str(mode))
        if not entries:
            report.success = True
            report.blocked = []
            return report

        # 闸门 1：黑名单二次校验（执行前不可绕过）
        allowed: list[DataPathEntry] = []
        for entry in entries:
            verdict = paths.check_path_safety(entry.path)
            if verdict.blocked:
                report.blocked.append((entry.path, verdict.reason))
                logger.warning("黑名单拦截：%s（%s）", entry.path, verdict.reason)
                continue
            allowed.append(entry)

        if not allowed:
            report.success = True
            logger.info("全部目标均被黑名单拦截，未执行任何删除")
            return report

        # 闸门 2：先备份后删除
        if mode == DeleteMode.BACKUP_THEN_DELETE:
            pseudo = self._build_pseudo_software(allowed)
            backup_report = self.backuper.backup(pseudo)
            if not backup_report.success:
                report.success = False
                report.error = f"备份未完成，已中止删除（数据未动）：{backup_report.error}"
                report.skipped.append(SkippedItem("", report.error))
                logger.error(report.error)
                return report
            report.archive_path = backup_report.archive_path
            for item in backup_report.skipped:
                report.skipped.append(item)

        # 闸门 3：执行删除
        total = len(allowed)
        index = 0
        if mode == DeleteMode.RECYCLE_BIN:
            targets = [e.path for e in allowed]
            ok, failed = send_to_recycle_bin(targets)
            ok_set = {os.path.normcase(p) for p in ok}
            for entry in allowed:
                index += 1
                if os.path.normcase(entry.path) in ok_set:
                    report.deleted_count += 1
                    report.deleted_bytes += max(0, entry.size)
                    entry.exists = False
                if on_progress is not None:
                    on_progress(index, total, entry.path)
            for path, reason in failed:
                report.skipped.append(SkippedItem(path, reason))
        else:
            for entry in allowed:
                index += 1
                deleted, reason = self._delete_permanent(entry)
                if deleted:
                    report.deleted_count += 1
                    report.deleted_bytes += max(0, entry.size)
                    entry.exists = False
                else:
                    report.skipped.append(SkippedItem(entry.path, reason))
                if on_progress is not None:
                    on_progress(index, total, entry.path)

        report.success = not report.skipped or report.deleted_count > 0
        logger.info(
            "删除完成（%s）：成功 %d 项 / %s，黑名单拦截 %d 项，失败 %d 项",
            report.mode, report.deleted_count, human_size(report.deleted_bytes),
            len(report.blocked), len(report.skipped),
        )
        return report

    # ---- 永久删除 ----

    @staticmethod
    def _delete_permanent(entry: DataPathEntry) -> tuple[bool, str]:
        """永久删除单个条目。

        Returns:
            ``(是否成功, 中文原因)``。
        """
        # 删除前复查（防止路径在两次校验之间被替换为危险路径）
        verdict = paths.check_path_safety(entry.path)
        if verdict.blocked:
            return False, verdict.reason

        target = paths.to_long_path(entry.path)
        try:
            if entry.kind == EntryKind.DIR:
                if not os.path.isdir(target):
                    return False, "目录不存在或已被删除"
                shutil.rmtree(target, ignore_errors=False, onerror=lambda *_args: None)
                if os.path.exists(target):
                    return False, "目录未能完全删除（可能有文件被占用或权限不足）"
            else:
                if not os.path.exists(target):
                    return False, "文件不存在或已被删除"
                os.remove(target)
            return True, ""
        except PermissionError as exc:
            return False, f"权限不足，无法删除：{exc}"
        except FileNotFoundError:
            return False, "路径不存在或已被删除"
        except OSError as exc:
            return False, f"删除失败：{exc}"
