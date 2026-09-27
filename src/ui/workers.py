# -*- coding: utf-8 -*-
"""后台 Worker（L5）：全部耗时操作均在 QThread 子类中执行，只通过 Signal 回传 UI。

统一信号协议：
    * ``stageChanged(str)``        阶段/状态文本
    * ``progressChanged(int,int,str)`` 已完成 / 总数 / 当前项
    * ``entrySized(str,object,object)``  单条路径大小计算完成（路径 / 字节 / 文件数）
    * ``finished(object)``         任务完成，携带结果对象
    * ``errorOccurred(str)``       失败原因（中文）
    * ``logEmitted(str)``          需要写入状态栏的文本

取消协议：``request_cancel()`` 设置 ``threading.Event``，core 层在循环内检查后尽快返回。
"""

from __future__ import annotations

import threading
from typing import Callable

from PySide6.QtCore import QThread, Signal

from ..core.backuper import Backuper
from ..core.deleter import Deleter
from ..core.models import (
    BackupReport,
    DataPathEntry,
    DeleteMode,
    DeleteReport,
    InstalledSoftware,
    ScanResult,
    UninstallReport,
)
from ..core.scan_service import ScanService
from ..core.size_calculator import SizeCalculator
from ..core.uninstaller import Uninstaller
from ..core.utils import Throttler

#: 进度信号节流间隔（毫秒）
PROGRESS_THROTTLE_MS: int = 100


class BaseWorker(QThread):
    """Worker 基类：统一信号、取消协议与节流发送。"""

    stageChanged = Signal(str)
    progressChanged = Signal(int, int, str)
    entrySized = Signal(str, object, object)  # 用 object 避免 32 位 int 溢出（目录 > 2 GiB 时）
    finished = Signal(object)
    errorOccurred = Signal(str)
    logEmitted = Signal(str)

    def __init__(self, parent=None) -> None:
        """初始化。

        Args:
            parent: 父对象（通常为 MainWindow）。
        """
        super().__init__(parent)
        self._cancel_event: threading.Event = threading.Event()
        self._throttler: Throttler = Throttler(PROGRESS_THROTTLE_MS)
        self._error: str = ""

    # ---- 取消协议 ----

    def request_cancel(self) -> None:
        """请求取消（主线程调用）。"""
        self._cancel_event.set()

    @property
    def cancel_event(self) -> threading.Event:
        """供 core 层使用的取消事件。"""
        return self._cancel_event

    @property
    def cancelled(self) -> bool:
        """是否已被请求取消。"""
        return self._cancel_event.is_set()

    # ---- 节流发送 ----

    def emit_stage(self, text: str) -> None:
        """发送阶段文本（立即发送）。"""
        self.stageChanged.emit(text)

    def emit_progress(self, done: int, total: int, text: str, force: bool = False) -> None:
        """发送进度（默认 100ms 节流）。

        Args:
            done: 已完成数量。
            total: 总数量。
            text: 当前项描述。
            force: 是否强制发送（忽略节流）。
        """
        if force or self._throttler.allow():
            self.progressChanged.emit(int(done), int(total), str(text))

    def emit_log(self, text: str) -> None:
        """发送一条状态文本。"""
        self.logEmitted.emit(str(text))

    def emit_error(self, text: str) -> None:
        """发送错误信息。"""
        self._error = text
        self.errorOccurred.emit(str(text))

    @property
    def error(self) -> str:
        """最近一次错误信息。"""
        return self._error

    # ---- 安全包装 ----

    def run_safely(self, body: Callable[[], object]) -> None:
        """执行任务体并统一捕获异常，避免子线程崩溃导致界面无响应。"""
        try:
            result = body()
            self.finished.emit(result)
        except Exception as exc:  # noqa: BLE001 - 兜底上报
            self.emit_error(f"后台任务异常：{exc}")


# --------------------------------------------------------------------------
# 扫描
# --------------------------------------------------------------------------


class ScanWorker(BaseWorker):
    """完整扫描 Worker（四阶段流水线 + 渐进式大小）。"""

    #: 归属完成、大小计算前的"渐进式首屏"信号
    scanReady = Signal(object)

    def __init__(self, config, parent=None) -> None:
        """初始化。

        Args:
            config: :class:`AppConfig`。
            parent: 父对象。
        """
        super().__init__(parent)
        self._config = config
        self._service: ScanService | None = None
        #: 路径 → 条目 映射，用于把大小变化逐条回传 UI
        self._entry_map: dict[str, DataPathEntry] = {}

    @property
    def service(self) -> ScanService | None:
        """当前使用的扫描服务（供主线程读取手动指派等状态）。"""
        return self._service

    def run(self) -> None:
        """执行扫描（子线程）。"""
        self.run_safely(self._scan)

    def _scan(self) -> ScanResult:
        service = ScanService(self._config)
        self._service = service

        def on_stage(text: str) -> None:
            self.emit_stage(text)
            self.emit_log(text)

        def on_progress(done: int, total: int, path: str) -> None:
            entry = self._entry_map.get(path)
            if entry is not None and entry.size >= 0:
                try:
                    self.entrySized.emit(path, entry.size, entry.file_count)
                except Exception:  # noqa: BLE001 - 单条回传失败不应中断整个扫描
                    pass
            if self._throttler.allow():
                self.progressChanged.emit(done, total, path)

        def on_ready(result: ScanResult) -> None:
            # 渐进式首屏：先把"无大小"的结果交给主线程渲染
            self._entry_map = {e.path: e for e in result.all_entries()}
            self.scanReady.emit(result)

        return service.full_scan(
            on_stage=on_stage,
            on_progress=on_progress,
            cancel_event=self._cancel_event,
            on_ready=on_ready,
        )


class SizeWorker(BaseWorker):
    """单独重算若干条目大小的 Worker（如缓存未命中时手动触发）。"""

    def __init__(self, entries: list[DataPathEntry], parent=None) -> None:
        """初始化。

        Args:
            entries: 待计算条目（就地写回）。
            parent: 父对象。
        """
        super().__init__(parent)
        self._entries = list(entries)

    def run(self) -> None:
        """执行大小计算（子线程）。"""
        self.run_safely(self._compute)

    def _compute(self) -> int:
        calculator = SizeCalculator(self._cancel_event)
        total = len(self._entries)

        def on_progress(done: int, count: int, path: str) -> None:
            for entry in self._entries:
                if entry.path == path and entry.size >= 0:
                    try:
                        self.entrySized.emit(path, entry.size, entry.file_count)
                    except Exception:  # noqa: BLE001 - 单条回传失败不应中断整个扫描
                        pass
                    break
            self.emit_progress(done, count, path)

        calculator.compute_all(self._entries, on_progress)
        self.emit_progress(total, total, "大小计算完成", force=True)
        return total


# --------------------------------------------------------------------------
# 备份 / 删除 / 卸载
# --------------------------------------------------------------------------


class BackupWorker(BaseWorker):
    """备份打包 Worker。"""

    def __init__(
        self,
        software_list: list[InstalledSoftware],
        dest_dir: str,
        exclude_cache_log: bool = True,
        parent=None,
    ) -> None:
        """初始化。

        Args:
            software_list: 待备份软件列表。
            dest_dir: 归档输出目录。
            exclude_cache_log: 是否排除缓存与日志。
            parent: 父对象。
        """
        super().__init__(parent)
        self._software_list = list(software_list)
        self._dest_dir = dest_dir
        self._exclude_cache_log = exclude_cache_log

    def run(self) -> None:
        """执行备份（子线程）。"""
        self.run_safely(self._backup)

    def _backup(self) -> BackupReport:
        backuper = Backuper(dest_dir=self._dest_dir, exclude_cache_log=self._exclude_cache_log)
        self.emit_stage("准备备份…")
        estimated = backuper.estimate_size(self._software_list)
        free = backuper.free_space()
        self.emit_log(f"预计需要 {estimated} 字节，目标磁盘可用 {free} 字节")

        def on_progress(done: int, total: int, path: str) -> None:
            self.emit_progress(done, total, path)

        return backuper.backup(self._software_list, on_progress=on_progress, cancel_event=self._cancel_event)


class DeleteWorker(BaseWorker):
    """删除 Worker（内部仍会执行黑名单二次校验）。"""

    def __init__(
        self,
        entries: list[DataPathEntry],
        mode: DeleteMode,
        backuper: Backuper | None = None,
        parent=None,
    ) -> None:
        """初始化。

        Args:
            entries: 待删除条目。
            mode: 删除策略。
            backuper: "先备份后删除"使用的备份器。
            parent: 父对象。
        """
        super().__init__(parent)
        self._entries = list(entries)
        self._mode = mode
        self._backuper = backuper

    def run(self) -> None:
        """执行删除（子线程）。"""
        self.run_safely(self._delete)

    def _delete(self) -> DeleteReport:
        deleter = Deleter(backuper=self._backuper)
        self.emit_stage("正在删除…")

        def on_progress(done: int, total: int, path: str) -> None:
            self.emit_progress(done, total, path)

        return deleter.delete(self._entries, self._mode, on_progress=on_progress)


class UninstallWorker(BaseWorker):
    """调用官方卸载程序 Worker。"""

    def __init__(
        self,
        software: InstalledSoftware,
        quiet: bool = True,
        timeout: int = 300,
        all_users: bool = False,
        parent=None,
    ) -> None:
        """初始化。

        Args:
            software: 目标软件。
            quiet: 是否静默卸载。
            timeout: 超时秒数。
            all_users: MSIX 是否针对所有用户。
            parent: 父对象。
        """
        super().__init__(parent)
        self._software = software
        self._quiet = quiet
        self._timeout = timeout
        self._all_users = all_users

    def run(self) -> None:
        """执行卸载（子线程）。"""
        self.run_safely(self._uninstall)

    def _uninstall(self) -> UninstallReport:
        uninstaller = Uninstaller(timeout=self._timeout)
        self.emit_stage(f"正在卸载 {self._software.name}…")
        self.emit_progress(0, 1, self._software.name, force=True)
        report = uninstaller.uninstall(
            self._software, quiet=self._quiet, timeout=self._timeout, all_users=self._all_users
        )
        self.emit_progress(1, 1, "卸载结束", force=True)
        return report
