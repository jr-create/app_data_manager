# -*- coding: utf-8 -*-
"""占用大小计算（L2）：递归统计目录字节数与文件数。

特点：
    * 使用 ``os.scandir`` 迭代遍历（非递归调用，避免栈溢出）；
    * 全程 ``\\\\?\\`` 长路径前缀，兼容 >260 字符路径；
    * 跳过符号链接与挂载点，避免循环与重复计数；
    * 支持 ``threading.Event`` 取消，取消后已完成的条目结果保留。
"""

from __future__ import annotations

import logging
import os
import threading

from . import paths
from .models import DataPathEntry, EntryKind

logger = logging.getLogger("scan.size")


class SizeCalculator:
    """目录/文件占用大小计算器。"""

    def __init__(self, cancel_event: threading.Event | None = None) -> None:
        """初始化。

        Args:
            cancel_event: 取消事件；在遍历过程中被置位时尽快返回。
        """
        self._cancel: threading.Event | None = cancel_event

    # ---- 取消协议 ----

    @property
    def cancelled(self) -> bool:
        """是否已被请求取消。"""
        return bool(self._cancel is not None and self._cancel.is_set())

    def set_cancel_event(self, cancel_event: threading.Event | None) -> None:
        """替换取消事件（Worker 复用同一实例时使用）。"""
        self._cancel = cancel_event

    # ---- 核心计算 ----

    def compute_path(self, path: str, is_dir: bool = True) -> tuple[int, int]:
        """计算单个路径的 ``(字节数, 文件数)``。

        Args:
            path: 规范化绝对路径。
            is_dir: 是否为目录；``False`` 时直接 ``os.stat``。

        Returns:
            ``(字节数, 文件数)``；被取消、路径不存在或无法访问时返回 ``(-1, -1)``
            （与"空目录 = (0, 0)"区分，UI 据此继续显示"计算中…"）。
        """
        if not path:
            return (-1, -1)
        if self.cancelled:
            return (-1, -1)

        if not is_dir:
            try:
                stat_result = os.stat(paths.to_long_path(path), follow_symlinks=False)
            except OSError:
                return (-1, -1)
            return (int(stat_result.st_size), 1)

        total = 0
        count = 0
        stack: list[str] = [paths.to_long_path(path)]
        opened_root = False
        while stack:
            if self.cancelled:
                return (-1, -1)
            current = stack.pop()
            try:
                with os.scandir(current) as iterator:
                    opened_root = True
                    for item in iterator:
                        try:
                            # 符号链接 + junction/挂载点一并跳过（is_symlink 对 junction 返回 False）
                            if item.is_symlink() or paths.is_reparse_point(item):
                                continue
                            if item.is_dir(follow_symlinks=False):
                                stack.append(item.path)
                                continue
                            stat_result = item.stat(follow_symlinks=False)
                            total += int(stat_result.st_size)
                            count += 1
                        except OSError:
                            continue  # 单点失败不影响整体（P0-1）
            except OSError:
                # 根目录首次 scandir 即失败（路径不存在/无权限）→ 返回 -1 以便与"空目录"区分
                if not opened_root:
                    return (-1, -1)
                continue
            if self.cancelled:
                return (-1, -1)
        if not opened_root:
            return (-1, -1)
        return (total, count)

    def compute(self, entry: DataPathEntry) -> tuple[int, int]:
        """计算并**写回**条目的 ``size`` / ``file_count``。

        Args:
            entry: 待计算的条目。

        Returns:
            ``(字节数, 文件数)``；被取消时保持 ``-1`` 并返回 ``(-1, -1)``。
        """
        is_dir = entry.kind == EntryKind.DIR
        size, count = self.compute_path(entry.path, is_dir=is_dir)
        if size < 0:
            return (-1, -1)
        entry.size = size
        entry.file_count = count
        return (size, count)

    def compute_all(
        self,
        entries: list[DataPathEntry],
        on_progress: "callable | None" = None,
    ) -> None:
        """批量计算条目大小。

        Args:
            entries: 条目列表（就地写回）。
            on_progress: 进度回调 ``(已完成数, 总数, 当前路径)``，可为空。
        """
        total = len(entries)
        for index, entry in enumerate(entries, start=1):
            if self.cancelled:
                logger.info("大小计算被取消：已完成 %d/%d 项", index - 1, total)
                return
            self.compute(entry)
            if on_progress is not None:
                on_progress(index, total, entry.path)
        logger.info("大小计算完成：%d 项", total)


def compute_size(path: str, is_dir: bool = True, cancel_event: threading.Event | None = None) -> tuple[int, int]:
    """便捷函数：计算单个路径的占用大小。

    Args:
        path: 绝对路径。
        is_dir: 是否为目录。
        cancel_event: 取消事件。

    Returns:
        ``(字节数, 文件数)``。
    """
    return SizeCalculator(cancel_event).compute_path(path, is_dir=is_dir)
