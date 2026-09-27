# -*- coding: utf-8 -*-
"""扫描编排层（L4）：串起"软件扫描 → 目录枚举 → 归属推断 → 渐进式大小"四阶段流水线。

同时负责：扫描缓存读写（二次打开秒显，A3：7 天 TTL + mtime 双条件失效）、
卸载后残留扫描（P1-1）与手动指派持久化（P1-4）。
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Callable

from . import config as config_mod
from .attribution import AttributionEngine
from .config import AppConfig, load_config
from .dir_scanner import DirScanner
from .models import (
    ContentType,
    DataPathEntry,
    InstalledSoftware,
    ScanResult,
    ScanStats,
)
from .size_calculator import SizeCalculator
from .software_scanner import MsixScanner, RegistryScanner
from .utils import human_size

logger = logging.getLogger("scan.service")

#: 缓存的 mtime 容差（秒）：目录 mtime 变化超过该值即视为缓存失效
MTIME_TOLERANCE: float = 1.0


class ScanService:
    """扫描流水线编排器。"""

    def __init__(self, config: AppConfig | None = None) -> None:
        """初始化。

        Args:
            config: 应用配置；为 ``None`` 时从磁盘加载。
        """
        self.config: AppConfig = config or load_config()
        self.warnings: list[dict] = []
        self._engine: AttributionEngine | None = None
        self._owner_map: dict[str, str] = {}
        self._cancel: threading.Event = threading.Event()

    # ---- 取消协议 ----

    def cancel(self) -> None:
        """请求取消当前扫描（供 UI 取消按钮调用）。"""
        self._cancel.set()

    def reset_cancel(self, cancel_event: threading.Event | None = None) -> threading.Event:
        """重置取消状态并返回新的事件对象。"""
        self._cancel = cancel_event if cancel_event is not None else threading.Event()
        return self._cancel

    @property
    def cancelled(self) -> bool:
        """是否已被请求取消。"""
        return self._cancel.is_set()

    # ---- 阶段 1：软件扫描 ----

    def scan_software(self) -> list[InstalledSoftware]:
        """扫描注册表卸载项 + MSIX 应用（去重后返回）。"""
        collected: list[InstalledSoftware] = []

        registry = RegistryScanner(include_system_component=self.config.show_system_component)
        collected.extend(registry.scan())
        self.warnings.extend(registry.warnings)

        if self.cancelled:
            return collected

        msix = MsixScanner(all_users=self.config.msix_all_users)
        collected.extend(msix.scan())
        self.warnings.extend(msix.warnings)

        return self._dedupe_software(collected)

    @staticmethod
    def _dedupe_software(items: list[InstalledSoftware]) -> list[InstalledSoftware]:
        """软件去重：HKLM 优先于 HKCU，按（归一化名 + 发布商）判重。"""
        ordered = sorted(items, key=lambda s: 0 if s.source.value == "registry" and s.id.startswith("reg:HKLM") else
                         (1 if s.source.value == "registry" else 2))
        seen: set[tuple[str, str]] = set()
        result: list[InstalledSoftware] = []
        for sw in ordered:
            key = (sw.norm_name, sw.norm_publisher)
            if key in seen:
                continue
            seen.add(key)
            result.append(sw)
        return result

    # ---- 阶段 2：候选目录枚举 ----

    @property
    def dir_scanner(self) -> DirScanner:
        """按当前配置构造目录扫描器。"""
        return DirScanner(roots=self.config.resolved_data_roots())

    def scan_candidates(self) -> list[DataPathEntry]:
        """枚举用户数据根目录第一层子项（含内容类型判定与黑名单标记）。"""
        scanner = self.dir_scanner
        entries = scanner.scan()
        self.warnings.extend(scanner.warnings)
        return entries

    # ---- 阶段 3：归属推断 ----

    def build_engine(self, software: list[InstalledSoftware]) -> AttributionEngine:
        """构造归属推断引擎并载入手动指派（P1-4）。"""
        engine = AttributionEngine(software, threshold=self.config.fuzzy_threshold)
        engine.apply_manual_overrides(config_mod.load_manual_overrides())
        engine.build_index()
        self._engine = engine
        return engine

    def attribute(self, candidates: list[DataPathEntry]) -> dict:
        """对候选条目执行归属推断（引擎缺失时按当前软件列表懒构建）。"""
        if self._engine is None:
            self.build_engine(self.scan_software())
        assert self._engine is not None
        return self._engine.attribute(candidates)

    # ---- 阶段 4：渐进式大小 ----

    def _apply_cache(self, entries: list[DataPathEntry]) -> int:
        """用本地缓存填充已知大小（二次打开秒显）。

        Returns:
            命中缓存的条目数。
        """
        cache = config_mod.load_size_cache()
        if not cache:
            return 0
        hit = 0
        for entry in entries:
            info = cache.get(entry.path)
            if not info:
                continue
            try:
                size = int(info.get("size", -1))
                count = int(info.get("file_count", -1))
                mtime = float(info.get("mtime", 0) or 0)
            except (TypeError, ValueError):
                continue
            if size < 0:
                continue
            if entry.mtime and mtime and abs(entry.mtime - mtime) > MTIME_TOLERANCE:
                continue  # mtime 变化 → 缓存失效
            entry.size = size
            entry.file_count = count
            hit += 1
        if hit:
            logger.info("大小缓存命中 %d 条（共 %d 条缓存）", hit, len(cache))
        return hit

    def progressive_size(
        self,
        result: ScanResult,
        on_progress: Callable[[int, int, str], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> None:
        """渐进式计算占用大小（UI 可在此期间保持响应）。

        Args:
            result: 扫描结果（就地填充条目的 size/file_count）。
            on_progress: 进度回调 ``(已完成, 总数, 当前路径)``。
            cancel_event: 取消事件。
        """
        event = cancel_event if cancel_event is not None else self._cancel
        entries = result.all_entries()
        pending = [e for e in entries if e.size < 0]
        calculator = SizeCalculator(event)

        def _callback(done: int, total: int, path: str) -> None:
            sw_id = self._owner_map.get(path)
            if sw_id:
                sw = result.get(sw_id)
                if sw is not None:
                    sw.total_size = sum(max(0, e.size) for e in sw.data_paths)
            if on_progress is not None:
                on_progress(done, total, path)

        calculator.compute_all(pending, _callback)
        for sw in result.software.values():
            sw.total_size = sum(max(0, e.size) for e in sw.data_paths)
        result.stats.total_size = sum(max(0, e.size) for e in result.all_entries())

    # ---- 完整流水线 ----

    def full_scan(
        self,
        on_stage: Callable[[str], None] | None = None,
        on_progress: Callable[[int, int, str], None] | None = None,
        cancel_event: threading.Event | None = None,
        on_ready: Callable[[ScanResult], None] | None = None,
    ) -> ScanResult:
        """执行完整四阶段扫描。

        Args:
            on_stage: 阶段变化回调。
            on_progress: 大小计算进度回调。
            cancel_event: 取消事件。
            on_ready: 归属完成、大小计算前的回调（用于渐进式首屏渲染）。

        Returns:
            :class:`ScanResult`。
        """
        started = time.time()
        self.warnings = []
        self._owner_map = {}
        self.reset_cancel(cancel_event)

        result = ScanResult(started_at=started)

        def stage(text: str) -> None:
            if on_stage is not None:
                on_stage(text)
            logger.info("扫描阶段：%s", text)

        # 1/4 注册表 + 2/4 MSIX
        stage("1/4 注册表卸载项")
        software_list = self.scan_software()
        stage(f"2/4 MSIX/Store 应用（已获取 {len(software_list)} 个软件）")
        result.software = {sw.id: sw for sw in software_list}
        result.warnings.extend(self.warnings)

        if self.cancelled:
            return self._finalize(result)

        # 3/4 目录枚举 + 归属推断
        stage("3/4 用户数据目录枚举")
        candidates = self.scan_candidates()
        self.build_engine(software_list)
        matches = self.attribute(candidates)

        for entry in candidates:
            match = matches.get(entry.path)
            owner_id = match.software_id if match else None
            if owner_id and owner_id in result.software:
                result.software[owner_id].data_paths.append(entry)
                self._owner_map[entry.path] = owner_id
            else:
                result.orphan_entries.append(entry)

        self._apply_cache(candidates)
        self._refresh_stats(result)
        logger.info(
            "扫描阶段 3 完成：候选 %d 条，已识别 %d 条，未识别 %d 条",
            len(candidates), result.stats.identified_count, result.stats.orphan_count,
        )

        # 渐进式首屏：先把无大小的结果交给 UI 渲染
        if on_ready is not None:
            on_ready(result)

        if self.cancelled:
            return self._finalize(result)

        # 4/4 渐进式大小
        stage("4/4 计算占用大小（较慢，可取消）")
        self.progressive_size(result, on_progress, self._cancel)

        return self._finalize(result)

    def _finalize(self, result: ScanResult) -> ScanResult:
        """收尾：刷新统计、写缓存、记录耗时。"""
        self._refresh_stats(result)
        result.finished_at = time.time()
        result.stats.elapsed_sec = round(result.finished_at - result.started_at, 3)
        try:
            self.save_cache(result)
        except OSError:
            logger.warning("扫描缓存写入失败（不影响使用）")
        logger.info(
            "扫描完成：%d 个软件 / %d 条路径 / 未识别 %d 条 / 合计 %s / 用时 %.2f 秒",
            result.stats.software_count, result.stats.entry_count,
            result.stats.orphan_count, human_size(result.stats.total_size),
            result.stats.elapsed_sec,
        )
        return result

    @staticmethod
    def refresh_stats(result: ScanResult) -> None:
        """刷新 :class:`ScanStats`（公开入口）。"""
        entries = result.all_entries()
        identified = sum(1 for e in entries if e.owner_id)
        result.stats = ScanStats(
            software_count=len(result.software),
            entry_count=len(entries),
            identified_count=identified,
            orphan_count=len(entries) - identified,
            blacklisted_count=sum(1 for e in entries if e.is_blacklisted),
            total_size=sum(max(0, e.size) for e in entries),
            elapsed_sec=round(time.time() - result.started_at, 3) if result.started_at else 0.0,
        )

    # 保留旧名以兼容内部调用
    _refresh_stats = refresh_stats

    # ---- 缓存 ----

    def load_cache(self) -> dict[str, dict]:
        """读取大小缓存。"""
        return config_mod.load_size_cache()

    def save_cache(self, result: ScanResult) -> None:
        """写入大小缓存（仅记录已计算成功的条目）。"""
        cache = config_mod.load_size_cache()
        now = time.time()
        for entry in result.all_entries():
            if entry.size < 0:
                continue
            cache[entry.path] = {
                "size": entry.size,
                "file_count": entry.file_count,
                "mtime": entry.mtime,
                "cached_at": now,
            }
        config_mod.save_size_cache(cache)

    # ---- 残留扫描（P1-1）----

    @staticmethod
    def snapshot(result: ScanResult) -> dict[str, str | None]:
        """生成"路径 → 归属 id"快照，供卸载前后对比。"""
        return {e.path: e.owner_id for e in result.all_entries()}

    def scan_residual(self, before: dict[str, str | None] | list[str], after: ScanResult | list[DataPathEntry]) -> list[DataPathEntry]:
        """对比卸载前后，识别疑似残留目录（P1-1）。

        判定规则（满足其一即列为疑似残留）：
            1. 卸载前不存在、卸载后新增，且当前无归属；
            2. 卸载前有归属、卸载后失去归属（软件已卸载，目录仍在）。

        Args:
            before: 卸载前快照（``{路径: 归属id}``）或路径列表。
            after: 卸载后的扫描结果或条目列表。

        Returns:
            疑似残留条目列表。
        """
        if isinstance(before, dict):
            before_map = {os.path.normcase(k): v for k, v in before.items()}
        else:
            before_map = {os.path.normcase(p): None for p in before}

        if isinstance(after, ScanResult):
            entries = after.all_entries()
        else:
            entries = list(after)

        residual: list[DataPathEntry] = []
        for entry in entries:
            key = os.path.normcase(entry.path)
            if key not in before_map:
                if entry.owner_id is None:
                    residual.append(entry)
                continue
            previous_owner = before_map.get(key)
            if previous_owner and entry.owner_id is None:
                residual.append(entry)
        logger.info("残留扫描完成：疑似残留 %d 项", len(residual))
        return residual

    # ---- 重新扫描（卸载后）----

    def rescan(
        self,
        on_stage: Callable[[str], None] | None = None,
        on_progress: Callable[[int, int, str], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> ScanResult:
        """重新执行一次完整扫描（卸载后刷新列表用）。"""
        return self.full_scan(on_stage=on_stage, on_progress=on_progress, cancel_event=cancel_event)

    # ---- 手动指派（P1-4）----

    def apply_manual_attribution(self, result: ScanResult, entry_path: str, software_id: str | None) -> None:
        """把某条路径手动指派给指定软件（或移出归属），并即时更新结果。

        Args:
            result: 当前扫描结果（就地修改）。
            entry_path: 条目路径。
            software_id: 目标软件 id；``None`` 表示移出归属（回到未识别）。
        """
        entry: DataPathEntry | None = None
        for item in result.all_entries():
            if os.path.normcase(item.path) == os.path.normcase(entry_path):
                entry = item
                break
        if entry is None:
            logger.warning("手动指派失败：未找到路径 %s", entry_path)
            return

        # 先从原归属中移除
        if entry.owner_id and entry.owner_id in result.software:
            old = result.software[entry.owner_id]
            old.data_paths = [e for e in old.data_paths if os.path.normcase(e.path) != os.path.normcase(entry.path)]
            old.total_size = sum(max(0, e.size) for e in old.data_paths)
        result.orphan_entries = [e for e in result.orphan_entries
                                 if os.path.normcase(e.path) != os.path.normcase(entry.path)]

        if software_id and software_id in result.software:
            target = result.software[software_id]
            entry.owner_id = software_id
            entry.match_level = entry.match_level.__class__.L1_EXACT
            entry.confidence = 1.0
            entry.is_fuzzy = False
            entry.is_manual = True
            target.data_paths.append(entry)
            target.total_size = sum(max(0, e.size) for e in target.data_paths)
            self._owner_map[entry.path] = software_id
        else:
            entry.owner_id = None
            entry.match_level = entry.match_level.__class__.NONE
            entry.confidence = 0.0
            entry.is_fuzzy = False
            entry.is_manual = False
            result.orphan_entries.append(entry)
            self._owner_map.pop(entry.path, None)

        # 持久化（A6：按路径字符串存储）
        if self._engine is not None:
            self._engine.set_manual_override(entry_path, software_id)
            config_mod.save_manual_overrides(self._engine.manual_overrides())
        else:
            overrides = config_mod.load_manual_overrides()
            if software_id:
                overrides[entry_path] = software_id
            else:
                overrides.pop(entry_path, None)
            config_mod.save_manual_overrides(overrides)

        self._refresh_stats(result)
        logger.info("手动指派：%s → %s", entry_path, software_id or "未识别")

    # ---- 内容类型过滤（备份/删除前的口径统一）----

    @staticmethod
    def filter_entries(
        entries: list[DataPathEntry],
        exclude_cache_log: bool = True,
        types: set[ContentType] | None = None,
    ) -> list[DataPathEntry]:
        """按内容类型过滤条目。"""
        result: list[DataPathEntry] = []
        for entry in entries:
            if exclude_cache_log and entry.content_type in (ContentType.CACHE, ContentType.LOG):
                continue
            if types is not None and entry.content_type not in types:
                continue
            result.append(entry)
        return result
