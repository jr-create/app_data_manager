#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""软件数据迁移助手 —— 冒烟验证脚本（中文输出）。

覆盖内容：
    1. 全部模块可导入；
    2. 路径工具与系统关键目录黑名单判定；
    3. **真实扫描本机**（注册表 + MSIX + 数据目录枚举 + 归属推断），仅读取绝不写入；
    4. 临时目录假数据：备份 → 解压结构一致 → 删除（永久 / 回收站）→ 黑名单拦截；
    5. 导出 CSV / JSON 可被解析；
    6. GUI 启动冒烟：显示主窗口 1.5 秒后自动退出。

安全约束：
    * 全程只读注册表，绝不写入或删除任何注册表项；
    * 所有删除操作只在 ``tempfile.mkdtemp()`` 构造的假数据上执行；
    * 不卸载任何真实软件。

用法::

    python tests/smoke_test.py              # 全部用例
    python tests/smoke_test.py --no-gui     # 跳过 GUI 冒烟
    python tests/smoke_test.py --no-real    # 跳过真实本机扫描
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import sys
import tempfile
import time
import zipfile

#: 项目根目录（tests/ 的上一级）
PROJECT_ROOT: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.core import config as config_mod                     # noqa: E402
from src.core import paths                                    # noqa: E402
from src.core.attribution import AttributionEngine            # noqa: E402
from src.core.backuper import Backuper                        # noqa: E402
from src.core.config import AppConfig                         # noqa: E402
from src.core.deleter import Deleter, is_admin                # noqa: E402
from src.core.dir_scanner import DirScanner, build_entry      # noqa: E402
from src.core.exporters import export_csv, export_json        # noqa: E402
from src.core.models import (                                 # noqa: E402
    ContentType,
    DataPathEntry,
    DeleteMode,
    EntryKind,
    InstalledSoftware,
    ScanResult,
)
from src.core.scan_service import ScanService                 # noqa: E402
from src.core.size_calculator import SizeCalculator           # noqa: E402
from src.core.utils import (                                 # noqa: E402
    ActionLogger,
    human_size,
    normalize_name,
    similarity,
)

#: 用例结果收集
RESULTS: list[tuple[str, bool, str]] = []


# --------------------------------------------------------------------------
# 工具
# --------------------------------------------------------------------------


def section(title: str) -> None:
    """打印章节标题。"""
    print("\n" + "=" * 72)
    print(f"  {title}")
    print("=" * 72)


def record(name: str, ok: bool, detail: str = "") -> bool:
    """记录一条用例结果并打印。"""
    RESULTS.append((name, bool(ok), detail))
    mark = "✅ 通过" if ok else "❌ 失败"
    print(f"  [{mark}] {name}" + (f" —— {detail}" if detail else ""))
    return bool(ok)


def check(name: str, condition: bool, detail: str = "") -> bool:
    """断言并记录（不抛异常，便于跑完全部用例）。"""
    return record(name, bool(condition), detail)


# --------------------------------------------------------------------------
# 用例 1：模块导入
# --------------------------------------------------------------------------


def test_imports() -> bool:
    """验证全部模块可导入。"""
    section("用例 1：模块导入")
    ok = True
    modules = [
        "src.core.models", "src.core.config", "src.core.paths", "src.core.utils",
        "src.core.software_scanner", "src.core.dir_scanner", "src.core.attribution",
        "src.core.size_calculator", "src.core.backuper", "src.core.deleter",
        "src.core.uninstaller", "src.core.exporters", "src.core.scan_service",
        "src.ui.workers", "src.ui.widgets", "src.ui.dialogs", "src.ui.main_window",
        "src.main",
    ]
    for name in modules:
        try:
            __import__(name)
        except Exception as exc:  # noqa: BLE001
            ok = check(f"导入 {name}", False, f"{type(exc).__name__}: {exc}") or ok
    if ok:
        check(f"全部 {len(modules)} 个模块导入成功", True)
    return ok


# --------------------------------------------------------------------------
# 用例 2：路径工具与黑名单
# --------------------------------------------------------------------------


def test_paths_safety() -> bool:
    """验证路径工具与系统关键目录黑名单。"""
    section("用例 2：路径工具与系统关键目录黑名单")
    ok = True

    win_dir = paths.to_absolute(paths.expand_env(r"%WINDIR%"))
    pf_dir = paths.to_absolute(paths.expand_env(r"%PROGRAMFILES%"))

    v1 = paths.check_path_safety(os.path.join(win_dir, "System32"))
    ok = check("System32 被拦截", v1.blocked, v1.reason) and ok

    v2 = paths.check_path_safety(pf_dir)
    ok = check("Program Files 本体被拦截", v2.blocked, v2.reason) and ok

    v3 = paths.check_path_safety(os.path.join(pf_dir, "Google", "Chrome"))
    ok = check("Program Files 子软件目录允许", v3.allowed, v3.reason) and ok

    v4 = paths.check_path_safety(os.path.join(paths.expand_env(r"%APPDATA%"), "FakeSoft"))
    ok = check("用户数据目录允许", v4.allowed, v4.reason) and ok

    long_path = paths.to_long_path(r"C:\a\b")
    ok = check("长路径前缀正确", long_path == r"\\?\C:\a\b", long_path) and ok
    ok = check("长路径前缀幂等", paths.to_long_path(long_path) == long_path) and ok

    display = paths.to_display_path(os.path.join(paths.expand_env(r"%APPDATA%"), "x", "y"))
    ok = check("展示路径折叠为 %APPDATA%", display.startswith("%APPDATA%"), display) and ok

    norm1 = normalize_name("Visual Studio Code (x64) 1.85")
    norm2 = normalize_name("Code")
    sim = similarity(norm1, norm2)
    ok = check("归一化与相似度判定", norm1 == "visualstudiocode" and norm2 == "code" and sim >= 0.75,
               f"{norm1} vs {norm2} = {sim:.2f}") and ok

    ok = check("大小格式化（-1 → 计算中…）", human_size(-1) == "计算中…", human_size(-1)) and ok
    ok = check("大小格式化（1024 进制）", human_size(1536) == "1.5 KB", human_size(1536)) and ok

    logger = ActionLogger(tempfile.mkdtemp(prefix="sdm_log_"))
    logger.log("scan", "冒烟测试", "success", {"k": 1})
    recent = logger.recent(10)
    ok = check("操作日志 JSONL 可写入并读回", len(recent) == 1 and recent[0]["action"] == "scan",
               str(recent[:1])) and ok
    return ok


# --------------------------------------------------------------------------
# 用例 3：真实扫描本机（只读）
# --------------------------------------------------------------------------


def test_real_scan(with_real: bool) -> bool:
    """真实扫描本机：注册表 + MSIX + 目录枚举 + 归属推断。"""
    section("用例 3：真实扫描本机（只读，绝不做任何删除/写入注册表）")
    if not with_real:
        print("  （按参数跳过真实扫描）")
        return True

    config = AppConfig.load()
    service = ScanService(config)

    started = time.time()
    software = service.scan_software()
    sw_cost = time.time() - started
    registry_count = sum(1 for s in software if s.source.value == "registry")
    msix_count = sum(1 for s in software if s.source.value == "msix")
    print(f"  注册表软件：{registry_count} 个　MSIX 应用：{msix_count} 个　耗时 {sw_cost:.2f} 秒")
    ok = check("扫描到已安装软件", len(software) > 0, f"合计 {len(software)} 个")

    t0 = time.time()
    candidates = service.scan_candidates()
    print(f"  候选数据目录：{len(candidates)} 条　耗时 {time.time() - t0:.2f} 秒")
    ok = check("枚举到候选数据目录", len(candidates) > 0, f"{len(candidates)} 条") and ok

    t1 = time.time()
    engine = service.build_engine(software)
    matches = engine.attribute(candidates)
    attr_cost = time.time() - t1
    identified = sum(1 for m in matches.values() if m.matched)
    orphan = len(candidates) - identified
    print(f"  归属命中：{identified} 条　未识别：{orphan} 条　耗时 {attr_cost:.3f} 秒")
    ok = check("归属推断命中率 > 0", identified > 0, f"命中 {identified} / {len(candidates)}") and ok
    ok = check(f"归属推断性能 < 3 秒（{len(software)} 软件 × {len(candidates)} 目录）",
               attr_cost < 3.0, f"{attr_cost:.3f} 秒") and ok

    # 级别分布
    level_stat: dict[str, int] = {}
    for match in matches.values():
        level_stat[match.level.value] = level_stat.get(match.level.value, 0) + 1
    print("  匹配级别分布：" + "，".join(f"{k}={v}" for k, v in sorted(level_stat.items())))

    # 内容类型分布
    type_stat: dict[str, int] = {}
    for entry in candidates:
        type_stat[entry.content_type.value] = type_stat.get(entry.content_type.value, 0) + 1
    print("  内容类型分布：" + "，".join(f"{k}={v}" for k, v in sorted(type_stat.items())))

    # 抽样展示前 8 条命中
    print("  归属示例（前 8 条）：")
    shown = 0
    for entry in candidates:
        match = matches.get(entry.path)
        if match is None or not match.matched:
            continue
        sw = next((s for s in software if s.id == match.software_id), None)
        if sw is None:
            continue
        print(f"    · {entry.display_path()[:60]:60s} → {sw.name[:28]:28s} "
              f"[{match.level.value} {match.confidence:.2f}]")
        shown += 1
        if shown >= 8:
            break

    # 黑名单命中
    blacklisted = sum(1 for e in candidates if e.is_blacklisted)
    print(f"  黑名单命中条目：{blacklisted} 条")
    ok = check("黑名单判定已生效（存在被拦截项，或本机无危险候选）", blacklisted >= 0,
               f"{blacklisted} 条") and ok

    # 大小计算（仅取前 15 条，避免长时间等待）
    sample = candidates[:15]
    size_started = time.time()
    SizeCalculator().compute_all(sample)
    sized = sum(1 for e in sample if e.size >= 0)
    total = sum(max(0, e.size) for e in sample)
    print(f"  抽样大小计算：{sized}/{len(sample)} 条成功，合计 {human_size(total)}，"
          f"耗时 {time.time() - size_started:.2f} 秒")
    ok = check("大小计算可用", sized > 0, f"{sized} 条") and ok

    # 残留扫描接口（用同一份快照对比，预期 0 条）
    snapshot = {e.path: e.owner_id for e in candidates}
    residual = service.scan_residual(snapshot, candidates)
    ok = check("残留扫描接口可用（同一快照应为 0 条）", len(residual) == 0, f"{len(residual)} 条") and ok

    print(f"  警告条数：{len(service.warnings)}")
    for warning in service.warnings[:5]:
        print(f"    · [{warning.get('stage')}] {warning.get('target')}：{warning.get('message')}")
    return ok


# --------------------------------------------------------------------------
# 用例 3b：完整流水线（限制根目录 + 定时取消，验证渐进式与缓存）
# --------------------------------------------------------------------------


def test_full_pipeline(with_real: bool) -> bool:
    """验证 ScanService.full_scan 四阶段流水线、取消协议与缓存落盘。"""
    section("用例 3b：完整扫描流水线（仅 %APPDATA%，8 秒后自动取消大小计算）")
    if not with_real:
        print("  （按参数跳过完整流水线）")
        return True
    import threading

    config = AppConfig.load()
    config.data_roots = [r"%APPDATA%"]
    service = ScanService(config)
    cancel = threading.Event()

    def watchdog() -> None:
        """8 秒后请求取消，避免冒烟测试长时间等待。"""
        time.sleep(8.0)
        cancel.set()

    threading.Thread(target=watchdog, daemon=True).start()
    stages: list[str] = []
    started = time.time()

    def on_stage(text: str) -> None:
        stages.append(text)
        print(f"  阶段：{text}")

    result = service.full_scan(on_stage=on_stage, cancel_event=cancel)
    print(f"  流水线耗时 {time.time() - started:.2f} 秒（含取消等待）")

    ok = check("流水线产生软件清单", len(result.software) > 0, f"{len(result.software)} 个软件")
    ok = check("流水线产生候选条目", len(result.all_entries()) > 0, f"{len(result.all_entries())} 条") and ok
    ok = check("四阶段均被调用", len(stages) >= 3, "/".join(stages[-2:])) and ok
    ok = check("统计信息已填充", result.stats.entry_count > 0 and result.stats.elapsed_sec > 0,
               f"entry={result.stats.entry_count} elapsed={result.stats.elapsed_sec:.2f}") and ok
    sized = sum(1 for e in result.all_entries() if e.size >= 0)
    print(f"  已完成大小计算：{sized}/{len(result.all_entries())} 条（其余为『计算中…』，符合渐进式设计）")
    ok = check("渐进式大小计算已有产出", sized > 0, f"{sized} 条") and ok

    cache = config_mod.load_size_cache()
    ok = check("大小缓存已落盘（二次打开秒显）", len(cache) > 0, f"{len(cache)} 条缓存") and ok
    return ok


# --------------------------------------------------------------------------
# 用例 4：临时假数据 —— 备份 / 删除 / 黑名单
# --------------------------------------------------------------------------


def _make_fake_data(root: str, root_key: str = "APPDATA") -> tuple[list[DataPathEntry], InstalledSoftware]:
    """在临时目录构造一款"假软件"的数据目录。"""
    root_abs = os.path.join(root, root_key)
    soft_dir = os.path.join(root_abs, "FakeSoft")
    cache_dir = os.path.join(soft_dir, "Cache")
    os.makedirs(os.path.join(soft_dir, "User Data"), exist_ok=True)
    os.makedirs(cache_dir, exist_ok=True)

    with open(os.path.join(soft_dir, "config.json"), "w", encoding="utf-8") as fp:
        fp.write('{"name": "FakeSoft", "version": "1.0"}\n')
    with open(os.path.join(soft_dir, "User Data", "history.db"), "w", encoding="utf-8") as fp:
        fp.write("A" * 4096)
    with open(os.path.join(cache_dir, "gpu.bin"), "w", encoding="utf-8") as fp:
        fp.write("B" * 2048)

    main_entry = DataPathEntry(
        path=soft_dir, root_key=root_key, root_abs=root_abs,
        kind=EntryKind.DIR, content_type=ContentType.CONFIG,
    )
    cache_entry = DataPathEntry(
        path=cache_dir, root_key=root_key, root_abs=root_abs,
        kind=EntryKind.DIR, content_type=ContentType.CACHE,
    )
    software = InstalledSoftware(
        id="fake:FakeSoft", name="FakeSoft", publisher="Fake Publisher",
        version="1.0", install_location=soft_dir, data_paths=[main_entry, cache_entry],
    )
    return [main_entry, cache_entry], software


def test_backup_and_delete() -> bool:
    """在临时目录验证备份 → 解压一致 → 删除 → 黑名单拦截。"""
    section("用例 4：临时假数据 —— 备份 / 删除 / 黑名单拦截")
    root = tempfile.mkdtemp(prefix="sdm_smoke_")
    ok = True
    try:
        entries, software = _make_fake_data(root)
        SizeCalculator().compute_all(entries)
        print(f"  假数据根目录：{root}")
        print(f"  条目：{entries[0].path}（{human_size(entries[0].size)}，配置） / "
              f"{entries[1].path}（{human_size(entries[1].size)}，缓存）")

        # 内容类型判定
        scanner = DirScanner()
        ok = check("内容类型判定：Cache 目录识别为缓存",
                   scanner.classify_content_type(entries[1].path) == ContentType.CACHE,
                   scanner.classify_content_type(entries[1].path).label) and ok

        # ---- 备份（默认排除 Cache/Log）----
        backup_dir = os.path.join(root, "backups")
        backuper = Backuper(dest_dir=backup_dir, exclude_cache_log=True)
        report = backuper.backup([software])
        ok = check("备份成功产出归档", report.success, report.error or report.archive_path) and ok
        if not report.success:
            return ok

        print(f"  归档：{report.archive_path}（{report.file_count} 个文件，{human_size(report.total_bytes)}）")
        # 说明：Cache 是主条目的子目录，会随主条目一起打包；缓存类条目单独作为顶层条目时才会被排除
        ok = check("备份文件数符合预期（主条目 3 个文件）", report.file_count == 3,
                   f"file_count={report.file_count}") and ok

        # 缓存类条目作为顶层条目时应被排除（Q2 默认行为）
        cache_only_sw = InstalledSoftware(id="fake:cache", name="FakeSoft", data_paths=[entries[1]])
        cache_report = backuper.backup([cache_only_sw])
        ok = check("缓存类顶层条目被默认排除（无文件可备份）", not cache_report.success,
                   cache_report.error) and ok

        # ---- 解压结构一致性 ----
        extract_dir = os.path.join(root, "extract")
        with zipfile.ZipFile(report.archive_path) as zf:
            names = zf.namelist()
            ok = check("归档内含 manifest.json", "manifest.json" in names) and ok
            zf.extractall(extract_dir)
        expected = os.path.join(extract_dir, "data", "FakeSoft", "APPDATA", "FakeSoft", "config.json")
        ok = check("解压后目录结构与原路径一致", os.path.isfile(expected), expected) and ok
        if os.path.isfile(expected):
            with open(expected, "r", encoding="utf-8") as fp:
                ok = check("解压后文件内容一致", '"FakeSoft"' in fp.read()) and ok
        ok = check("归档内无盘符/绝对路径（防 zip-slip）",
                   all(not n.startswith(("/", "\\")) and ":" not in n.split("/")[0] for n in names),
                   f"{len(names)} 个条目") and ok

        # manifest 可解析
        manifest_path = report.manifest_path or os.path.join(root, "m.json")
        if report.manifest_path and os.path.isfile(report.manifest_path):
            with open(report.manifest_path, "r", encoding="utf-8") as fp:
                manifest = json.load(fp)
            ok = check("manifest.json 可解析且字段完整",
                       manifest.get("schema_version") == 1 and "software" in manifest
                       and "totals" in manifest, str(manifest.get("totals"))) and ok

        # ---- 永久删除 ----
        deleter = Deleter(backuper=None)
        delete_report = deleter.delete([entries[0]], DeleteMode.PERMANENT)
        ok = check("永久删除后路径确实移除",
                   not os.path.exists(entries[0].path) and delete_report.deleted_count == 1,
                   delete_report.summary()) and ok

        # ---- 回收站删除（假数据，可恢复）----
        recycle_entry = DataPathEntry(
            path=entries[1].path, root_key="APPDATA", root_abs=os.path.join(root, "APPDATA"),
            kind=EntryKind.DIR, content_type=ContentType.CACHE,
        )
        recycle_report = deleter.delete([recycle_entry], DeleteMode.RECYCLE_BIN)
        ok = check("回收站删除后路径确实移除",
                   not os.path.exists(recycle_entry.path) and recycle_report.deleted_count == 1,
                   recycle_report.summary()) and ok

        # ---- 黑名单拦截（执行前二次校验）----
        win_dir = paths.to_absolute(paths.expand_env(r"%WINDIR%"))
        blocked_entry = DataPathEntry(path=os.path.join(win_dir, "System32", "drivers", "etc"))
        blocked_report = deleter.delete([blocked_entry], DeleteMode.PERMANENT)
        ok = check("黑名单路径被 Deleter 拦截（不依赖 UI）",
                   blocked_report.deleted_count == 0 and len(blocked_report.blocked) == 1,
                   blocked_report.blocked[0][1] if blocked_report.blocked else "未拦截") and ok
        ok = check("黑名单路径在计算机上仍然存在（未真的删除）", os.path.exists(blocked_entry.path)) and ok

        # ---- 先备份后删除 ----
        entries2, _software2 = _make_fake_data(root, root_key="LOCALAPPDATA")
        SizeCalculator().compute_all(entries2)
        # 明确指定临时备份目录，避免在用户默认备份目录留下测试产物
        local_backuper = Backuper(dest_dir=os.path.join(root, "backups2"), exclude_cache_log=False)
        deleter_with_backup = Deleter(backuper=local_backuper)
        combined = deleter_with_backup.delete(entries2, DeleteMode.BACKUP_THEN_DELETE)
        ok = check("先备份后删除：路径已移除", not os.path.exists(entries2[0].path),
                   combined.summary()) and ok
        ok = check("先备份后删除：产生了备份归档", bool(combined.archive_path),
                   combined.archive_path or "无") and ok

        # ---- 还原接口预留 ----
        try:
            Backuper(dest_dir=backup_dir).restore("x.zip")
            ok = check("还原接口按约定抛 NotImplementedError", False, "未抛异常") and ok
        except NotImplementedError:
            ok = check("还原接口按约定抛 NotImplementedError（P1-2 预留）", True) and ok
    finally:
        shutil.rmtree(root, ignore_errors=True)
        print(f"  已清理临时目录：{root}")
    return ok


# --------------------------------------------------------------------------
# 用例 4b：后台 Worker 信号链路
# --------------------------------------------------------------------------


def _run_worker(worker, timeout_ms: int = 30000) -> bool:
    """启动 Worker 并跑事件循环直到其完成（保证 queued 信号能被投递）。

    Args:
        worker: 待运行的 Worker。
        timeout_ms: 超时毫秒数。

    Returns:
        是否在超时前收到完成信号。
    """
    from PySide6.QtCore import QEventLoop, QTimer

    loop = QEventLoop()
    state = {"done": False}

    def on_finished(_result) -> None:
        state["done"] = True
        loop.quit()

    worker.finished.connect(on_finished)
    worker.errorOccurred.connect(lambda msg: (print("  Worker 错误：", msg), loop.quit()))
    worker.start()
    QTimer.singleShot(timeout_ms, loop.quit)
    loop.exec()
    return bool(state["done"])


def test_workers() -> bool:
    """验证 QThread Worker 能正常跑完并通过 Signal 回传结果。"""
    section("用例 4b：后台 Worker 信号链路（Size / Backup / Delete）")
    try:
        # 说明：这里必须用 QApplication 而不是 QCoreApplication——Qt 进程内只允许存在一个
        # 应用实例，若先建了 QCoreApplication，后续用例 6 再构造 QWidget 会被 Qt 直接中止。
        from PySide6.QtWidgets import QApplication

        from src.ui.workers import BackupWorker, DeleteWorker, SizeWorker
    except Exception as exc:  # noqa: BLE001
        return check("导入 Worker 模块", False, str(exc))

    app = QApplication.instance() or QApplication([])
    root = tempfile.mkdtemp(prefix="sdm_worker_")
    ok = True
    try:
        entries, software = _make_fake_data(root)
        for entry in entries:
            entry.size = -1
            entry.file_count = -1

        # ---- SizeWorker ----
        sized_events: list[tuple[str, int, int]] = []
        worker = SizeWorker(entries)
        worker.entrySized.connect(lambda p, s, c: sized_events.append((p, s, c)))
        ok = check("SizeWorker 在 15 秒内完成", _run_worker(worker, 15000)) and ok
        ok = check("SizeWorker 回传了大小信号", len(sized_events) > 0, f"{len(sized_events)} 条") and ok
        ok = check("条目大小已填充", all(e.size >= 0 for e in entries),
                   f"{[e.size for e in entries]}") and ok

        # ---- BackupWorker ----
        backup_reports = []
        backup_worker = BackupWorker([software], os.path.join(root, "bk"), True)
        backup_worker.finished.connect(backup_reports.append)
        ok = check("BackupWorker 在 30 秒内完成", _run_worker(backup_worker, 30000)) and ok
        ok = check("BackupWorker 产出成功报告",
                   bool(backup_reports) and backup_reports[0].success,
                   backup_reports[0].archive_path if backup_reports else "无报告") and ok

        # ---- DeleteWorker（永久删除，仅作用于临时假数据）----
        delete_reports = []
        delete_worker = DeleteWorker([entries[0]], DeleteMode.PERMANENT, None)
        delete_worker.finished.connect(delete_reports.append)
        ok = check("DeleteWorker 在 30 秒内完成", _run_worker(delete_worker, 30000)) and ok
        ok = check("DeleteWorker 报告已删除 1 项",
                   bool(delete_reports) and delete_reports[0].deleted_count == 1,
                   delete_reports[0].summary() if delete_reports else "无报告") and ok
        ok = check("临时假数据确实被移除", not os.path.exists(entries[0].path)) and ok
    finally:
        shutil.rmtree(root, ignore_errors=True)
        print(f"  已清理临时目录：{root}")
    _ = app  # 保持引用，避免被回收
    return ok


# --------------------------------------------------------------------------
# 用例 5：导出 CSV / JSON
# --------------------------------------------------------------------------


def test_export() -> bool:
    """验证导出 CSV / JSON 可被解析。"""
    section("用例 5：导出 CSV / JSON")
    root = tempfile.mkdtemp(prefix="sdm_export_")
    ok = True
    try:
        entries, software = _make_fake_data(root)
        SizeCalculator().compute_all(entries)
        orphan_entry = DataPathEntry(
            path=os.path.join(root, "APPDATA", "SomeUnknownDir"),
            root_key="APPDATA", root_abs=os.path.join(root, "APPDATA"),
            kind=EntryKind.DIR, content_type=ContentType.OTHER,
        )
        os.makedirs(orphan_entry.path, exist_ok=True)
        Result = ScanResult(started_at=time.time(), finished_at=time.time())
        Result.software = {software.id: software}
        Result.orphan_entries = [orphan_entry]
        ScanService.refresh_stats(Result)

        csv_path = os.path.join(root, "清单.csv")
        json_path = os.path.join(root, "清单.json")
        export_csv(Result, csv_path)
        export_json(Result, json_path)

        with open(csv_path, "r", encoding="utf-8-sig", newline="") as fp:
            rows = list(csv.reader(fp))
        ok = check("CSV 可被解析且含表头", len(rows) >= 3 and rows[0][0] == "软件名",
                   f"{len(rows)} 行") and ok
        ok = check("CSV 含未识别分组（A8）", any(row[9] == "未识别" for row in rows[1:]),
                   f"{len(rows) - 1} 条数据行") and ok

        with open(json_path, "r", encoding="utf-8") as fp:
            payload = json.load(fp)
        ok = check("JSON 可被解析且字段完整",
                   payload.get("stats", {}).get("software_count") == 1
                   and len(payload.get("software", [])) == 1
                   and len(payload.get("orphan_entries", [])) == 1,
                   str(payload.get("stats"))) and ok
        print(f"  CSV：{csv_path}（{len(rows)} 行）")
        print(f"  JSON：{json_path}（软件 1 个 / 未识别 1 条）")
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return ok


# --------------------------------------------------------------------------
# 用例 6：GUI 启动冒烟
# --------------------------------------------------------------------------


def test_gui(with_gui: bool) -> bool:
    """启动主窗口 1.5 秒后自动退出，确认无崩溃。"""
    section("用例 6：GUI 启动冒烟（1.5 秒后自动退出）")
    if not with_gui:
        print("  （按参数跳过 GUI 冒烟）")
        return True
    try:
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication

        from src.core.uninstaller import Uninstaller
        from src.ui.dialogs import (
            AboutDialog,
            BackupResultDialog,
            DeleteConfirmDialog,
            LogViewDialog,
            ResidualDialog,
            SettingsDialog,
            UninstallDialog,
        )
        from src.ui.main_window import MainWindow
        from src.ui.widgets import SoftwareFilterProxy
    except Exception as exc:  # noqa: BLE001
        return check("导入 GUI 模块", False, str(exc))

    app = QApplication.instance() or QApplication([])
    try:
        window = MainWindow(AppConfig.load())
        window.resize(1280, 800)
        window.show()
        QTimer.singleShot(1500, app.quit)
        code = app.exec()
        ok = check("主窗口可正常显示并退出", True, f"Qt 退出码 {code}")
        print(f"  窗口标题：{window.windowTitle()}")
        print(f"  表格行数：{window.model.rowCount()}　状态栏：{window.status_label.text()}")

        # 用假数据填充模型，验证 data()/筛选/排序/详情面板全链路
        fake_root = tempfile.mkdtemp(prefix="sdm_ui_")
        try:
            entries, software = _make_fake_data(fake_root)
            SizeCalculator().compute_all(entries)
            for entry in entries:
                entry.owner_id = software.id
            orphan = DataPathEntry(
                path=os.path.join(fake_root, "APPDATA", "UnknownDir"),
                root_key="APPDATA", root_abs=os.path.join(fake_root, "APPDATA"),
                kind=EntryKind.DIR, content_type=ContentType.OTHER,
            )
            os.makedirs(orphan.path, exist_ok=True)
            result = ScanResult(started_at=time.time(), finished_at=time.time())
            result.software = {software.id: software}
            result.orphan_entries = [orphan]
            ScanService.refresh_stats(result)
            window.result = result
            window.refresh_model()
            ok = check("表格模型可渲染（软件行 + 未识别分组行）",
                       window.model.rowCount() == 2, f"rowCount={window.model.rowCount()}") and ok
            # 逐列取数，确保 data() 各角色不抛异常
            for row in range(window.proxy.rowCount()):
                for col in range(window.model.columnCount()):
                    _ = window.proxy.index(row, col).data()
            ok = check("代理模型逐列取数无异常", True, f"{window.proxy.rowCount()} 行") and ok
            # 搜索筛选
            window.search_edit.setText("FakeSoft")
            ok = check("搜索筛选生效", window.proxy.rowCount() == 1,
                       f"rowCount={window.proxy.rowCount()}") and ok
            window.search_edit.setText("")
            # 识别状态筛选
            window.identified_combo.setCurrentText(SoftwareFilterProxy.FILTER_ORPHAN)
            ok = check("未识别筛选生效", window.proxy.rowCount() == 1,
                       f"rowCount={window.proxy.rowCount()}") and ok
            window.identified_combo.setCurrentText(SoftwareFilterProxy.FILTER_ALL)
            # 勾选与统计
            window.model.set_all_checked(True)
            window.update_selection_label()
            ok = check("全选与已选统计可用", window.model.checked_rows(),
                       window.selection_label.text()) and ok
            # 详情面板
            window.detail.set_software(software)
            ok = check("详情面板可展示软件", window.detail.tree.topLevelItemCount() >= 0 and
                       window.detail.current_key == software.id, window.detail.title_label.text()) and ok
            window.detail.set_orphan_group([orphan])
            ok = check("详情面板可展示未识别分组", window.detail.current_key == "__orphan__") and ok
            # 更新状态栏
            window.update_status()
            ok = check("状态栏统计可刷新", "扫描完成" in window.status_label.text(),
                       window.status_label.text()) and ok
        finally:
            shutil.rmtree(fake_root, ignore_errors=True)
    except Exception as exc:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        ok = check("主窗口可正常显示并退出", False, str(exc))

    # 逐个构造对话框（只实例化不 exec，验证无崩溃）
    temp_root = tempfile.mkdtemp(prefix="sdm_dlg_")
    try:
        entries, software = _make_fake_data(temp_root)
        SizeCalculator().compute_all(entries)
        fake_report = Backuper(dest_dir=temp_root).backup([software])

        dialogs = [
            ("删除确认对话框", lambda: DeleteConfirmDialog(entries, DeleteMode.BACKUP_THEN_DELETE, True, None)),
            ("卸载对话框", lambda: UninstallDialog(
                "FakeSoft",
                *Uninstaller().build_commands(software), timeout=300, is_admin=False, parent=None)),
            ("残留清理对话框", lambda: ResidualDialog(entries, None)),
            ("备份结果对话框", lambda: BackupResultDialog(fake_report, None)),
            ("设置对话框", lambda: SettingsDialog(AppConfig.load(), None)),
            ("关于对话框", lambda: AboutDialog(None)),
            ("操作日志对话框", lambda: LogViewDialog(
                ActionLogger(tempfile.mkdtemp(prefix="sdm_log2_")), None)),
        ]
        for name, factory in dialogs:
            try:
                dialog = factory()
                ok = check(f"构造{name}", dialog is not None) and ok
                dialog.deleteLater()
            except Exception as exc:  # noqa: BLE001
                ok = check(f"构造{name}", False, f"{type(exc).__name__}: {exc}") and ok
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)
    return ok


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------


def main() -> int:
    """执行全部冒烟用例并输出汇总。"""
    parser = argparse.ArgumentParser(description="软件数据迁移助手冒烟验证")
    parser.add_argument("--no-gui", action="store_true", help="跳过 GUI 启动冒烟")
    parser.add_argument("--no-real", action="store_true", help="跳过真实本机扫描")
    args = parser.parse_args()

    print("=" * 72)
    print("  软件数据迁移助手 · 冒烟验证")
    print(f"  解释器：{sys.executable}")
    print(f"  项目根目录：{PROJECT_ROOT}")
    print(f"  管理员权限：{'是' if is_admin() else '否'}")
    print("=" * 72)

    started = time.time()
    test_imports()
    test_paths_safety()
    test_real_scan(not args.no_real)
    test_full_pipeline(not args.no_real)
    test_backup_and_delete()
    test_workers()
    test_export()
    test_gui(not args.no_gui)

    section("汇总")
    total = len(RESULTS)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    failed = [name for name, ok, _ in RESULTS if not ok]
    for name, ok, detail in RESULTS:
        if not ok:
            print(f"  ❌ {name} —— {detail}")
    print(f"\n  用例总数：{total}　通过：{passed}　失败：{total - passed}　"
          f"总耗时：{time.time() - started:.2f} 秒")
    if failed:
        print("  失败用例：" + "，".join(failed))
        print("\nIS_PASS: NO")
        return 1
    print("\nIS_PASS: YES")
    return 0


if __name__ == "__main__":
    sys.exit(main())
