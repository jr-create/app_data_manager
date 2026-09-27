# -*- coding: utf-8 -*-
"""主窗口（L5）：工具条 + 软件表格 + 详情面板 + 批量操作栏 + 状态栏。

所有耗时操作均交给 :mod:`workers` 中的 QThread 子类，本窗口只在主线程操作控件。
"""

from __future__ import annotations

import os
import subprocess

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from ..core import config as config_mod
from ..core.backuper import Backuper
from ..core.exporters import export_csv, export_json
from ..core.models import (
    ContentType,
    DataPathEntry,
    DeleteMode,
    InstalledSoftware,
    ScanResult,
)
from ..core.scan_service import ScanService
from ..core.uninstaller import Uninstaller
from ..core.utils import ActionLogger, human_size
from .dialogs import (
    AboutDialog,
    BackupResultDialog,
    DeleteConfirmDialog,
    LogViewDialog,
    ResidualDialog,
    SettingsDialog,
    UninstallDialog,
    show_error,
)
from .widgets import (
    COL_NAME,
    ROW_ROLE,
    DetailPanel,
    SoftwareFilterProxy,
    SoftwareTableModel,
    SoftwareTableView,
    build_rows,
)
from .workers import BackupWorker, DeleteWorker, ScanWorker, UninstallWorker

#: 未识别分组在下拉框中的显示文本
_ORPHAN_LABEL: str = "（未识别分组）"


class MainWindow(QMainWindow):
    """软件数据迁移助手主窗口。"""

    def __init__(self, config) -> None:
        """初始化。

        Args:
            config: :class:`AppConfig`。
        """
        super().__init__()
        self.config = config
        self.result: ScanResult | None = None
        self._service: ScanService = ScanService(config)
        dirs = config_mod.get_app_dirs(create=True)
        self._action_logger: ActionLogger = ActionLogger(dirs["logs"])
        self._path_to_key: dict[str, str] = {}
        self._scan_worker: ScanWorker | None = None
        self._backup_worker: BackupWorker | None = None
        self._delete_worker: DeleteWorker | None = None
        self._uninstall_worker: UninstallWorker | None = None
        self._pending_residual: bool = False

        self.setWindowTitle("软件数据迁移助手")
        self._build_ui()
        self._connect_signals()
        self._apply_config_to_ui()
        self.status_label.setText("就绪：点击左上角『扫描』开始")

    # ------------------------------------------------------------------
    # 界面装配
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """装配全部控件。"""
        central = QWidget()
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(8, 8, 8, 8)
        root_layout.setSpacing(6)

        # 顶栏
        top_layout = QHBoxLayout()
        title = QLabel("软件数据迁移助手")
        title_font = title.font()
        title_font.setPointSize(title_font.pointSize() + 4)
        title_font.setBold(True)
        title.setFont(title_font)
        self.scan_button = QPushButton("扫描")
        self.cancel_button = QPushButton("取消")
        self.cancel_button.setEnabled(False)
        self.settings_button = QPushButton("设置")
        self.log_button = QPushButton("操作日志")
        self.about_button = QPushButton("关于")
        top_layout.addWidget(title)
        top_layout.addStretch(1)
        top_layout.addWidget(self.scan_button)
        top_layout.addWidget(self.cancel_button)
        top_layout.addWidget(self.settings_button)
        top_layout.addWidget(self.log_button)
        top_layout.addWidget(self.about_button)
        root_layout.addLayout(top_layout)

        # 工具条
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("搜索："))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("软件名 / 发布商 / 路径关键字")
        self.search_edit.setClearButtonEnabled(True)
        filter_layout.addWidget(self.search_edit, stretch=2)

        filter_layout.addWidget(QLabel("类型："))
        self.type_combo = QComboBox()
        self.type_combo.addItem("全部", None)
        for content_type in ContentType:
            self.type_combo.addItem(content_type.label, content_type.value)
        filter_layout.addWidget(self.type_combo)

        filter_layout.addWidget(QLabel("仅显示："))
        self.identified_combo = QComboBox()
        self.identified_combo.addItems([
            SoftwareFilterProxy.FILTER_ALL,
            SoftwareFilterProxy.FILTER_IDENTIFIED,
            SoftwareFilterProxy.FILTER_ORPHAN,
        ])
        filter_layout.addWidget(self.identified_combo)

        self.top_check = QCheckBox("仅看占用 Top")
        self.top_spin = QComboBox()
        self.top_spin.addItems(["10", "20", "50", "100"])
        self.top_spin.setCurrentText(str(self.config.top_n))
        filter_layout.addWidget(self.top_check)
        filter_layout.addWidget(self.top_spin)

        self.select_all_check = QCheckBox("全选")
        filter_layout.addWidget(self.select_all_check)
        filter_layout.addStretch(1)
        root_layout.addLayout(filter_layout)

        # 主区（左表格 / 右详情）
        self.model = SoftwareTableModel(self)
        self.proxy = SoftwareFilterProxy(self)
        self.proxy.setSourceModel(self.model)
        self.table = SoftwareTableView()
        self.table.setModel(self.proxy)
        self.detail = DetailPanel()

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self.table)
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 65)
        splitter.setStretchFactor(1, 35)
        splitter.setSizes([860, 420])
        root_layout.addWidget(splitter, stretch=1)

        # 底部操作栏
        bottom_layout = QHBoxLayout()
        self.selection_label = QLabel("已选 0 项 / 合计 0 B")
        self.backup_button = QPushButton("批量备份")
        self.delete_button = QPushButton("批量删除")
        self.uninstall_button = QPushButton("调用卸载")
        self.export_csv_button = QPushButton("导出 CSV")
        self.export_json_button = QPushButton("导出 JSON")
        bottom_layout.addWidget(self.selection_label)
        bottom_layout.addStretch(1)
        bottom_layout.addWidget(self.backup_button)
        bottom_layout.addWidget(self.delete_button)
        bottom_layout.addWidget(self.uninstall_button)
        bottom_layout.addWidget(self.export_csv_button)
        bottom_layout.addWidget(self.export_json_button)
        root_layout.addLayout(bottom_layout)

        self.setCentralWidget(central)

        # 状态栏
        status = QStatusBar()
        self.status_label = QLabel("就绪")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedWidth(220)
        status.addWidget(self.status_label, stretch=1)
        status.addPermanentWidget(self.progress_bar)
        self.setStatusBar(status)

    def _connect_signals(self) -> None:
        """连接全部信号与槽。"""
        self.scan_button.clicked.connect(self.on_scan_clicked)
        self.cancel_button.clicked.connect(self.on_cancel_clicked)
        self.settings_button.clicked.connect(self.on_settings_clicked)
        self.log_button.clicked.connect(self.on_log_clicked)
        self.about_button.clicked.connect(self.on_about_clicked)

        self.search_edit.textChanged.connect(self.on_filter_changed)
        self.type_combo.currentIndexChanged.connect(self.on_filter_changed)
        self.identified_combo.currentIndexChanged.connect(self.on_filter_changed)
        self.top_check.stateChanged.connect(self.on_filter_changed)
        self.top_spin.currentTextChanged.connect(self.on_filter_changed)
        self.select_all_check.stateChanged.connect(self.on_select_all_changed)

        self.table.selectionModel().currentChanged.connect(self.on_current_changed)
        self.model.dataChanged.connect(self.on_model_data_changed)

        self.detail.openInExplorerRequested.connect(self.on_open_in_explorer)
        self.detail.removeAttributionRequested.connect(self.on_remove_attribution)
        self.detail.assignAttributionRequested.connect(self.on_assign_attribution)

        self.backup_button.clicked.connect(self.on_backup_clicked)
        self.delete_button.clicked.connect(self.on_delete_clicked)
        self.uninstall_button.clicked.connect(self.on_uninstall_clicked)
        self.export_csv_button.clicked.connect(self.on_export_csv_clicked)
        self.export_json_button.clicked.connect(self.on_export_json_clicked)

    def _apply_config_to_ui(self) -> None:
        """把配置中的开关同步到工具条。"""
        self.top_spin.setCurrentText(str(self.config.top_n))

    # ------------------------------------------------------------------
    # 数据刷新
    # ------------------------------------------------------------------

    def refresh_model(self) -> None:
        """按当前结果重建表格行。"""
        if self.result is None:
            self.model.set_rows([])
            self._path_to_key = {}
            self.detail.clear()
            self.update_selection_label()
            return
        rows = build_rows(self.result)
        self.model.set_rows(rows)
        self._path_to_key = {}
        for row in rows:
            for entry in row.entries:
                self._path_to_key[entry.path] = row.key
        self.proxy.set_top_n(int(self.top_spin.currentText()) if self.top_check.isChecked() else 0)
        self.proxy.invalidateFilter()
        self.update_selection_label()

    def update_selection_label(self) -> None:
        """刷新底部"已选"统计。"""
        rows = self.model.checked_rows()
        total = sum(r.size for r in rows if r.size > 0)
        self.selection_label.setText(f"已选 {len(rows)} 项 / 合计 {human_size(total)}")

    def update_status(self) -> None:
        """刷新状态栏统计信息。"""
        if self.result is None:
            self.status_label.setText("尚未扫描")
            return
        stats = self.result.stats
        self.status_label.setText(
            f"扫描完成 · 共 {stats.software_count} 个软件 · {stats.entry_count} 条路径 · "
            f"未识别 {stats.orphan_count} 项 · 合计 {human_size(stats.total_size)} · "
            f"用时 {stats.elapsed_sec:.1f} 秒"
        )

    # ------------------------------------------------------------------
    # 扫描
    # ------------------------------------------------------------------

    def on_scan_clicked(self) -> None:
        """启动一次完整扫描（后台线程）。"""
        if self._scan_worker is not None and self._scan_worker.isRunning():
            QMessageBox.information(self, "正在扫描", "扫描已在后台进行中。")
            return
        self.scan_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("正在扫描…")

        worker = ScanWorker(self.config, self)
        worker.stageChanged.connect(self.on_scan_stage)
        worker.progressChanged.connect(self.on_scan_progress)
        worker.entrySized.connect(self.on_entry_sized)
        worker.scanReady.connect(self.on_scan_ready)
        worker.finished.connect(self.on_scan_finished)
        worker.errorOccurred.connect(self.on_worker_error)
        self._scan_worker = worker
        worker.start()
        self._action_logger.log("scan", "完整扫描", "started", {})

    def on_cancel_clicked(self) -> None:
        """取消当前扫描。"""
        if self._scan_worker is not None:
            self._scan_worker.request_cancel()
            self.status_label.setText("正在取消…")
            self.cancel_button.setEnabled(False)

    def on_scan_stage(self, text: str) -> None:
        """扫描阶段变化。"""
        self.status_label.setText(text)

    def on_scan_progress(self, done: int, total: int, text: str) -> None:
        """扫描进度（已节流）。"""
        if total > 0:
            self.progress_bar.setValue(min(100, int(done * 100 / max(1, total))))
        if text:
            self.status_label.setText(f"计算大小：{done}/{total} · {text}")

    def on_scan_ready(self, result: ScanResult) -> None:
        """渐进式首屏：先渲染无大小的结果。"""
        self.result = result
        self.model.sizing_done = False  # 新一轮大小计算开始
        self.detail.sizing_done = False
        self.refresh_model()
        self.update_status()

    def on_entry_sized(self, path: str, size: int, file_count: int) -> None:
        """单条路径大小计算完成 → 就地更新表格。"""
        key = self._path_to_key.get(path)
        if key is None:
            return
        row = self.model.row_by_key(key)
        if row is not None:
            row.size = sum(max(0, e.size) for e in row.entries)
            self.model.update_row_size(key)
        if self.detail.current_key == key:
            self.refresh_detail_for_key(key)
        self.update_selection_label()

    def on_scan_finished(self, result: ScanResult) -> None:
        """扫描完成。"""
        self.result = result
        self.model.sizing_done = True  # 大小计算结束：-1 视为"路径不存在"，显示 "—"
        self.detail.sizing_done = True
        self.refresh_model()
        self.update_status()
        self.progress_bar.setValue(100)
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        stats = result.stats
        self._action_logger.log("scan", "完整扫描", "success", {
            "software": stats.software_count,
            "entries": stats.entry_count,
            "orphan": stats.orphan_count,
            "bytes": stats.total_size,
        })
        if result.warnings:
            self.status_label.setText(
                self.status_label.text() + f"（{len(result.warnings)} 条警告，详见运行日志）"
            )
        worker = self._scan_worker
        self._scan_worker = None
        if worker is not None:
            worker.deleteLater()

    def on_worker_error(self, message: str) -> None:
        """后台任务错误统一弹窗。"""
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        show_error(self, "后台任务出错", message)
        self._action_logger.log("error", "后台任务", "failed", {"message": message})

    # ------------------------------------------------------------------
    # 筛选与选择
    # ------------------------------------------------------------------

    def on_filter_changed(self, *_args) -> None:
        """工具条筛选条件变化。"""
        self.proxy.set_search(self.search_edit.text())
        data = self.type_combo.currentData()
        self.proxy.set_content_type(ContentType(data) if data else None)
        self.proxy.set_identified(self.identified_combo.currentText())
        n = int(self.top_spin.currentText()) if self.top_check.isChecked() else 0
        self.proxy.set_top_n(n)
        self.config.top_n = int(self.top_spin.currentText())

    def on_select_all_changed(self, state: int) -> None:
        """全选 / 取消全选。"""
        self.model.set_all_checked(bool(state))
        self.update_selection_label()

    def on_model_data_changed(self, *_args) -> None:
        """模型数据变化（含勾选变化）。"""
        self.update_selection_label()

    def on_current_changed(self, current, _previous) -> None:
        """选中行变化 → 刷新详情面板。"""
        if not current.isValid():
            return
        source_index = self.proxy.mapToSource(current)
        row = self.model.data(self.model.index(source_index.row(), COL_NAME), ROW_ROLE)
        if row is None:
            return
        if row.is_orphan:
            self.detail.set_orphan_group(row.entries)
        elif row.software is not None:
            self.detail.set_software(row.software)

    def refresh_detail_for_key(self, key: str) -> None:
        """按行键刷新详情面板。"""
        row = self.model.row_by_key(key)
        if row is None:
            return
        if row.is_orphan:
            self.detail.set_orphan_group(row.entries)
        elif row.software is not None:
            self.detail.set_software(row.software)

    # ------------------------------------------------------------------
    # 归属修正（P1-4）
    # ------------------------------------------------------------------

    def on_remove_attribution(self, path: str) -> None:
        """移除某条路径的归属。"""
        if self.result is None:
            return
        answer = QMessageBox.question(
            self, "移除归属",
            f"确定把该路径移出当前软件归属吗？\n{path}",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        self._service.apply_manual_attribution(self.result, path, None)
        self.refresh_model()
        self._action_logger.log("attribution", path, "removed", {})

    def on_assign_attribution(self, path: str) -> None:
        """手动把某条路径指派给某个软件（P1-4）。"""
        if self.result is None:
            return
        names: list[str] = []
        id_map: dict[str, str] = {}
        for sw in self.result.software.values():
            label = sw.name or sw.id
            names.append(label)
            id_map[label] = sw.id
        if not names:
            QMessageBox.information(self, "无法指派", "当前没有可指派的软件，请先扫描。")
            return
        chosen, ok = QInputDialog.getItem(self, "手动指派归属", f"把路径指派给：\n{path}", names, 0, False)
        if not ok or not chosen:
            return
        self._service.apply_manual_attribution(self.result, path, id_map[chosen])
        self.refresh_model()
        self._action_logger.log("attribution", path, "assigned", {"software": chosen})

    # ------------------------------------------------------------------
    # 备份
    # ------------------------------------------------------------------

    def _checked_software(self) -> list[InstalledSoftware]:
        """返回已勾选的软件对象（不含未识别分组）。"""
        result: list[InstalledSoftware] = []
        if self.result is None:
            return result
        for row in self.model.checked_rows():
            if row.software is not None:
                result.append(row.software)
        return result

    def _checked_entries(self) -> list[DataPathEntry]:
        """返回已勾选行对应的全部条目。"""
        if self.result is None:
            return []
        return self.model.checked_entries()

    def on_backup_clicked(self) -> None:
        """批量备份已勾选软件。"""
        software_list = self._checked_software()
        if not software_list:
            QMessageBox.information(self, "未选择软件", "请先在左侧勾选需要备份的软件。")
            return
        dest = QFileDialog.getExistingDirectory(
            self, "选择备份存放目录", self.config.backup_dir_resolved
        )
        if not dest:
            return
        self.config.backup_dir = dest
        self._start_backup(software_list, dest)

    def _start_backup(self, software_list: list[InstalledSoftware], dest: str) -> None:
        """启动备份 Worker。"""
        worker = BackupWorker(software_list, dest, self.config.exclude_cache_log, self)
        worker.stageChanged.connect(lambda text: self.status_label.setText(text))
        worker.progressChanged.connect(self.on_task_progress)
        worker.finished.connect(self.on_backup_finished)
        worker.errorOccurred.connect(self.on_worker_error)
        self._backup_worker = worker
        self.progress_bar.setValue(0)
        worker.start()

    def on_task_progress(self, done: int, total: int, text: str) -> None:
        """通用任务进度。"""
        if total > 0:
            self.progress_bar.setValue(min(100, int(done * 100 / max(1, total))))
        if text:
            self.status_label.setText(f"{done}/{total} · {text}")

    def on_backup_finished(self, report) -> None:
        """备份完成 → 结果对话框 + 日志。"""
        self.progress_bar.setValue(100)
        dialog = BackupResultDialog(report, self)
        dialog.exec()
        self._action_logger.log("backup", report.archive_path or "-",
                                "success" if report.success else "failed", {
                                    "files": report.file_count,
                                    "bytes": report.total_bytes,
                                    "skipped": len(report.skipped),
                                    "error": report.error,
                                })
        worker = self._backup_worker
        self._backup_worker = None
        if worker is not None:
            worker.deleteLater()

    # ------------------------------------------------------------------
    # 删除
    # ------------------------------------------------------------------

    def on_delete_clicked(self) -> None:
        """批量删除（四道闸门）。"""
        entries = self._checked_entries()
        if not entries:
            QMessageBox.information(self, "未选择路径", "请先在左侧勾选需要清理的软件或路径。")
            return
        if not self.config.allow_delete_orphan:
            entries = [e for e in entries if e.owner_id is not None]
            if not entries:
                QMessageBox.information(
                    self, "无可删除项",
                    "已勾选项全部属于『未识别』分组，当前设置禁止删除该分组（可在设置中开启）。"
                )
                return
        dialog = DeleteConfirmDialog(entries, self.config.delete_mode, self.config.allow_delete_orphan, self)
        if dialog.exec() != DeleteConfirmDialog.Accepted:
            return
        selected = dialog.selected_entries()
        if not selected:
            QMessageBox.information(self, "无需删除", "没有勾选任何可删除的路径。")
            return
        mode = dialog.selected_mode()
        self._start_delete(selected, mode)

    def _start_delete(self, entries: list[DataPathEntry], mode: DeleteMode) -> None:
        """启动删除 Worker。"""
        backuper = Backuper(
            dest_dir=self.config.backup_dir_resolved,
            exclude_cache_log=self.config.exclude_cache_log,
        )
        worker = DeleteWorker(entries, mode, backuper, self)
        worker.stageChanged.connect(lambda text: self.status_label.setText(text))
        worker.progressChanged.connect(self.on_task_progress)
        worker.finished.connect(self.on_delete_finished)
        worker.errorOccurred.connect(self.on_worker_error)
        self._delete_worker = worker
        self.progress_bar.setValue(0)
        worker.start()

    def on_delete_finished(self, report) -> None:
        """删除完成 → 报告 + 刷新。"""
        self.progress_bar.setValue(100)
        message = report.summary()
        if report.blocked:
            message += "\n\n被黑名单拦截：\n" + "\n".join(
                f"⛔ {path}（{reason}）" for path, reason in report.blocked[:10]
            )
        if report.skipped:
            message += "\n\n失败/跳过：\n" + "\n".join(
                f"· {item.path}（{item.reason}）" for item in report.skipped[:10]
            )
        QMessageBox.information(self, "删除结果", message)
        self._action_logger.log(
            "delete" if report.mode != DeleteMode.RECYCLE_BIN.value else "recycle",
            f"{report.deleted_count} 项", "success" if report.deleted_count else "failed", {
                "mode": report.mode,
                "bytes": report.deleted_bytes,
                "blocked": len(report.blocked),
                "skipped": len(report.skipped),
                "archive": report.archive_path,
            })
        # 刷新：移除已删除条目
        if self.result is not None:
            deleted_paths = {e.path for e in self.result.all_entries() if not e.exists}
            for sw in self.result.software.values():
                sw.data_paths = [e for e in sw.data_paths if e.path not in deleted_paths]
            self.result.orphan_entries = [e for e in self.result.orphan_entries if e.path not in deleted_paths]
            self.refresh_model()
            self.update_status()
        worker = self._delete_worker
        self._delete_worker = None
        if worker is not None:
            worker.deleteLater()

    # ------------------------------------------------------------------
    # 卸载
    # ------------------------------------------------------------------

    def on_uninstall_clicked(self) -> None:
        """调用官方卸载程序。"""
        software = self._current_software()
        if software is None:
            QMessageBox.information(self, "未选择软件", "请先在左侧选中一款软件（未识别分组不支持卸载）。")
            return
        uninstaller = Uninstaller()
        quiet_command, standard_command = uninstaller.build_commands(software)
        if not quiet_command and not standard_command:
            QMessageBox.warning(
                self, "无法卸载",
                f"『{software.name}』没有可用的卸载命令（可能为用户级安装的绿色软件）。"
            )
            return
        from ..core.deleter import is_admin as _is_admin

        dialog = UninstallDialog(
            software.name, quiet_command, standard_command,
            timeout=300, is_admin=_is_admin(), parent=self,
        )
        if dialog.exec() != UninstallDialog.Accepted:
            return
        self._pending_residual = dialog.scan_residual
        self._start_uninstall(software, dialog.quiet, dialog.timeout)

    def _start_uninstall(self, software: InstalledSoftware, quiet: bool, timeout: int) -> None:
        """启动卸载 Worker。"""
        worker = UninstallWorker(software, quiet, timeout, False, self)
        worker.stageChanged.connect(lambda text: self.status_label.setText(text))
        worker.progressChanged.connect(self.on_task_progress)
        worker.finished.connect(self.on_uninstall_finished)
        worker.errorOccurred.connect(self.on_worker_error)
        self._uninstall_worker = worker
        self.progress_bar.setValue(0)
        worker.start()

    def on_uninstall_finished(self, report) -> None:
        """卸载完成 → 结果 + 可选残留扫描。"""
        self.progress_bar.setValue(100)
        QMessageBox.information(self, "卸载结果", report.summary())
        self._action_logger.log("uninstall", report.command or "-",
                                "success" if report.success else "failed", {
                                    "exit_code": report.exit_code,
                                    "elapsed": round(report.elapsed_sec, 2),
                                    "error": report.error,
                                })
        worker = self._uninstall_worker
        self._uninstall_worker = None
        if worker is not None:
            worker.deleteLater()
        if self._pending_residual:
            self._pending_residual = False
            self._run_residual_scan()

    def _run_residual_scan(self) -> None:
        """卸载后残留扫描（P1-1）。"""
        if self.result is None:
            return
        before = ScanService.snapshot(self.result)
        self.status_label.setText("正在扫描残留目录…")
        QMessageBox.information(
            self, "残留扫描", "即将重新扫描一次用户数据目录以识别残留，可能需要几十秒。"
        )
        worker = ScanWorker(self.config, self)
        worker.stageChanged.connect(self.on_scan_stage)
        worker.progressChanged.connect(self.on_scan_progress)
        worker.finished.connect(lambda result: self._on_residual_scanned(before, result))
        worker.errorOccurred.connect(self.on_worker_error)
        self._scan_worker = worker
        worker.start()

    def _on_residual_scanned(self, before: dict, after: ScanResult) -> None:
        """残留扫描完成 → 弹出残留清单。"""
        self.result = after
        self.refresh_model()
        self.update_status()
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        residual = self._service.scan_residual(before, after)
        self._action_logger.log("residual_clean", "残留扫描", "success", {"count": len(residual)})
        if not residual:
            QMessageBox.information(self, "残留扫描", "未发现疑似残留目录。")
            return
        dialog = ResidualDialog(residual, self)
        if dialog.exec() != ResidualDialog.Accepted:
            return
        selected = dialog.selected_entries()
        if not selected:
            return
        # 复用删除闸门
        confirm = DeleteConfirmDialog(selected, self.config.delete_mode, True, self)
        if confirm.exec() != DeleteConfirmDialog.Accepted:
            return
        self._start_delete(confirm.selected_entries(), confirm.selected_mode())

    # ------------------------------------------------------------------
    # 导出
    # ------------------------------------------------------------------

    def _ensure_result(self) -> bool:
        """检查是否已有扫描结果。"""
        if self.result is None:
            QMessageBox.information(self, "尚无数据", "请先执行一次扫描再导出。")
            return False
        return True

    def on_export_csv_clicked(self) -> None:
        """导出 CSV。"""
        if not self._ensure_result():
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "导出 CSV", os.path.join(os.path.expanduser("~"), "软件数据清单.csv"),
            "CSV 文件 (*.csv)"
        )
        if not path:
            return
        try:
            export_csv(self.result, path)
        except OSError as exc:
            show_error(self, "CSV 导出失败", str(exc))
            return
        self._action_logger.log("export", path, "success", {"format": "csv"})
        QMessageBox.information(self, "导出完成", f"已导出到：\n{path}")

    def on_export_json_clicked(self) -> None:
        """导出 JSON。"""
        if not self._ensure_result():
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "导出 JSON", os.path.join(os.path.expanduser("~"), "软件数据清单.json"),
            "JSON 文件 (*.json)"
        )
        if not path:
            return
        try:
            export_json(self.result, path)
        except OSError as exc:
            show_error(self, "JSON 导出失败", str(exc))
            return
        self._action_logger.log("export", path, "success", {"format": "json"})
        QMessageBox.information(self, "导出完成", f"已导出到：\n{path}")

    # ------------------------------------------------------------------
    # 设置 / 关于 / 日志 / 打开目录
    # ------------------------------------------------------------------

    def on_settings_clicked(self) -> None:
        """打开设置对话框并持久化。"""
        dialog = SettingsDialog(self.config, self)
        if dialog.exec() != SettingsDialog.Accepted:
            return
        try:
            self.config.save()
        except RuntimeError as exc:
            show_error(self, "设置保存失败", str(exc))
            return
        self._service = ScanService(self.config)
        self._apply_config_to_ui()
        self.on_filter_changed()
        QMessageBox.information(self, "设置已保存", "部分设置（如数据根目录）将在下次扫描时生效。")

    def on_about_clicked(self) -> None:
        """关于对话框。"""
        AboutDialog(self).exec()

    def on_log_clicked(self) -> None:
        """操作日志对话框。"""
        LogViewDialog(self._action_logger, self).exec()

    def on_open_in_explorer(self, path: str) -> None:
        """在资源管理器中定位路径。"""
        if not path or not os.path.exists(path):
            QMessageBox.warning(self, "无法打开", f"路径不存在：{path}")
            return
        try:
            if os.path.isdir(path):
                subprocess.Popen(["explorer", os.path.normpath(path)])
            else:
                subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
        except OSError as exc:
            show_error(self, "打开失败", str(exc))

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------

    def _current_software(self) -> InstalledSoftware | None:
        """返回当前选中行对应的软件（未识别分组返回 ``None``）。"""
        index = self.table.selectionModel().currentIndex()
        if not index.isValid():
            return None
        source_index = self.proxy.mapToSource(index)
        row = self.model.data(self.model.index(source_index.row(), COL_NAME), ROW_ROLE)
        if row is None or row.is_orphan:
            return None
        return row.software

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt 接口命名
        """关闭窗口时保存窗口尺寸并等待后台线程退出。"""
        self.config.window_width = self.width()
        self.config.window_height = self.height()
        try:
            self.config.save()
        except RuntimeError:
            pass
        for worker in (self._scan_worker, self._backup_worker,
                       self._delete_worker, self._uninstall_worker):
            if worker is not None and worker.isRunning():
                worker.request_cancel()
                worker.wait(3000)
        super().closeEvent(event)
