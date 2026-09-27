# -*- coding: utf-8 -*-
"""安全对话框（L5）：删除四道闸门、卸载、残留清理、备份结果、设置、关于、日志。

删除流程严格实现 PRD 4.3 的六条安全机制：
    1. 强制列出全部目标路径、文件数、总大小；
    2. 三种删除方式，默认"先备份后删除"；
    3. 黑名单项置灰 + ⛔ + 原因，用户无法勾选；
    4. 确认按钮默认禁用，需输入 ``DELETE``；
    5. 执行前再次弹出系统级 QMessageBox 确认；
    6. 全程记录操作日志（由 MainWindow 写 ActionLogger）。
"""

from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.models import AppError, DataPathEntry, DeleteMode
from ..core.utils import format_time, human_size

# --------------------------------------------------------------------------
# 删除确认对话框（四道闸门）
# --------------------------------------------------------------------------


class DeleteConfirmDialog(QDialog):
    """删除二次确认对话框（路径清单 + 方式选择 + DELETE 输入 + 系统级确认）。"""

    #: 确认文本（必须原样输入才启用按钮）
    CONFIRM_WORD: str = "DELETE"

    def __init__(
        self,
        entries: list[DataPathEntry],
        default_mode: DeleteMode = DeleteMode.BACKUP_THEN_DELETE,
        allow_orphan: bool = True,
        parent: QWidget | None = None,
    ) -> None:
        """初始化。

        Args:
            entries: 待删除条目（含黑名单项，此处仅展示并置灰）。
            default_mode: 默认删除策略。
            allow_orphan: 是否允许删除未识别分组条目（A5）。
            parent: 父窗口。
        """
        super().__init__(parent)
        self._entries: list[DataPathEntry] = list(entries)
        self._default_mode: DeleteMode = default_mode
        self._allow_orphan: bool = allow_orphan
        self.setWindowTitle("⚠ 确认删除（危险操作）")
        self.setMinimumSize(760, 560)
        self._build_ui()

    def _build_ui(self) -> None:
        """装配控件。"""
        layout = QVBoxLayout(self)

        total_bytes = sum(max(0, e.size) for e in self._entries)
        self.header_label = QLabel(
            f"即将删除 <b>{len(self._entries)}</b> 个路径，合计 <b>{human_size(total_bytes)}</b>"
        )
        self.header_label.setTextFormat(Qt.RichText)
        layout.addWidget(self.header_label)

        # 删除方式
        mode_group = QGroupBox("删除方式")
        mode_layout = QVBoxLayout(mode_group)
        self.mode_backup = QRadioButton("先备份再删除（推荐）")
        self.mode_recycle = QRadioButton("移入回收站（可恢复）")
        self.mode_permanent = QRadioButton("永久删除（不可恢复）")
        mode_layout.addWidget(self.mode_backup)
        mode_layout.addWidget(self.mode_recycle)
        mode_layout.addWidget(self.mode_permanent)
        default_map = {
            DeleteMode.BACKUP_THEN_DELETE: self.mode_backup,
            DeleteMode.RECYCLE_BIN: self.mode_recycle,
            DeleteMode.PERMANENT: self.mode_permanent,
        }
        default_map.get(self._default_mode, self.mode_backup).setChecked(True)
        layout.addWidget(mode_group)

        # 路径清单
        list_group = QGroupBox("目标路径清单（黑名单项不可勾选）")
        list_layout = QVBoxLayout(list_group)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["", "路径", "大小", "文件数", "备注"])
        self.tree.setRootIsDecorated(False)
        self.tree.setSelectionMode(QAbstractItemView.NoSelection)
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.tree.header().setStretchLastSection(True)
        self.tree.setColumnWidth(1, 380)
        list_layout.addWidget(self.tree)
        select_layout = QHBoxLayout()
        self.select_all_button = QPushButton("全选可删项")
        self.select_none_button = QPushButton("全部取消")
        select_layout.addWidget(self.select_all_button)
        select_layout.addWidget(self.select_none_button)
        select_layout.addStretch(1)
        list_layout.addLayout(select_layout)
        layout.addWidget(list_group, stretch=1)

        # 黑名单提示
        blocked_count = sum(1 for e in self._entries if e.is_blacklisted)
        self.warn_label = QLabel(
            f"⚠ 黑名单目录已自动排除，不可勾选（{blocked_count} 项）"
        )
        self.warn_label.setStyleSheet("color:#b23c3c;font-weight:bold;")
        layout.addWidget(self.warn_label)

        if not self._allow_orphan and any(e.owner_id is None for e in self._entries):
            orphan_label = QLabel("⚠ 当前设置禁止删除『未识别』分组的条目，相关项已取消勾选")
            orphan_label.setStyleSheet("color:#c07a1e;font-weight:bold;")
            layout.addWidget(orphan_label)

        # DELETE 输入
        confirm_layout = QHBoxLayout()
        confirm_layout.addWidget(QLabel(f'请输入 "{self.CONFIRM_WORD}" 以确认：'))
        self.confirm_input = QLineEdit()
        self.confirm_input.setPlaceholderText(self.CONFIRM_WORD)
        self.confirm_input.setMinimumWidth(160)
        confirm_layout.addWidget(self.confirm_input)
        confirm_layout.addStretch(1)
        layout.addLayout(confirm_layout)

        # 按钮
        self.button_box = QDialogButtonBox()
        self.confirm_button = QPushButton("确认删除")
        self.confirm_button.setEnabled(False)
        self.confirm_button.setStyleSheet("font-weight:bold;")
        self.button_box.addButton(self.confirm_button, QDialogButtonBox.AcceptRole)
        self.button_box.addButton("取消", QDialogButtonBox.RejectRole)
        layout.addWidget(self.button_box)

        self.confirm_input.textChanged.connect(self._on_confirm_text_changed)
        self.confirm_button.clicked.connect(self._on_confirm_clicked)
        self.button_box.rejected.connect(self.reject)
        self.select_all_button.clicked.connect(self._on_select_all)
        self.select_none_button.clicked.connect(self._on_select_none)

        self._fill_tree()

    # ---- 路径清单 ----

    def _fill_tree(self) -> None:
        """填充路径清单（黑名单项置灰 + ⛔）。"""
        for entry in self._entries:
            blocked = entry.is_blacklisted
            if blocked:
                flags = Qt.ItemIsSelectable  # 不可勾选、不可编辑
                prefix = "⛔"
                note = entry.block_reason or "黑名单拦截"
            else:
                flags = Qt.ItemIsSelectable | Qt.ItemIsEnabled | Qt.ItemIsUserCheckable
                prefix = "☑"
                note = entry.content_type.label
                if entry.owner_id is None and not self._allow_orphan:
                    note = "未识别分组（当前设置禁止删除）"
            item = QTreeWidgetItem([
                prefix,
                entry.display_path(),
                human_size(entry.size),
                str(entry.file_count) if entry.file_count >= 0 else "计算中…",
                note,
            ])
            item.setFlags(flags)
            if not blocked and not (entry.owner_id is None and not self._allow_orphan):
                item.setCheckState(0, Qt.Checked)
            else:
                item.setCheckState(0, Qt.Unchecked)
            item.setToolTip(1, entry.path)
            item.setData(0, Qt.UserRole, entry.path)
            self.tree.addTopLevelItem(item)
        self.tree.resizeColumnToContents(0)

    def _iter_items(self):
        """遍历全部清单项。"""
        for i in range(self.tree.topLevelItemCount()):
            yield self.tree.topLevelItem(i)

    def _on_select_all(self) -> None:
        """全选未被拦截的项。"""
        for item in self._iter_items():
            if item.flags() & Qt.ItemIsUserCheckable:
                item.setCheckState(0, Qt.Checked)

    def _on_select_none(self) -> None:
        """取消全部勾选。"""
        for item in self._iter_items():
            if item.flags() & Qt.ItemIsUserCheckable:
                item.setCheckState(0, Qt.Unchecked)

    # ---- 交互 ----

    def _on_confirm_text_changed(self, text: str) -> None:
        """输入 ``DELETE`` 后才启用确认按钮。"""
        self.confirm_button.setEnabled(text.strip() == self.CONFIRM_WORD)

    def _on_confirm_clicked(self) -> None:
        """系统级二次确认（QMessageBox 双保险）。"""
        selected = self.selected_entries()
        if not selected:
            QMessageBox.information(self, "无需删除", "没有勾选任何可删除的路径。")
            return
        total_bytes = sum(max(0, e.size) for e in selected)
        answer = QMessageBox.warning(
            self,
            "再次确认",
            f"即将删除 {len(selected)} 个路径，合计 {human_size(total_bytes)}。\n\n"
            f"删除方式：{self.selected_mode().label}\n"
            "此操作不可轻易撤销，确定继续吗？",
            QMessageBox.Ok | QMessageBox.Cancel,
            QMessageBox.Cancel,
        )
        if answer == QMessageBox.Ok:
            self.accept()

    # ---- 结果 ----

    def selected_entries(self) -> list[DataPathEntry]:
        """返回用户勾选且未被拦截的条目。"""
        path_map = {os.path.normcase(e.path): e for e in self._entries}
        result: list[DataPathEntry] = []
        for item in self._iter_items():
            if not (item.flags() & Qt.ItemIsUserCheckable):
                continue
            if item.checkState(0) != Qt.Checked:
                continue
            path = str(item.data(0, Qt.UserRole) or "")
            entry = path_map.get(os.path.normcase(path))
            if entry is not None:
                result.append(entry)
        return result

    def selected_mode(self) -> DeleteMode:
        """返回用户选择的删除方式。"""
        if self.mode_recycle.isChecked():
            return DeleteMode.RECYCLE_BIN
        if self.mode_permanent.isChecked():
            return DeleteMode.PERMANENT
        return DeleteMode.BACKUP_THEN_DELETE


# --------------------------------------------------------------------------
# 卸载对话框
# --------------------------------------------------------------------------


class UninstallDialog(QDialog):
    """调用官方卸载程序对话框（PRD 4.4 线框）。"""

    def __init__(
        self,
        software_name: str,
        quiet_command: str,
        standard_command: str,
        timeout: int = 300,
        is_admin: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        """初始化。

        Args:
            software_name: 软件名称。
            quiet_command: 静默卸载命令。
            standard_command: 标准卸载命令。
            timeout: 默认超时秒数。
            is_admin: 当前是否具备管理员权限。
            parent: 父窗口。
        """
        super().__init__(parent)
        self.setWindowTitle(f"卸载软件：{software_name}")
        self.setMinimumSize(620, 400)
        self._quiet_command = quiet_command
        self._standard_command = standard_command
        self._build_ui(software_name, timeout, is_admin, bool(quiet_command))

    def _build_ui(self, software_name: str, timeout: int, is_admin: bool, has_quiet: bool) -> None:
        """装配控件。"""
        layout = QVBoxLayout(self)

        mode_group = QGroupBox("卸载方式")
        mode_layout = QVBoxLayout(mode_group)
        self.quiet_radio = QRadioButton("静默卸载（QuietUninstallString，无界面）")
        self.standard_radio = QRadioButton("标准卸载（显示卸载程序界面）")
        self.quiet_radio.setChecked(has_quiet)
        self.standard_radio.setChecked(not has_quiet)
        self.quiet_radio.setEnabled(has_quiet)
        mode_layout.addWidget(self.quiet_radio)
        mode_layout.addWidget(self.standard_radio)
        layout.addWidget(mode_group)

        form = QFormLayout()
        self.command_label = QTextBrowser()
        self.command_label.setMaximumHeight(90)
        self.command_label.setPlainText(self._quiet_command or self._standard_command or "（无可用卸载命令）")
        form.addRow("命令：", self.command_label)

        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(30, 3600)
        self.timeout_spin.setValue(timeout)
        self.timeout_spin.setSuffix(" 秒")
        form.addRow("超时：", self.timeout_spin)

        self.residual_check = QCheckBox("卸载完成后自动扫描残留目录（P1-1）")
        self.residual_check.setChecked(True)
        form.addRow("", self.residual_check)
        layout.addLayout(form)

        tip = "⚠ 卸载可能需要管理员权限，当前已具备管理员权限。" if is_admin else \
              "⚠ 卸载可能需要管理员权限，建议以管理员身份运行本程序。"
        tip_label = QLabel(tip)
        tip_label.setWordWrap(True)
        tip_label.setStyleSheet("color:#c07a1e;font-weight:bold;")
        layout.addWidget(tip_label)

        self.button_box = QDialogButtonBox()
        self.ok_button = QPushButton("开始卸载")
        self.ok_button.setStyleSheet("font-weight:bold;")
        self.button_box.addButton(self.ok_button, QDialogButtonBox.AcceptRole)
        self.button_box.addButton("取消", QDialogButtonBox.RejectRole)
        layout.addWidget(self.button_box)

        self.quiet_radio.toggled.connect(self._on_mode_changed)
        self.ok_button.clicked.connect(self.accept)
        self.button_box.rejected.connect(self.reject)

        if not (self._quiet_command or self._standard_command):
            self.ok_button.setEnabled(False)
            self.ok_button.setText("无可用卸载命令")

    def _on_mode_changed(self, checked: bool) -> None:
        """切换卸载方式时更新命令预览。"""
        command = self._quiet_command if self.quiet_radio.isChecked() else self._standard_command
        self.command_label.setPlainText(command or "（该方式无可用命令）")

    # ---- 结果 ----

    @property
    def quiet(self) -> bool:
        """是否静默卸载。"""
        return self.quiet_radio.isChecked()

    @property
    def timeout(self) -> int:
        """超时秒数。"""
        return int(self.timeout_spin.value())

    @property
    def scan_residual(self) -> bool:
        """卸载后是否扫描残留。"""
        return self.residual_check.isChecked()


# --------------------------------------------------------------------------
# 残留扫描结果对话框（P1-1）
# --------------------------------------------------------------------------


class ResidualDialog(QDialog):
    """卸载后残留目录清单（可勾选清理，复用删除闸门）。"""

    def __init__(self, entries: list[DataPathEntry], parent: QWidget | None = None) -> None:
        """初始化。

        Args:
            entries: 疑似残留条目。
            parent: 父窗口。
        """
        super().__init__(parent)
        self._entries = list(entries)
        self.setWindowTitle("残留扫描结果")
        self.setMinimumSize(720, 460)
        self._build_ui()

    def _build_ui(self) -> None:
        """装配控件。"""
        layout = QVBoxLayout(self)
        total = sum(max(0, e.size) for e in self._entries)
        layout.addWidget(QLabel(
            f"共发现 <b>{len(self._entries)}</b> 个疑似残留目录，合计 {human_size(total)}。"
            "勾选后可交给删除流程处理（同样受黑名单保护）。"
        ))

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["", "路径", "大小", "文件数", "最后修改"])
        self.tree.setRootIsDecorated(False)
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.tree.header().setStretchLastSection(True)
        self.tree.setColumnWidth(1, 380)
        for entry in self._entries:
            blocked = entry.is_blacklisted
            item = QTreeWidgetItem([
                "⛔" if blocked else "☐",
                entry.display_path(),
                human_size(entry.size),
                str(entry.file_count) if entry.file_count >= 0 else "计算中…",
                format_time(entry.mtime),
            ])
            item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled |
                          (Qt.ItemIsUserCheckable if not blocked else Qt.NoItemFlags))
            if not blocked:
                item.setCheckState(0, Qt.Checked)
            item.setToolTip(1, entry.path)
            item.setData(0, Qt.UserRole, entry.path)
            self.tree.addTopLevelItem(item)
        layout.addWidget(self.tree, stretch=1)

        select_layout = QHBoxLayout()
        all_button = QPushButton("全选")
        none_button = QPushButton("全不选")
        select_layout.addWidget(all_button)
        select_layout.addWidget(none_button)
        select_layout.addStretch(1)
        layout.addLayout(select_layout)

        self.button_box = QDialogButtonBox()
        self.clean_button = QPushButton("清理所选")
        self.clean_button.setStyleSheet("font-weight:bold;")
        self.button_box.addButton(self.clean_button, QDialogButtonBox.AcceptRole)
        self.button_box.addButton("关闭", QDialogButtonBox.RejectRole)
        layout.addWidget(self.button_box)

        all_button.clicked.connect(lambda: self._set_all(True))
        none_button.clicked.connect(lambda: self._set_all(False))
        self.clean_button.clicked.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        if not self._entries:
            self.clean_button.setEnabled(False)

    def _set_all(self, checked: bool) -> None:
        """全选 / 全不选。"""
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            if item.flags() & Qt.ItemIsUserCheckable:
                item.setCheckState(0, Qt.Checked if checked else Qt.Unchecked)

    def selected_entries(self) -> list[DataPathEntry]:
        """返回勾选的残留条目。"""
        path_map = {os.path.normcase(e.path): e for e in self._entries}
        result: list[DataPathEntry] = []
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            if not (item.flags() & Qt.ItemIsUserCheckable):
                continue
            if item.checkState(0) != Qt.Checked:
                continue
            entry = path_map.get(os.path.normcase(str(item.data(0, Qt.UserRole) or "")))
            if entry is not None:
                result.append(entry)
        return result


# --------------------------------------------------------------------------
# 备份结果对话框
# --------------------------------------------------------------------------


class BackupResultDialog(QDialog):
    """备份结果展示：归档路径、文件数、字节数与被跳过清单。"""

    def __init__(self, report, parent: QWidget | None = None) -> None:
        """初始化。

        Args:
            report: :class:`BackupReport`。
            parent: 父窗口。
        """
        super().__init__(parent)
        self._report = report
        self.setWindowTitle("备份结果" if report.success else "备份失败")
        self.setMinimumSize(680, 420)
        self._build_ui()

    def _build_ui(self) -> None:
        """装配控件。"""
        layout = QVBoxLayout(self)
        report = self._report
        if report.success:
            layout.addWidget(QLabel(
                f"✅ 备份完成\n归档：{report.archive_path}\n"
                f"文件数：{report.file_count}　体积：{human_size(report.total_bytes)}"
            ))
        else:
            layout.addWidget(QLabel(f"❌ 备份失败\n原因：{report.error or '未知原因'}"))

        skipped = getattr(report, "skipped", []) or []
        layout.addWidget(QLabel(f"被跳过（被占用或权限不足）：{len(skipped)} 项"))
        self.table = QTableWidget()
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["路径", "原因"])
        self.table.setRowCount(len(skipped))
        self.table.horizontalHeader().setStretchLastSection(True)
        for i, item in enumerate(skipped):
            self.table.setItem(i, 0, QTableWidgetItem(getattr(item, "path", "")))
            self.table.setItem(i, 1, QTableWidgetItem(getattr(item, "reason", "")))
        layout.addWidget(self.table, stretch=1)

        self.button_box = QDialogButtonBox()
        self.open_button = QPushButton("打开所在目录")
        self.button_box.addButton(self.open_button, QDialogButtonBox.ActionRole)
        self.button_box.addButton("关闭", QDialogButtonBox.AcceptRole)
        layout.addWidget(self.button_box)
        self.open_button.clicked.connect(self._on_open_dir)
        self.button_box.accepted.connect(self.accept)

    def _on_open_dir(self) -> None:
        """在资源管理器中打开归档所在目录。"""
        path = self._report.archive_path
        if not path:
            return
        directory = os.path.dirname(os.path.abspath(path))
        try:
            os.startfile(directory)  # noqa: S606 - Windows 专用打开目录
        except OSError as exc:
            QMessageBox.warning(self, "打开失败", f"无法打开目录：{exc}")


# --------------------------------------------------------------------------
# 设置对话框
# --------------------------------------------------------------------------


class SettingsDialog(QDialog):
    """设置对话框：数据根目录、阈值、排除开关、删除策略、Top-N 等。"""

    def __init__(self, config, parent: QWidget | None = None) -> None:
        """初始化。

        Args:
            config: :class:`AppConfig`（就地修改，点保存后由调用方持久化）。
            parent: 父窗口。
        """
        super().__init__(parent)
        self._config = config
        self.setWindowTitle("设置")
        self.setMinimumSize(560, 520)
        self._build_ui()

    def _build_ui(self) -> None:
        """装配控件。"""
        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.roots_edit = QPlainTextEdit()
        self.roots_edit.setPlainText("\n".join(self._config.data_roots))
        self.roots_edit.setToolTip("每行一个数据根目录，支持环境变量，如 %APPDATA%")
        self.roots_edit.setFixedHeight(110)
        form.addRow("数据根目录：", self.roots_edit)

        self.threshold_spin = QDoubleSpinBox()
        self.threshold_spin.setRange(0.5, 0.95)
        self.threshold_spin.setSingleStep(0.05)
        self.threshold_spin.setValue(float(self._config.fuzzy_threshold))
        self.threshold_spin.setDecimals(2)
        form.addRow("模糊匹配阈值：", self.threshold_spin)

        self.exclude_check = QCheckBox("备份时默认排除缓存与日志类路径")
        self.exclude_check.setChecked(bool(self._config.exclude_cache_log))
        form.addRow("", self.exclude_check)

        self.msix_check = QCheckBox("扫描 MSIX 时包含所有用户（需管理员权限）")
        self.msix_check.setChecked(bool(self._config.msix_all_users))
        form.addRow("", self.msix_check)

        self.system_check = QCheckBox("显示系统组件条目")
        self.system_check.setChecked(bool(self._config.show_system_component))
        form.addRow("", self.system_check)

        self.orphan_check = QCheckBox("允许删除『未识别』分组的条目")
        self.orphan_check.setChecked(bool(self._config.allow_delete_orphan))
        form.addRow("", self.orphan_check)

        self.mode_combo = QComboBox()
        for mode in DeleteMode:
            self.mode_combo.addItem(mode.label, mode.value)
        index = self.mode_combo.findData(self._config.default_delete_mode)
        self.mode_combo.setCurrentIndex(index if index >= 0 else 0)
        form.addRow("默认删除策略：", self.mode_combo)

        self.top_spin = QSpinBox()
        self.top_spin.setRange(5, 200)
        self.top_spin.setValue(int(self._config.top_n))
        form.addRow("Top-N 视图条数：", self.top_spin)

        backup_layout = QHBoxLayout()
        self.backup_edit = QLineEdit(self._config.backup_dir or "")
        self.backup_edit.setPlaceholderText("留空则使用默认目录")
        self.backup_button = QPushButton("浏览…")
        backup_layout.addWidget(self.backup_edit, stretch=1)
        backup_layout.addWidget(self.backup_button)
        backup_widget = QWidget()
        backup_widget.setLayout(backup_layout)
        form.addRow("备份默认目录：", backup_widget)

        layout.addLayout(form, stretch=1)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        self.button_box.button(QDialogButtonBox.Save).setText("保存")
        self.button_box.button(QDialogButtonBox.Cancel).setText("取消")
        layout.addWidget(self.button_box)

        self.backup_button.clicked.connect(self._on_browse)
        self.button_box.accepted.connect(self._on_accept)
        self.button_box.rejected.connect(self.reject)

    def _on_browse(self) -> None:
        """选择备份目录。"""
        directory = QFileDialog.getExistingDirectory(self, "选择备份存放目录", self.backup_edit.text() or "")
        if directory:
            self.backup_edit.setText(directory)

    def _on_accept(self) -> None:
        """校验并写回配置。"""
        roots = [line.strip() for line in self.roots_edit.toPlainText().splitlines() if line.strip()]
        if not roots:
            QMessageBox.warning(self, "设置无效", "数据根目录至少需要保留一项。")
            return
        self._config.data_roots = roots
        self._config.fuzzy_threshold = float(self.threshold_spin.value())
        self._config.exclude_cache_log = self.exclude_check.isChecked()
        self._config.msix_all_users = self.msix_check.isChecked()
        self._config.show_system_component = self.system_check.isChecked()
        self._config.allow_delete_orphan = self.orphan_check.isChecked()
        self._config.default_delete_mode = str(self.mode_combo.currentData() or DeleteMode.BACKUP_THEN_DELETE.value)
        self._config.top_n = int(self.top_spin.value())
        self._config.backup_dir = self.backup_edit.text().strip()
        self.accept()

    @property
    def config(self):
        """返回（已修改的）配置对象。"""
        return self._config


# --------------------------------------------------------------------------
# 关于 / 日志
# --------------------------------------------------------------------------


class AboutDialog(QDialog):
    """关于对话框。"""

    def __init__(self, parent: QWidget | None = None) -> None:
        """初始化。"""
        super().__init__(parent)
        self.setWindowTitle("关于")
        self.setMinimumSize(460, 300)
        layout = QVBoxLayout(self)
        text = QTextBrowser()
        text.setHtml(
            "<h3>软件数据迁移助手</h3>"
            "<p>版本：0.1.0（MVP）</p>"
            "<p>用途：扫描已安装软件，列出它们在 C 盘的全部数据存储路径、"
            "占用大小与内容类型，并支持批量备份、删除与调用官方卸载程序。"
            "面向『换机』场景设计。</p>"
            "<p><b>安全提示</b>：系统关键目录已硬编码拦截；删除前会强制列出路径清单、"
            "要求输入 DELETE 并二次确认；默认策略为『先备份后删除』。</p>"
            "<p>技术栈：Python 3.13 + PySide6 6.8.3，其余能力均由标准库实现。</p>"
        )
        text.setOpenExternalLinks(True)
        layout.addWidget(text)
        box = QDialogButtonBox(QDialogButtonBox.Ok)
        box.button(QDialogButtonBox.Ok).setText("确定")
        box.accepted.connect(self.accept)
        layout.addWidget(box)


class LogViewDialog(QDialog):
    """操作日志查看对话框（P1-8，读取 JSONL）。"""

    def __init__(self, action_logger, parent: QWidget | None = None) -> None:
        """初始化。

        Args:
            action_logger: :class:`utils.ActionLogger`。
            parent: 父窗口。
        """
        super().__init__(parent)
        self._logger = action_logger
        self.setWindowTitle("操作日志")
        self.setMinimumSize(760, 460)
        self._build_ui()

    def _build_ui(self) -> None:
        """装配控件。"""
        layout = QVBoxLayout(self)
        path = getattr(self._logger, "path", "") or ""
        layout.addWidget(QLabel(f"日志文件：{path or '（未设置目录）'}"))

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["时间", "动作", "目标", "结果", "详情"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        records = self._logger.recent(300)
        self.table.setRowCount(len(records))
        for i, record in enumerate(records):
            self.table.setItem(i, 0, QTableWidgetItem(str(record.get("ts", ""))))
            self.table.setItem(i, 1, QTableWidgetItem(str(record.get("action", ""))))
            self.table.setItem(i, 2, QTableWidgetItem(str(record.get("target", ""))))
            self.table.setItem(i, 3, QTableWidgetItem(str(record.get("result", ""))))
            self.table.setItem(i, 4, QTableWidgetItem(str(record.get("detail", ""))[:400]))
        layout.addWidget(self.table, stretch=1)

        self.button_box = QDialogButtonBox()
        refresh_button = QPushButton("刷新")
        self.button_box.addButton(refresh_button, QDialogButtonBox.ActionRole)
        self.button_box.addButton("关闭", QDialogButtonBox.AcceptRole)
        layout.addWidget(self.button_box)
        refresh_button.clicked.connect(self._on_refresh)
        self.button_box.accepted.connect(self.accept)

    def _on_refresh(self) -> None:
        """重新读取日志。"""
        records = self._logger.recent(300)
        self.table.setRowCount(len(records))
        for i, record in enumerate(records):
            self.table.setItem(i, 0, QTableWidgetItem(str(record.get("ts", ""))))
            self.table.setItem(i, 1, QTableWidgetItem(str(record.get("action", ""))))
            self.table.setItem(i, 2, QTableWidgetItem(str(record.get("target", ""))))
            self.table.setItem(i, 3, QTableWidgetItem(str(record.get("result", ""))))
            self.table.setItem(i, 4, QTableWidgetItem(str(record.get("detail", ""))[:400]))


def show_error(parent: QWidget | None, message: str, detail: str = "") -> None:
    """统一错误弹窗。"""
    if detail:
        QMessageBox.critical(parent, "出错了", f"{message}\n\n{detail}")
    else:
        QMessageBox.critical(parent, "出错了", message)


def show_app_error(parent: QWidget | None, error: AppError) -> None:
    """展示 :class:`AppError`。"""
    show_error(parent, error.message, error.detail)
