# -*- coding: utf-8 -*-
"""界面组件（L5）：软件表格模型、筛选代理、详情面板与图标提取。

图标提取属于 UI 能力（P1-5），因此放在本模块；core 层不引入任何 Qt 依赖。
"""

from __future__ import annotations

import os
from collections import OrderedDict
from dataclasses import dataclass, field

from PySide6.QtCore import (
    QAbstractTableModel,
    QFileInfo,
    QRect,
    QSortFilterProxyModel,
    Qt,
    Signal,
)
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QIcon,
    QPainter,
    QPixmap,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileIconProvider,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableView,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.models import (
    ContentType,
    DataPathEntry,
    InstalledSoftware,
)
from ..core.software_scanner import resolve_exe_from_install_location
from ..core.utils import LARGE_DIR_BYTES, format_time, human_size

# --------------------------------------------------------------------------
# 常量：列定义与自定义数据角色
# --------------------------------------------------------------------------

#: 表格列标题
COLUMN_HEADERS: tuple[str, ...] = ("", "图标", "软件名", "发布商", "版本", "占用", "路径数")

COL_CHECK: int = 0
COL_ICON: int = 1
COL_NAME: int = 2
COL_PUBLISHER: int = 3
COL_VERSION: int = 4
COL_SIZE: int = 5
COL_PATH_COUNT: int = 6

#: 行标识（软件 id 或 ``__orphan__``）
KEY_ROLE: int = int(Qt.UserRole) + 1
#: 数值排序用原始值
RAW_ROLE: int = int(Qt.UserRole) + 2
#: 行对象本体
ROW_ROLE: int = int(Qt.UserRole) + 3

#: 未识别分组的行标识
ORPHAN_KEY: str = "__orphan__"

#: 超大目录高亮红色（亮红 #FF5252 = QColor(255, 82, 82)）。
#: 选择此亮红而非纯 #FF0000：在应用自带的浅/深色调色板下都清晰可辨，
#: 且在深色背景上不会因过暗而看不清。该色不依赖 IDE 主题变量。
LARGE_DIR_COLOR: QColor = QColor(255, 82, 82)


@dataclass
class Row:
    """表格中的一行（软件行或未识别分组行）。"""

    key: str
    name: str = ""
    publisher: str = ""
    version: str = ""
    size: int = 0
    path_count: int = 0
    is_orphan: bool = False
    software: InstalledSoftware | None = None
    entries: list[DataPathEntry] = field(default_factory=list)
    checked: bool = False


# --------------------------------------------------------------------------
# 图标提取与缓存（P1-5）
# --------------------------------------------------------------------------


class IconProvider:
    """软件图标提取器（零第三方依赖，失败时降级为自绘占位图标）。"""

    #: 缓存上限（LRU）
    MAX_CACHE: int = 500

    def __init__(self) -> None:
        """初始化图标缓存与系统图标提供者。"""
        self._cache: "OrderedDict[str, QIcon]" = OrderedDict()
        self._provider: QFileIconProvider = QFileIconProvider()
        self._placeholder_cache: dict[str, QIcon] = {}

    def icon_for(self, sw: InstalledSoftware) -> QIcon:
        """返回软件图标（带 LRU 缓存）。"""
        key = sw.id or sw.name
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        icon = self._build_icon(sw)
        self._cache[key] = icon
        if len(self._cache) > self.MAX_CACHE:
            self._cache.popitem(last=False)
        return icon

    # ---- 内部 ----

    @staticmethod
    def _exe_path(sw: InstalledSoftware) -> str:
        """从 DisplayIcon / 安装目录推断可执行文件路径。"""
        raw = (sw.display_icon or "").strip()
        if raw:
            exe = raw.split(",")[0].strip().strip('"')
            if exe.lower().endswith(".exe") and os.path.exists(exe):
                return exe
        found = resolve_exe_from_install_location(sw)
        return found

    def _build_icon(self, sw: InstalledSoftware) -> QIcon:
        """按优先级提取图标：DisplayIcon → 安装目录最大 exe → 占位图标。"""
        exe = self._exe_path(sw)
        if exe:
            try:
                icon = self._provider.icon(QFileInfo(exe))
                if icon is not None and not icon.isNull():
                    return icon
            except (OSError, RuntimeError):
                pass
        return self.placeholder(sw.name)

    def placeholder(self, name: str) -> QIcon:
        """生成纯色圆形 + 首字的占位图标。"""
        text = (name or "?").strip()[:1] or "?"
        if text in self._placeholder_cache:
            return self._placeholder_cache[text]
        hue = sum(ord(ch) for ch in (name or "?")) % 360
        color = QColor()
        color.setHsv(hue, 150, 210)
        pixmap = QPixmap(32, 32)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setPen(Qt.NoPen)
        painter.setBrush(color)
        painter.drawEllipse(0, 0, 32, 32)
        painter.setPen(QColor(255, 255, 255))
        font = QFont()
        font.setPointSize(14)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(QRect(0, 0, 32, 32), Qt.AlignCenter, text)
        painter.end()
        icon = QIcon(pixmap)
        self._placeholder_cache[text] = icon
        return icon


# --------------------------------------------------------------------------
# 表格模型
# --------------------------------------------------------------------------


class SoftwareTableModel(QAbstractTableModel):
    """软件列表表格模型（含复选框列与图标列）。"""

    def __init__(self, parent=None) -> None:
        """初始化。

        Args:
            parent: 父对象。
        """
        super().__init__(parent)
        self._rows: list[Row] = []
        self._icons: IconProvider = IconProvider()

    # ---- 基础 ----

    def rowCount(self, parent=None) -> int:  # noqa: N802 - Qt 接口命名
        return len(self._rows)

    def columnCount(self, parent=None) -> int:  # noqa: N802 - Qt 接口命名
        return len(COLUMN_HEADERS)

    def headerData(self, section: int, orientation, role: int = Qt.DisplayRole):  # noqa: N802
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            if 0 <= section < len(COLUMN_HEADERS):
                return COLUMN_HEADERS[section]
        return super().headerData(section, orientation, role)

    def data(self, index, role: int = Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        col = index.column()

        if role == KEY_ROLE:
            return row.key
        if role == ROW_ROLE:
            return row

        if col == COL_CHECK:
            if role == Qt.CheckStateRole:
                return Qt.Checked if row.checked else Qt.Unchecked
            if role == Qt.DisplayRole:
                return ""
            if role == Qt.TextAlignmentRole:
                return int(Qt.AlignCenter)
            return None

        if col == COL_ICON:
            if role == Qt.DecorationRole:
                if row.software is not None:
                    return self._icons.icon_for(row.software)
                return self._icons.placeholder(row.name)
            if role == Qt.DisplayRole:
                return ""
            return None

        if role == Qt.DisplayRole:
            if col == COL_NAME:
                return row.name
            if col == COL_PUBLISHER:
                return row.publisher
            if col == COL_VERSION:
                return row.version
            if col == COL_SIZE:
                return human_size(row.size) if row.size >= 0 else "计算中…"
            if col == COL_PATH_COUNT:
                return str(row.path_count)
        if role == RAW_ROLE:
            if col == COL_SIZE:
                return int(row.size)
            if col == COL_PATH_COUNT:
                return int(row.path_count)
        if role == Qt.ToolTipRole and col == COL_NAME:
            return self._tooltip(row)

        # 超大目录高亮：当该行任一关联路径 size 超过阈值（且已完成计算，size != -1）时，
        # 将「软件名」与「占用」列以醒目红色加粗显示，提示"该软件包含超大目录"。
        is_large = bool(row.entries) and any(
            e.size > LARGE_DIR_BYTES for e in row.entries
        )
        if is_large and col in (COL_NAME, COL_SIZE):
            if role == Qt.ForegroundRole:
                return QBrush(LARGE_DIR_COLOR)
            if role == Qt.FontRole:
                font = QFont()
                font.setBold(True)
                return font
        return None

    def flags(self, index):
        base = super().flags(index)
        if index.column() == COL_CHECK:
            return base | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable
        return base | Qt.ItemIsEnabled | Qt.ItemIsSelectable

    def setData(self, index, value, role: int = Qt.EditRole) -> bool:
        if not index.isValid():
            return False
        if index.column() == COL_CHECK and role == Qt.CheckStateRole:
            row = self._rows[index.row()]
            row.checked = (value == Qt.Checked or value == int(Qt.Checked))
            self.dataChanged.emit(index, index, [Qt.CheckStateRole])
            return True
        return False

    def sort(self, column: int, order=Qt.AscendingOrder) -> None:  # noqa: N802 - Qt 接口命名
        """模型自身不排序（交由代理模型），此处保留空实现以避免破坏代理排序。"""
        return

    # ---- 数据装配 ----

    @staticmethod
    def _tooltip(row: Row) -> str:
        """生成悬浮提示。"""
        if row.is_orphan:
            return f"未识别分组：{row.path_count} 条路径，合计 {human_size(row.size)}"
        sw = row.software
        if sw is None:
            return row.name
        lines = [
            f"名称：{sw.name}",
            f"发布商：{sw.publisher or '-'}",
            f"版本：{sw.version or '-'}",
            f"来源：{sw.source.label}",
            f"安装目录：{sw.install_location or '-'}",
            f"关联路径：{len(sw.data_paths)} 条",
        ]
        return "\n".join(lines)

    def set_rows(self, rows: list[Row]) -> None:
        """整体替换行数据（保留已存在的勾选状态）。"""
        previous: dict[str, bool] = {r.key: r.checked for r in self._rows}
        for row in rows:
            if row.key in previous:
                row.checked = previous[row.key]
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def rows(self) -> list[Row]:
        """返回全部行对象。"""
        return list(self._rows)

    def row_by_key(self, key: str) -> Row | None:
        """按键查找行。"""
        for row in self._rows:
            if row.key == key:
                return row
        return None

    def checked_rows(self) -> list[Row]:
        """返回已勾选的行。"""
        return [r for r in self._rows if r.checked]

    def checked_entries(self) -> list[DataPathEntry]:
        """返回已勾选行对应的全部条目。"""
        entries: list[DataPathEntry] = []
        for row in self.checked_rows():
            entries.extend(row.entries)
        return entries

    def set_checked(self, key: str, checked: bool) -> None:
        """设置单行的勾选状态。"""
        for i, row in enumerate(self._rows):
            if row.key == key:
                row.checked = checked
                index = self.index(i, COL_CHECK)
                self.dataChanged.emit(index, index, [Qt.CheckStateRole])
                return

    def set_all_checked(self, checked: bool) -> None:
        """全选 / 全不选。"""
        for row in self._rows:
            row.checked = checked
        if self._rows:
            self.dataChanged.emit(
                self.index(0, COL_CHECK),
                self.index(len(self._rows) - 1, COL_CHECK),
                [Qt.CheckStateRole],
            )

    def update_row_size(self, key: str) -> None:
        """通知某行的大小已变化（触发重绘）。"""
        for i, row in enumerate(self._rows):
            if row.key == key:
                left = self.index(i, COL_SIZE)
                right = self.index(i, COL_PATH_COUNT)
                self.dataChanged.emit(left, right, [Qt.DisplayRole])
                return

    # ---- 排序支持（供代理模型取原始值）----

    def top_n_keys(self, n: int) -> set[str]:
        """返回占用大小前 N 行的键集合。"""
        if n <= 0:
            return set()
        ordered = sorted(self._rows, key=lambda r: (-max(0, r.size), r.name))
        return {r.key for r in ordered[:n]}


# --------------------------------------------------------------------------
# 筛选代理模型
# --------------------------------------------------------------------------


class SoftwareFilterProxy(QSortFilterProxyModel):
    """搜索 / 类型 / 识别状态 / Top-N 四维筛选代理。"""

    #: 识别状态筛选模式
    FILTER_ALL: str = "全部"
    FILTER_IDENTIFIED: str = "已识别"
    FILTER_ORPHAN: str = "未识别"

    def __init__(self, parent=None) -> None:
        """初始化。"""
        super().__init__(parent)
        self._search: str = ""
        self._content_type: ContentType | None = None
        self._identified: str = self.FILTER_ALL
        self._top_n: int = 0
        self._top_keys: set[str] = set()

    # ---- 配置 ----

    def set_search(self, text: str) -> None:
        """设置搜索关键字（软件名 / 发布商 / 路径）。"""
        self._search = (text or "").strip().lower()
        self.invalidateFilter()

    def set_content_type(self, content_type: ContentType | None) -> None:
        """设置内容类型筛选（``None`` 表示全部）。"""
        self._content_type = content_type
        self.invalidateFilter()

    def set_identified(self, mode: str) -> None:
        """设置识别状态筛选。"""
        self._identified = mode or self.FILTER_ALL
        self.invalidateFilter()

    def set_top_n(self, n: int) -> None:
        """设置 Top-N 视图（``0`` 表示不限制）。"""
        self._top_n = int(n or 0)
        self.refresh_top_keys()

    def refresh_top_keys(self) -> None:
        """按当前源模型重算 Top-N 键集合。"""
        source = self.sourceModel()
        if isinstance(source, SoftwareTableModel) and self._top_n > 0:
            self._top_keys = source.top_n_keys(self._top_n)
        else:
            self._top_keys = set()
        self.invalidateFilter()

    @property
    def top_n(self) -> int:
        """当前 Top-N 设置。"""
        return self._top_n

    # ---- 过滤 ----

    def filterAcceptsRow(self, source_row: int, source_parent) -> bool:  # noqa: N802 - Qt 接口命名
        source = self.sourceModel()
        if source is None:
            return True
        name_index = source.index(source_row, COL_NAME, source_parent)
        row: Row | None = source.data(name_index, ROW_ROLE)
        if row is None:
            return True

        if self._top_n > 0 and self._top_keys and row.key not in self._top_keys:
            return False

        if self._identified == self.FILTER_IDENTIFIED and row.is_orphan:
            return False
        if self._identified == self.FILTER_ORPHAN and not row.is_orphan:
            return False

        if self._content_type is not None:
            if not any(e.content_type == self._content_type for e in row.entries):
                return False

        if self._search:
            haystack = " ".join([
                row.name,
                row.publisher,
                row.version,
                *(e.display_path() for e in row.entries),
            ]).lower()
            if self._search not in haystack:
                return False
        return True

    # ---- 排序 ----

    def lessThan(self, left, right) -> bool:  # noqa: N802 - Qt 接口命名
        if left.column() in (COL_SIZE, COL_PATH_COUNT):
            left_value = left.data(RAW_ROLE)
            right_value = right.data(RAW_ROLE)
            try:
                return int(left_value or 0) < int(right_value or 0)
            except (TypeError, ValueError):
                return False
        left_text = str(left.data(Qt.DisplayRole) or "")
        right_text = str(right.data(Qt.DisplayRole) or "")
        return left_text.lower() < right_text.lower()


# --------------------------------------------------------------------------
# 表格视图
# --------------------------------------------------------------------------


class SoftwareTableView(QTableView):
    """软件列表视图（列宽、选择行为、排序开关已预设）。"""

    def __init__(self, parent=None) -> None:
        """初始化。"""
        super().__init__(parent)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.verticalHeader().setVisible(False)
        # 注意：本机 PySide6 6.8.3 的 setSectionResizeMode(索引, 模式) 重载会崩溃，
        # 因此统一使用"全局模式 + 逐列设定宽度"的写法。
        header = self.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        self.setColumnWidth(COL_CHECK, 42)
        self.setColumnWidth(COL_ICON, 40)
        self.setColumnWidth(COL_NAME, 240)
        self.setColumnWidth(COL_PUBLISHER, 170)
        self.setColumnWidth(COL_VERSION, 90)
        self.setColumnWidth(COL_SIZE, 100)
        self.setColumnWidth(COL_PATH_COUNT, 70)


# --------------------------------------------------------------------------
# 详情面板
# --------------------------------------------------------------------------

#: 详情面板树列
DETAIL_HEADERS: tuple[str, ...] = ("类型", "路径", "大小", "文件数", "最后修改")


class DetailPanel(QWidget):
    """右侧详情面板：展示选中软件/未识别分组的关联路径明细。"""

    #: 请求移除归属（P1-4），参数为条目路径
    removeAttributionRequested = Signal(str)
    #: 请求手动指派归属（P1-4），参数为条目路径
    assignAttributionRequested = Signal(str)
    #: 请求在资源管理器中打开，参数为条目路径
    openInExplorerRequested = Signal(str)

    def __init__(self, parent=None) -> None:
        """初始化。"""
        super().__init__(parent)
        self._current_key: str = ""
        self._current_name: str = ""
        self._entries: list[DataPathEntry] = []
        self._build_ui()

    def _build_ui(self) -> None:
        """装配内部控件。"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        self.title_label = QLabel("未选择软件")
        title_font = self.title_label.font()
        title_font.setBold(True)
        title_font.setPointSize(title_font.pointSize() + 2)
        self.title_label.setFont(title_font)
        layout.addWidget(self.title_label)

        self.meta_label = QLabel("")
        self.meta_label.setWordWrap(True)
        layout.addWidget(self.meta_label)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(list(DETAIL_HEADERS))
        self.tree.setAlternatingRowColors(True)
        self.tree.setRootIsDecorated(True)
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.tree.header().setStretchLastSection(True)
        self.tree.setColumnWidth(0, 110)
        self.tree.setColumnWidth(1, 300)
        self.tree.setColumnWidth(2, 90)
        self.tree.setColumnWidth(3, 70)
        self.tree.setColumnWidth(4, 130)
        layout.addWidget(self.tree, stretch=1)

        button_layout = QHBoxLayout()
        self.open_button = QPushButton("在资源管理器中打开")
        self.copy_button = QPushButton("复制路径")
        self.remove_button = QPushButton("移除归属")
        self.assign_button = QPushButton("归属到…")
        button_layout.addWidget(self.open_button)
        button_layout.addWidget(self.copy_button)
        button_layout.addStretch(1)
        button_layout.addWidget(self.remove_button)
        button_layout.addWidget(self.assign_button)
        layout.addLayout(button_layout)

        self.open_button.clicked.connect(self._on_open_clicked)
        self.copy_button.clicked.connect(self._on_copy_clicked)
        self.remove_button.clicked.connect(self._on_remove_clicked)
        self.assign_button.clicked.connect(self._on_assign_clicked)

    # ---- 数据装配 ----

    def set_software(self, sw: InstalledSoftware) -> None:
        """展示某个软件的详情。"""
        self._current_key = sw.id
        self._current_name = sw.name
        self._entries = list(sw.data_paths)
        self.title_label.setText(sw.name or "(未命名)")
        total = sum(max(0, e.size) for e in sw.data_paths)
        self.meta_label.setText(
            f"发布商：{sw.publisher or '-'}　版本：{sw.version or '-'}　来源：{sw.source.label}\n"
            f"安装目录：{sw.install_location or '-'}\n"
            f"关联路径 {len(sw.data_paths)} 条　合计占用 {human_size(total)}"
        )
        self._fill_tree(sw.data_paths)
        self._update_buttons(enabled=True, manual_allowed=True)

    def set_orphan_group(self, entries: list[DataPathEntry]) -> None:
        """展示"未识别"分组的详情。"""
        self._current_key = ORPHAN_KEY
        self._current_name = "未识别分组"
        self._entries = list(entries)
        total = sum(max(0, e.size) for e in entries)
        self.title_label.setText("未识别分组")
        self.meta_label.setText(
            f"共 {len(entries)} 条路径，合计占用 {human_size(total)}\n"
            "这些目录未能自动归属到任何已安装软件，可手动指派或谨慎处理。"
        )
        self._fill_tree(entries)
        self._update_buttons(enabled=True, manual_allowed=True)

    def clear(self) -> None:
        """清空面板。"""
        self._current_key = ""
        self._current_name = ""
        self._entries = []
        self.title_label.setText("未选择软件")
        self.meta_label.setText("")
        self.tree.clear()
        self._update_buttons(enabled=False, manual_allowed=False)

    def _update_buttons(self, enabled: bool, manual_allowed: bool) -> None:
        """更新按钮可用性。"""
        self.open_button.setEnabled(enabled)
        self.copy_button.setEnabled(enabled)
        self.remove_button.setEnabled(enabled and manual_allowed)
        self.assign_button.setEnabled(enabled and manual_allowed)

    def _fill_tree(self, entries: list[DataPathEntry]) -> None:
        """按内容类型分组填充树控件。"""
        self.tree.clear()
        grouped: dict[str, list[DataPathEntry]] = {}
        for entry in entries:
            grouped.setdefault(entry.content_type.value, []).append(entry)

        for type_value in ("config", "data", "plugin", "cache", "log", "other"):
            items = grouped.get(type_value)
            if not items:
                continue
            content_type = ContentType(type_value)
            group_total = sum(max(0, e.size) for e in items)
            group_item = QTreeWidgetItem([
                f"{content_type.label}",
                f"{len(items)} 项",
                human_size(group_total),
                "",
                "",
            ])
            group_item.setFlags(group_item.flags() & ~Qt.ItemIsSelectable)
            self.tree.addTopLevelItem(group_item)
            for entry in sorted(items, key=lambda e: -max(0, e.size)):
                group_item.addChild(self._entry_item(entry))
            group_item.setExpanded(True)

    @staticmethod
    def _entry_item(entry: DataPathEntry) -> QTreeWidgetItem:
        """构造单条路径的树节点。"""
        tags: list[str] = []
        if entry.is_blacklisted:
            tags.append("⛔黑名单")
        if entry.is_fuzzy:
            tags.append("模糊")
        if entry.conflict_ids:
            tags.append("冲突")
        if entry.is_manual:
            tags.append("手动")
        level_text = entry.match_level.label
        if tags:
            level_text = f"{level_text}（{'/'.join(tags)}）"
        path_text = entry.display_path()
        if entry.block_reason:
            path_text = f"{path_text} ｜ {entry.block_reason}"

        # 体积超过阈值时，在尺寸文本后追加醒目提示，并把该路径行标红。
        # size == -1 表示"未计算"，不计为超大目录。
        is_large = entry.size > LARGE_DIR_BYTES
        size_text = human_size(entry.size)
        if is_large:
            size_text = f"{size_text} ⚠超大(>2GiB)"

        item = QTreeWidgetItem([
            level_text,
            path_text,
            size_text,
            str(entry.file_count) if entry.file_count >= 0 else "计算中…",
            format_time(entry.mtime),
        ])
        item.setData(0, Qt.UserRole, entry.path)
        item.setToolTip(1, entry.path)
        if entry.is_blacklisted:
            item.setForeground(1, QColor(180, 60, 60))
        if is_large:
            # 醒目红色（亮红 #FF5252），在明暗主题下均清晰；覆盖路径列与尺寸列。
            item.setForeground(1, QBrush(LARGE_DIR_COLOR))
            item.setForeground(2, QBrush(LARGE_DIR_COLOR))
            item.setToolTip(2, "该目录体积超过 2 GiB，备份/删除需谨慎")
        return item

    # ---- 交互 ----

    def _selected_entry_path(self) -> str:
        """返回当前选中条目对应的路径。"""
        item = self.tree.currentItem()
        if item is None:
            return ""
        return str(item.data(0, Qt.UserRole) or "")

    def _on_open_clicked(self) -> None:
        """在资源管理器中打开选中路径。"""
        path = self._selected_entry_path()
        if path:
            self.openInExplorerRequested.emit(path)

    def _on_copy_clicked(self) -> None:
        """复制选中路径到剪贴板。"""
        from PySide6.QtWidgets import QApplication  # 局部导入，避免循环依赖

        path = self._selected_entry_path()
        if not path:
            return
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(path)

    def _on_remove_clicked(self) -> None:
        """请求移除选中条目的归属。"""
        path = self._selected_entry_path()
        if path:
            self.removeAttributionRequested.emit(path)

    def _on_assign_clicked(self) -> None:
        """请求手动指派选中条目的归属。"""
        path = self._selected_entry_path()
        if path:
            self.assignAttributionRequested.emit(path)

    @property
    def current_key(self) -> str:
        """当前展示的行键。"""
        return self._current_key

    @property
    def current_name(self) -> str:
        """当前展示的名称。"""
        return self._current_name


def build_rows(result) -> list[Row]:
    """把扫描结果转换为表格行（软件行 + 未识别分组行）。"""
    rows: list[Row] = []
    for sw in result.software.values():
        size = sw.total_size if sw.total_size > 0 else sum(max(0, e.size) for e in sw.data_paths)
        rows.append(Row(
            key=sw.id,
            name=sw.name or "(未命名)",
            publisher=sw.publisher,
            version=sw.version,
            size=size,
            path_count=len(sw.data_paths),
            is_orphan=False,
            software=sw,
            entries=list(sw.data_paths),
        ))
    if result.orphan_entries:
        total = sum(max(0, e.size) for e in result.orphan_entries)
        rows.append(Row(
            key=ORPHAN_KEY,
            name=f"（未识别 {len(result.orphan_entries)} 项）",
            publisher="-",
            version="-",
            size=total,
            path_count=len(result.orphan_entries),
            is_orphan=True,
            software=None,
            entries=list(result.orphan_entries),
        ))
    return rows
