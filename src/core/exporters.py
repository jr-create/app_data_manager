# -*- coding: utf-8 -*-
"""导出清单（L3）：CSV（``utf-8-sig``，Excel 可直接打开）与 JSON（结构化）。

导出范围包含"未识别"分组（A8 裁决），并在归属列标注 ``未识别``。
"""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime

from .models import DataPathEntry, InstalledSoftware, ScanResult
from .utils import format_time, human_size, now_iso

#: CSV 表头（中文，字段完整）
CSV_HEADERS: tuple[str, ...] = (
    "软件名",
    "发布商",
    "版本",
    "来源",
    "安装路径",
    "安装日期",
    "总占用(字节)",
    "总占用",
    "关联路径数",
    "归属",
    "路径(显示)",
    "路径(绝对)",
    "类型",
    "条目类型",
    "大小(字节)",
    "大小",
    "文件数",
    "最后修改",
    "匹配级别",
    "置信度",
    "模糊匹配",
    "黑名单",
    "拦截原因",
    "手动指派",
)


def _owner_label(entry: DataPathEntry, result: ScanResult) -> str:
    """返回条目归属列的文本（未识别时标注"未识别"）。"""
    if not entry.owner_id:
        return "未识别"
    sw = result.get(entry.owner_id)
    return sw.name if sw is not None else entry.owner_id


def _rows_for_software(sw: InstalledSoftware, result: ScanResult) -> list[list[str]]:
    """生成单个软件（含其全部关联路径）的 CSV 行。"""
    rows: list[list[str]] = []
    for entry in sw.data_paths:
        rows.append([
            sw.name,
            sw.publisher,
            sw.version,
            sw.source.label,
            sw.install_location,
            sw.install_date,
            str(max(0, sw.total_size)),
            human_size(sw.total_size),
            str(len(sw.data_paths)),
            _owner_label(entry, result),
            entry.display_path(),
            entry.path,
            entry.content_type.label,
            entry.kind.label,
            str(entry.size),
            human_size(entry.size),
            str(entry.file_count),
            format_time(entry.mtime),
            entry.match_level.label,
            f"{entry.confidence:.2f}",
            "是" if entry.is_fuzzy else "否",
            "是" if entry.is_blacklisted else "否",
            entry.block_reason,
            "是" if entry.is_manual else "否",
        ])
    if not sw.data_paths:
        rows.append([
            sw.name, sw.publisher, sw.version, sw.source.label, sw.install_location,
            sw.install_date, str(max(0, sw.total_size)), human_size(sw.total_size), "0",
            "无关联路径", "-", "-", "-", "-", "0", human_size(0), "0", "-",
            "-", "0.00", "否", "否", "", "否",
        ])
    return rows


def export_csv(result: ScanResult, path: str) -> None:
    """导出扫描结果为 CSV（``utf-8-sig`` 编码，Excel 打开无乱码）。

    Args:
        result: 扫描结果。
        path: 目标文件路径。
    """
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerow(CSV_HEADERS)
        for sw in result.software.values():
            for row in _rows_for_software(sw, result):
                writer.writerow(row)
        # A8：未识别分组同样导出，末列标注归属=未识别
        for entry in result.orphan_entries:
            writer.writerow([
                "(未识别)", "-", "-", "-", "-", "-",
                str(max(0, entry.size)), human_size(entry.size), "1",
                "未识别",
                entry.display_path(), entry.path,
                entry.content_type.label, entry.kind.label,
                str(entry.size), human_size(entry.size), str(entry.file_count),
                format_time(entry.mtime), entry.match_level.label, f"{entry.confidence:.2f}",
                "是" if entry.is_fuzzy else "否",
                "是" if entry.is_blacklisted else "否",
                entry.block_reason,
                "是" if entry.is_manual else "否",
            ])


def export_json(result: ScanResult, path: str) -> None:
    """导出扫描结果为 JSON（``ensure_ascii=False``，中文原样可读）。

    Args:
        result: 扫描结果。
        path: 目标文件路径。
    """
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)

    software_items: list[dict] = []
    for sw in result.software.values():
        item = sw.to_dict()
        item["source_label"] = sw.source.label
        item["total_size_human"] = human_size(sw.total_size)
        item["entries"] = [e.to_dict() for e in sw.data_paths]
        software_items.append(item)

    orphan_items = [e.to_dict() for e in result.orphan_entries]

    payload: dict = {
        "schema_version": 1,
        "tool_version": "0.1.0",
        "exported_at": now_iso(),
        "scanned_at": datetime.fromtimestamp(result.started_at).isoformat(timespec="seconds")
        if result.started_at else "",
        "stats": {
            "software_count": result.stats.software_count,
            "entry_count": result.stats.entry_count,
            "identified_count": result.stats.identified_count,
            "orphan_count": result.stats.orphan_count,
            "blacklisted_count": result.stats.blacklisted_count,
            "total_size": result.stats.total_size,
            "total_size_human": human_size(result.stats.total_size),
            "elapsed_sec": round(result.stats.elapsed_sec, 3),
        },
        "software": software_items,
        "orphan_entries": orphan_items,
        "warnings": result.warnings,
    }
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, ensure_ascii=False, indent=2)


def export_all(result: ScanResult, csv_path: str, json_path: str) -> tuple[str, str]:
    """同时导出 CSV 与 JSON。

    Returns:
        ``(csv 路径, json 路径)`` 二元组。
    """
    export_csv(result, csv_path)
    export_json(result, json_path)
    return csv_path, json_path
