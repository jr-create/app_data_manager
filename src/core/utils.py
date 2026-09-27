# -*- coding: utf-8 -*-
"""通用工具（L1）：名称归一化、分词、相似度、大小/时间格式化、操作日志、节流器。

本模块不依赖任何上层模块与 PySide6，可被任意层安全引用。
"""

from __future__ import annotations

import difflib
import json
import logging
import os
import re
import threading
import time
from datetime import datetime

# --------------------------------------------------------------------------
# 名称归一化
# --------------------------------------------------------------------------

#: 归一化时剔除的企业后缀词
_CORP_SUFFIXES: tuple[str, ...] = (
    "inc", "llc", "ltd", "corp", "corporation", "co", "company", "gmbh",
    "limited", "plc", "sa", "ag", "ab", "oy", "bv", "kk", "srl", "pte",
    "holdings", "group", "technology", "technologies", "software", "studio", "labs",
)

#: 版本号模式：1.85 / 2023.1 / v2 / 3.9.10.1
_VERSION_RE = re.compile(r"(?:\d+\.){1,}\d+|\bv?\d+(?:\.\d+)*\b")

#: 括号内容（含中英文括号）
_BRACKET_RE = re.compile(r"[(\[{\uff08\uff3b\uff5b][^)\]}\uff09\uff3d\uff5d]*[)\]}\uff09\uff3d\uff5d]")

#: 归一化保留的字符：小写字母、数字、中日韩文字
_KEEP_RE = re.compile(r"[^a-z0-9\u4e00-\u9fff]+")

#: 分词用分隔符
_SPLIT_RE = re.compile(r"[^a-z0-9\u4e00-\u9fff]+")


def normalize_name(name: str) -> str:
    """把软件名/目录名归一化为可比较的紧凑字符串。

    处理步骤：转小写 → 去括号内容 → 下划线/连字符转空格 → 去版本号 →
    去企业后缀 → 仅保留字母数字与中日韩文字并拼接。

    Args:
        name: 原始名称。

    Returns:
        归一化后的字符串，如 ``normalize_name("Visual Studio Code (x64) 1.85")``
        → ``visualstudiocode``。
    """
    if not name:
        return ""
    s = str(name).strip().lower()
    s = _BRACKET_RE.sub(" ", s)
    s = s.replace("_", " ").replace("-", " ").replace(".", " ")
    s = _VERSION_RE.sub(" ", s)
    tokens = [t for t in _SPLIT_RE.split(s) if t]
    while len(tokens) > 1 and tokens[-1] in _CORP_SUFFIXES:
        tokens.pop()
    return "".join(tokens)


def tokenize(name: str, min_len: int = 3) -> list[str]:
    """把名称切成用于倒排索引的关键词列表。

    Args:
        name: 原始名称（可为目录名或软件名）。
        min_len: 单关键字最小长度，过短的噪声词（如 ``x``）会被丢弃。

    Returns:
        去重后的关键词列表（小写），包含完整归一化名与各分词。
    """
    if not name:
        return []
    raw = str(name).strip().lower()
    norm = normalize_name(raw)
    parts: list[str] = []
    if norm:
        parts.append(norm)
    for piece in _SPLIT_RE.split(raw):
        piece = piece.strip()
        if len(piece) >= min_len:
            parts.append(piece)
    # 中文名称按整串与二元切分补充召回
    if re.search(r"[\u4e00-\u9fff]", norm):
        cjk = "".join(re.findall(r"[\u4e00-\u9fff]", norm))
        if len(cjk) >= 2:
            parts.append(cjk)
            parts.extend(cjk[i:i + 2] for i in range(len(cjk) - 1))
    seen: set[str] = set()
    result: list[str] = []
    for p in parts:
        if p and p not in seen:
            seen.add(p)
            result.append(p)
    return result


def similarity(a: str, b: str) -> float:
    """计算两个字符串的相似度（0.0~1.0）。

    基于 :class:`difflib.SequenceMatcher`；当一方是另一方的子串时保底返回 0.80，
    以便 ``visualstudiocode`` 与 ``code`` 这类情况能被判定为高相似。

    Args:
        a: 字符串一（建议传归一化后的名称）。
        b: 字符串二。

    Returns:
        相似度浮点数。
    """
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    short, long_ = (a, b) if len(a) <= len(b) else (b, a)
    ratio = difflib.SequenceMatcher(None, a, b).ratio()
    if len(short) >= 3 and short in long_:
        ratio = max(ratio, 0.80)
    return ratio


# --------------------------------------------------------------------------
# 格式化
# --------------------------------------------------------------------------

_SIZE_UNITS: tuple[str, ...] = ("B", "KB", "MB", "GB", "TB", "PB")


def human_size(n: int | float | None) -> str:
    """把字节数格式化为可读文本（1024 进制，保留 1 位小数）。

    ``-1``（未计算）与 ``None`` 统一显示为 ``计算中…``。
    """
    if n is None:
        return "计算中…"
    try:
        value = float(n)
    except (TypeError, ValueError):
        return "计算中…"
    if value < 0:
        return "计算中…"
    idx = 0
    while value >= 1024.0 and idx < len(_SIZE_UNITS) - 1:
        value /= 1024.0
        idx += 1
    if idx == 0:
        return f"{int(value)} {_SIZE_UNITS[idx]}"
    return f"{value:.1f} {_SIZE_UNITS[idx]}"


def format_time(ts: float) -> str:
    """把 UNIX 时间戳格式化为 ``2026-09-20 10:11``。"""
    if not ts:
        return "-"
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M")
    except (OSError, OverflowError, ValueError):
        return "-"


def format_duration(seconds: float) -> str:
    """把秒数格式化为 ``01:23`` 或 ``1 小时 02 分`` 形式的中文文本。"""
    try:
        total = int(max(0.0, float(seconds)))
    except (TypeError, ValueError):
        return "-"
    if total < 60:
        return f"{total} 秒"
    mm, ss = divmod(total, 60)
    if mm < 60:
        return f"{mm:02d} 分 {ss:02d} 秒"
    hh, mm = divmod(mm, 60)
    return f"{hh} 小时 {mm:02d} 分"


def now_iso() -> str:
    """返回带时区偏移的本地 ISO 时间串，如 ``2026-09-27T11:58:00+08:00``。"""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def stamp() -> str:
    """返回 ``YYYYMMDD_HHMMSS`` 形式的时间戳（用于归档命名）。"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


# --------------------------------------------------------------------------
# 日志
# --------------------------------------------------------------------------

LOG_FORMAT: str = "%(asctime)s.%(msecs)03d | %(levelname)-7s | %(name)-18s | %(message)s"
LOG_DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"


def setup_logging(log_dir: str, level: int = logging.INFO) -> logging.Logger:
    """初始化运行日志（文件 + 控制台）。

    Args:
        log_dir: 日志目录，不存在时自动创建。
        level: 日志级别，默认 INFO。

    Returns:
        根记录器（已挂载处理器）。
    """
    try:
        os.makedirs(log_dir, exist_ok=True)
    except OSError:
        log_dir = ""
    logger = logging.getLogger()
    logger.setLevel(level)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass
    formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    if log_dir:
        name = f"app-{datetime.now().strftime('%Y%m%d')}.log"
        try:
            file_handler = logging.FileHandler(
                os.path.join(log_dir, name), encoding="utf-8", mode="a"
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except OSError:
            pass
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    logger.addHandler(stream)
    return logger


class ActionLogger:
    """操作日志（P1-8）：以 JSONL 逐行落盘，便于回溯与 UI 查看。

    文件位于 ``<log_dir>\\actions-YYYYMMDD.jsonl``，一行一条：
    ``{"ts","action","target","result","detail"}``。
    ``action`` 取值：scan / backup / delete / recycle / uninstall / residual_clean / export。
    """

    def __init__(self, log_dir: str = "") -> None:
        """初始化。

        Args:
            log_dir: 日志目录；为空时 :meth:`log` 静默跳过落盘。
        """
        self._log_dir: str = log_dir or ""
        self._lock: threading.Lock = threading.Lock()

    def set_dir(self, log_dir: str) -> None:
        """设置（或切换）日志目录。"""
        self._log_dir = log_dir or ""

    @property
    def dir(self) -> str:
        """当前日志目录。"""
        return self._log_dir

    @property
    def path(self) -> str:
        """当日操作日志文件的完整路径。"""
        if not self._log_dir:
            return ""
        return os.path.join(self._log_dir, f"actions-{datetime.now().strftime('%Y%m%d')}.jsonl")

    def log(self, action: str, target: str, result: str, detail: dict | None = None) -> dict:
        """写入一条操作日志。

        Args:
            action: 动作类型。
            target: 操作对象（软件名 / 路径）。
            result: 结果，如 ``success`` / ``failed`` / ``skipped``。
            detail: 附加信息字典。

        Returns:
            实际写入的记录字典（未落盘时也返回，便于调用方复用）。
        """
        record: dict = {
            "ts": now_iso(),
            "action": action,
            "target": target,
            "result": result,
            "detail": detail or {},
        }
        if not self._log_dir:
            return record
        line = json.dumps(record, ensure_ascii=False)
        with self._lock:
            try:
                os.makedirs(self._log_dir, exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as fp:
                    fp.write(line + "\n")
            except OSError:
                # 日志写入失败不影响主流程，但绝不静默：输出到 stderr
                print(f"[警告] 操作日志写入失败：{line}", flush=True)
        return record

    def recent(self, limit: int = 200) -> list[dict]:
        """读取最近若干条操作日志（跨天合并当日与近期文件）。

        Args:
            limit: 最多返回条数。

        Returns:
            记录字典列表，最新在前。
        """
        if not self._log_dir or not os.path.isdir(self._log_dir):
            return []
        files: list[str] = []
        try:
            for name in os.listdir(self._log_dir):
                if name.startswith("actions-") and name.endswith(".jsonl"):
                    files.append(os.path.join(self._log_dir, name))
        except OSError:
            return []
        files.sort(reverse=True)
        records: list[dict] = []
        for fp in files:
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            except OSError:
                continue
            if len(records) >= limit:
                break
        records.reverse()
        return records[-limit:]

    def clear(self) -> None:
        """清空当日操作日志文件。"""
        target = self.path
        if not target or not os.path.isfile(target):
            return
        try:
            os.remove(target)
        except OSError:
            pass


# --------------------------------------------------------------------------
# 节流器
# --------------------------------------------------------------------------


class Throttler:
    """单调节流器：限制信号/回调的发送频率（默认 100ms 一次）。

    用于后台线程向 UI 发送进度，避免每文件一次信号打爆事件循环。
    """

    def __init__(self, min_interval_ms: int = 100) -> None:
        """初始化。

        Args:
            min_interval_ms: 最小发送间隔（毫秒）。
        """
        self._min_interval_ms: int = max(0, int(min_interval_ms))
        self._last_ms: float = 0.0

    def allow(self) -> bool:
        """是否允许本次发送；允许时内部时间戳会被更新。"""
        now = time.monotonic() * 1000.0
        if now - self._last_ms < self._min_interval_ms:
            return False
        self._last_ms = now
        return True

    def reset(self) -> None:
        """重置计时，使下一次 :meth:`allow` 必定通过。"""
        self._last_ms = 0.0


def dedupe_paths(paths: list[str]) -> list[str]:
    """按规范化路径去重（忽略大小写与斜杠方向），保持原顺序。"""
    seen: set[str] = set()
    result: list[str] = []
    for p in paths:
        key = os.path.normcase(os.path.normpath(os.path.abspath(p)))
        if key in seen:
            continue
        seen.add(key)
        result.append(p)
    return result


# --------------------------------------------------------------------------
# 超大目录阈值（UI 高亮提示用）
# --------------------------------------------------------------------------

#: 单条数据目录体积超过该阈值（2 GiB = 2 * 1024**3 字节）即视为"超大目录"，
#: 在 UI 上以醒目红色高亮提示用户"体积异常大，备份/删除需谨慎"。
#:
#: 背景：目录大小超过 32 位有符号 int 上限（约 2.1 GiB = 2**31 - 1）会让后台「大小计算」
#: 回传信号溢出，历史上因此出过 bug。这里以 2 GiB 为保守阈值做 UI 预警，
#: 与扫描/判定逻辑无关（扫描层不做任何改动，仅呈现层引用此常量）。
LARGE_DIR_BYTES: int = 2 * 1024 ** 3
