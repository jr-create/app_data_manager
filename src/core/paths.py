# -*- coding: utf-8 -*-
"""路径基础设施（L1）：规范化、环境变量折叠、长路径前缀、系统关键目录黑名单。

设计要点：
    * 内部存储与逻辑一律使用**规范化绝对路径**（不含 ``\\\\?\\`` 前缀）；
    * 仅在调用磁盘 API（``os.scandir`` / ``os.stat`` / ``zipfile``）前加 ``\\\\?\\`` 前缀；
    * 展示层用 ``to_display_path()`` 折叠为 ``%APPDATA%\\...``，便于用户阅读；
    * 黑名单判定用 ``normcase(abspath())`` 前缀比较，UI 与 Deleter 双重复核。
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass

# --------------------------------------------------------------------------
# 常量区
# --------------------------------------------------------------------------

#: 预置的用户数据根目录：(根标识, 环境变量模板)
DEFAULT_DATA_ROOTS: list[tuple[str, str]] = [
    ("APPDATA", r"%APPDATA%"),
    ("LOCALAPPDATA", r"%LOCALAPPDATA%"),
    ("LOCALAPPDATA_PROGRAMS", r"%LOCALAPPDATA%\Programs"),
    ("PROGRAMDATA", r"%PROGRAMDATA%"),
    ("USERPROFILE", r"%USERPROFILE%"),
    ("PUBLIC_DOCS", r"%PUBLIC%\Documents"),
]

#: 展示折叠时参与匹配的环境变量（按声明顺序尝试，取最长匹配）
_DISPLAY_ENV_VARS: tuple[str, ...] = (
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "USERPROFILE",
    "PUBLIC",
    "ONEDRIVE",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "WINDIR",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
)

#: 黑名单缓存（延迟构建，进程内只算一次）
_BLACKLIST_CACHE: list[tuple[str, bool, str]] | None = None

#: Windows 重解析点属性（符号链接 / 目录联接 junction / 挂载点共用该标志位）
FILE_ATTRIBUTE_REPARSE_POINT: int = 0x0400

#: 本机主机名集合缓存（识别 ``\\localhost\C$`` 一类管理共享用）
_LOCAL_HOST_NAMES: set[str] | None = None


@dataclass(frozen=True)
class SafetyVerdict:
    """路径安全判定结果。

    Attributes:
        allowed: 是否允许对该路径执行删除等危险操作。
        reason: 被拦截时的中文原因；允许时为空字符串。
    """

    allowed: bool
    reason: str = ""

    @property
    def blocked(self) -> bool:
        """是否命中黑名单（``allowed`` 的反义）。"""
        return not self.allowed


# --------------------------------------------------------------------------
# 基础转换
# --------------------------------------------------------------------------


def expand_env(p: str) -> str:
    """展开环境变量与 ``~``，如 ``%APPDATA%`` → ``C:\\Users\\seer\\AppData\\Roaming``。"""
    if not p:
        return ""
    return os.path.expanduser(os.path.expandvars(p))


def to_absolute(p: str) -> str:
    """返回规范化绝对路径（保留原始大小写），用于持久化与展示。"""
    if not p:
        return ""
    return os.path.normpath(os.path.abspath(expand_env(p)))


def normalize_path(p: str) -> str:
    """返回用于**比较**的规范化路径（``abspath`` + ``normcase``）。"""
    if not p:
        return ""
    return os.path.normcase(to_absolute(p))


def to_long_path(p: str) -> str:
    """为磁盘 API 添加 ``\\\\?\\`` 前缀，解除 260 字符限制（幂等）。

    * 本地路径 ``C:\\a\\b`` → ``\\\\?\\C:\\a\\b``
    * UNC 路径 ``\\\\server\\share\\x`` → ``\\\\?\\UNC\\server\\share\\x``
    """
    if not p:
        return p
    if p.startswith("\\\\?\\"):
        return p
    ap = to_absolute(p)
    if ap.startswith("\\\\"):
        return "\\\\?\\UNC\\" + ap[2:]
    return "\\\\?\\" + ap


def strip_long_prefix(p: str) -> str:
    """去掉 ``\\\\?\\`` 长路径前缀（``to_long_path`` 的逆操作，幂等）。

    ``\\\\?\\UNC\\server\\share`` → ``\\\\server\\share``；``\\\\?\\C:\\a`` → ``C:\\a``。
    """
    if not p:
        return p
    if p.startswith("\\\\?\\UNC\\"):
        return "\\\\" + p[8:]
    if p.startswith("\\\\?\\"):
        return p[4:]
    return p


def to_display_path(p: str) -> str:
    """折叠为 ``%APPDATA%\\...`` 形式，便于 UI 展示。"""
    if not p:
        return ""
    ap = to_absolute(p)
    ap_key = os.path.normcase(ap)
    best_var = ""
    best_val = ""
    for var in _DISPLAY_ENV_VARS:
        val = expand_env(f"%{var}%")
        if not val:
            continue
        val_abs = to_absolute(val)
        val_key = os.path.normcase(val_abs)
        if ap_key == val_key:
            return f"%{var}%"
        if ap_key.startswith(val_key.rstrip(os.sep) + os.sep) and len(val_abs) > len(best_val):
            best_var, best_val = var, val_abs
    if best_var:
        return f"%{best_var}%" + ap[len(best_val):]
    return ap


def is_reparse_point(target: "str | os.DirEntry[str]") -> bool:
    """判断目标是否为重解析点（符号链接 / 目录联接 junction / 挂载点）。

    Windows 上 ``DirEntry.is_symlink()`` 对 **junction 返回 False**（junction 不是
    符号链接），因此仅靠 ``is_symlink()`` 会把 junction 当普通目录递归，造成
    **重复计数**（架构约定：跳过符号链接与挂载点）。本函数通过
    ``st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT`` 一并识别二者。

    Args:
        target: 绝对路径字符串，或 :class:`os.DirEntry` 对象。

    Returns:
        ``True`` 表示应跳过；属性查询失败时按非重解析点处理（不阻断流程）。
    """
    try:
        if isinstance(target, os.DirEntry):
            stat_result = target.stat(follow_symlinks=False)
        else:
            stat_result = os.lstat(to_long_path(str(target)))
    except (OSError, ValueError):
        return False
    attrs = getattr(stat_result, "st_file_attributes", 0)
    try:
        return bool(int(attrs) & FILE_ATTRIBUTE_REPARSE_POINT)
    except (TypeError, ValueError):
        return False


def _local_host_names() -> set[str]:
    """返回可指代本机的主机名集合（小写，进程内缓存）。"""
    global _LOCAL_HOST_NAMES
    if _LOCAL_HOST_NAMES is None:
        names = {"localhost", "127.0.0.1", "::1", "."}
        try:
            names.add(str(socket.gethostname() or "").lower())
            names.add(str(socket.getfqdn() or "").lower())
        except OSError:
            pass
        names.add(str(os.environ.get("COMPUTERNAME") or "").lower())
        names.discard("")
        _LOCAL_HOST_NAMES = names
    return _LOCAL_HOST_NAMES


def _strip_device_prefix(p: str) -> str:
    """剥离 ``\\\\?\\`` / ``\\\\.\\`` 设备路径前缀（含 ``\\\\?\\UNC\\``）。

    Python 的 ``ntpath.normpath/abspath`` 对设备路径**拒绝规范化**（原样返回），
    若不剥离，``\\\\?\\C:\\Windows`` 永远无法与黑名单条目 ``C:\\Windows`` 匹配，
    从而成为绕过通道；安全判定前必须先调用本函数。
    """
    if not p:
        return p
    s = str(p)
    lead = 0
    while lead < len(s) and s[lead] in "\\/":
        lead += 1
    if lead < 2:
        return s  # 本地路径或盘符相对路径，原样返回
    rest = s[lead:]
    if rest[:1] in ("?", "."):
        # \\?\C:\x / \\.\C:\x / \\?\UNC\server\share（含多余分隔符写法）
        rest = rest[1:].lstrip("\\/")
        if rest[:3].upper() == "UNC" and rest[3:4] in ("\\", "/"):
            return "\\\\" + rest[4:]
        return rest
    return "\\\\" + rest  # 普通 UNC 路径


def _resolve_admin_share(p: str) -> str:
    """把管理共享还原为本地路径：``\\\\host\\C$\\x`` → ``C:\\x``。

    经 ``C$`` / ``ADMIN$`` 一类管理共享可直达系统目录，若不还原，
    ``\\\\localhost\\C$\\Windows`` 将无法命中 ``C:\\Windows`` 黑名单条目。

    本工具只处理本机数据，**任何主机**的单字母盘符共享（``C$``）与 ``ADMIN$``
    都按本地盘还原后再判定——即便目标确实指向网络主机，判定结果也更保守
    （宁可拦截，不可放行）。
    """
    if not p.startswith("\\\\"):
        return p
    parts = [seg for seg in p[2:].split("\\") if seg]
    if len(parts) < 2:
        return p
    share = parts[1]
    tail = "\\".join(parts[2:])
    if len(share) == 2 and share[0].isalpha() and share[1] == "$":
        base = share[0].upper() + ":\\"
        return base + tail if tail else base
    if share.upper() == "ADMIN$":
        base = to_absolute(expand_env(r"%WINDIR%") or r"C:\Windows")
        return os.path.join(base, tail) if tail else base
    return p


def normalize_for_safety(p: str) -> str:
    """**安全专用**归一化：剥离设备前缀 → 还原本机管理共享 → 展开 8.3 短名。

    与 :func:`to_absolute` 的区别：本函数专供黑名单等安全判定使用，会主动消除
    一切可用于绕过判定的等价写法（``\\\\?\\``、``\\\\.\\``、多余前导分隔符、
    本机管理共享、``C:\\PROGRA~1`` 一类 8.3 短名）；展示与持久化仍应使用
    ``to_absolute``，避免改变既有语义。

    Returns:
        可用于前缀比较的规范化路径（``normcase`` 小写）；无法解析时返回空串。
    """
    if not p or not str(p).strip():
        return ""
    s = expand_env(str(p)).strip()
    s = _strip_device_prefix(s)
    s = _resolve_admin_share(s)
    if "~" in s:
        # 仅在可能出现 8.3 短名时才展开，避免全量 realpath 开销
        try:
            real = os.path.realpath(s)
            if real:
                s = real
        except OSError:
            pass
    try:
        return os.path.normcase(os.path.normpath(os.path.abspath(s)))
    except (OSError, ValueError):
        return ""


def is_subpath(child: str, parent: str) -> bool:
    """判断 ``child`` 是否位于 ``parent`` 之下（严格子路径）。"""
    if not child or not parent:
        return False
    c = normalize_for_safety(child)
    p = normalize_for_safety(parent).rstrip(os.sep)
    if not c or not p:
        return False
    if not p.endswith(os.sep) and len(p) == 2 and p[1] == ":":
        p += os.sep
    return c.startswith(p + os.sep)


def safe_join_name(name: str, fallback: str = "unnamed") -> str:
    """把任意字符串清洗为安全的单层目录名（用于 zip 内部路径，防 zip-slip）。

    Args:
        name: 原始名称（如软件名）。
        fallback: 清洗后为空时使用的兜底名称。

    Returns:
        不含盘符、路径分隔符、``..`` 与非法字符的安全名称。
    """
    cleaned = "".join(ch for ch in (name or "").strip() if ch not in '\\/:*?"<>|')
    cleaned = cleaned.replace("..", ".").strip().rstrip(".")
    return cleaned or fallback


# --------------------------------------------------------------------------
# 系统关键目录黑名单
# --------------------------------------------------------------------------


def _build_blacklist() -> list[tuple[str, bool, str]]:
    """构建黑名单条目列表。

    Returns:
        ``(绝对路径, 是否允许子项, 拦截原因)`` 三元组列表。
        ``是否允许子项=True`` 表示仅本体被拦截（如 ``C:\\Program Files`` 本体，
        其下的软件目录可正常操作）。
    """
    win_dir = to_absolute(expand_env(r"%WINDIR%") or r"C:\Windows")
    sys_root = to_absolute(expand_env(r"%SYSTEMROOT%") or win_dir)
    pf = to_absolute(expand_env(r"%PROGRAMFILES%") or r"C:\Program Files")
    pf86 = to_absolute(expand_env(r"%PROGRAMFILES(X86)%") or r"C:\Program Files (x86)")
    programdata = to_absolute(expand_env(r"%PROGRAMDATA%") or r"C:\ProgramData")
    profile = to_absolute(expand_env(r"%USERPROFILE%") or "")
    public = to_absolute(expand_env(r"%PUBLIC%") or r"C:\Users\Public")
    localappdata = to_absolute(expand_env(r"%LOCALAPPDATA%") or "")
    users_dir = os.path.dirname(profile) if profile else os.path.dirname(win_dir)
    drive = (os.path.splitdrive(profile or win_dir)[0] + os.sep) or "C:\\"

    specs: list[tuple[str, bool, str]] = [
        (win_dir, False, "系统保护目录（Windows 安装目录），禁止删除"),
        (sys_root, False, "系统保护目录（SystemRoot），禁止删除"),
        (os.path.join(win_dir, "System32"), False, "系统保护目录（System32），禁止删除"),
        (os.path.join(win_dir, "SysWOW64"), False, "系统保护目录（SysWOW64），禁止删除"),
        (os.path.join(win_dir, "WinSxS"), False, "系统保护目录（WinSxS），禁止删除"),
        (os.path.join(win_dir, "SystemApps"), False, "系统保护目录（SystemApps），禁止删除"),
        (pf, True, "Program Files 本体不可删除（其下软件目录可操作）"),
        (pf86, True, "Program Files (x86) 本体不可删除（其下软件目录可操作）"),
        (programdata, True, "ProgramData 本体不可删除（其下软件目录可操作）"),
        (os.path.join(users_dir, "Default"), True, "系统默认用户配置目录，本体不可删除"),
        # users_dir 本体（C:\Users）必须与 Program Files / ProgramData 口径一致地保护：
        # 缺失该条目时，删除 C:\Users 会摧毁全部用户配置文件（含短名形式 C:\DOCUME~1）
        (users_dir, True, "用户目录本体不可删除（其下各用户配置目录可操作）"),
        (public, True, "公共用户目录本体不可删除"),
        (profile, True, "当前用户主目录本体不可删除"),
        (drive, True, "磁盘根目录不可删除"),
        (os.path.join(localappdata, "Microsoft", "Windows"), False, "系统组件目录，禁止删除"),
        (os.path.join(localappdata, "Microsoft", "WindowsApps"), False, "系统组件目录，禁止删除"),
        (os.path.join(localappdata, "Packages"), False, "系统组件目录（MSIX 容器），禁止删除"),
    ]
    result: list[tuple[str, bool, str]] = []
    for p, allow_children, reason in specs:
        if not p:
            continue
        ap = to_absolute(p)
        if ap and (ap, allow_children, reason) not in result:
            result.append((ap, allow_children, reason))
    return result


def get_blacklist() -> list[tuple[str, bool, str]]:
    """返回黑名单条目（进程内缓存）。"""
    global _BLACKLIST_CACHE
    if _BLACKLIST_CACHE is None:
        _BLACKLIST_CACHE = _build_blacklist()
    return _BLACKLIST_CACHE


def check_path_safety(p: str) -> SafetyVerdict:
    """判定路径是否允许执行删除等危险操作。

    安全判定统一使用 :func:`normalize_for_safety`，先剥离 ``\\\\?\\`` / ``\\\\.\\``
    设备前缀、还原本机管理共享、展开 8.3 短名，再与黑名单做前缀比较，
    避免出现"换一种写法就能绕过黑名单"的通道。

    Args:
        p: 待判定的绝对路径（也可以是含环境变量的路径）。

    Returns:
        :class:`SafetyVerdict`；``allowed=False`` 时携带中文拦截原因。
    """
    if not p or not str(p).strip():
        return SafetyVerdict(False, "路径为空，已拒绝操作")
    target = normalize_for_safety(p)
    if not target:
        return SafetyVerdict(False, "路径无法解析，已拒绝操作")
    if target.startswith("\\\\"):
        if not target[2:].split("\\", 1)[0]:
            return SafetyVerdict(False, "无法解析的 UNC 路径，已拒绝操作")
    elif not os.path.splitdrive(target)[0]:
        return SafetyVerdict(False, "无法解析的设备路径（如 \\\\?\\GLOBALROOT\\...），已拒绝操作")

    for root, allow_children, reason in get_blacklist():
        rk = normalize_for_safety(root)
        if not rk:
            continue
        if target == rk:
            return SafetyVerdict(False, reason)
        if rk.endswith(os.sep):
            # 盘根一类以分隔符结尾的条目：只拦截本体
            continue
        if target.startswith(rk + os.sep):
            if allow_children:
                continue
            return SafetyVerdict(False, reason)
    return SafetyVerdict(True, "")


def mark_entry_safety(entry_path: str) -> tuple[bool, str]:
    """便捷接口：返回 ``(是否安全, 拦截原因)`` 二元组。"""
    verdict = check_path_safety(entry_path)
    return verdict.allowed, verdict.reason
