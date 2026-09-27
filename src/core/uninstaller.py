# -*- coding: utf-8 -*-
"""调用官方卸载程序（L3）：解析卸载命令、拼装静默参数、超时控制、MSIX 走 PowerShell。"""

from __future__ import annotations

import logging
import os
import shlex
import subprocess
import time
from typing import Sequence

from . import deleter as deleter_mod
from .models import InstalledSoftware, SoftwareSource, UninstallReport

logger = logging.getLogger("uninstall")

#: 默认卸载超时（秒）
DEFAULT_TIMEOUT: int = 300

#: 已包含静默语义的参数（避免重复追加）
_QUIET_MARKERS: tuple[str, ...] = (
    "/quiet", "-quiet", "/qn", "-qn", "/s", "-s", "/silent", "-silent",
    "/verysilent", "-verysilent", "/passive", "--silent", "/s /v", "-q",
)


def _decode_output(data: bytes | None) -> str:
    """把子进程输出按 utf-8 → cp936 顺序尝试解码（PowerShell 中文输出为 GBK，
    纯 utf-8 解码会得到乱码甚至令读取线程崩溃）。"""
    if not data:
        return ""
    for enc in ("utf-8", "cp936"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


class Uninstaller:
    """官方卸载程序调用器。"""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT) -> None:
        """初始化。

        Args:
            timeout: 默认超时秒数。
        """
        self.timeout: int = int(timeout)

    # ---- 命令构造 ----

    @staticmethod
    def _is_msi(command: str) -> bool:
        """判断命令是否为 msiexec 调用。"""
        return command.strip().lower().lstrip('"').startswith(("msiexec", "msiexec.exe"))

    def build_command(self, sw: InstalledSoftware, quiet: bool = True) -> str:
        """构造卸载命令字符串（供预览与实际执行）。

        Args:
            sw: 目标软件。
            quiet: 是否静默卸载。

        Returns:
            可执行的命令字符串；无可用卸载命令时返回空字符串。
        """
        if sw.source == SoftwareSource.MSIX or (not sw.uninstall_string and not sw.quiet_uninstall_string):
            if sw.package_family_name or sw.id.startswith("msix:"):
                query = self._msix_selector(sw)
                if not query:
                    return ""
                return (
                    'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass '
                    f'-Command "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; '
                    f'{query} | Remove-AppxPackage -ErrorAction Stop"'
                )
            return ""

        command = ""
        if quiet and sw.quiet_uninstall_string:
            command = sw.quiet_uninstall_string.strip()
        elif sw.uninstall_string:
            command = sw.uninstall_string.strip()
        elif sw.quiet_uninstall_string:
            command = sw.quiet_uninstall_string.strip()
        if not command:
            return ""

        lower = command.lower()
        if quiet:
            if self._is_msi(command):
                if "/quiet" not in lower and "/qn" not in lower and "/passive" not in lower:
                    command += " /quiet"
                if "/norestart" not in lower:
                    command += " /norestart"
            elif not any(marker in lower for marker in _QUIET_MARKERS):
                command += " /S"
        return command

    @staticmethod
    def _msix_selector(sw: InstalledSoftware) -> str:
        """构造 ``Get-AppxPackage`` 查询段（管道前的部分）。

        优先按 ``PackageFamilyName`` 过滤（版本无关——商店应用自动更新后
        ``PackageFullName`` 中的版本号会变化，旧全名会匹配失败）。
        注意：Windows PowerShell 5.1 的 ``Get-AppxPackage`` **没有**
        ``-PackageFamilyName`` 参数（实测踩坑），故用 ``Where-Object`` 过滤。

        Returns:
            形如 ``Get-AppxPackage | Where-Object PackageFamilyName -eq 'xxx'``
            的查询段；无法确定时返回空串。
        """
        family = sw.package_family_name.strip()
        if family:
            return f"Get-AppxPackage | Where-Object PackageFamilyName -eq '{family}'"
        name = ""
        if sw.id.startswith("msix:"):
            name = sw.id[len("msix:"):].strip()
        if not name:
            name = sw.name.strip()
        if not name:
            return ""
        return f"Get-AppxPackage -Name '{name}'"

    @staticmethod
    def _strip_outer_quotes(part: str) -> str:
        """剥离参数首尾对称的一层引号（``shlex.split(posix=False)`` 会原样保留）。"""
        if len(part) >= 2 and part[0] == part[-1] and part[0] in ('"', "'"):
            return part[1:-1]
        return part

    @staticmethod
    def split_command(command: str) -> list[str]:
        """把命令字符串切分为参数列表（兼容带引号的 Windows 路径）。

        关键：必须剥离参数首尾的包裹引号。否则形如
        ``powershell -Command "Remove-AppxPackage ..."`` 的命令会把**带引号的
        字符串**传给 ``-Command``，PowerShell 将其当作字符串字面量**回显而非执行**，
        进程退出码仍为 0 —— 造成"卸载成功"的假象（实测踩坑）。
        """
        if not command:
            return []
        try:
            parts = shlex.split(command, posix=False)
        except ValueError:
            parts = [command]
        # posix=False 时 shlex 会原样保留 Windows 路径中的反斜杠与包裹引号；
        # 反斜杠保留是需要的，包裹引号则必须剥掉（subprocess 会按需重新加引号）。
        return [Uninstaller._strip_outer_quotes(p) for p in parts if p]

    # ---- 执行 ----

    def uninstall(
        self,
        sw: InstalledSoftware,
        quiet: bool = True,
        timeout: int | None = None,
        all_users: bool = False,
    ) -> UninstallReport:
        """执行卸载。

        Args:
            sw: 目标软件。
            quiet: 是否静默卸载。
            timeout: 超时秒数；``None`` 时用实例默认值。
            all_users: MSIX 卸载是否针对所有用户（需管理员）。

        Returns:
            :class:`UninstallReport`。
        """
        report = UninstallReport()
        command = self.build_command(sw, quiet=quiet)
        if all_users and sw.source == SoftwareSource.MSIX and command:
            command = command.replace("Remove-AppxPackage", "Remove-AppxPackage -AllUsers")
        report.command = command
        if not command:
            report.error = "未找到可用的卸载命令（注册表无 UninstallString）"
            return report

        args = self.split_command(command)
        limit = int(timeout or self.timeout)
        started = time.perf_counter()
        try:
            # 字节捕获：PowerShell 等程序的控制台输出编码是 GBK，直接以 utf-8
            # 文本模式读取会乱码/解码异常，统一改为字节捕获后按序解码。
            completed = subprocess.run(
                args,
                shell=False,
                timeout=limit,
                capture_output=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except FileNotFoundError as exc:
            report.elapsed_sec = time.perf_counter() - started
            report.error = f"卸载程序不存在或已损坏：{exc}"
            logger.error("卸载失败：%s", report.error)
            return report
        except subprocess.TimeoutExpired:
            report.elapsed_sec = time.perf_counter() - started
            report.error = f"卸载超时（超过 {limit} 秒），请手动确认卸载结果"
            logger.error("卸载超时：%s", sw.name)
            return report
        except OSError as exc:
            report.elapsed_sec = time.perf_counter() - started
            report.error = f"卸载调用失败（可能需要管理员权限）：{exc}"
            logger.error("卸载调用失败：%s", exc)
            return report
        except PermissionError as exc:
            report.elapsed_sec = time.perf_counter() - started
            report.error = f"权限不足，无法启动卸载程序：{exc}"
            return report

        report.elapsed_sec = time.perf_counter() - started
        report.exit_code = int(completed.returncode)
        report.stdout = _decode_output(completed.stdout)[:2000]
        report.stderr = _decode_output(completed.stderr)[:2000]
        report.success = report.exit_code == 0
        if not report.success:
            report.error = f"卸载程序返回非零退出码 {report.exit_code}"
            if not deleter_mod.is_admin():
                report.error += "（当前非管理员权限，建议以管理员身份重试）"
            logger.info("卸载 %s：退出码 %d，用时 %.1f 秒", sw.name, report.exit_code, report.elapsed_sec)
            return report

        # MSIX 专项：卸载命令退出码 0 不代表真的卸载了（PowerShell 非终止性错误 /
        # 空管道均为 0）。执行后回查包是否仍存在，仍存在则如实报失败。
        if sw.source == SoftwareSource.MSIX:
            still_there, verify_err = self._verify_msix_removed(sw)
            if still_there is None:
                report.success = False
                report.error = f"卸载后验证失败，无法确认结果：{verify_err}"
            elif still_there:
                report.success = False
                hint = "" if deleter_mod.is_admin() else "（当前非管理员权限，建议以管理员身份重试）"
                report.error = f"卸载命令已执行，但应用仍安装在系统中，可能需要管理员权限或包名已变更{hint}"
                logger.warning("MSIX 卸载验证失败：%s 仍存在", sw.name)
            else:
                logger.info("MSIX 卸载验证通过：%s 已移除", sw.name)
        logger.info("卸载 %s：退出码 %d，用时 %.1f 秒", sw.name, report.exit_code, report.elapsed_sec)
        return report

    def _verify_msix_removed(self, sw: InstalledSoftware) -> tuple[bool | None, str]:
        """回查 MSIX 包是否已从系统中移除。

        Returns:
            ``(still_installed, error)``：``still_installed`` 为 ``True``/``False``
            表示确认仍在/已移除；``None`` 表示验证本身失败（``error`` 给出原因）。
        """
        query = self._msix_selector(sw)
        if not query:
            return None, "无包名可供验证"
        # 直接构造参数列表，彻底绕开命令串引号问题
        args = [
            "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-Command",
            f"[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
            f"if ({query}) {{ Write-Output STILL_INSTALLED }} "
            f"else {{ Write-Output REMOVED }}",
        ]
        try:
            completed = subprocess.run(
                args,
                shell=False,
                timeout=min(self.timeout, 60),
                capture_output=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return None, str(exc)
        out = _decode_output(completed.stdout).strip().upper()
        err = _decode_output(completed.stderr)
        if completed.returncode != 0:
            return None, f"验证命令退出码 {completed.returncode}：{err[:300]}"
        if "STILL_INSTALLED" in out:
            return True, ""
        if "REMOVED" in out:
            return False, ""
        return None, f"验证输出无法识别：{out[:300]}"

    # ---- P2-2 扩展位 ----

    def clean_registry(self, sw: InstalledSoftware) -> None:
        """卸载后注册表残留清理（P2-2）。

        Raises:
            NotImplementedError: 高风险能力，默认关闭（``AppConfig.expert_mode``），MVP 不实现。
        """
        raise NotImplementedError("P2-2 注册表残留清理：需专家模式，MVP 不实现")

    # ---- 辅助 ----

    @staticmethod
    def describe(sw: InstalledSoftware) -> str:
        """返回卸载方式的人类可读描述（供对话框展示）。"""
        if sw.source == SoftwareSource.MSIX:
            return "Microsoft Store 应用（PowerShell Remove-AppxPackage）"
        if sw.quiet_uninstall_string:
            return "静默卸载（QuietUninstallString 可用）"
        if sw.uninstall_string:
            return "标准卸载（UninstallString）"
        return "无可用卸载命令"

    def build_commands(self, sw: InstalledSoftware) -> Sequence[str]:
        """返回 ``(静默命令, 标准命令)`` 二元组，便于对话框切换展示。"""
        return (self.build_command(sw, quiet=True), self.build_command(sw, quiet=False))
