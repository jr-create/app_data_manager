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
                package = self._msix_package_name(sw)
                if not package:
                    return ""
                return (
                    'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass '
                    f'-Command "Remove-AppxPackage -Package {package}"'
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
    def _msix_package_name(sw: InstalledSoftware) -> str:
        """取 MSIX 包全名（``PackageFullName``）。"""
        if sw.id.startswith("msix:"):
            return sw.id[len("msix:"):].strip()
        return sw.package_family_name.strip()

    @staticmethod
    def split_command(command: str) -> list[str]:
        """把命令字符串切分为参数列表（兼容带引号的 Windows 路径）。"""
        if not command:
            return []
        try:
            parts = shlex.split(command, posix=False)
        except ValueError:
            parts = [command]
        # posix=False 时 shlex 会原样保留 Windows 路径中的反斜杠，无需额外还原
        if not parts:
            return []
        # 若首段是 powershell 且后续被错误合并，交给 subprocess 原样执行
        return parts

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
            completed = subprocess.run(
                args,
                shell=False,
                timeout=limit,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
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
        report.stdout = (completed.stdout or "")[:2000]
        report.stderr = (completed.stderr or "")[:2000]
        report.success = report.exit_code == 0
        if not report.success:
            report.error = f"卸载程序返回非零退出码 {report.exit_code}"
            if not deleter_mod.is_admin():
                report.error += "（当前非管理员权限，建议以管理员身份重试）"
        logger.info("卸载 %s：退出码 %d，用时 %.1f 秒", sw.name, report.exit_code, report.elapsed_sec)
        return report

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
