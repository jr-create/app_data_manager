#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""软件数据迁移助手 —— 一键启动脚本。

职责：
    1. 把项目根目录加入 ``sys.path``，保证 ``src`` 包可被导入；
    2. 校验 Python 版本与 PySide6 依赖是否就绪，缺依赖时给出中文提示；
    3. 调用 ``src.main.main()`` 启动图形界面，并捕获启动期异常。

用法::

    python run.py
"""

from __future__ import annotations

import os
import sys
import traceback

#: 项目根目录（本文件所在目录）
PROJECT_ROOT: str = os.path.dirname(os.path.abspath(__file__))

#: 最低 Python 版本要求
MIN_PYTHON: tuple[int, int] = (3, 10)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

#: 冻结（PyInstaller --windowed）模式下，stdout/stderr 会被引导器重定向到管道；
#: 若 Python 侧（日志 / 三方库）持续写入，引导器的复制线程可能阻塞，导致进程退出挂起。
#: 窗口程序本就无控制台，这里在入口处将二者重定向到 nul，确保打包产物可干净退出。
if getattr(sys, "frozen", False):
    try:
        sys.stdout = open(os.devnull, "w")
        sys.stderr = open(os.devnull, "w")
    except OSError:
        pass


def check_python() -> None:
    """校验当前解释器版本是否满足最低要求。

    Raises:
        SystemExit: 版本过低时直接退出进程。
    """
    if sys.version_info < MIN_PYTHON:
        need = ".".join(str(v) for v in MIN_PYTHON)
        cur = ".".join(str(v) for v in sys.version_info[:3])
        print(f"[错误] Python 版本过低：需要 {need} 及以上，当前为 {cur}")
        print("       请改用满足要求的解释器，例如：")
        print(r"       C:\Users\seer\.workbuddy\binaries\python\envs\default\Scripts\python.exe run.py")
        raise SystemExit(1)


def check_pyside6() -> None:
    """校验 PySide6 是否已安装。

    Raises:
        SystemExit: 未安装时打印安装指引并退出。
    """
    try:
        import PySide6  # noqa: F401  仅用于探测依赖是否可用
    except ImportError:
        print("[错误] 未检测到依赖包 PySide6。请先安装：")
        print("       pip install PySide6-Essentials==6.8.3")
        print("       或参考同目录下的 requirements.txt。")
        raise SystemExit(1)


def check_platform() -> None:
    """在非 Windows 平台上给出明确警告（本工具 MVP 仅支持 Windows）。"""
    if not sys.platform.startswith("win"):
        print(f"[警告] 当前平台为 {sys.platform}，本工具 MVP 仅支持 Windows 10/11，"
              "注册表扫描与 MSIX 扫描将不可用。")


def main() -> int:
    """启动应用，返回进程退出码。"""
    check_python()
    check_platform()
    check_pyside6()

    try:
        from src.main import main as app_main
    except Exception:  # pragma: no cover - 启动期兜底
        print("[错误] 导入应用主模块失败，详细堆栈如下：")
        traceback.print_exc()
        return 1

    try:
        return int(app_main() or 0)
    except Exception:  # pragma: no cover - 运行期兜底
        print("[错误] 应用运行期发生未捕获异常，详细堆栈如下：")
        traceback.print_exc()
        return 2


if __name__ == "__main__":
    sys.exit(main())
