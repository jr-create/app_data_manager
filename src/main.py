# -*- coding: utf-8 -*-
"""应用入口（L5）：QApplication 初始化、全局异常钩子、主窗口装配。

用法::

    python run.py          # 由启动脚本调用
    python -m src.main     # 亦可直接以模块方式启动
"""

from __future__ import annotations

import os
import sys
import traceback

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication, QMessageBox

from . import __app_name__, __version__
from .core import config as config_mod
from .core.utils import setup_logging

#: 高 DPI 缩放策略（Qt6 默认已开启高 DPI，此处仅关闭像素取整带来的模糊）
_QT_HIGH_DPI_POLICY = getattr(Qt, "HighDpiScaleFactorRoundingPolicy", None)


def _build_application(argv: list[str]) -> QApplication:
    """创建并配置 QApplication。

    Args:
        argv: 命令行参数列表。

    Returns:
        已配置中文字体与应用元信息的 QApplication 实例。
    """
    if _QT_HIGH_DPI_POLICY is not None:
        try:
            QApplication.setHighDpiScaleFactorRoundingPolicy(
                _QT_HIGH_DPI_POLICY.PassThrough
            )
        except Exception:
            pass

    app = QApplication(argv)
    app.setApplicationName(__app_name__)
    app.setApplicationDisplayName(f"{__app_name__} v{__version__}")
    app.setOrganizationName("SoftwareDataMigrator")

    # 中文字体：优先微软雅黑，缺失时回退到系统默认
    font = QFont("Microsoft YaHei UI", 9)
    if font.exactMatch():
        app.setFont(font)
    else:
        fallback = QFont("Microsoft YaHei", 9)
        app.setFont(fallback if fallback.exactMatch() else QFont())
    return app


def _install_excepthook(app: QApplication) -> None:
    """安装全局异常钩子：写日志 + 弹窗提示，避免静默崩溃。"""

    def handler(exc_type, exc_value, exc_tb) -> None:
        text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        sys.__excepthook__(exc_type, exc_value, exc_tb)
        try:
            QMessageBox.critical(
                None,
                "程序异常",
                f"发生未捕获异常，程序可能不稳定：\n{exc_value}\n\n详细信息已写入运行日志。",
            )
        except Exception:
            pass

    sys.excepthook = handler


def main(argv: list[str] | None = None) -> int:
    """启动应用主循环。

    Args:
        argv: 命令行参数列表；为空时回退到 ``sys.argv``。
            支持 ``--selftest``：仅初始化主窗口并展示，2 秒后自动退出，
            用于打包产物（exe）的自动化冒烟验证，不影响正常 GUI 使用。

    Returns:
        进程退出码（0 表示正常退出）。
    """
    argv = list(sys.argv if argv is None else argv)
    selftest = "--selftest" in argv

    dirs = config_mod.get_app_dirs(create=True)
    logger = setup_logging(dirs["logs"])
    logger.info("应用启动：%s v%s（Python %s）", __app_name__, __version__, sys.version.split()[0])

    app = _build_application(argv)
    _install_excepthook(app)

    cfg = config_mod.load_config()
    logger.info("配置已加载：数据根目录 %d 个，模糊阈值 %.2f", len(cfg.data_roots), cfg.fuzzy_threshold)

    try:
        from .ui.main_window import MainWindow  # 延迟导入，避免日志未就绪时报错被吞
    except Exception as exc:  # pragma: no cover - 防御性
        logger.exception("主窗口模块导入失败")
        QMessageBox.critical(None, "启动失败", f"界面模块加载失败：{exc}")
        return 1

    window = MainWindow(cfg)
    window.resize(cfg.window_width, cfg.window_height)
    window.show()
    logger.info("主窗口已显示")

    if selftest:
        # 自测模式：不进入人工交互，2 秒后由定时器自动退出。
        # 用于验证打包产物可正常初始化 GUI（PySide6 全部模块 / 扫描服务 import 均无误）。
        # 冻结（PyInstaller --windowed）环境下 QApplication 析构可能阻塞解释器关闭，
        # 故直接以退出码 0 终止进程，保证自测可干净退出。
        logger.info("自测模式：主窗口初始化成功，2 秒后自动退出")
        QTimer.singleShot(2000, app.quit)
        app.exec()
        logger.info("自测模式：已自动退出")
        logger.info("SELFTEST_ABOUT_TO_EXIT")  # 诊断哨兵：确认即将强制退出
        os._exit(0)

    code = app.exec()
    logger.info("应用退出，退出码 %d", code)
    # 与自测模式一致：冻结环境下强制退出，避免 GUI 关闭后进程残留。
    os._exit(int(code))


if __name__ == "__main__":
    sys.exit(main())
