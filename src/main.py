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

from PySide6.QtCore import Qt
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


def main() -> int:
    """启动应用主循环。

    Returns:
        进程退出码（0 表示正常退出）。
    """
    dirs = config_mod.get_app_dirs(create=True)
    logger = setup_logging(dirs["logs"])
    logger.info("应用启动：%s v%s（Python %s）", __app_name__, __version__, sys.version.split()[0])

    app = _build_application(sys.argv)
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

    code = app.exec()
    logger.info("应用退出，退出码 %d", code)
    return int(code)


if __name__ == "__main__":
    sys.exit(main())
