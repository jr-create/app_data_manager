# -*- coding: utf-8 -*-
"""UI 层（L5）：PySide6 控件、对话框与后台 Worker。

铁律：
    * 只有主线程可以创建/修改 QWidget 与数据模型；
    * core 层禁止出现任何 PySide6 导入，UI 层单向依赖 core。
"""
