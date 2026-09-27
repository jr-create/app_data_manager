# -*- coding: utf-8 -*-
"""应用配置与本地持久化（L1）。

配置目录固定为 ``%LOCALAPPDATA%\\SoftwareDataMigrator\\``，其下包含：
``config.json``（主配置）、``manual_attribution.json``（P1-4 手动指派）、
``cache/size_cache.json``（大小缓存）、``logs/``（运行与操作日志）。
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field

from . import paths
from .models import DeleteMode

# --------------------------------------------------------------------------
# 常量
# --------------------------------------------------------------------------

#: 本地数据目录名（位于 %LOCALAPPDATA% 下）
APP_DIR_NAME: str = "SoftwareDataMigrator"

#: 备份归档默认目录（A1 裁决）
DEFAULT_BACKUP_DIRNAME: str = r"%USERPROFILE%\Documents\SoftwareDataMigrator_Backups"

#: 大小缓存有效期（天）（A3 裁决）
SIZE_CACHE_TTL_DAYS: int = 7


def get_app_dirs(create: bool = True) -> dict[str, str]:
    """返回本地数据目录集合，可选自动创建。

    Returns:
        ``{"root","cache","logs"}`` 三个键的绝对路径字典。
    """
    base = os.path.join(paths.expand_env(r"%LOCALAPPDATA%") or os.path.expanduser("~"), APP_DIR_NAME)
    dirs = {
        "root": base,
        "cache": os.path.join(base, "cache"),
        "logs": os.path.join(base, "logs"),
    }
    if create:
        for d in dirs.values():
            try:
                os.makedirs(d, exist_ok=True)
            except OSError:
                pass
    return dirs


def get_config_path() -> str:
    """返回 ``config.json`` 路径。"""
    return os.path.join(get_app_dirs()["root"], "config.json")


def get_manual_overrides_path() -> str:
    """返回 ``manual_attribution.json`` 路径（P1-4）。"""
    return os.path.join(get_app_dirs()["root"], "manual_attribution.json")


def get_size_cache_path() -> str:
    """返回 ``cache/size_cache.json`` 路径。"""
    return os.path.join(get_app_dirs()["cache"], "size_cache.json")


def get_default_backup_dir() -> str:
    """返回备份归档默认存放目录。"""
    return paths.expand_env(DEFAULT_BACKUP_DIRNAME)


# --------------------------------------------------------------------------
# 配置模型
# --------------------------------------------------------------------------


@dataclass
class AppConfig:
    """应用配置。

    Attributes:
        data_roots: 用户数据根目录模板列表（形如 ``%APPDATA%``）。
        fuzzy_threshold: L5 模糊匹配的相似度阈值。
        exclude_cache_log: 备份时是否默认排除缓存与日志类路径。
        msix_all_users: MSIX 扫描是否包含所有用户（需管理员）。
        show_system_component: 是否显示系统组件条目。
        show_orphan: 是否展示"未识别"分组。
        allow_delete_orphan: 是否允许删除未识别分组的条目（A5 默认允许）。
        default_delete_mode: 默认删除策略。
        top_n: Top-N 视图条数。
        backup_dir: 备份归档默认目录；为空时用默认目录。
        expert_mode: 专家模式开关（P2-2 预留）。
        window_width / window_height: 主窗口尺寸记忆。
    """

    data_roots: list[str] = field(default_factory=lambda: [tpl for _, tpl in paths.DEFAULT_DATA_ROOTS])
    fuzzy_threshold: float = 0.75
    exclude_cache_log: bool = True
    msix_all_users: bool = False
    show_system_component: bool = False
    show_orphan: bool = True
    allow_delete_orphan: bool = True
    default_delete_mode: str = DeleteMode.BACKUP_THEN_DELETE.value
    top_n: int = 20
    backup_dir: str = ""
    expert_mode: bool = False
    window_width: int = 1280
    window_height: int = 800

    # ---- 派生属性 ----

    @property
    def delete_mode(self) -> DeleteMode:
        """返回删除策略枚举（遇到非法值时回退为默认策略）。"""
        try:
            return DeleteMode(self.default_delete_mode)
        except ValueError:
            return DeleteMode.BACKUP_THEN_DELETE

    @property
    def backup_dir_resolved(self) -> str:
        """返回实际可用的备份目录（含兜底）。"""
        return paths.to_absolute(self.backup_dir) if self.backup_dir else get_default_backup_dir()

    def resolved_data_roots(self) -> list[tuple[str, str]]:
        """把配置中的数据根目录模板解析为 ``(标识, 绝对路径)`` 列表。

        Returns:
            解析后的根目录列表；无法解析的模板会被跳过。
        """
        known: dict[str, str] = {tpl: key for key, tpl in paths.DEFAULT_DATA_ROOTS}
        result: list[tuple[str, str]] = []
        seen: set[str] = set()
        for tpl in self.data_roots:
            abs_path = paths.to_absolute(paths.expand_env(tpl))
            if not abs_path:
                continue
            key = os.path.normcase(abs_path)
            if key in seen:
                continue
            seen.add(key)
            result.append((known.get(tpl, paths.safe_join_name(os.path.basename(abs_path), "ROOT")), abs_path))
        return result

    # ---- 持久化 ----

    @classmethod
    def load(cls) -> "AppConfig":
        """从磁盘加载配置；文件缺失或损坏时返回默认配置。"""
        file_path = get_config_path()
        if not os.path.isfile(file_path):
            return cls()
        try:
            with open(file_path, "r", encoding="utf-8") as fp:
                data = json.load(fp)
        except (OSError, json.JSONDecodeError):
            return cls()
        if not isinstance(data, dict):
            return cls()
        valid = {f for f in cls().__dataclass_fields__}
        kwargs = {k: v for k, v in data.items() if k in valid}
        cfg = cls(**kwargs)
        # 类型兜底校正，避免手工编辑 config.json 导致运行期异常
        if not isinstance(cfg.data_roots, list) or not cfg.data_roots:
            cfg.data_roots = [tpl for _, tpl in paths.DEFAULT_DATA_ROOTS]
        try:
            cfg.fuzzy_threshold = float(cfg.fuzzy_threshold)
        except (TypeError, ValueError):
            cfg.fuzzy_threshold = 0.75
        try:
            cfg.top_n = int(cfg.top_n)
        except (TypeError, ValueError):
            cfg.top_n = 20
        return cfg

    def save(self) -> None:
        """写入配置到磁盘（目录不存在时自动创建）。"""
        file_path = get_config_path()
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as fp:
                json.dump(asdict(self), fp, ensure_ascii=False, indent=2)
        except OSError as exc:
            raise RuntimeError(f"配置写入失败：{exc}") from exc


# --------------------------------------------------------------------------
# 模块级便捷函数
# --------------------------------------------------------------------------


def load_config() -> AppConfig:
    """加载应用配置（模块级便捷函数）。"""
    return AppConfig.load()


def save_config(cfg: AppConfig) -> None:
    """保存应用配置（模块级便捷函数）。"""
    cfg.save()


def load_manual_overrides() -> dict[str, str]:
    """加载手动指派映射 ``{条目路径: 软件 id}``（P1-4）。"""
    file_path = get_manual_overrides_path()
    if not os.path.isfile(file_path):
        return {}
    try:
        with open(file_path, "r", encoding="utf-8") as fp:
            data = json.load(fp)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items()}


def save_manual_overrides(overrides: dict[str, str]) -> None:
    """保存手动指派映射（P1-4）。"""
    file_path = get_manual_overrides_path()
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as fp:
            json.dump(overrides, fp, ensure_ascii=False, indent=2)
    except OSError as exc:
        raise RuntimeError(f"手动指派写入失败：{exc}") from exc


def load_size_cache() -> dict[str, dict]:
    """加载大小缓存 ``{路径: {"size","file_count","mtime","cached_at"}}``。"""
    file_path = get_size_cache_path()
    if not os.path.isfile(file_path):
        return {}
    try:
        with open(file_path, "r", encoding="utf-8") as fp:
            data = json.load(fp)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    import time as _time
    ttl = SIZE_CACHE_TTL_DAYS * 86400.0
    now = _time.time()
    result: dict[str, dict] = {}
    for key, value in data.items():
        if not isinstance(value, dict):
            continue
        cached_at = float(value.get("cached_at", 0) or 0)
        if cached_at and now - cached_at > ttl:
            continue  # A3：7 天 TTL 失效
        result[str(key)] = value
    return result


def save_size_cache(cache: dict[str, dict]) -> None:
    """写入大小缓存。"""
    file_path = get_size_cache_path()
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as fp:
            json.dump(cache, fp, ensure_ascii=False)
    except OSError:
        pass
