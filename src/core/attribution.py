# -*- coding: utf-8 -*-
"""路径 → 软件 归属推断引擎（L2，核心难点）。

采用**分级规则 L1→L6 命中即停** + **归一化倒排索引**（先召回 ≤20 个候选软件，
再算相似度），避免 O(N×M) 全量 difflib，保证 300 软件 × 2000 目录在 3 秒内完成。
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field

from . import paths
from .models import DataPathEntry, InstalledSoftware, MatchLevel
from .utils import normalize_name, similarity, tokenize

logger = logging.getLogger("scan.attribution")

# --------------------------------------------------------------------------
# 置信度基线常量
# --------------------------------------------------------------------------

#: L1 精确名匹配置信度
CONF_L1: float = 1.00
#: L2 发布商匹配置信度
CONF_L2: float = 0.90
#: L3 安装路径反查置信度
CONF_L3: float = 0.95
#: L4 可执行文件名 / 包族名匹配置信度
CONF_L4: float = 0.85
#: L5 子串命配置信度
CONF_L5_SUBSTR: float = 0.80
#: L5 相似度命中上限
CONF_L5_MAX: float = 0.85
#: L6 别名表置信度
CONF_L6: float = 0.80
#: 冲突裁决阈值：次高与最高差值小于该值时标记为冲突
CONFLICT_DELTA: float = 0.05
#: L5 召回的候选软件上限
MAX_CANDIDATES: int = 20
#: 判定为"泛发布商目录"的软件数下限：共享同一发布商的软件达到该数量时，
#: 目录（如 %APPDATA%\Microsoft）不应被单一软件独占，需标记为待确认
GENERIC_PUBLISHER_MIN: int = 4

#: **超通用发布商目录名**（归一化形式）：这类目录几乎必然是数十款软件共用
#: （如 %APPDATA%\Microsoft 下既有 Office 又有 Edge、VS Installer……），
#: 若按 L2 发布商规则归属给"恰好排第一"的那一款软件，会**误导用户整目录删除**。
#: 命中本集合的目录一律**不归属给单一软件**：降级为未识别，并把全部候选软件
#: 记入 ``conflict_ids`` 供 UI 提示"多软件共用，请手动确认"。
#:
#: 注：``baidu`` 一类虽是厂商名，但国内几乎只对应单一产品（百度网盘），
#: 且主理人要求 ``%APPDATA%\\baidu`` 必须能挂到百度网盘，故**不列入**。
GENERIC_DIR_NAMES: frozenset[str] = frozenset({
    "microsoft", "google", "tencent", "adobe", "apple", "oracle", "intel",
    "nvidia", "meta", "facebook", "amazon", "huawei", "alibaba", "bytedance",
    "xiaomi", "samsung", "sony", "ibm", "sap", "siemens", "kingsoft",
    "microsoftcorporation", "googleinc", "tencenttechnology",
})

# --------------------------------------------------------------------------
# 别名表（L6 兜底）：归一化软件名 -> 常见归一化目录名
#
# 说明：ALIAS_TABLE 收录英文键，ALIAS_TABLE_CN 收录**中文软件名 → 英文目录名**
# （国内软件普遍以中文注册 DisplayName，却在 %APPDATA% 下建英文目录，
# 只有中文键才能让「微信」命中 WeChat Files）。两张表在模块加载时合并，
# 并经 _build_alias_reverse 建立双向映射，因此中英文任一侧都能互相命中。
# --------------------------------------------------------------------------

#: 英文/拼音软件名 → 常见目录名
_ALIAS_TABLE_EN: dict[str, tuple[str, ...]] = {
    "visualstudiocode": ("code", "vscode", "vscodium", "codium", "visualstudiocode"),
    "microsoftvisualstudio": ("visualstudio", "vs2022", "vs2019", "vs2017", "microsoftvisualstudio"),
    "visualstudio": ("visualstudio", "vs", "microsoftvisualstudio"),
    "nodejs": ("npm", "nodejs", "node", "npmcache", "nvm"),
    "python": ("python", "python3", "pythons", "pip", "anaconda", "miniconda"),
    "anaconda": ("anaconda", "anaconda3", "miniconda", "conda"),
    "googlechrome": ("chrome", "googlechrome", "chromium", "chromebook"),
    "microsoftedge": ("edge", "msedge", "microsoftedge", "edgeupdate"),
    "mozillafirefox": ("firefox", "mozillafirefox", "mozilla"),
    "microsoftteams": ("msteams", "teams", "microsoftteams", "msteamsupdate"),
    "discord": ("discord", "discordptb", "discordcanary", "discorddevelopment"),
    "spotify": ("spotify", "spotifymusic"),
    "steam": ("steam", "steamapps", "valve"),
    "epicgames": ("epicgames", "epic", "unrealengine"),
    "git": ("git", "gitforwindows", "githubdesktop", "gitconfig", "gitkraken",
            "gitkrakencli"),
    "github": ("github", "githubdesktop", "gh"),
    "wget2": ("wget", "wget2"),
    "xmind": ("xmind", "mindjet"),
    "traecodecn": ("trae", "traecn", "traecode", "traecodecn", "traeaicc"),
    "workbuddy": ("workbuddy", "codebuddy", "genieworkbuddydesktopupdater"),
    "dockerdesktop": ("docker", "dockerdesktop", "dockersetting"),
    "dockdesktop": ("docker", "dockerdesktop"),
    "wechat": ("wechat", "wechatfiles", "tencentwechat", "wechatwin"),
    "qq": ("qq", "tencentqq", "qqmusic"),
    "tim": ("tim", "tencenttim"),
    "dingtalk": ("dingtalk", "dingding"),
    "feishu": ("feishu", "lark", "bytedance"),
    "wps": ("wps", "wpscloudfiles", "kingsoft", "wpsoffice"),
    "microsoftoffice": ("office", "microsoftoffice", "office16", "msocache"),
    "notepad": ("notepad", "notepadplusplus"),
    "7zip": ("7zip", "7-zip"),
    "vlcmediaplayer": ("vlc", "videolan"),
    "potplayer": ("potplayer", "potplayermini"),
    "obsstudio": ("obsstudio", "obs", "obs-studio"),
    "telegramdesktop": ("telegram", "telegramdesktop"),
    "thunder": ("thunder", "xunlei", "thundernetwork"),
    "baidunetdisk": ("baidunetdisk", "baidu", "baiduyun"),
    "aliyundrive": ("aliyundrive", "aliyun", "aDrive"),
    "postman": ("postman", "postmanagent"),
    "figma": ("figma", "figmadesktop"),
    "notion": ("notion", "notiondesktop"),
    "obsidian": ("obsidian",),
    "typora": ("typora",),
    "sublimetext": ("sublimetext", "sublimetext3", "sublime"),
    "jetbrains": ("jetbrains", "jetbrains toolbox", "toolbox"),
    "pycharm": ("pycharm", "pycharm20231", "pycharm20232", "pycharm20241"),
    "intellijidea": ("intellijidea", "idea", "ideaic"),
    "webstorm": ("webstorm",),
    "goland": ("goland",),
    "androidstudio": ("androidstudio", "android", "google"),
    "java": ("java", "jre", "jdk", "oracle"),
    "golang": ("go", "golang"),
    "rust": ("rust", "cargo", "rustup"),
    "nvidiacorporation": ("nvidia", "nvidiashare", "nvidia corporation"),
    "adobe": ("adobe", "adobeacrobat", "acrobar"),
    "acrobat": ("acrobat", "adobeacrobat", "acrobar"),
    "photoshop": ("photoshop", "adobephotoshop"),
    "everything": ("everything", "voidtools"),
    "everythingtoolbar": ("everythingtoolbar",),
    "powertoys": ("powertoys", "microsoftpowertoys"),
    "windowsterminal": ("windowsterminal", "terminal"),
    "powershell": ("powershell", "windowspowershell"),
    "wsl": ("wsl", "windowssubsystemforlinux", "ubuntu"),
    "vmware": ("vmware", "vmwareworkstation"),
    "virtualbox": ("virtualbox", "oraclevmvirtualbox"),
    "evernote": ("evernote",),
    "youdaodict": ("youdao", "youdaodict", "youdaonote"),
    "neteasemusic": ("neteasemusic", "cloudmusic"),
    "bilibili": ("bilibili", "bili"),
    "qbittorrent": ("qbittorrent",),
    "utorrent": ("utorrent", "utorrentweb"),
    "zotero": ("zotero",),
    "sumatra": ("sumatrapdf",),
    "clash": ("clash", "clashforwindows", "clashverge"),
    "wechatwork": ("wechatwork", "wxwork"),
    "tencentmeeting": ("tencentmeeting", "wemeet"),
    "zoom": ("zoom", "zoomus"),
    "larkshell": ("larkshell", "lark", "feishu"),
    "mongodbcompass": ("mongodbcompass", "mongodb"),
    "switchhosts": ("switchhosts", "switchhost"),
    "drawio": ("drawio", "draw io", "diagramsnet"),
    "claude": ("claude", "claudedesktop", "claudenest", "anthropic"),
    "cursor": ("cursor", "cursorai"),
    "chatgpt": ("chatgpt", "openai"),
    "windsurf": ("windsurf", "codeium"),
    "trae": ("trae", "traecn"),
    "orayclient": ("orayclient", "oray", "sunlogin", "awesun"),
    "geekuninstaller": ("geekuninstaller", "geek"),
    "winrar": ("winrar", "winrarx64"),
    "bandizip": ("bandizip",),
}

#: 中文软件名 → 常见英文目录名（M-3：此前中文名无法挂接英文别名表）
ALIAS_TABLE_CN: dict[str, tuple[str, ...]] = {
    "微信": ("wechat", "wechatfiles", "wechatwin", "tencentwechat", "wechatupdate"),
    "企业微信": ("wxwork", "wechatwork", "wecom"),
    "微信开发者工具": ("wechatwebdevtools", "wechatdevtools"),
    "qq": ("qq", "tencentqq", "qqnt", "qqfiles"),
    "qq音乐": ("qqmusic", "qqmusicx"),
    "腾讯会议": ("wemeet", "tencentmeeting"),
    "腾讯视频": ("qqlive", "tencentvideo", "tenvideo"),
    "腾讯文档": ("tencentdocs", "docsqq"),
    "钉钉": ("dingtalk", "dingding"),
    "飞书": ("feishu", "lark", "bytedance", "larkshell", "larkshellsingleton"),
    "百度网盘": ("baidu", "baidunetdisk", "baiduyun", "baiduyunguanjia",
                "baiduyunkernel", "bdpan"),
    "百度输入法": ("baiduinput", "bdinput", "baidupinyin"),
    "阿里云盘": ("aliyundrive", "aliyun", "adrive"),
    "迅雷": ("thunder", "xunlei", "thundernetwork", "xunleidownload"),
    "向日葵远程控制": ("awesun", "oray", "orayclient", "sunlogin"),
    "豆包": ("doubao", "doubaodesktop"),
    "wps office": ("wps", "kingsoft", "wpsoffice", "wpscloudfiles"),
    "wps": ("wps", "kingsoft", "wpsoffice", "wpscloudfiles"),
    "金山文档": ("kingsoft", "wps", "kdocs"),
    "网易云音乐": ("cloudmusic", "neteasemusic", "ncm"),
    "酷狗音乐": ("kugou", "kugoumusic"),
    "qq浏览器": ("qqbrowser",),
    "哔哩哔哩": ("bilibili", "bili", "biliwin"),
    "抖音": ("douyin", "aweme"),
    "剪映": ("jianyingpro", "capcut"),
    "有道词典": ("youdao", "youdaodict"),
    "有道笔记": ("youdaonote", "youdao"),
    "搜狗输入法": ("sogouinput", "sogou", "sougou"),
    "360安全卫士": ("360safe", "360sd", "qihoo"),
    "火绒安全软件": ("huorong", "sysdiag"),
    "网易邮箱大师": ("neteasemail", "mailmaster"),
    "微信读书": ("weread",),
    "美图秀秀": ("meitu", "xiuxiu"),
}


def _merge_alias_tables() -> dict[str, tuple[str, ...]]:
    """合并中英文别名表，并为中文名补建**反向**条目（英文目录名 ⇄ 中文软件名）。"""
    merged: dict[str, tuple[str, ...]] = {k: tuple(v) for k, v in _ALIAS_TABLE_EN.items()}
    for cn_name, dirs in ALIAS_TABLE_CN.items():
        key = normalize_name(cn_name)
        if not key:
            continue
        merged[key] = tuple(dict.fromkeys(merged.get(key, ()) + tuple(dirs)))
        for alias_name in dirs:
            dk = normalize_name(alias_name)
            if dk and cn_name not in merged.get(dk, ()):
                merged[dk] = tuple(merged.get(dk, ())) + (cn_name,)
    return merged


#: 合并后的最终别名表（键与值均为归一化名）
ALIAS_TABLE: dict[str, tuple[str, ...]] = _merge_alias_tables()


# --------------------------------------------------------------------------
# 匹配结果
# --------------------------------------------------------------------------


@dataclass
class Match:
    """单条归属匹配结果。

    Attributes:
        software_id: 命中的软件 id；``None`` 表示未识别。
        level: 命中级别。
        confidence: 置信度 0.0~1.0。
        is_fuzzy: 是否为模糊匹配（L5），UI 需提示"模糊匹配，请确认"。
        conflict_ids: 置信度接近的竞争软件 id 列表（存在冲突）。
    """

    software_id: str | None = None
    level: MatchLevel = MatchLevel.NONE
    confidence: float = 0.0
    is_fuzzy: bool = False
    conflict_ids: list[str] = field(default_factory=list)

    @property
    def matched(self) -> bool:
        """是否命中了软件。"""
        return self.software_id is not None


# --------------------------------------------------------------------------
# 归属推断引擎
# --------------------------------------------------------------------------


class AttributionEngine:
    """归属推断引擎（L1→L6 分级匹配 + 倒排索引召回 + 冲突裁决 + 手动覆盖）。"""

    def __init__(self, software: list[InstalledSoftware], threshold: float = 0.75) -> None:
        """初始化。

        Args:
            software: 已安装软件列表。
            threshold: L5 模糊匹配的相似度阈值（可在设置中调整）。
        """
        self._software: list[InstalledSoftware] = list(software)
        self._threshold: float = float(threshold)
        self._by_id: dict[str, InstalledSoftware] = {}
        self._by_norm_name: dict[str, list[InstalledSoftware]] = {}
        self._by_publisher: dict[str, list[InstalledSoftware]] = {}
        self._by_pub_token: dict[str, list[InstalledSoftware]] = {}
        self._by_install_root: dict[str, list[InstalledSoftware]] = {}
        self._install_prefixes: list[tuple[str, str]] = []
        self._by_exe: dict[str, list[InstalledSoftware]] = {}
        self._by_family: dict[str, list[InstalledSoftware]] = {}
        self._by_alias: dict[str, list[InstalledSoftware]] = {}
        self._by_token: dict[str, list[str]] = {}
        self._long_tokens: list[str] = []
        self._manual: dict[str, str] = {}
        self._manual_nc: dict[str, str] = {}
        self._built: bool = False

    # ---- 索引构建 ----

    @staticmethod
    def _push(index: dict[str, list[InstalledSoftware]], key: str, sw: InstalledSoftware) -> None:
        """向倒排索引追加一条记录。"""
        if not key:
            return
        index.setdefault(key, []).append(sw)

    def build_index(self) -> None:
        """构建全部倒排索引（软件列表变化后需重新调用）。"""
        start = time.perf_counter()
        self._by_id.clear()
        self._by_norm_name.clear()
        self._by_publisher.clear()
        self._by_pub_token.clear()
        self._by_install_root.clear()
        self._install_prefixes = []
        self._by_exe.clear()
        self._by_family.clear()
        self._by_alias.clear()
        self._by_token.clear()

        alias_reverse: dict[str, list[str]] = {}
        for alias_dir, software_names in ALIAS_TABLE.items():
            for name in software_names:
                alias_reverse.setdefault(normalize_name(name), []).append(alias_dir)

        for sw in self._software:
            if not sw.norm_name:
                sw.norm_name = normalize_name(sw.name)
            if not sw.norm_publisher:
                sw.norm_publisher = normalize_name(sw.publisher)
            self._by_id[sw.id] = sw

            self._push(self._by_norm_name, sw.norm_name, sw)
            if sw.norm_publisher:
                self._push(self._by_publisher, sw.norm_publisher, sw)
                for token in tokenize(sw.publisher, min_len=4):
                    self._push(self._by_pub_token, token, sw)

            root_name = sw.install_root_name()
            if root_name:
                self._push(self._by_install_root, root_name, sw)
            if sw.install_location:
                prefix = os.path.normcase(paths.to_absolute(sw.install_location)).rstrip(os.sep) + os.sep
                if len(prefix) > 3:
                    self._install_prefixes.append((prefix, sw.id))

            for exe in sw.exe_names:
                self._push(self._by_exe, exe.lower(), sw)
            if sw.package_family_name:
                family_base = sw.package_family_name.split("_")[0].lower()
                self._push(self._by_family, family_base, sw)
                self._push(self._by_family, normalize_name(family_base), sw)

            for alias_dir in alias_reverse.get(sw.norm_name, []):
                for alias_name in ALIAS_TABLE.get(alias_dir, ()):
                    self._push(self._by_alias, normalize_name(alias_name), sw)
                    self._push(self._by_alias, alias_name.lower(), sw)
            # 别名表也可能以"目录名"作为键直接命中软件名
            for alias_name in ALIAS_TABLE.get(sw.norm_name, ()):
                self._push(self._by_alias, normalize_name(alias_name), sw)
                self._push(self._by_alias, alias_name.lower(), sw)

            for token in tokenize(sw.name, min_len=3):
                self._by_token.setdefault(token, [])
                if sw.id not in self._by_token[token]:
                    self._by_token[token].append(sw.id)

        self._install_prefixes.sort(key=lambda item: len(item[0]), reverse=True)
        # 长关键词（≥4 字符）按长度倒序，供"目录名包含软件关键词"的子串召回使用
        self._long_tokens = sorted((k for k in self._by_token if len(k) >= 4),
                                   key=lambda k: -len(k))
        self._built = True
        logger.info(
            "归属索引构建完成：%d 款软件，关键词 %d 个，耗时 %.3f 秒",
            len(self._software), len(self._by_token), time.perf_counter() - start,
        )

    def _ensure_index(self) -> None:
        """确保索引已构建（懒构建）。"""
        if not self._built:
            self.build_index()

    # ---- 手动指派（P1-4）----

    def apply_manual_overrides(self, overrides: dict[str, str]) -> None:
        """应用手动指派映射，用户指派优先于一切规则。

        Args:
            overrides: ``{条目路径: 软件 id}`` 映射。
        """
        for path, sw_id in (overrides or {}).items():
            if not path:
                continue
            self._manual[str(path)] = str(sw_id)
            self._manual_nc[os.path.normcase(paths.to_absolute(path))] = str(sw_id)

    def set_manual_override(self, path: str, sw_id: str | None) -> None:
        """设置或清除单条手动指派。

        Args:
            path: 条目路径。
            sw_id: 目标软件 id；``None`` 表示清除指派（移出归属）。
        """
        key = os.path.normcase(paths.to_absolute(path))
        if sw_id is None:
            self._manual_nc.pop(key, None)
            for k in list(self._manual):
                if os.path.normcase(paths.to_absolute(k)) == key:
                    self._manual.pop(k, None)
            return
        self._manual[str(path)] = str(sw_id)
        self._manual_nc[key] = str(sw_id)

    def manual_overrides(self) -> dict[str, str]:
        """返回当前生效的手动指派映射（供持久化）。"""
        return dict(self._manual)

    def is_manual(self, path: str) -> bool:
        """该路径是否存在手动指派。"""
        return os.path.normcase(paths.to_absolute(path)) in self._manual_nc

    # ---- 各级匹配 ----

    def _level1(self, norm_dir: str, raw_dir: str, full_path: str) -> list[tuple[str, float]]:
        """L1：归一化目录名 == 归一化 DisplayName。"""
        return [(sw.id, CONF_L1) for sw in self._by_norm_name.get(norm_dir, [])]

    def _level2(self, norm_dir: str, raw_dir: str, full_path: str) -> list[tuple[str, float]]:
        """L2：归一化目录名 == 归一化 Publisher，或命中发布商主键词。"""
        hits: dict[str, float] = {}
        for sw in self._by_publisher.get(norm_dir, []):
            hits[sw.id] = CONF_L2
        for sw in self._by_pub_token.get(norm_dir, []):
            hits.setdefault(sw.id, CONF_L2)
        return list(hits.items())

    def _level3(self, norm_dir: str, raw_dir: str, full_path: str) -> list[tuple[str, float]]:
        """L3：目录名 == InstallLocation 末级名，或目录位于 InstallLocation 之下。"""
        hits: dict[str, float] = {}
        for sw in self._by_install_root.get(raw_dir, []):
            hits[sw.id] = CONF_L3
        if full_path:
            fp = os.path.normcase(paths.to_absolute(full_path))
            for prefix, sw_id in self._install_prefixes:
                if fp.startswith(prefix):
                    hits.setdefault(sw_id, CONF_L3)
        return list(hits.items())

    def _level4(self, norm_dir: str, raw_dir: str, full_path: str) -> list[tuple[str, float]]:
        """L4：目录名 == 主可执行文件名，或命中 PackageFamilyName 主键词。"""
        hits: dict[str, float] = {}
        for key in (norm_dir, raw_dir):
            for sw in self._by_exe.get(key, []):
                hits[sw.id] = CONF_L4
            for sw in self._by_family.get(key, []):
                hits[sw.id] = CONF_L4
        return list(hits.items())

    def _recall_candidates(self, norm_dir: str, raw_dir: str) -> list[str]:
        """按倒排索引召回候选软件 id（上限 :data:`MAX_CANDIDATES`）。"""
        tokens = set(tokenize(raw_dir, min_len=3))
        if norm_dir:
            tokens.add(norm_dir)
        scores: dict[str, int] = {}
        for token in tokens:
            for sw_id in self._by_token.get(token, ()):  # 命中关键词
                scores[sw_id] = scores.get(sw_id, 0) + 1
        if scores:
            ordered = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
            return [sw_id for sw_id, _ in ordered[:MAX_CANDIDATES]]
        # 分词召回为空时的补充召回：目录名"包含"软件关键词
        # （如目录 WorkBuddyExtension 无法按空格分词，但含关键词 workbuddy）
        for token in self._long_tokens:
            if token != norm_dir and token in norm_dir:
                for sw_id in self._by_token.get(token, ()):
                    scores[sw_id] = scores.get(sw_id, 0) + 1
        if scores:
            ordered = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
            return [sw_id for sw_id, _ in ordered[:MAX_CANDIDATES]]
        # 召回为空且软件规模不大时退化为全量比较，避免小规模场景漏判
        if len(self._software) <= 50:
            return [sw.id for sw in self._software[:MAX_CANDIDATES]]
        return []

    def _level5(self, norm_dir: str, raw_dir: str, full_path: str) -> list[tuple[str, float]]:
        """L5：互为子串或相似度达阈值（模糊匹配，标记 is_fuzzy）。"""
        hits: list[tuple[str, float]] = []
        for sw_id in self._recall_candidates(norm_dir, raw_dir):
            sw = self._by_id.get(sw_id)
            if sw is None or not sw.norm_name:
                continue
            short, long_ = (norm_dir, sw.norm_name) if len(norm_dir) <= len(sw.norm_name) else (sw.norm_name, norm_dir)
            if len(short) >= 3 and short and short in long_:
                # 子串命中同样受 fuzzy_threshold 约束：用户在设置里调高阈值应能收紧匹配
                if CONF_L5_SUBSTR >= self._threshold:
                    hits.append((sw_id, CONF_L5_SUBSTR))
                continue
            ratio = similarity(norm_dir, sw.norm_name)
            if ratio >= self._threshold:
                hits.append((sw_id, min(CONF_L5_MAX, 0.6 + ratio * 0.3)))
        return hits

    def _is_generic_publisher_dir(self, norm_dir: str) -> bool:
        """该目录名是否为"多家软件共享的泛发布商名"（如 microsoft / google / tencent）。

        两条判定路径，任一命中即视为通用目录：

        1. **按名判定**（:data:`GENERIC_DIR_NAMES`）：Microsoft / Google / Tencent
           一类超通用发布商，无论本机装了几款都算通用——只有按名判定才能覆盖
           ``Google``（本机仅 1 款）、``Tencent``（3 款）这类"数量不够但确实共用"的情况；
        2. **按数量判定**（:data:`GENERIC_PUBLISHER_MIN`）：同一发布商名下软件数量
           达到阈值，说明该目录无法归属给其中任意一款。
        """
        if norm_dir in GENERIC_DIR_NAMES:
            return True
        if len(self._by_publisher.get(norm_dir, ())) >= GENERIC_PUBLISHER_MIN:
            return True
        return len(self._by_pub_token.get(norm_dir, ())) >= GENERIC_PUBLISHER_MIN

    def _level6(self, norm_dir: str, raw_dir: str, full_path: str) -> list[tuple[str, float]]:
        """L6：内置别名表兜底。"""
        hits: dict[str, float] = {}
        for key in (norm_dir, raw_dir.lower()):
            for sw in self._by_alias.get(key, []):
                hits[sw.id] = CONF_L6
        return list(hits.items())

    def _levels(self) -> list[tuple[MatchLevel, object]]:
        """返回按优先级排列的级别判定函数列表。"""
        return [
            (MatchLevel.L1_EXACT, self._level1),
            (MatchLevel.L2_PUBLISHER, self._level2),
            (MatchLevel.L3_INSTALL_PATH, self._level3),
            (MatchLevel.L4_EXE_OR_FAMILY, self._level4),
            (MatchLevel.L5_FUZZY, self._level5),
            (MatchLevel.L6_ALIAS, self._level6),
        ]

    @staticmethod
    def _resolve(level: MatchLevel, hits: list[tuple[str, float]]) -> Match:
        """在同一级别的多个命中中裁决出最优归属并计算冲突。"""
        ordered = sorted(hits, key=lambda item: -item[1])
        best_id, best_conf = ordered[0]
        conflict_ids = [sid for sid, conf in ordered[1:] if best_conf - conf < CONFLICT_DELTA]
        return Match(
            software_id=best_id,
            level=level,
            confidence=round(best_conf, 3),
            is_fuzzy=(level == MatchLevel.L5_FUZZY),
            conflict_ids=conflict_ids,
        )

    # ---- 对外接口 ----

    def match_one(self, dir_name: str, full_path: str = "") -> Match:
        """对单个目录/文件名执行 L1→L6 归属推断（命中即停）。

        Args:
            dir_name: 目录名或文件名（不含父路径）。
            full_path: 完整路径（L3 前缀判定与手动指派用），可为空。

        Returns:
            :class:`Match`；全未命中时 ``software_id=None`` 且级别为 ``NONE``。
        """
        self._ensure_index()
        if full_path:
            manual = self._manual.get(str(full_path))
            if manual is None:
                manual = self._manual_nc.get(os.path.normcase(paths.to_absolute(full_path)))
            if manual:
                return Match(
                    software_id=manual,
                    level=MatchLevel.L1_EXACT,
                    confidence=CONF_L1,
                    is_fuzzy=False,
                )
        raw_dir = str(dir_name or "").strip().lower()
        norm_dir = normalize_name(raw_dir)
        if not norm_dir:
            return Match(None, MatchLevel.NONE, 0.0)

        for level, func in self._levels():
            hits = func(norm_dir, raw_dir, full_path)  # type: ignore[operator]
            if not hits:
                continue
            match = self._resolve(level, hits)
            # 说明（K-2）：通用目录仅在**确实存在多家竞争软件**时才降级为未识别。
            # 若本机只有 1 款该发布商的软件（QA 构造的单软件场景），目录并无"共享"事实，
            # 降级反而会平白丢失一条正确归属，因此要求候选 ≥2 才触发。
            if match.matched and len(hits) >= 2 and self._is_generic_publisher_dir(norm_dir):
                # 超通用发布商目录（%APPDATA%\Microsoft / Google / Tencent ...）：
                # 数十款软件共用，**不得归属给"恰好排第一"的那一款**，否则用户看到
                # "Microsoft → Microsoft Visual Studio Installer" 会误以为整目录
                # 都属于该软件而删除。处理：降级为未识别（owner 为空），并把全部
                # 候选软件 id 记入 conflict_ids，UI 可提示"多软件共用，请手动确认"。
                shared = [sw_id for sw_id, _conf in hits]
                return Match(
                    software_id=None,
                    level=MatchLevel.NONE,
                    confidence=0.0,
                    is_fuzzy=False,
                    conflict_ids=shared,
                )
            return match
        return Match(None, MatchLevel.NONE, 0.0)

    def attribute(self, candidates: list[DataPathEntry]) -> dict[str, Match]:
        """批量归属推断，并写回每个条目的归属字段。

        Args:
            candidates: 候选条目列表。

        Returns:
            ``{条目路径: Match}`` 映射。
        """
        self._ensure_index()
        start = time.perf_counter()
        result: dict[str, Match] = {}
        for entry in candidates:
            name = os.path.basename(entry.path)
            match = self.match_one(name, entry.path)
            entry.owner_id = match.software_id
            entry.match_level = match.level
            entry.confidence = match.confidence
            entry.is_fuzzy = match.is_fuzzy
            entry.conflict_ids = list(match.conflict_ids)
            entry.is_manual = self.is_manual(entry.path)
            result[entry.path] = match
        elapsed = time.perf_counter() - start
        logger.info(
            "归属推断完成：%d 条候选，命中 %d 条，耗时 %.3f 秒",
            len(candidates), sum(1 for m in result.values() if m.matched), elapsed,
        )
        return result

    @property
    def threshold(self) -> float:
        """当前 L5 相似度阈值。"""
        return self._threshold

    @threshold.setter
    def threshold(self, value: float) -> None:
        try:
            self._threshold = float(value)
        except (TypeError, ValueError):
            self._threshold = 0.75
