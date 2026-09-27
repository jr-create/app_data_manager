# 软件数据迁移助手（Software Data Migrator）

面向 **Windows 10 / 11 换机场景**的桌面工具：扫描本机已安装软件，推断其散落在
`%APPDATA%`、`%LOCALAPPDATA%`、`%PROGRAMDATA%` 等处的用户数据目录，把"软件 ↔ 数据"
对应成清单，支持**先备份后删除**、调用软件自带卸载命令，并导出 CSV / JSON 清单。

> 工具**只读**注册表、只操作用户数据目录，绝不会触碰系统目录。

---

## 一、快速开始

### 1. 环境要求

* Windows 10 / 11（x64）
* Python 3.10 及以上
* 依赖：`PySide6-Essentials==6.8.3`（其余能力全部使用 Python 标准库实现）

```powershell
# 安装依赖（仓库内已提供 requirements.txt）
pip install -r requirements.txt
```

### 2. 启动

```powershell
# 方式一：一键启动（推荐，会自检解释器 / 平台 / 依赖）
python run.py

# 方式二：直接以模块方式启动
python -m src.main
```

如需读取更完整的 MSIX/应用商店应用列表或卸载系统级软件，建议**以管理员身份运行**；
非管理员也能正常使用，只是部分条目会提示权限不足。

---

## 二、五步工作流

| 步骤 | 界面位置 | 说明 |
| --- | --- | --- |
| ① 扫描 | 左上角「扫描」 | 依次执行：注册表卸载项 → MSIX/商店应用 → 数据目录枚举与归属推断 → 渐进式计算占用大小。随时可「取消」 |
| ② 查看/筛选 | 顶部筛选栏 | 支持关键字搜索、内容类型（配置/数据/缓存/日志/插件/其他）、识别状态、**Top-N 大目录**；下方详情面板按类型分组展示路径，可打开文件夹、复制路径；**单条数据目录体积超过 2 GiB 时，会在界面（软件名/占用列与详情面板路径行）以红色高亮提示「⚠超大(>2GiB)」，提醒用户体积异常大、备份/删除需谨慎** |
| ③ 人工校正 | 详情面板 / 右键 | 归属错误可「取消归属」或「手动指派」给指定软件；手动指派会持久化到 `manual_attribution.json`，下次扫描自动生效 |
| ④ 备份 | 底部「备份选中」 | 勾选条目后打包为 `SDM_backup_时间戳.zip`，归档内含 `manifest.json` 清单，目录结构为 `data/{软件名}/{根标识}/...` |
| ⑤ 删除 / 卸载 | 底部「删除选中」「卸载软件」 | 删除需通过四道确认闸门（见下）；卸载直接调用软件自带的 `UninstallString`（可选静默参数） |

扫描结果还可随时**导出 CSV / JSON**（CSV 为 `utf-8-sig`，Excel 双击不乱码；JSON 为 `utf-8`）。

---

## 三、安全红线（设计约束，代码层面双重保障）

1. **系统关键目录黑名单**：`Windows`、`System32`、`SysWOW64`、`WinSxS`、`SystemApps`、
   `LOCALAPPDATA\Microsoft\Windows*`、`Packages` 等整棵目录树禁止删除；
   `Program Files`、`ProgramData`、用户配置目录（`Default`/`Public`/各用户profile）、盘符根目录
   **仅本体保护**，其下的软件子目录允许操作。
   判定在 `src/core/paths.py::check_path_safety()` 中实现，并且
   **UI 展示层与 `Deleter` 执行层各校验一次**（UI 中被拦截的条目直接不可勾选）。
   判定前会先做安全归一化（`normalize_for_safety`）：剥离 `\\?\` / `\\.\` 设备前缀、
   还原本机管理共享（`\\localhost\C$`、`ADMIN$`）、展开 8.3 短名（`C:\PROGRA~1`），
   **换一种写法不能绕过黑名单**。
2. **删除四道闸门**：
   ① 删除前弹窗**完整列出待删路径** → ② 选择删除方式（默认「先备份后删除」）
   → ③ 必须手动输入 `DELETE` 才解锁确认按钮 → ④ 弹 `QMessageBox` 二次确认。
3. **注册表只读**：全程只 `winreg.OpenKey` 读取卸载项，**不做任何写入/删除**
   （卸载后的注册表残留清理为 P2 预留，MVP 不实现）。
4. **备份归档防穿越（zip-slip）**：归档内一律使用 `data/...` 相对路径、正斜杠、剔除盘符与 `..`，
   解压后目录结构与原路径一一对应。
5. **回收站优先**：删除方式默认提供「移入回收站」（自实现 `SHFileOperationW` + `FOF_ALLOWUNDO`，
   不引入 `send2trash`），可撤销；永久删除会二次警示。

---

## 四、目录结构

```
软件数据迁移助手/
├── run.py                      # 一键启动入口（自检解释器/平台/依赖）
├── requirements.txt            # 仅 PySide6-Essentials，其余全部标准库
├── README.md                   # 本文件
├── docs/                       # 需求与架构文档（PRD.md / ARCHITECTURE.md）
├── src/
│   ├── main.py                 # 应用入口：日志、全局异常钩子、主窗口装配
│   ├── core/                   # 业务内核（严禁 import PySide6）
│   │   ├── models.py           # 枚举与数据类（软件/条目/报告/错误）
│   │   ├── config.py           # 配置与持久化（config.json/手动指派/大小缓存）
│   │   ├── paths.py            # 路径规范化、长路径、系统目录黑名单
│   │   ├── utils.py            # 名称归一化、相似度、格式化、JSONL 操作日志
│   │   ├── software_scanner.py # 注册表卸载项 + MSIX(PowerShell) 扫描
│   │   ├── dir_scanner.py      # 数据根目录枚举与内容类型判定
│   │   ├── attribution.py      # L1~L6 归属推断（倒排召回 + difflib + 冲突裁决）
│   │   ├── size_calculator.py  # 渐进式目录大小计算（可取消、带缓存）
│   │   ├── backuper.py         # ZIP 备份 + manifest.json（还原为 P1 预留）
│   │   ├── deleter.py          # 三种删除模式 + 黑名单复核 + 回收站
│   │   ├── uninstaller.py      # 卸载命令解析与执行（MSI/EXE/MSIX）
│   │   ├── exporters.py        # CSV / JSON 导出
│   │   └── scan_service.py     # 四阶段扫描编排（L4 门面）
│   └── ui/                     # 界面层（仅主线程操作控件）
│       ├── workers.py          # QThread 后台任务（只用 Signal 回传）
│       ├── widgets.py          # 表格模型/代理筛选/详情面板/图标提供器
│       ├── dialogs.py          # 删除确认、卸载、残留、备份结果、设置等对话框
│       └── main_window.py      # 主窗口
└── tests/
    └── smoke_test.py           # 冒烟验证（含真实本机扫描，中文输出）
```

**分层约束**：`src/core` 五层单向依赖（L1 基础设施 → L2 领域 → L3 操作 → L4 编排 → L5 UI），
`core` 不感知 Qt；所有耗时任务放进 `ui/workers.py` 的 `QThread`，**后台线程绝不直接操作控件**。

---

## 五、本地数据存放位置

| 内容 | 路径 |
| --- | --- |
| 主配置 | `%LOCALAPPDATA%\SoftwareDataMigrator\config.json` |
| 手动归属指派 | `%LOCALAPPDATA%\SoftwareDataMigrator\manual_attribution.json` |
| 目录大小缓存（7 天有效） | `%LOCALAPPDATA%\SoftwareDataMigrator\cache\size_cache.json` |
| 运行日志 / 操作日志 | `%LOCALAPPDATA%\SoftwareDataMigrator\logs\` |
| 备份归档（默认） | `%USERPROFILE%\Documents\SoftwareDataMigrator_Backups\` |

---

## 六、归属推断规则（一句话版）

按 L1→L6 **命中即停止**：注册表 `InstallLocation` 直连 → 发布者/名称精确归一 →
常见别名表（`ALIAS_TABLE`）→ 可执行文件名 → 模糊相似（阈值 0.75）→  publisher 目录兜底。
置信度相近（差值 < 0.05）时判定为**冲突**，界面上标记待人工确认。

* 别名表同时收录**中文软件名 → 英文目录名**（如「微信」⇄ `WeChat Files`、飞书 ⇄ `LarkShell`），
  并自动建立双向映射；模糊匹配的相似度与子串命中**都受设置里的阈值约束**。
* 「泛发布商目录」（`Microsoft`、`Google`、`Tencent` 等被 4 款以上软件共用的目录名）
  不再被某一款软件静默独占：保留归属但标记为**待确认**，并把同发布商的其他软件全部记入冲突列表。
* 大小计算会跳过符号链接**与 junction/挂载点**（Windows 下 `is_symlink()` 对 junction 返回 False，
  额外判 `FILE_ATTRIBUTE_REPARSE_POINT`），避免重复计数。

---

## 七、已知限制（MVP 边界）

1. **备份还原未实现**：`Backuper.restore()` 为接口预留，调用抛 `NotImplementedError`（P1-2）。
   目前备份归档是标准 ZIP，可手工解压取回。
2. **卸载后注册表残留清理未实现**：`Uninstaller.clean_registry()` 为 P2 预留；
   卸载后可用「残留扫描」功能重新扫描并手动清理残留数据目录。
3. **扫描范围**：仅枚举数据根目录的**第一层**目录（不做全盘递归枚举），
   以保证扫描速度；大小计算时才递归统计。
4. **MSIX 扫描**依赖 PowerShell 的 `Get-AppxPackage`，耗时约 1~3 秒；
   非管理员下默认只枚举当前用户，可在「设置」中勾选枚举所有用户。
5. **识别率有限**：`ALIAS_TABLE` 覆盖常见国产/主流软件的中英文别名，但绿色软件、
   未在卸载项登记的软件，以及 `NuGet`、`Packages` 一类通用目录仍会落入「未识别」分组
   （本机实测识别率约 20%~30%，取决于软件构成），可通过手动指派补齐（会持久化）。
6. 部分软件占用中的文件可能备份失败，会以「跳过」条目列在备份结果中，不会中断整体备份。

---

## 八、冒烟验证

```powershell
# 全部用例（含真实本机扫描 + GUI 启动），约 15 秒
python tests/smoke_test.py

# 跳过 GUI
python tests/smoke_test.py --no-gui

# 跳过真实本机扫描
python tests/smoke_test.py --no-real
```

脚本会验证：模块导入、路径黑名单、真实扫描（注册表+MSIX+归属+大小）、完整流水线、
临时假数据的备份/删除/拦截、后台 Worker 信号链路、CSV/JSON 导出、GUI 启动与对话框构造，
末尾输出 `IS_PASS: YES/NO`。**全过程只读取本机信息，绝不删除/卸载真实软件与真实用户数据。**
