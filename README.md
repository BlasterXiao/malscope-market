# MalScope 插件市场

静态样本分析的 Claude Code 插件目录。外部的好插件原样收录，自己写的插件也放在这里。分析人员按手上的样本和工具，自己挑插件、自己组合。

## 设计思想：人做编排，插件做专家

- 每个插件是一位“专家”的经验和工具：SQL 逆向、写 YARA、整理技术点、出报告。需要时加载进 Claude，它就按这位专家的套路干活。
- 分析人员是编排者：这次用哪几个插件、按什么顺序、哪些结论要人确认，由人决定。
- 本仓库是专家花名册：最外层只说明有哪些插件、适合什么场景，不做包办一切的万能插件。
- 插件之间没有包装层和强制依赖。同一个会话里加载了 idasql 和 yara，yara 就会直接用 idasql 取汇编。

## 插件目录

| 插件 | 来源 | 适用场景 | 本机需要 | 怎么用 |
|------|------|----------|----------|--------|
| **bnsql** | 外部 [0xeb/bnsql-skills](https://github.com/0xeb/bnsql-skills) | 有 Binary Ninja，用 SQL 查函数、伪代码、交叉引用，写回改名注释 | BN + bnsql | `/bnsql:connect` 起步，再用 `/bnsql:functions`、`/bnsql:xrefs` 等 |
| **idasql** | 外部 [allthingsida/idasql-skills](https://github.com/allthingsida/idasql-skills) | 有 IDA Pro；支持无头 CLI 和 UI 端口两种模式 | IDA + idasql.exe/.dll，`where idasql` 能找到 | `/idasql:connect` 起步，最后 `/idasql:storage` 保存 |
| **ghidrasql** | 外部 [0xeb/ghidrasql-skills](https://github.com/0xeb/ghidrasql-skills) | 只有免费工具，或需要批量无头分析 | Ghidra + ghidrasql | `/ghidrasql:connect` 起步 |
| **yara** | 自有 | 按固定模板写检测规则，五原则自检，用汇编核对特征 | yara / yarac | `/yara`，或直接说“写一条 yara 规则” |
| **techniques** | 自有 | 提取样本用到的技术点，标注 ATT&CK，生成 HTML 详细记录 | 无 | `/techniques`，或说“整理这个样本的技术点” |
| **report** | 自有 | 把一次分析过程整理成 HTML / Markdown 记录 | 无 | `/report html`、`/report md` |
| **envcheck** | 自有 | 检查本机程序是否装好、版本是否与插件匹配，缺什么给出安装步骤 | 无 | `/envcheck`、`/envcheck all`、`/envcheck idasql` |

> 自有插件的完整命令是 `/yara:yara`、`/techniques:techniques`、`/report:report`，一定可用。没有重名时通常也能直接输入 `/yara`，以 `/` 菜单里显示的为准。也可以不打命令，直接用中文说需求，技能会自动触发。

## 按场景挑

| 场景 | 插件 |
|------|------|
| 手上有 IDA，要看函数逻辑 | idasql |
| 手上有 BN | bnsql |
| 只有免费工具 | ghidrasql |
| 要写检测规则 | yara + 任一 *sql |
| 要整理样本用了哪些技术 | techniques + 任一 *sql |
| 分析完要留档 | report（可附 techniques 记录和 yara 规则） |

一个典型流程：

```
/idasql:connect                     连接样本
/idasql:functions 体积前十 + /idasql:xrefs 对齐系统 API
/idasql:decompiler WinMain          看关键函数
/idasql:annotations 改名加注释      写回
/idasql:storage                     保存
/techniques 样本A                   整理技术点
/yara                               写规则
/report html                        出记录
```

SQL 分析的详细套路见 [docs/sql-workflow.md](docs/sql-workflow.md)。

## 安装

```
/plugin marketplace add BlasterXiao/malscope-market
/plugin
```

在 `/plugin` 界面里按上面的目录挑要装的插件，装几个都行。也可以直接装：

```
/plugin install idasql@malscope-market
/plugin install yara@malscope-market
```

本地调试：`/plugin marketplace add <本仓库的本地路径>`。

> 如果之前单独添加过上游市场（如 `bnsql-tools`），同名插件会装两份，保留其中一个即可。

## 每台机器要自己装的

插件只是说明书，分析器本体要每台机器自己装。装好外部插件后，先装 `envcheck` 并运行 `/envcheck`，它会列出缺什么、版本对不对，并指向下面的安装文档。

| 工具 | 本机需要 | 推荐程序版本 | 安装文档 |
|------|----------|--------------|----------|
| bnsql | Binary Ninja + bnsql，`BN_INSTALL_DIR` 或 PATH 指向 BN | 0.0.13 | [setup/bnsql.md](plugins/envcheck/skills/envcheck/setup/bnsql.md) |
| idasql | IDA Pro 9.2–9.4 + 对应构建的 idasql.exe / idasql.dll | 0.0.19 | [setup/idasql.md](plugins/envcheck/skills/envcheck/setup/idasql.md) |
| ghidrasql | Ghidra 12.1+、JDK 21、LibGhidraHost 扩展 + ghidrasql | 0.0.7 | [setup/ghidrasql.md](plugins/envcheck/skills/envcheck/setup/ghidrasql.md) |
| yara | yara、yarac 在 PATH | 4.x | [setup/yara.md](plugins/envcheck/skills/envcheck/setup/yara.md) |

推荐版本与本市场钉住的插件提交对应，记录在 `plugins/envcheck/skills/envcheck/tools.json`。程序版本和插件版本不一致时，常见症状是查询报“表或列不存在”。

## 产出与安全约定

- 所有分析产出（技术点记录、规则、报告）只写到分析目录下的 `./output/<样本名>/`，`.gitignore` 已排除，不进本仓库。
- 仓库里不放样本、样本哈希、真实 IOC、个人路径。技术点库只写通用知识。
- 插件不执行、不调试样本。

## 扩展

**加一个外部插件**

1. 在 `.claude-plugin/marketplace.json` 加一条 `git-subdir` 条目：仓库地址、插件子目录、钉住的提交。
2. 在上面的插件目录表和场景表各加一行。

**加一个自己的插件**

1. 复制 `plugins/_template/`，按其中的 README 改名、写 `SKILL.md`。
2. `marketplace.json` 加一条 `"source": "./plugins/<插件名>"`，目录表加一行。

**补充技术点库**

`techniques` 遇到库里没有的技术点时，会在 `./output/library-drafts/` 生成草稿。检查无样本信息后，复制到 `plugins/techniques/skills/techniques/library/`，并更新该目录的 `README.md` 索引。

## 升级外部插件

外部插件钉在某个提交上，上游更新不会自动影响你。要升级时：

```
git ls-remote https://github.com/0xeb/bnsql-skills.git refs/heads/main
git ls-remote https://github.com/allthingsida/idasql-skills.git refs/heads/main
git ls-remote https://github.com/0xeb/ghidrasql-skills.git refs/heads/main
```

把输出的提交号替换到 `marketplace.json` 对应条目的 `sha`。同时更新 `plugins/envcheck/skills/envcheck/tools.json` 里的 `plugin_pin` 和 `recommended_program`，以及对应 setup 文档的“版本组合”表。提交推送后，在 `/plugin` 里更新市场。

## 目录结构

```
malscope-market/
├── README.md                     插件目录（本文件）
├── .claude-plugin/marketplace.json
├── docs/sql-workflow.md          SQL 分析套路
└── plugins/
    ├── _template/                新建自有插件时复制
    ├── yara/
    │   └── skills/yara/          SKILL.md + templates/default.yar
    ├── techniques/
    │   └── skills/techniques/    SKILL.md + record.html + library/
    ├── report/
    │   └── skills/report/        SKILL.md + report.html + report.md
    └── envcheck/
        └── skills/envcheck/      SKILL.md + tools.json + setup/*.md
```
