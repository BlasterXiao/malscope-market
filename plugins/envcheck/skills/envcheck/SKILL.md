---
name: envcheck
description: "检查本机分析环境：bnsql / idasql / ghidrasql / yara 的程序是否装好、版本是否与插件匹配、宿主工具（Binary Ninja、IDA、Ghidra 扩展）是否就位，缺什么给出安装步骤。Use when the user asks to check the environment, 环境检查, 装好了没, 为什么连不上, or when a *sql connect step fails because a program is missing."
argument-hint: "[all | bnsql | idasql | ghidrasql | yara]"
---

# 本机环境检查

只检查、只报告，不安装、不下载、不修改环境变量。

## 检查范围

- 无参数：检查本机已安装的插件对应的工具（用 `claude plugin list` 看装了哪些，匹配 `tools.json` 里的 `plugin` 字段）。
- `all`：检查 `tools.json` 里的全部工具。
- 工具名：只检查这一个。

## 执行方式

- 用 Bash 工具执行，命令一律按程序名调用（`where idasql`、`idasql --version`）。
- 不要用 `& "路径"`、python、node 等方式执行，本机可能有样本目录执行保护 hook，会拦截这类命令。
- 某条命令被 hook 拦截时，在结果里写“被拦截，未检查”，不要绕过。

## 步骤

对每个工具，按本技能目录下 `tools.json` 的记录逐项检查：

1. **插件**：`claude plugin list` 里是否有 `<plugin>@malscope-market`（或其他市场的同名插件，注明来源）。
2. **程序**：`where <binary>`，记下路径；`extra_binaries` 也逐个 `where`。
3. **版本**：执行 `version_cmd`，从输出里取版本号，与 `recommended_program` 比较：
   - 相同：✔
   - 低于推荐：⚠，建议升级到推荐版本
   - 高于推荐：⚠，提示插件可能还没跟上，出现查询表不存在等问题时回退或升级插件
   - 无法运行：✘，把错误信息与 `common_errors` 对照，给出对应原因
4. **宿主**：按 `host_checks` 逐条用只读命令核对（`echo $VAR`、`ls`、`where`、`java -version`）。无法自动判断的条目标“需人工确认”。
5. **下一步**：每个 ⚠ / ✘ 给出一句话修复建议，并指向 `setup/<工具>.md` 里的对应小节。

## 输出

一张表，然后是修复清单：

| 工具 | 插件 | 程序路径 | 版本（本机 / 推荐） | 宿主 | 结论 |
|------|------|----------|---------------------|------|------|
| idasql | ✔ | C:\...\idasql.exe | 0.0.18.1 / 0.0.19 | IDA 9.2 ✔ | ⚠ 程序版本低于插件 |

修复清单按严重程度排：先 ✘（用不了），再 ⚠（能用但有风险）。全部 ✔ 时只回一句“环境就绪”。

## 不做的事

- 不自动下载或安装任何程序，BN、IDA 需要授权，下载执行程序由用户自己决定。
- 不修改 PATH、环境变量、注册表。
- 不执行样本，不读取样本内容。
