---
name: yara
description: "按模板编写 YARA 检测规则，并按五原则自检（准确性、唯一性、通用检测性、低误报、快速性）。Use when the user asks to write, generate, review, or fix a YARA rule (写 yara、写规则、检测规则、检查规则) for a sample analyzed in this session. Pulls exact bytes and disassembly through whichever *sql plugin is loaded (bnsql / idasql / ghidrasql)."
argument-hint: "[模板名] | 检查 <规则文件>"
---

# YARA 规则编写

把本次分析得到的特征写成 YARA 规则，套用固定模板，并逐条自检。

两种用法：

- **写新规则**：`/yara`、`/yara 用 shellcode 模板`，或直接说“写一条 yara 规则”
- **检查已有规则**：`/yara 检查 <规则文件>`，只跑下面的“五原则自检”和“编译”，不改内容，列出问题和修改建议

## 硬性约束

- 不执行、不调试样本。对样本只做静态读取和 `yara` 扫描。
- 每条 string / hex 都必须能追到样本里的地址，不允许凭记忆或推测写字节。
- md5 只在本机计算，不发给任何外部服务。
- 生成的规则只写到本地 `./output/<样本名>/`，不写进插件仓库。
- 国家、组织、家族这类归因信息由用户提供或确认，不要自己猜。

## 第 0 步：选模板

1. 列出本技能目录下 `templates/*.yar`。
2. 用户没指定就用 `templates/default.yar`。用户说“用 xxx 模板”就用 `templates/xxx.yar`，找不到时列出可用模板让用户选。
3. 用户直接贴了一份模板，就用他贴的那份；问他要不要存进 `templates/`。

## 第 1 步：收集元信息

需要以下字段，缺的向用户问，一次问完：

| 字段 | 来源 |
|------|------|
| 国家 CC | 用户提供。ISO 3166-1 alpha-2 两位大写代码，如 `IN` |
| 组织 Group | 用户提供 |
| 家族 Family | 用户提供或分析结论，用户确认 |
| author / copyright | 用户第一次提供后，记在当前目录 `./output/yara-profile.json`，以后直接读 |
| description | 分析结论给出建议，用户确认 |
| filetype / score / reference | 模板里写死的值（默认模板为 `exe`、`80`、`*`）原样保留；样本明显不是 exe（如 dll、sys）或用户要求时才改 |
| md5 | 本机计算：PowerShell `(Get-FileHash -Algorithm MD5 <样本>).Hash.ToLower()` |
| date / last_modified | 当天日期 `YYYY-MM-DD` |

## 第 2 步：取候选特征

使用本会话已加载并已连接的 *sql 插件（bnsql / idasql / ghidrasql 都可以；如果都没连接，先请用户连接一个）。

按价值从高到低找：

1. **核心逻辑的指令序列**：解密循环、配置解析、协议封包、字符串解码、API 哈希计算。用该插件的 disassembly / decompiler 能力，按函数地址取汇编和原始字节。
2. **专有常量**：密钥、魔数、自定义结构标记、API 哈希值。
3. **专有字符串**：只有这个家族才会有的格式串、路径片段、互斥体名模板（不要只用一个可变的具体 IOC）。

每条候选都记下：来源函数名与地址、起止地址、原始字节、对应汇编。

## 第 3 步：五原则筛选

逐条检查，不通过就剔除或改写：

| 原则 | 检查 |
|------|------|
| **准确性** | 字节是从 *sql 查询结果复制的，并附来源地址注释；汇编与字节一一对应。 |
| **唯一性** | 特征所在函数不是库代码。剔除 CRT/UCRT、STL、异常处理（如 `__CxxFrameHandler`、`FindHandler`）、`memcpy`/`memset`/`qsort`/`strlen`/`parse_integer` 这类函数；编译器生成的函数序言、栈检查、安全 cookie 代码也不用。 |
| **通用检测性** | 指令序列里会随编译变化的部分打通配符：寄存器编码、栈偏移、绝对地址、call/jmp 的相对偏移。可变长度用跳跃 `[2-6]`。优先代码逻辑，少用 IP、域名、完整路径等易变 IOC。只有一个样本时，在 description 末尾注明“单样本，通用性未验证”。 |
| **低误报** | 不用短于 4 字节的串；不单独用常见 API 名、常见 DLL 名、常见 UI 字符串；condition 要求多个特征组合命中。 |
| **快速性** | condition 最前面写 `uint16(0) == 0x5A4D` 和 `filesize` 上限（取样本大小的 2 到 4 倍，向上取整到 KB/MB）；hex 串不以通配符开头，每条至少含一段 4 字节以上的固定字节；不用 `.*` 这类宽泛正则。 |

hex 写法示例（取自汇编，字节占位）：

```
// 0x1400xxxxx  decrypt_config: xor 解密循环
$code1 = { 8A 04 ?? 34 ?? 88 04 ?? 4? FF C? 4? 3B ?? 7C ?? }
```

## 第 4 步：命名

规则名：`apt_<CC>_<Group>_<Family>_<YYYYMMDDNN>`

- `CC`：ISO 3166-1 alpha-2 大写。
- `Group`、`Family`：转驼峰。按非字母数字字符切分，每段首字母大写、其余保持原样，再拼接；去掉所有非 `[A-Za-z0-9]` 字符。例：`patch work` → `PatchWork`，`back-door x` → `BackDoorX`。
- `YYYYMMDDNN`：当天日期 + 两位序号。扫描 `./output/**/*.yar` 中 `_YYYYMMDD\d{2}` 结尾的规则名，取当天最大序号加一，没有就从 `01` 开始。
- 最终规则名只能包含字母、数字、下划线，且不以数字开头。

## 第 5 步：填模板

把模板里的 `{{...}}` 全部替换，不留占位符。strings 按类型分组命名：`$code*`（指令）、`$const*`（常量）、`$str*`（字符串）。每条上方用注释写来源地址。

condition 骨架：

```
uint16(0) == 0x5A4D and filesize < 2MB and
(
    2 of ($code*) or
    (1 of ($code*) and 2 of ($const*, $str*))
)
```

按实际特征数量调整，但保持“多个特征组合命中”。

## 第 6 步：编译与命中

1. 编译：`yarac <规则文件> NUL`（Windows）或 `yarac <规则文件> /dev/null`。有错误或性能警告（如 slowing down scanning）都算不通过，回到第 3 步。
2. 命中：如果用户给了本地样本路径，执行 `yara -s <规则文件> <样本>`，确认命中，并核对命中的偏移是否就是第 2 步记录的地址对应的文件偏移。没命中回到第 2 步。
3. `yarac` / `yara` 不在 PATH 时，告诉用户装好再验证，不要跳过并声称通过。
4. 如果命令被本机的安全 hook 拦截（例如样本目录禁止执行的保护），如实告诉用户哪一步被拦，规则标为“未验证”，不要换别的方式绕过，也不要声称通过。

## 第 7 步：输出

- 写到 `./output/<样本名>/<规则名>.yar`。`<样本名>` 用用户给的简称，不要用哈希。
- 在对话里给出：规则全文、五原则检查结果（每条一行：通过 / 原因）、编译和命中结果。
- 请用户确认。用户修改后，`last_modified` 改为当天，`version` 小版本加一。
