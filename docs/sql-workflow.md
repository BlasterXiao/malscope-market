# 用 SQL 插件分析样本的套路

适用于 bnsql / idasql / ghidrasql。三者的核心能力名字一样（connect、analysis、functions、data、decompiler、disassembly、xrefs、types、annotations），所以套路通用，只有保存方式等少数地方不同。

**为什么用 SQL：** 大模型非常熟悉 SQL，一条查询就能精确拿到需要的列和行，比逐个调用 MCP 工具省 token。所有写回（改名、注释、类型）也是 SQL。

**为什么不容易幻觉：** 写回后逆向引擎会重新反编译。如果 AI 推断的结构体大小或类型错了，新的伪代码会出现类型冲突或逻辑断裂，下一次查询就能发现并纠正。“修改 → 重新反编译 → 校验”是这套方法的核心。

## 标准流程

### 1. 连接

用 `/<工具>:connect`，例如 `/idasql:connect`。样本没有数据库时，首次连接会做自动分析。

连接后先做一次概览：

```sql
-- 样本基本信息，排除哈希字段
SELECT key, value FROM binary WHERE key NOT IN ('md5', 'sha256');

SELECT COUNT(*) AS funcs   FROM funcs;
SELECT COUNT(*) AS xrefs   FROM xrefs;
SELECT COUNT(*) AS strings FROM strings;
```

### 2. 圈候选函数

常用提问写法：

> 获取函数大小前十的函数 `/functions`，通过交叉引用获取其调用的系统 API 个数 `/xrefs`，并显示每个函数内部调用的系统 API 个数和名称，一一对应。

结果里要注意剔除库函数：`memcpy`、`qsort`、`log10`、UCRT 的 `parse_integer`、异常处理的 `FindHandler` 这类函数体积大但和样本逻辑无关。

### 3. 取伪代码 / 汇编

只按地址取，不整库拉：

> 查看 WinMain 的反汇编 `/disassembly`，拉取反编译、局部变量和字符串引用，筛出需要标注的内部函数。

### 4. 写回

> 对 WinMain 进行类型和变量重命名 `/types`，加上注释 `/annotations`，WinMain 调用的相关函数也一一进行同样的操作。

改名的 SQL 形式：

```sql
INSERT INTO names(addr, name) VALUES (0x<地址>, 'g_socket');
INSERT INTO names(addr, name) VALUES (0x<地址>, 'p_WSAStartup');
```

### 5. 自检

改完再查一遍，确认名字已生效、伪代码没有出现类型冲突：

```sql
SELECT printf('0x%X', addr) AS addr, name
FROM funcs
WHERE addr IN (0x<地址1>, 0x<地址2>)
ORDER BY addr;
```

然后重新取一次相关函数的伪代码，检查有没有类型冲突或逻辑断裂，有就回到第 4 步。

### 6. 保存并关闭

| 工具 | 保存方式 |
|------|----------|
| idasql | `/idasql:storage` |
| bnsql | 写操作后执行 `SELECT save()` 才会落盘 |
| ghidrasql | 按上游 `/ghidrasql:connect` 说明保存工程 |

## 两种模式

- **CLI 无头模式**：不开界面，直接用 SQL 分析，适合批量和快速分析。
- **UI 模式**：在 IDA / BN 里打开插件，插件会开一个端口，连上后操作的就是光标所在函数，适合边看上下文边修正。端口可以配置到远程虚拟机上。

## 本机准备（以 idasql 为例）

1. `/plugin` 里从本市场安装 `idasql`。
2. 下载 idasql 程序：`idasql.exe` 放到 IDA 安装目录，`idasql.dll` 放到 IDA 的 `plugins` 目录。
3. 配好环境变量，保证 `where idasql` 能找到。

bnsql、ghidrasql 同理，具体以各自上游仓库说明为准。

## 速度

慢的时候通常是模型推理慢，不是工具慢，可以换更快的模型。
