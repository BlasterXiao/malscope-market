# ghidrasql 本机安装

插件只提供使用说明，下面这些需要每台机器自己装。

## 需要什么

| 项 | 要求 |
|----|------|
| Ghidra | 12.1 或更高 |
| JDK | 21 |
| LibGhidraHost 扩展 | 来自 https://github.com/0xeb/libghidra ，装在你实际使用的那个 Ghidra 版本里 |
| ghidrasql 程序 | 推荐最新发布版 0.0.7（上游未写明与插件提交的对应关系） |

## 安装步骤

上游只提供 Linux x86-64 的预编译包，Windows 需要按源码安装。上游仓库带了给 AI 代理用的安装说明 `install-prompt.md`，可以让代理按它逐步完成。

1. 安装 Ghidra 12.1+ 和 JDK 21。
2. 安装 LibGhidraHost 扩展：在 `libghidra/ghidra-extension/` 下执行

   ```
   gradle installExtension -PGHIDRA_INSTALL_DIR=<Ghidra 安装目录>
   ```

3. 在 Ghidra 里启用：CodeBrowser → File → Configure → Ghidra Core 的 Configure → 搜索 libghidra → 勾选 LibGhidraHostPlugin → OK。插件不出现时，清理 Ghidra 的 OSGi bundle 缓存后重启。
4. 构建 ghidrasql，把 `ghidrasql.exe` 放到 PATH 中的目录。
5. 重开终端，验证：

   ```
   where ghidrasql
   ghidrasql --version
   ```

## 两种模式

- **无头模式**：`ghidrasql --binary <样本>` 直接分析。
- **GUI 模式**：Ghidra 里 Tools → libghidra Host → Start Server…，默认端口 18080，然后 `ghidrasql --url http://127.0.0.1:18080 -q "SELECT COUNT(*) FROM funcs"` 验证。

## 升级 Ghidra 时注意

扩展是装在具体 Ghidra 版本里的。升级 Ghidra（或切换 `current` 之类的链接到新版本）后，要给新版本**重新执行第 2、3 步**，否则会报 `failed to locate LibGhidraHeadlessServer.java`。

## 常见问题

| 现象 | 原因 | 处理 |
|------|------|------|
| `failed to locate LibGhidraHeadlessServer.java` | 当前 Ghidra 没装 LibGhidraHost | 第 2、3 步 |
| 工程打不开、提示锁 | Ghidra 上次没正常退出 | 结束残留的 java.exe，删除工程目录里的 `*.lock` 和 `*.lock~` |
| 查询报表或列不存在 | 程序版本落后 | 升级到推荐版本 |

## 版本组合

| 插件提交 | 推荐 ghidrasql 程序 | Ghidra | 实测通过 |
|----------|---------------------|--------|----------|
| 619e6dd | 0.0.7 | 12.1+ | 待填 |

升级插件提交后，在这里加一行；实测通过后在最后一列写上日期和 Ghidra 版本。
