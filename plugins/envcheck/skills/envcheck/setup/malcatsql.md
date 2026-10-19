# malcatsql 本机安装

插件只提供使用说明，引擎（Python 包）在本仓库 `tools/malcatsql`，需要每台机器自己装一次。

## 需要什么

| 项 | 要求 |
|----|------|
| Malcat | 0.9.x，授权支持 Python API（实测 0.9.15） |
| Python | **CPython 3.13**。Malcat 的 `malcat.pyd` 只支持 3.13，别的版本导入不了 |
| malcatsql 引擎 | 推荐 0.3.0，与本市场的插件 0.3.0 对应 |

## 安装步骤

1. 让 Python 3.13 能 `import malcat`：在 Malcat 安装目录用 3.13 执行一次

   ```
   py -3.13 install_api.py
   ```

2. 安装引擎（在本仓库根目录执行）：

   ```
   py -3.13 -m pip install -e "tools/malcatsql[server]"
   ```

3. 让 `malcatsql` 命令能直接敲：pip 会把 `malcatsql.exe` 放进 Python 3.13 的 Scripts 目录（用户安装时是 `%APPDATA%\Python\Python313\Scripts`）。把这个目录加入**用户** PATH。
4. 重开终端，验证：

   ```
   where malcatsql
   malcatsql --version
   ```

## 为什么一定要用 `malcatsql` 命令

本机可能装了样本目录执行保护 hook：命令里同时出现受保护样本目录和 `python` / `.exe` 等字样就会被拦截。用 `malcatsql <样本>` 调用，样本按哈希命名、不带可执行后缀时不会被误拦；写成 `python -m malcatsql ...` 一定会被拦。被拦截时不要绕过，由分析人员决定是否 `/unprotect`。

## 常见问题

| 现象 | 原因 | 处理 |
|------|------|------|
| `No module named 'malcat'` | 3.13 还没装 Malcat API | 第 1 步 |
| `where malcatsql` 找不到 | Scripts 目录不在 PATH | 第 3 步 |
| 导入 `malcat.pyd` 失败 | 用的不是 3.13 | 用 `py -3.13` 重新执行第 2 步 |
| 查询报表或列不存在 | 引擎与插件版本不一致 | 在仓库根目录 `git pull` 后重新执行第 2 步 |

## 版本组合

| 插件版本 | 推荐引擎 | 实测通过 |
|----------|----------|----------|
| 0.3.0 | 0.3.0 | 待填 |

插件和引擎在同一个仓库里一起发布，升级时一起拉取即可。
