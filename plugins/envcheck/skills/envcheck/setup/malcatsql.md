# malcatsql 本机安装

插件只提供使用说明，引擎（Python 包）在本仓库 `tools/malcatsql`，每台机器要装一次。插件自带安装脚本，agent 可以替你装。

## 需要什么

| 项 | 要求 |
|----|------|
| Malcat | 0.9.x，授权支持 Python API（实测 0.9.15） |
| Python | **CPython 3.13**。Malcat 的 `malcat.pyd` 只支持 3.13，别的版本导入不了 |
| malcatsql 引擎 | 推荐 0.3.0，与本市场的插件 0.3.0 对应 |

## 安装步骤

**推荐：让 agent 自己装。** 在 Claude 里说"装一下 malcatsql"，或者直接开始用 `/malcatsql:connect`，agent 发现命令不存在时会先征求你同意，然后运行插件自带的安装脚本：

```
pwsh -NoProfile -File <malcatsql 插件目录>\scripts\install.ps1
```

脚本会做四件事，可以重复运行（重复运行就是升级）：

1. 检查 CPython 3.13 是否存在。没有就停下，提示安装（`winget install Python.Python.3.13`）。
2. 让 3.13 能 `import malcat`：在用户 site-packages 写一个 `malcat.pth`，内容是 `<Malcat>\bin`。这和 Malcat 自带的 `install_api.py` 效果一样。Malcat 目录会自动查找，找不到时加参数 `-MalcatDir <含 bin\malcat.pyd 的目录>`。Malcat 授权激活要你自己在 Malcat 里做，脚本不碰授权。
3. 用 pip 从本仓库 GitHub 安装引擎（`tools/malcatsql`）。
4. 把 `malcatsql.exe` 所在目录加入**用户** PATH。新开的终端和会话里直接敲 `malcatsql` 即可。

**手动安装**（等价）：

```
py -3.13 <Malcat 目录>\install_api.py
py -3.13 -m pip install "malcatsql[server] @ git+https://github.com/BlasterXiao/malscope-market.git#subdirectory=tools/malcatsql"
```

再把 `%APPDATA%\Python\Python313\Scripts` 加入用户 PATH，重开终端后验证：

```
where malcatsql
malcatsql --version
```

**开发本仓库时**用可编辑安装，改代码立即生效：

```
pwsh -NoProfile -File plugins\malcatsql\scripts\install.ps1 -Source tools\malcatsql -Editable
```

## 为什么一定要用 `malcatsql` 命令

本机可能装了样本目录执行保护 hook：命令里同时出现受保护样本目录和 `python` / `.exe` 等字样就会被拦截。用 `malcatsql <样本>` 调用，样本按哈希命名、不带可执行后缀时不会被误拦；写成 `python -m malcatsql ...` 一定会被拦。被拦截时不要绕过，由分析人员决定是否 `/unprotect`。

## 常见问题

| 现象 | 原因 | 处理 |
|------|------|------|
| `No module named 'malcat'` | 3.13 还没装 Malcat API | 重新运行安装脚本，必要时加 `-MalcatDir` |
| `where malcatsql` 找不到 | Scripts 目录不在 PATH，或终端是安装前打开的 | 重开终端；仍不行就重新运行安装脚本 |
| 导入 `malcat.pyd` 失败 | 用的不是 3.13 | 安装脚本只用 `py -3.13`，重新运行即可 |
| 查询报表或列不存在 | 引擎与插件版本不一致 | 更新插件后重新运行安装脚本 |

## 版本组合

| 插件版本 | 推荐引擎 | 实测通过 |
|----------|----------|----------|
| 0.3.0 | 0.3.0 | 待填 |

插件和引擎在同一个仓库里一起发布，升级时一起拉取即可。
