# yara 本机安装

`yara` 插件写规则后要用本机的 `yarac` 编译、用 `yara` 核对命中。

## 安装步骤

1. 从 https://github.com/VirusTotal/yara/releases 下载 4.x 的 Windows 64 位包。
2. 解压后把 `yara64.exe`、`yarac64.exe` 改名或复制为 `yara.exe`、`yarac.exe`（如果包里已经是这两个名字就不用改），放到 PATH 中的某个目录。
3. 重开终端，验证：

   ```
   where yara
   where yarac
   yara --version
   ```

## 注意

如果本机对样本目录有执行保护，在命令里同时出现样本目录路径和 `.exe` 时可能被拦截。这种情况下 `yara` 插件会把规则标为“未验证”，需要到允许的位置再核对命中。
