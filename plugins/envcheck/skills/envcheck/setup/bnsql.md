# bnsql 本机安装

插件只提供使用说明，下面这些需要每台机器自己装。

## 需要什么

| 项 | 要求 |
|----|------|
| Binary Ninja | 已安装并有有效授权。bnsql 以无界面方式加载 BN 核心库，请确认你的授权支持无界面（headless）使用，以 Vector35 官方说明为准 |
| bnsql 程序 | 推荐 0.0.13，与本市场钉住的插件 0.0.13 对应 |

## 安装步骤

1. 从 https://github.com/0xeb/bnsql/releases 下载与插件对应版本的 Windows 包。
2. 把 `bnsql.exe` 放到 PATH 中的某个目录，或者放在 `binaryninja.exe` 同一目录。
3. 让 bnsql 找到 BN 核心库，二选一：
   - 设置环境变量 `BN_INSTALL_DIR`，值为 BN 安装目录（Windows 默认 `C:\Program Files\Vector35\BinaryNinja`）
   - 把 BN 安装目录加入 PATH
4. 重开终端，验证：

   ```
   where bnsql
   bnsql --version
   ```

## 常见问题

| 现象 | 原因 | 处理 |
|------|------|------|
| `Binary Ninja core library (binaryninjacore.dll) was not found` | 找不到 BN 安装目录 | 按第 3 步设置 `BN_INSTALL_DIR` 或 PATH |
| 查询报表或列不存在 | bnsql 程序与插件版本不一致 | 把程序换成推荐版本 |

## 版本组合

| 插件提交 | 插件版本 | 推荐 bnsql 程序 | 实测通过 |
|----------|----------|-----------------|----------|
| fef0d4f | 0.0.13 | 0.0.13 | 待填 |

升级插件提交后，在这里加一行；实测通过后在最后一列写上日期和 BN 版本。
