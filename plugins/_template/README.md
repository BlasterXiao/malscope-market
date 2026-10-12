# 新建自有插件

1. 复制整个 `_template/` 目录，改成新插件名（小写短横线，如 `config-extract`）。
2. 改 `.claude-plugin/plugin.json` 里的 `name`、`description`。
3. 把 `skills/my-plugin/` 改成和插件同名，例如 `skills/config-extract/`，再改 `SKILL.md` 的 `name` 和内容。完整命令是 `/config-extract:config-extract`；没有重名时通常也能直接输入 `/config-extract`，以 `/` 菜单显示为准。
4. 需要模板或参考资料，放在技能目录里，在 `SKILL.md` 里用相对路径引用。
5. 在仓库根目录的 `.claude-plugin/marketplace.json` 加一条：

   ```json
   {
     "name": "config-extract",
     "description": "【自有】一句话说明适用场景",
     "category": "security",
     "source": "./plugins/config-extract"
   }
   ```

6. 在根目录 `README.md` 的插件目录表加一行。

`_template` 本身没有登记在 `marketplace.json` 里，不会被安装。
