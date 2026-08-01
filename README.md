# 芙芙启动器主插件合成台重定向解限补丁

一个轻量级工具，用于移除芙芙启动器主插件（FufuLauncher-Plugin）中 `RedirectCraft` 的场景限制。

## 下载与使用

1. 前往 [Releases](../../releases) 页面，下载最新的 `FufuPluginRedirectCraftPatcher.exe`。
2. 双击运行（无需安装任何依赖）。
3. 在弹出的窗口中点击 **Browse…**，选择**芙芙启动器的根目录**（即包含 `FufuLauncher.exe` 和 `Plugins` 文件夹的目录）。
4. 点击 **Analyze**，等待分析完成。
5. 如果状态显示绿色的 `Patchable`，点击 **Apply patch** 即可完成。

> **提示**：操作前请完全退出游戏和启动器，否则 DLL 可能被占用无法写入。

### 关于 Windows Defender / SmartScreen 提示

由于 EXE 由 PowerShell 脚本打包生成且无数字签名，Windows 或安全软件可能会弹出警告。如果遇到拦截，请点击"更多信息" → "仍要运行"，或将文件添加到杀软白名单。

如果你对 EXE 的来源有疑虑，也可以直接从源码运行（见下方[开发者说明](#开发者说明)）。

## 状态说明

| 状态颜色 | 含义 |
|----------|------|
| 🟢 **Patchable** | 可以安全打补丁 |
| 🔵 **AlreadyPatched** | 当前 DLL 已是补丁后的版本 |
| 🔴 **Unsupported** | 当前 DLL 不符合自动补丁条件（如签名无效、非官方版本等） |

## 工具做了什么

工具只移除 `RedirectCraft` 场景检查中的一个条件跳转，保留：

- `RedirectCraft` 功能开关
- 自动烹饪和自动探索派遣各自的场景判断
- 插件初始化、游戏前台、热键及对象有效性检查

工具不使用固定偏移，而是通过语义字符串与代码控制流自动定位。对于任何带有效数字签名的官方 DLL，工具会验证：

1. 文件是 64 位 DLL（AMD64 PE），并具有有效的原始 Authenticode 签名
2. 关键字符串（`RedirectCraft`、合成台日志、自动烹饪日志）在文件中均唯一
3. 合成台日志存在唯一的 RIP-relative 代码引用
4. 功能开关条件分支和场景条件分支跳向同一个 Craft 代码块末尾
5. 只准备移除紧邻 Craft 代码块的第二个条件分支
6. 所有相关地址位于同一个 `.pdata` 函数范围内
7. 最终必须恰好得到一个候选位置

任一条件不成立时，工具会显示 `Unsupported` 并拒绝写入。这意味着它能自动适配代码结构相近的更新，但不能保证适配源码结构或编译器输出发生较大变化的任意未来版本。

## 备份与还原

补丁前会在 DLL 同目录创建：

- `*.fufu-backup` —— 原始官方 DLL，不以 `.dll` 结尾，避免被启动器扫描
- `*.redirectcraft.json` —— 记录原始/补丁哈希、偏移和字节的校验清单

点击 **Restore backup** 可按清单校验并还原。工具会自动查找与当前 DLL 哈希匹配的清单；如果自动查找失败，也可以手动选择 JSON 文件。

> ⚠️ 不要删除与当前插件版本对应的备份和 JSON 清单。

## 注意事项

- 修改 DLL 后数字签名必然失效，安全软件或反作弊系统可能拦截。
- 启动器或插件更新程序可能覆盖补丁；更新后需要对新的官方 DLL 再运行一次工具。
- 请自行评估使用第三方注入插件可能带来的稳定性与账号风险。

## 开发者说明

如果你更喜欢从源码运行，或者需要命令行自动化：

### 环境要求

- Windows 10 / 11
- PowerShell 5.1（系统自带）

### 运行方式

```powershell
# GUI 模式（需要 STA 线程模型，建议用 CMD 启动）
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File .\RedirectCraftPatcher.ps1

# 命令行模式
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\RedirectCraftPatcher.ps1 `
  -Action Analyze -Path "D:\Games\FufuLauncher"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\RedirectCraftPatcher.ps1 `
  -Action Patch -Path "D:\Games\FufuLauncher"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\RedirectCraftPatcher.ps1 `
  -Action Restore -Path "D:\Games\FufuLauncher"