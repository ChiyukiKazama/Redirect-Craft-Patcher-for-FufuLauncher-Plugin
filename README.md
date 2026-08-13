# RedirectCraft Patcher for FufuLauncher Plugin

单exe、免安装的 Windows GUI 工具，用于移除芙芙启动器主插件中“启用合成台重定向”的场景限制。

## 使用

1. 建议先完全退出原神游戏本体和芙芙启动器。
2. 运行 `FufuRedirectCraftPatcher.exe`。
3. 选择芙芙启动器文件夹（FufuLauncher）。
4. 等待程序自动定位：

   ```text
   FufuLauncher\Plugins\FuFuPlugin\FufuLauncher.UnlockerIsland.dll
   ```

5. 状态为绿色 `PATCHABLE` 后点击 `Patch 应用补丁`。

蓝色 `PATCHED` 表示当前 DLL 已修改；红色 `UNPATCHABLE` 表示工具无法安全地唯一确认目标条件，拒绝写入文件。

## 安全机制

- 数字签名和文件版本只作为报告信息展示，不再参与 `Patchable` 判定。
- 所有 DLL 统一通过 UPX 解包及语义/控制流结构验证。
- 支持普通 PE 和标准 UPX 压缩的 AMD64 DLL。
- UPX 5.2.0 嵌入 EXE，释放后先校验 SHA256，再隐藏运行。
- 通过配置字符串、Craft/AutoCook 日志引用、相同跳转目标和 `.pdata` 函数范围
  验证目标条件。
- 恰好只有一个候选位置时才允许写入。
- 原始 DLL 备份为 `*.fufu-backup`，不会被当作插件 DLL 扫描。
- JSON 清单记录原始/解包/补丁哈希及补丁字节，还原前重新校验。
- 补丁文件先写入临时文件，验证后使用文件替换；异常时不会留下半写文件。

## UPX 与许可证

本程序嵌入官方 UPX 5.2.0 Win64 二进制。UPX 项目：
https://github.com/upx/upx

UPX 的 `LICENSE` 和 `COPYING` 文件作为嵌入资源随 EXE 一同提供。UPX 仅用于在
临时目录解包用户选择的、经过验证的插件副本；解包结束后临时目录会被自动清理。

## 构建

运行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

使用 Windows 自带的 .NET Framework C# 编译器，生成无控制台窗口的单 EXE。
