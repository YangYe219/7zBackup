# 7zBackup — 7z 加密备份小工具

> Drag-and-drop encrypted backup for Windows: AES-256 + encrypted file names, builds with nothing but the compiler Windows already ships.
>
> 把文件/文件夹拖进窗口，输入密码，回车 —— 得到一个高强度加密的 `.7z`，适合上传网盘做备份。

## 它解决什么问题

往网盘放备份需要真加密：**AES-256 + 文件名加密（`-mhe`）**，没有密码的人连压缩包里有哪些文件都看不到。压缩完成后默认自动校验包完整性，还可以生成 SHA-256 校验清单，确保传到网盘上的是可用备份。

## 特性

- **拖拽即用**：文件/文件夹拖进窗口（或点"添加文件/文件夹"），输入密码回车即压缩；WinForms 绿色单文件，免安装
- **高强度加密**：AES-256（7z 默认）+ 文件名加密；压缩完自动校验完整性
- **三档压缩等级**：仅存储（照片/视频首选）/ 标准（LZMA2，32MB 字典）/ 极限（128MB 字典）；加密强度与等级无关，只取决于密码
- **批量模式**：拖入的每个项目各自压一包，同名自动改名互不覆盖，逐包校验、失败自动重试、失败包不影响其他包 —— 适合按月/按项目增量备份
- **分卷**：切成固定大小（如 2GB）多个文件，应对网盘单文件限制；解压只需用 7-Zip 打开第一个 `.001`
- **SHA-256 校验清单**：记录每个包的指纹供上传后核对；清单不含包内文件名，可随备份一起上传不泄密
- **细节兜底**：自动排除 Thumbs.db 等垃圾文件、输出前磁盘空间预检、输出文件不会把自己压进去、归档内不泄露本机绝对路径
- **高 DPI 适配**：手动控件树缩放 + Anchor 摘锚重排，150% 缩放屏不重叠不截断；中文文件名全程 UTF-8 不乱码
- **密码绝不落盘**：设置文件只记住界面选项，永不保存密码
- **自带自检**：`7zBackup.exe --selftest` 共 17 项（压缩、加密、解压逐字节比对、相对路径、分卷、批量、清单、垃圾排除……）

## 密码批量验证器（7zPwdCheck）

担心密码记错？配套的 `7zPwdCheck.exe` 一次拖入多个压缩包批量验密：

- 本工具生成的包（文件名加密）**列目录即验密，秒级出结果**，不用解压数据
- 可选"完整校验"：真正解密全部数据核对完整性，相当于给备份做体检
- 分卷包只需拖入 `.001`；验证器同样不保存密码
- 建议每季度做一次恢复演练：从网盘随机下载一个包完整校验一遍

## 快速上手

1. 从 [Releases](../../releases) 下载 `7zBackup.exe`（或按下一节自己编译）
2. 双击运行，把要备份的东西拖进窗口
3. 输入密码 → 回车，完成后点「打开所在文件夹」
4. 把生成的 `.7z` 传到网盘

**注意事项**

- 密码丢了 = 备份永远解不开。程序不保存密码，请务必记牢（建议另抄一份与网盘账号分开存放）
- 密码建议 12 位以上混合大小写/数字/符号；**不能包含英文双引号 `"`**
- 不要"以管理员身份运行"，否则 Windows 会禁用拖拽
- 解压用 7-Zip、Bandizip 等任意支持 7z 的工具，输密码即可

## 从源码构建（零环境）

改了源码后双击 `build.bat`（主程序）或 `build_pwdcheck.bat`（验证器）即可重新编译 —— 使用 **Windows 自带的 .NET Framework C# 编译器**（`csc.exe`），不需要安装任何 SDK 或 Visual Studio。

- 系统要求：Windows 10/11；运行时需要已安装 [7-Zip](https://www.7-zip.org/)（自动按 Program Files → 注册表 → PATH 三级查找）
- 自检：命令行运行 `7zBackup.exe --selftest` / `7zPwdCheck.exe --selftest`，结果写入同名 `*_result.txt`

## 目录结构

```
7zBackup.cs          主程序源代码（拖拽加密备份）
7zPwdCheck.cs        密码批量验证器源代码
build.bat            一键编译主程序（免 SDK）
build_pwdcheck.bat   一键编译验证器
docs/
  development-notes.md   开发复盘：20+ 条踩坑记录与可复用结论
```

## 开发笔记

[docs/development-notes.md](docs/development-notes.md) 记录了本项目踩过的全部坑，做同类 Windows 工具可直接照抄：

- 7z 命令行的加密/分卷/进度/中文编码细节，以及密码验证"列目录即验密"的思路
- 用系统自带 csc 零环境编译（C# 5 语法上限、`/codepage:65001` 必加）
- WinForms 高 DPI 的手动缩放方案（`AutoScaleMode.Dpi` 不可靠、缩放前必须摘掉 Anchor）
- 自检要"真刀真枪"：错误密码必须失败、解压逐字节比对、用不可压缩数据测分卷

## English (short)

A pair of small Windows utilities for encrypted cloud-drive backups:

- **7zBackup** — drag files/folders in, type a password, get an AES-256 `.7z` with encrypted file names (`-mhe`). Supports batch mode (one archive per item), volumes, SHA-256 manifest, junk-file exclusion, disk-space preflight, and a 17-item `--selftest`.
- **7zPwdCheck** — batch password checker; name-encrypted archives verify instantly by listing, with optional full-decrypt verification.

No SDK needed to build: `build.bat` compiles with the .NET Framework `csc.exe` that ships with Windows. Runtime requirements: Windows 10/11 + 7-Zip. Passwords are never stored. Documentation is in Chinese; the tool UI is Chinese as well.

## License

[MIT](LICENSE)
