# K04M 日志解析器

一个用于 Minecraft 服务端日志的 **Krypt04Mcg** 分片重组、二进制包结构查看与 JSON 导出工具。GUI 使用 Rust + egui，支持 `.log` 与 `.log.gz`。

![Rust](https://img.shields.io/badge/Rust-2024-000000?logo=rust)
![GUI](https://img.shields.io/badge/GUI-egui-1f6feb)

## 功能

- 扫描一个或多个 `.log` / `.log.gz` 文件，或递归扫描整个 `logs` 文件夹。
- 识别 `[KRYPT04MCG] <32位消息ID> <索引> <总数> <Base64URL载荷>` 分片。
- 支持乱序重组、跨文件合并、重复分片检测、索引冲突/总数冲突报告。
- 按 Krypt04Mcg `PacketCodec` 的 v1–v4 线格式解析完整二进制包：
  - 协议版本、包类型、标志位
  - `sender` / `receiver` 的 UTF-8 字符串与长度前缀
  - 毫秒时间戳、16 字节消息 ID
  - v4 会话消息的 `sessionId` 与 `sequence`
  - KEM / 签名 / AEAD / HKDF 算法标识
  - nonce、KEM 封装密文、AEAD 密文与认证标签、签名
  - 旧版 v1/v2 的 AAD 分片索引/总数
  - 尾随字节和截断位置
- 所有重组结果（包含不完整、冲突、结构错误的消息）显示在同一个列表。
- 消息详情左右分栏：左侧字段树，右侧十六进制查看器。
  - 点击字段：黄色高亮该字段对应的全部二进制字节。
  - 悬停不超过 64 字节的字段：蓝色临时预览；大字段只在点击后高亮，避免整屏噪声。
  - 可选按字段类别着色。
  - 自动滚动到被选字段。
- 查看分片来源：文件、行号、时间、载荷长度、重复/缺失。
- 一键导出**全部消息**为 JSON，包含字段树、字段偏移、分片来源、原始二进制（Base64URL 与十六进制）。

## 构建与运行

需要稳定版 Rust（1.88+）：

```bash
cargo test
cargo build --release
./target/release/k04m-log-parser
```

直接加载日志：

```bash
./target/release/k04m-log-parser /path/to/logs
./target/release/k04m-log-parser /path/to/logs/latest.log
```

无界面导出 JSON：

```bash
./target/release/k04m-log-parser --export parsed.json /path/to/logs
```

其他参数：

```text
--export <路径>  解析后导出 JSON，不启动图形界面
-h, --help      显示帮助
-V, --version   显示版本
```

GUI 快捷方式：

| 快捷键 | 功能 |
| --- | --- |
| `Ctrl+O` | 打开日志文件 |
| `Ctrl+Shift+O` | 打开日志文件夹 |
| `Ctrl+R` | 重新加载当前路径 |
| `Ctrl+E` | 导出 JSON |

也可以把文件或文件夹直接拖入窗口。

## 界面说明

### 消息列表

每条**消息 ID + 传输发送者**组合为一个重组单元。一条消息可能由多个分片组成，也可能来自多个日志文件。状态含义：

- **已解析**：所有分片齐全、Base64URL 解码成功、包结构解析成功。
- **不完整**：缺少部分分片，无法生成完整二进制。
- **错误**：分片总数冲突、Base64URL 解码失败、包结构错误、尾随字节、同索引载荷冲突等。

> “已解析”仅表示结构符合 `PacketCodec`，**不代表**签名已验证、密文已认证或发送者已受信任。

### 字段与字节高亮

字段面板中的每个节点都有精确的二进制偏移和长度：

- 字符串字段的范围包含 `u16` 长度前缀和 UTF-8 正文；子节点分别显示长度前缀与正文。
- `i32`/`u32` 长度字段的字节范围包含长度前缀。
- AEAD 密文会进一步拆为“加密正文”和“16 字节认证标签”。
- 混合 KEM/签名算法只展示总长度，不猜测其内部复合编码。

点击字段后，右侧十六进制视图中该范围会以黄色背景显示，ASCII 列同步高亮。若所选字段长度为 0（例如会话消息中不存在的 KEM 算法字段），会显示“该字段不占用字节”。

### 分片来源

展开“分片与来源”可以查看每个分片的所有出现位置，包括重复行。缺失索引会明确列出。

## 协议解析范围

线格式按 `Krypt04Mcg` 的 `PacketCodec.java` 实现：

```text
u8   protocolVersion
u8   packetType
u8   flags
u16  senderLength + senderUtf8
u16  receiverLength + receiverUtf8
i64  timestampMillis
 16  messageId
--- SESSION_MESSAGE(v4) only ---
u16  sessionIdLength + sessionIdUtf8
i64  sequence
--- v1/v2 only ---
i16  aadFragmentIndex
i16  aadFragmentTotal
--- conditional ---
u16  kemAlgorithmLength + kemAlgorithmUtf8
u16  signatureAlgorithmLength + signatureAlgorithmUtf8
u16  aeadAlgorithmLength + aeadAlgorithmUtf8
u16  hkdfAlgorithmLength + hkdfAlgorithmUtf8
u16  nonceLength + nonce
i32  kemCiphertextLength + kemCiphertext
i32  ciphertextLength + ciphertext
i32  signatureLength + signature        (omitted for SESSION_MESSAGE)
```

字段存在性遵循 v3/v4 规则：

- v3/v4 不再编码旧版分片索引/总数。
- 未签名包不编码签名算法字符串。
- v4 `SESSION_MESSAGE` 不编码 KEM 算法、签名算法和签名字段。
- v4 `SESSION_MESSAGE` 在消息 ID 后编码会话 ID 和序号。

## JSON 导出结构

根对象包含：

```json
{
  "tool": "K04M 日志解析器",
  "version": "0.1.0",
  "format_version": 1,
  "exported_at_utc": "...",
  "cryptographic_verification": false,
  "payload_decrypted": false,
  "summary": {
    "source_files": 7,
    "fragment_lines": 259,
    "malformed_lines": 0,
    "total_messages": 13,
    "parsed_messages": 13,
    "incomplete_messages": 0,
    "invalid_messages": 0
  },
  "sources": [ ... ],
  "messages": [ ... ]
}
```

每条消息包含：

- `message_id`、`transport_sender`、`status`、`first_seen` / `last_seen`
- `fragment_total`、`unique_fragments`、`occurrence_count`、`duplicate_count`、`conflicts`、`missing_indices`
- `binary_length`、`binary_base64url`、`binary_hex`（完整重组二进制）
- `packet`：解析后的结构字段、算法、时间戳、session 信息、`fields` 字段树
- `fragments`：每个物理分片所在文件、行号、时间和载荷

字段树中的每个 `DataField` 都含 `offset` 与 `length`，可直接用于定位原始字节：

```json
{
  "name": "sender",
  "label": "发送者 (sender)",
  "offset": 3,
  "length": 8,
  "value": "tester",
  "category": 1,
  "children": [ ... ]
}
```

## 重要限制

- 日志里只有**加密后的包**。没有会话密钥或长期私钥时，无法解密聊天正文；本工具不尝试伪造解密结果。
- 不执行签名验证、AEAD 认证、会话重放检查或 TOFU 信任判断。它只读取日志中可见的协议结构。
- 包时间戳是发送方声明值，未经过本工具认证；日志行时间来自服务器日志。
- 混合 KEM 封装和混合签名内部由 Bouncy Castle 复合格式定义，本工具只展示整体字节范围。
- 超大日志会一次性读入内存并同步解析；当前目标场景是 Minecraft `logs/` 目录（通常几十 MB 以内）。

## GitHub Actions

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) 会在以下场景自动运行：

- push 任意分支
- pull request
- 手动 `workflow_dispatch`

流程：

1. **Check**：在 Ubuntu 上安装 Linux GUI 构建依赖，执行 `cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test --locked`。
2. **Release build**：测试通过后，在 Linux、Windows、macOS 上分别执行 `cargo build --release --locked`。
3. **Artifacts**：将三平台 release 二进制上传到本次 Actions 运行页面，保留 14 天。artifact 名称格式为 `k04m-log-parser-<OS>-<ARCH>`。

无需在仓库中配置任何 secrets；`Cargo.lock` 已锁定依赖版本。发布 job 已在工作流中显式申请 `contents: write`，用于创建 GitHub Release。

### 发布 Release

[`.github/workflows/release.yml`](.github/workflows/release.yml) 用于发布 GitHub Release。

触发方式：

- 推送符合 `v*` 的 tag，例如 `v0.1.0`
- 在 GitHub Actions 页面手动运行 **Release**，输入一个已存在的 tag

发布流程：

1. 校验 tag 必须以 `v` 开头，且必须与 `Cargo.toml` 中的版本完全对应（例如 `v0.1.0` ↔ `version = "0.1.0"`）。
2. 再次执行格式、Clippy 和测试检查。
3. 在 Linux、Windows、macOS 上构建 release 二进制并打包：
   - Unix：`k04m-log-parser-<version>-<OS>-<ARCH>.tar.gz`
   - Windows：`k04m-log-parser-<version>-<OS>-<ARCH>.zip`
4. 生成 `SHA256SUMS.txt`。
5. 创建 GitHub Release，上传全部包和校验和，并自动生成 release notes。
   带 `-` 的版本 tag（如 `v0.2.0-rc.1`）会标记为 pre-release。

发布示例：

```bash
# 先更新 Cargo.toml 中的 version 并提交
git tag v0.1.0
git push origin v0.1.0
```

重复运行发布工作流时会覆盖同名 release assets，不会重复创建 release。

## 开发

```bash
cargo fmt
cargo test
cargo clippy --all-targets -- -D warnings
```

模块划分：

| 文件 | 功能 |
| --- | --- |
| `src/fragment.rs` | 分片行识别、分组、重组、冲突检测 |
| `src/log_reader.rs` | 文件/目录发现、gzip、逐行扫描、日期推断 |
| `src/packet.rs` | v1–v4 二进制包结构解析、字段偏移与字段树 |
| `src/export.rs` | 完整 JSON 导出 |
| `src/app.rs` | egui 界面、消息列表、字段/十六进制联动 |
| `src/model.rs` | 数据模型 |

## 许可

本项目使用 [Unlicense](LICENSE)，发布为公有领域软件。
