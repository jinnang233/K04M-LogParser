# K04M 日志解析器

一个用于 Minecraft 服务端日志的 **Krypt04Mcg** 分片重组、二进制包结构查看、**私钥解密**与 JSON 导出工具。GUI 使用 Rust + egui，支持 `.log` 与 `.log.gz`。

![Rust](https://img.shields.io/badge/Rust-2024-000000?logo=rust)
![GUI](https://img.shields.io/badge/GUI-egui-1f6feb)

> [!WARNING]
> 本项目代码由 **AI 辅助生成**，**且尚未进行专业安全审计**。使用、修改、发布或集成前，请务必进行 **人工审查**，重点检查代码逻辑、网络请求、本地文件读写、依赖来源和许可证兼容性，并自行承担相应风险。
> 
> 在使用本项目的可执行文件前，请务必使用**VirusTotal**扫描代码，并使用**沙盒检查**。本项目**不能保证构建环境绝对干净安全**，**因此也不能保证最终构建产物一定没有木马病毒**，**如果您对此有顾虑，请不要使用本软件**。如果作为项目的维护者，我的电脑已经被木马病毒篡改，那构建产物同样可以被篡改。因此，如果可以，请尽可能在隔离环境（比如虚拟机环境）中运行。虽然这不能完全杜绝这种风险，比如虚拟机穿透的风险，但能在一定程度上减轻这种风险。最好的方式是不要直接运行构建产物，推荐审计代码和依赖后自行构建。
>
> 本项目使用 Rust 编写，但这并不代表代码、依赖或构建产物绝对安全。Rust 主要降低内存安全风险，不能防止逻辑漏洞、供应链攻击、恶意依赖、构建环境污染或错误的文件/网络操作。
>
> 如果您发现任何代码安全性问题，或者发现任何版权或许可证问题，亦或是发现供应链或构建产物安全问题，请在Issues中提出。感谢您的理解。 



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
- 加载一个或多个 Krypt04Mcg 私钥/账户，自动尝试解密包正文：
  - 支持 `LocalKeyMaterial`（`keys/private/local.json`）、`sessions/*.json`、账户目录，以及包含多个账户的父目录。
  - 自动读取账户 `secrets/master.key`（owner-only 与 Windows DPAPI 模式），解密 KMCGSEC1 加密的密钥与会话文件；私钥只在内存中使用，绝不会写入导出 JSON。
  - KEM：`ML-KEM-512/768/1024`、BC 原生 `ML-KEM-768+X25519` 与 `ML-KEM-1024+X448` 复合 KEM，以及项目自定义 `K04-HYBRID-V1` 的 ML-KEM+X25519/X448 混合 KEM。
  - AEAD：`AES-256-GCM`、`ChaCha20-Poly1305`；HKDF-SHA256；自动处理 `COMPRESSED` 标志的 raw DEFLATE。
  - `SESSION_MESSAGE` 使用加载的会话密钥按 `sessionId` 解密；会话交换请求可用长期私钥解密，响应因使用一次性临时 KEM 公钥通常无法从日志解密。
- 明文展示：UTF-8 文本直接显示，JSON 载荷格式化显示；可一键复制明文/JSON。
- 一键导出**全部消息**为 JSON，包含字段树、字段偏移、分片来源、原始二进制（Base64URL 与十六进制）、解密状态与明文。

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

加载私钥并解密：

```bash
# 单个 LocalKeyMaterial 文件
./target/release/k04m-log-parser --key /path/to/local.json /path/to/logs

# 账户目录（含 keys/private/local.json、sessions/、secrets/master.key）
./target/release/k04m-log-parser --key /path/to/config/krypt04mcg/accounts/<uuid> /path/to/logs

# 包含多个账户的父目录；--key 可重复
./target/release/k04m-log-parser --key /path/to/accounts --key /another/account /path/to/logs
```

无界面导出 JSON（同样支持 `--key`）：

```bash
./target/release/k04m-log-parser --key /path/to/account --export parsed.json /path/to/logs
```

其他参数：

```text
--key <路径>     加载私钥/会话密钥，可重复；支持 LocalKeyMaterial、
                  sessions 文件/目录、账户目录或包含多个账户的父目录
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
| `Ctrl+K` | 打开私钥/会话密钥窗口 |

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

### 解密结果

选中一条已成功解析的消息后，头部下方会显示“解密结果”面板：

- **已解密**：显示匹配的密钥所有者、算法、是否解压、明文长度。UTF-8 文本直接显示；JSON 载荷默认展开并格式化显示。右侧可复制明文或格式化 JSON。
- **缺少密钥 / 不支持 / 解密失败**：显示原因，并可展开查看每个候选密钥的尝试结果；“加载私钥…”可直接打开密钥窗口。
- 消息列表中的“明文”/“无密钥”标记以及“只看已解密”勾选项可快速筛选。

密钥窗口（`Ctrl+K`）列出所有已加载的私钥与会话密钥，包括所有者、算法、指纹和来源文件，可单独移除或全部清空。私钥内容不会显示在界面上，也不会写入导出。

## 解密包正文

点击工具栏的 **密钥**（`Ctrl+K`）打开密钥窗口：

- **加载私钥文件…**：可多选 `local.json`、`sessions/*.json` 或单个私钥记录 JSON。
- **加载账户/密钥目录…**：选择 Krypt04Mcg 账户目录、`keys/`、`sessions/`，或包含多个 `accounts/<uuid>/` 的父目录。工具会递归发现这些账户。
- 也可以把 `.json` 密钥文件或账户目录直接拖入窗口；日志文件仍按日志处理。
- 加载后会自动重新解密当前所有消息；移除单个密钥、清空密钥同样会立即刷新结果。

解密匹配规则：

- **KEM 消息（类型 1/2/3）**：按包内 `receiver` 匹配私钥 `owner`，并优先使用 KEM 算法一致的私钥。私钥可以先于日志加载，也可以随时补充。
- **会话消息（类型 4）**：按包内 `sessionId` 匹配已加载的会话密钥（来自 `sessions/*.json`）。会话消息与长期私钥无关。
- **会话交换请求（类型 3，无 `SESSION_RESPONSE`）**：用接收方长期 KEM 私钥解密，可查看握手 JSON。
- **会话交换响应（类型 3，带 `SESSION_RESPONSE`）**：加密到发起方的一次性临时 KEM 公钥，临时私钥只存在于内存中，日志通常无法解密。

密钥文件格式：

- 明文 `LocalKeyMaterial` JSON（含 `kemPrivateKey.keyData`）。
- KMCGSEC1 加密文件（`KMCGSEC1` magic + 12 字节 nonce + AES-256-GCM 密文）。工具会在文件祖先目录中查找 `secrets/master.key`，并以账户根相对路径作为 AAD 解密。owner-only 主密钥（模式 2，Linux/macOS 默认）直接使用；Windows DPAPI（模式 1）在 Windows 上通过当前用户 DPAPI 解包，必须与创建 `master.key` 的 Windows 用户相同。在 Linux/macOS 上遇到模式 1 会给出明确错误，需要先导出明文 `LocalKeyMaterial` 或 owner-only 密钥。
- `sessions/*.json` 的新版账本（含 `stateVersion`/`session`）和旧版单条 `SessionRecord` 都支持；待提交会话（`prepared.session`）也会加载并标注。也可以手工创建只含 `peer`、`sessionId`、`secret` 三个字段的 JSON 来导入单个会话密钥（`secret` 为 Base64URL 编码的 32 字节）。
- 会话轮换会覆盖账户中的旧 `sessions/*.json`；如果旧会话密钥没有备份，对应历史消息只能显示“缺少密钥”。

解密状态：

- **已解密**：KEM 解封装（或会话密钥派生）和 AEAD 认证都成功；若 `COMPRESSED` 标志存在，已先做 raw DEFLATE 解压。合法 UTF-8 直接显示，非 UTF-8 明文以十六进制显示。
- **缺少密钥**：没有 `owner` 或 `sessionId` 匹配的密钥；面板中可直接打开密钥窗口。
- **不支持**：算法不在本工具实现范围内（例如 CMCE/HQC/NTRU/S-NTRU KEM、RSA/ECDH 复合 KEM），或遇到临时 KEM 响应。
- **解密失败**：找到匹配密钥，但 KEM 解封装、AEAD 认证或解压失败。展开“已尝试的密钥”可查看每个候选的具体错误。

> 解密成功只表示 **AEAD 标签验证通过**，即密文由持有该密钥的一方生成。本工具**不验证** PQ 签名，也不建立发送者身份信任、新鲜度或重放结论。日志会同时记录双向消息，因此加载多个玩家的私钥可以解密各自收到的包。

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
  "format_version": 2,
  "exported_at_utc": "...",
  "cryptographic_verification": false,
  "payload_decrypted": true,
  "decryption_summary": {
    "decrypted_messages": 3,
    "no_matching_key": 8,
    "unsupported_messages": 1,
    "failed_messages": 0,
    "not_attempted": 1
  },
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
- `decryption`：解密状态、匹配的密钥所有者/来源/算法、`key_kind`（`private_key` 或 `session_secret`）、是否解压、明文字节长度、`plaintext`（合法 UTF-8 时）、`json`（明文为 JSON 对象/数组时）、`plaintext_hex`、`plaintext_base64url`、错误信息与全部候选密钥尝试
- `fragments`：每个物理分片所在文件、行号、时间和载荷

导出**不包含任何私钥或会话密钥材料**；只包含解密结果和密钥所有者/来源等来源信息。

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

- 日志里只有**加密后的包**。没有匹配的长期私钥（KEM 消息）或会话密钥（`SESSION_MESSAGE`）时，只能查看结构，本工具不会伪造解密结果。
- KEM 支持范围：`ML-KEM-512/768/1024`、BC 原生 `ML-KEM-768+X25519` / `ML-KEM-1024+X448` 复合 KEM，以及 `K04-HYBRID-V1` 的 ML-KEM+X25519/X448 混合 KEM。其他 KEM（CMCE、HQC、NTRU、S-NTRU、RSA/ECDH 复合等）会显示为“不支持”。
- AEAD 支持 `AES-256-GCM` 与 `ChaCha20-Poly1305`。流通道使用的 XChaCha20-Poly1305 不在此工具的数据包解密范围内。
- 会话交换响应使用一次性临时 KEM 公钥加密，临时私钥不落盘，通常无法从日志解密；会话消息需要账户 `sessions/` 中的会话密钥。
- Windows DPAPI 主密钥绑定创建它的 Windows 用户配置文件；换用户、换机器或复制到 Linux/macOS 后无法解包（除非有漫游配置文件或 DPAPI 备份密钥）。
- **不执行签名验证**、发送者信任、新鲜度或重放检查。AEAD 认证成功不等于发送者身份可信。
- 包时间戳是发送方声明值，未经过本工具认证；日志行时间来自服务器日志。
- 混合 KEM 封装和混合签名内部由 Bouncy Castle 复合格式定义，本工具只展示整体字节范围（解密封装除外）。
- 超大日志会一次性读入内存并同步解析；当前目标场景是 Minecraft `logs/` 目录（通常几十 MB 以内）。

## GitHub Actions

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) 会在以下场景自动运行：

- push 任意分支
- pull request
- 手动 `workflow_dispatch`

流程：

1. **Check**：在 Ubuntu 上安装 Linux GUI 构建依赖，执行 `cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test --locked`。
2. **Windows DPAPI**：在 `windows-latest` 上运行 `dpapi_protected_master_key_and_kmcg_round_trip`，验证 DPAPI 主密钥解包与 KMCGSEC1 路径 AAD。
3. **Release build**：测试通过后，在 Linux、Windows、macOS 上分别执行 `cargo build --release --locked`。
4. **Artifacts**：将三平台 release 二进制上传到本次 Actions 运行页面，保留 14 天。artifact 名称格式为 `k04m-log-parser-<OS>-<ARCH>`。

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
| `src/decrypt.rs` | 私钥/会话密钥加载、KMCGSEC1、KEM 解封装、AAD 重建、AEAD 解密 |
| `src/export.rs` | 完整 JSON 导出 |
| `src/app.rs` | egui 界面、消息列表、字段/十六进制联动、密钥与明文面板 |
| `src/model.rs` | 数据模型 |

### 解密测试向量

`tests/data/decryption-vectors.json` 由 Krypt04Mcg 的 Bouncy Castle 实现实际生成；其中的私钥均为一次性测试密钥，请勿用于真实流量。覆盖：

- ML-KEM-768+X25519 原生复合 KEM（AES-GCM / ChaCha20-Poly1305，压缩/未压缩）
- ML-KEM-1024+X448 原生复合 KEM
- 自定义 `K04-HYBRID-V1` ML-KEM-512+X25519 / ML-KEM-1024+X25519 / ML-KEM-512+X448
- 裸 ML-KEM-768
- SESSION_MESSAGE 会话密钥
- SESSION_EXCHANGE 请求
- KMCGSEC1 加密账户目录（`secrets/master.key` + `keys/private/local.json` + `sessions/`）
- Windows-only 测试：在 Windows CI 上用 `CryptProtectData` 生成 mode-1 主密钥，验证 DPAPI 解包与 KMCGSEC1 路径 AAD 的完整链路；Linux/macOS 构建不包含该分支

重新生成（需要先构建 Krypt04Mcg，并准备 BC 1.86 与 Gson jar）：

```bash
BC_JAR=/path/to/Krypt04Mcg/build/processIncludeJars/bcprov-jdk18on-1.86.jar
GSON_JAR=$(find ~/.gradle/caches -name 'gson-2.14.0.jar' | head -1)
KRYPT_CLASSES=/path/to/Krypt04Mcg/build/classes/java/main
javac -cp "$KRYPT_CLASSES:$BC_JAR:$GSON_JAR" -d /tmp/k04m-vectors \
    tools/generate_decryption_vectors.java
java -cp "/tmp/k04m-vectors:$KRYPT_CLASSES:$BC_JAR:$GSON_JAR" \
    GenVectors > tests/data/decryption-vectors.json
```

## 许可

本项目使用 [Unlicense](LICENSE)，发布为公有领域软件。
