# K04M 日志解析器

一个用于 Minecraft 服务端日志与抓包的 **Krypt04Mcg** 分片重组、二进制包结构查看、**私钥解密**、**签名验证**与 JSON 导出工具。GUI 使用 Rust + egui，支持 `.log`、`.log.gz`、`.pcap` 与 `.pcapng`。

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
- 加载一个或多个 Krypt04Mcg 私钥/账户，自动尝试解密包正文：
  - 支持 `LocalKeyMaterial`（`keys/private/local.json`）、`sessions/*.json`、账户目录，以及包含多个账户的父目录。
  - 自动读取账户 `secrets/master.key`（owner-only 与 Windows DPAPI 模式），解密 KMCGSEC1 加密的密钥与会话文件；私钥只在内存中使用，绝不会写入导出 JSON。
  - KEM：`ML-KEM-512/768/1024`、BC 原生 `ML-KEM-768+X25519` 与 `ML-KEM-1024+X448` 复合 KEM，以及项目自定义 `K04-HYBRID-V1` 的 ML-KEM+X25519/X448 混合 KEM。
  - AEAD：`AES-256-GCM`、`ChaCha20-Poly1305`；HKDF-SHA256；自动处理 `COMPRESSED` 标志的 raw DEFLATE。
  - `SESSION_MESSAGE` 使用加载的会话密钥按 `sessionId` 解密；会话交换请求可用长期私钥解密，响应因使用一次性临时 KEM 公钥通常无法从日志解密。
- 明文展示：UTF-8 文本直接显示，JSON 载荷格式化显示；可一键复制明文/JSON。
- 一键导出**全部消息**为 JSON，包含字段树、字段偏移、分片来源、原始二进制（Base64URL 与十六进制）、解密状态与明文。
- **签名验证**：使用加载的签名公钥验证包信封的 `signature` 字段，日志与抓包共用同一套匹配规则。
  - 支持 ML-DSA-44/65/87、SLH-DSA 全部 FIPS 205 参数集、项目的 `K04-HYBRID-SIGNATURE-V1` 自定义混合签名（PQ 分量为 ML-DSA/SLH-DSA，经典分量为 Ed25519/Ed448），以及 Bouncy Castle 原生复合签名 `MLDSA44-Ed25519-SHA512`、`MLDSA65-Ed25519-SHA512`、`MLDSA87-Ed448-SHAKE256`。
  - 公钥来源：账户 `keys/public/*.json`、`local.json` 的 `signaturePublicKey`、以及抓包 `krypt04mcg:public_key` 通道中的公钥共享。
  - 验签结果与解密相互独立，分别显示“签名有效 / 缺少公钥 / 不支持 / 签名无效”。
  - 其它签名算法（Falcon、SQIsign、SNOVA、MAYO、UOV、RSA/ECDSA 复合等）显示为“不支持”，不会误判为有效。
- **PCAP/PCAPNG 抓包分析**：使用 `tcpstreams` 重组 TCP、`mc_protocol` 解析 Minecraft 帧、`minecraft_data` 提供 Minecraft 26.3（协议 777）数据包 ID，提取并解析 Krypt04Mcg 的全部通道：
  - `krypt04mcg:chat_fragment`：加密聊天分片，跨两个方向合并重组并按 `PacketCodec` 解析/解密。
  - `krypt04mcg:public_key`：公钥 KeyShare 分片（`uuid:index:total:data`）重组为身份 JSON。
  - `krypt04mcg_stream:control`：流分配、会话交换、READY/END/RESET/ABORT，校验 HMAC-SHA256。
  - `krypt04mcg_stream:data/0` … `data/255`：按流方向派生 XChaCha20-Poly1305 密钥，逐条认证解密并重组业务字节流。
  - `krypt04mcg:tunnel`：旧版隧道信封结构解析。

## 构建与运行

需要稳定版 Rust（1.89+）：

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

打开或分析 pcap/pcapng 抓包：

```bash
# 直接打开 GUI
./target/release/k04m-log-parser --key /path/to/account capture.pcapng

# GUI 中也可以“打开文件/文件夹”或把 .pcap/.pcapng 拖入窗口
# 命令行分析并导出 JSON
./target/release/k04m-log-parser --key /path/to/account --export capture.json capture.pcapng

# 也可以显式使用 --pcap，并可重复
./target/release/k04m-log-parser --pcap capture.pcapng --export capture.json

# 提取所有已解密的 API 流方向到目录
./target/release/k04m-log-parser --pcap capture.pcapng \
    --key /path/to/account --extract-streams extracted-streams
```

其他参数：

```text
--key <路径>     加载私钥/会话密钥/签名公钥，可重复；支持 LocalKeyMaterial、
                  sessions、stream-api/sessions、keys/public、账户目录或
                  包含多个账户的父目录
--pcap <路径>    打开 pcap/pcapng 抓包，可重复；位置参数中的 .pcap/.pcapng
                  也会自动识别。与 --export/--extract-streams 同用时只做
                  命令行分析，否则启动图形界面
--extract-streams <目录>
                  把已解密的 API 流方向写入目录
--export <路径>  解析后导出 JSON，不启动图形界面
-h, --help      显示帮助
-V, --version   显示版本
```

GUI 快捷方式：

| 快捷键 | 功能 |
| --- | --- |
| `Ctrl+O` | 打开日志或抓包文件 |
| `Ctrl+Shift+O` | 打开文件夹（递归发现日志与抓包） |
| `Ctrl+R` | 重新加载当前路径 |
| `Ctrl+E` | 导出 JSON（日志或抓包） |
| `Ctrl+K` | 打开私钥/会话密钥/签名公钥窗口 |

也可以把文件或文件夹直接拖入窗口。

## PCAP/PCAPNG 抓包分析

GUI 与命令行都支持抓包分析。它从 pcap/pcapng 中重组 TCP 会话，解析 Minecraft 26.3 / 协议 777 的握手、登录、配置与 Play 阶段，并提取 Krypt04Mcg 通道。GUI 中聊天重组结果显示在主消息列表，其余连接、公钥共享、API 流与通道事件在“抓包详情”窗口中查看。

### 支持的通道

| 通道 | 方向 | 解析内容 |
| --- | --- | --- |
| `krypt04mcg:chat_fragment` | C2S/S2C | `peer`、`fragment`、`version`；分片文本按 `[KRYPT04MCG] <id> <index> <total> <payload>` 重组 |
| `krypt04mcg:public_key` | C2S/S2C | 公钥身份分片；按 `uuid:index:total:data` 重组并解析身份 JSON |
| `krypt04mcg_stream:control` | C2S/S2C | `EXCHANGE`、`OPEN`、`ASSIGNED`、`READY`、`END`、`RESET`、`ABORT`；HMAC-SHA256 校验 |
| `krypt04mcg_stream:data/0` … `data/255` | C2S/S2C | XChaCha20-Poly1305 记录；按槽位绑定、方向密钥与隐式计数器解密 |
| `krypt04mcg:tunnel` | C2S/S2C | `peer` + 信封（流 UUID、lease、内层 Krypt04Mcg 包） |

Minecraft 帧解析完全交给 `mc_protocol`（VarInt、字符串、压缩帧），数据包 ID 来自 `minecraft_data` 的 26.3 数据，而不是在本项目中硬编码。

### API 流与业务通道

`krypt04mcg_stream:control` 的 `OPEN`/`ASSIGNED`/`READY` 会把一个流绑定到客户端的某个 `data/N` 槽位。槽位在本地半关闭后仍会保留到对端 `END`，因此单向关闭之后仍在途的数据也能解密。每条流记录使用：

- HKDF-SHA256：`IKM = stream-api 会话 secret`，`salt = sessionId`，`info = krypt04mcg_stream/v1/data/<sessionId>/<streamUuid>/<slot>/<channel>/<source>/<target>`
- XChaCha20-Poly1305：`nonce = streamUuid(16B) || counter(8B BE)`，`AAD = krypt04mcg_stream/v1/<sessionId>/<streamUuid>/<slot>/<channel>`
- 每个方向独立从 0 开始计数；认证失败后停止该方向的后续解密并报告。

业务通道是应用自定义的不透明字节流。内置文件共享使用 `krypt04mcg_file:stream`（Java `writeUTF(name)` + `writeInt(size)` + 文件内容）；其他通道按 UTF-8/JSON/二进制自动识别，并计算 SHA-256。`--extract-streams` 会写出每个已解密流方向的完整字节。

### 密钥来源

- 聊天包/会话交换：`<account>/keys/private/local.json` 与 `<account>/sessions/*.json`。
- 原始加密流：`<account>/stream-api/sessions/*.json`（使用 `<account>/stream-api/secrets/master.key` 解密）。
- `--key` 指向账户目录时会同时加载这两套会话；也可以直接指向 `stream-api` 目录。

### 输出

`--export capture.json` 生成：

- `summary`：抓包、TCP 会话、Minecraft 连接、通道消息、聊天重组、公钥共享、API 流、流记录与明文字节统计。
- `connections`：每个 Minecraft 连接的玩家、协议版本、brand、压缩阈值、已注册通道。
- `events`：`chat_fragment`、`public_key`、`control`、`tunnel` 以及无法绑定/识别的通道消息，含时间、方向、连接、帧偏移和解析结果。
- `chat_transfers`：跨两个方向合并后的加密聊天消息、分片来源、`PacketCodec` 字段树与解密结果。
- `public_key_shares`：公钥 KeyShare 重组状态与身份摘要。
- `api_streams`：按流 UUID 合并的 API 流；每个方向包含记录索引、密文/明文长度、解密状态、内容类型、SHA-256、预览/JSON/Base64。完整解密字节只在内存中保留（`CaptureOptions::retain_stream_data`），可由 `--extract-streams` 写出，不写入 JSON。
- `warnings`：协议版本不匹配、HMAC 失败、缺失记录、未绑定槽位等。

### 限制

- 只支持未启用 Minecraft 协议加密（online-mode 的 AES 流）的抓包；本工具不实现 Minecraft 的登录加密。
- 需要抓包包含 Minecraft 握手/登录阶段，才能可靠确定协议状态、压缩阈值与玩家名；从中途开始的抓包可能只能提取服务端通道消息。
- `tcpstreams` 按四元组合并会话；同一抓包中复用相同端口的多条连接会被视为同一会话。IP 分片会被跳过。
- 流记录没有显式序号；抓包丢失或乱序会导致该方向后续记录认证失败。
- 验签需要对应发送者的签名公钥。抓包只会自动登记 `owner` 与公钥共享发送者一致的完整身份；缺失时可手动加载 `keys/public/*.json`。
- 签名算法支持范围见上文；不在范围内的算法显示“不支持”，不会被当作验证通过。
- 协议版本以 Minecraft 26.3（777）的数据包 ID 表为准；其他版本会给出警告，但可能无法正确识别数据包。

## 界面说明

### 消息列表

每条**消息 ID + 传输发送者**组合为一个重组单元。一条消息可能由多个分片组成，也可能来自多个日志文件。状态含义：

- **已解析**：所有分片齐全、Base64URL 解码成功、包结构解析成功。
- **不完整**：缺少部分分片，无法生成完整二进制。
- **错误**：分片总数冲突、Base64URL 解码失败、包结构错误、尾随字节、同索引载荷冲突等。

> “已解析”仅表示结构符合 `PacketCodec`，**不代表**签名已验证、密文已认证或发送者已受信任；签名与解密结果分别显示。

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

> 解密成功只表示 **AEAD 标签验证通过**，即密文由持有该密钥的一方生成。签名验证独立进行：只有加载了发送者的签名公钥且算法受支持时才会显示“签名有效”。验签通过也不建立额外的信任、新鲜度或重放结论。日志会同时记录双向消息，因此加载多个玩家的私钥可以解密各自收到的包。

### 验签结果

选中消息后，“验签结果”面板显示：

- **签名有效**：使用 `packet.sender` 匹配到的签名公钥验证通过。
- **缺少公钥**：没有该所有者的签名公钥；可从 `keys/public/*.json`、`local.json` 或抓包公钥共享加载。
- **不支持**：签名算法不在本工具实现范围内。
- **签名无效**：找到公钥但签名、公钥编码或算法声明不匹配。

公钥列表在密钥窗口（`Ctrl+K`）中，可单独移除；移除后立即重新验签。抓包模式下，完整的 `krypt04mcg:public_key` 共享会自动注册为签名公钥。

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
  "format_version": 3,
  "exported_at_utc": "...",
  "cryptographic_verification": true,
  "payload_decrypted": true,
  "decryption_summary": {
    "decrypted_messages": 3,
    "no_matching_key": 8,
    "unsupported_messages": 1,
    "failed_messages": 0,
    "not_attempted": 1
  },
  "signature_summary": {
    "signed_packets": 4,
    "verified": 2,
    "no_public_key": 1,
    "unsupported": 1,
    "failed": 0,
    "not_present_or_not_attempted": 9
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
- `signature`：验签状态、声称的签名者、匹配公钥的所有者/来源/算法、错误信息与全部候选公钥尝试
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
- 签名验证依赖发送者公钥。Falcon、SQIsign、SNOVA、MAYO、UOV、RSA/ECDSA 复合等未实现的算法显示为“不支持”；AEAD 认证成功不等于发送者身份可信。
- 包时间戳是发送方声明值，未经过本工具认证；日志行时间来自服务器日志。
- 混合 KEM 封装内部由 Bouncy Castle 复合格式定义，本工具只展示整体字节范围（解密封装除外）；混合签名可以验证，但字段树仍只展示整体字节范围。
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
| `src/decrypt.rs` | 私钥/会话密钥/签名公钥加载、KMCGSEC1、KEM 解封装、AAD 重建、AEAD 解密 |
| `src/signature.rs` | 公钥登记、规范签名输入、ML-DSA/SLH-DSA/混合与复合签名验证 |
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

`tests/data/signature-vectors.json` 覆盖 BC 原生复合签名、独立 ML-DSA/SLH-DSA 以及自定义混合签名；由 `tools/generate_signature_vectors.java` 生成。

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
