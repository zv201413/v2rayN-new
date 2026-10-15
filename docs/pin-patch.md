# TLS pin 补丁：原理与证据

## 问题

服务端 `argosbx.sh` 对 hy2/tuic 使用**自签证书**（`CN=www.bing.com`，SAN 同）并把
`pinSHA256=<base64 公钥指纹>` 写进节点链接（`argosbx.sh:2189`）。官方 v2rayN 无法据此建链，必须手工贴 PEM。

## 证据链（全部来自源码 / 本地实测）

### sing-box 侧：pin 是"可验证自签证书"的正规手段

- 文档 `docs/configuration/shared/tls.md`：`certificate_public_key_sha256`（**Client only**，Since **1.13.0**）
  = "List of SHA-256 hashes of server certificate public keys, in base64 format"，取值命令与 argosbx 生成 pin 的命令**完全一致**
- 源码 `common/tls/std_client.go:138-146`：

  ```go
  if len(options.CertificateSHA256) > 0 || len(options.CertificatePublicKeySHA256) > 0 {
      if len(options.Certificate) > 0 || options.CertificatePath != "" {
          return nil, E.New("certificate_sha256 or certificate_public_key_sha256 is conflict with certificate or certificate_path")
      }
      tlsConfig.InsecureSkipVerify = true
      tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
          return VerifyPinnedCertificate(options.CertificateSHA256, options.CertificatePublicKeySHA256, rawCerts)
      }
  }
  ```

  → 设置 pin 时内部自动跳过链校验、改为**比对公钥指纹**；与 `certificate`/`certificate_path` 互斥。

### 本地实测（sing-box 1.14.3，自签 CN=www.bing.com，与 argosbx 同参数）

| 用例 | 结果 | 证据 |
|---|---|---|
| hy2 + pin + `insecure:false` | PASS | 服务端日志 `inbound/hysteria2[hy2-in]: inbound connection from …` |
| hy2 无 pin + `insecure:false` | FAIL | `tls: failed to verify certificate: x509: certificate signed by unknown authority` |
| hy2 错 pin | FAIL | `unrecognized remote public key: wmmbGX49…`（真在比对） |
| hy2 错端口 + `insecure:true` | FAIL | `sendmsg: connection refused`（证明没有被直连绕过） |
| tuic + pin | PASS | — |
| tuic 无 pin | FAIL | `CRYPTO_ERROR 0x12a: x509: certificate signed by unknown authority` |
| 配置含未知字段 | 硬报错 | `decode config: … unknown field "this_field_does_not_exist"` |
| pin 与 `certificate` 同给 | 硬报错 | `certificate_public_key_sha256 is conflict with certificate or certificate_path` |

> 复现件在 `tests/`（server + 客户端变体 + `run.sh`）。

### v2rayN 侧：两个缺口

1. `ServiceLib/Handler/Fmt/Hysteria2Fmt.cs`（7.25.6 上游）
   - 导入：`pinSHA256` → `item.CertSha`，并**自动置 `AllowInsecure = true`**（上游注释：为兼容 Xray 的变更）
   - 导出：仅当 `CertSha` 不含逗号时才写回 `pinSHA256`；若仅有 PEM，则导出整证书 DER 的 hex 指纹，不能当作 SPKI pin
2. `ServiceLib/Services/CoreConfig/Singbox/SingboxOutboundService.cs` → `FillOutboundTls`
   - `tls.insecure = _node.GetAllowInsecure()`
   - 仅当 `_node.Cert`（整段 PEM）非空才 `tls.certificate = certs; tls.insecure = false`
   - **`_node.CertSha` 完全没有被使用**
3. `ServiceLib/Models/CoreConfigs/SingboxConfig.cs` → `class Tls4Sbox`：有 `certificate` / `insecure` /
   `utls` / `reality` / `ech`，**没有** `certificate_public_key_sha256` → 即使写了也会被序列化丢掉
4. `ServiceLib/Handler/Fmt/TuicFmt.cs` → `Resolve` 只读 `allow_insecure`；公共解析 `BaseFmt.ResolveUriQuery`
   不读 `insecure`/`allowInsecure`（服务端链接发的正是这两个名字 → TUIC 的"免验证"从来没生效）

### 上游态度

- `2dust/v2rayN` issue **#7866**：有人请求为 hy2 的 `pinSHA256` 做原生支持，维护者 2025-09-02 关闭并注明
  「没有计划支持」→ 走 fork 而不是等上游
- 相关：Xray-core 迁移 `allowInsecure` → `pinnedPeerCertSha256`，v2rayN 处于过渡期，这也是其
  `Hysteria2Fmt` 自动置 `AllowInsecure` 的原因（改动我们的补丁时留意这段仍可能变）

## 补丁内容（四处，全在 ServiceLib）

见 `README.md` 的「锚点清单」。要点：
- 模型补一个字段（否则序列化丢弃）
- 生成端在 `Cert`(PEM) 与 `CertSha`(pin) 之间**二选一**（互斥是 sing-box 的硬约束）
- 导入端让 TUIC 也认 `pinSHA256`
- `Hysteria2Fmt` 对有效公钥 pin 不再自动开启 `AllowInsecure`；hex 等旧格式保留兼容回退（详见下文）

## 与官方升级入口的相互作用

`优化开关` 第 30 项安装前明确拒绝 `+zvpin` 版本，另保留 `dpkg --verify v2rayn` 的文件修改检查。
本面板生成完整 deb，md5sums 包含补丁后的 DLL，因此成功安装后 `dpkg --verify` 应为空。
只有手工替换包文件时才会触发文件修改守卫；正式补丁包依靠版本守卫，防止官方升级覆盖补丁。

## 版本与打包

- 构建须对齐**当前安装的官方版本**（或有意升级到更新的官方 tag），deb 版本号用 `<上游版本>+zvpin2`
  （dpkg 版本比较中 `+` 后缀排序高于同版本裸串，低于下一官方版本）
- 若暂不打 deb，退路是直接替换 `/opt/v2rayN` 内文件（必须先备份；`state.json` 记录 hash 以便检测）

## 三种指纹格式对照（2026-10-15）

同一张证书的整证书 DER 哈希与公钥 SPKI 哈希是不同数据，不能在客户端仅靠换编码互换。

| 格式 | 哈希对象 | 使用方 | 本次 vps8 同证书样例 |
|---|---|---|---|
| base64 公钥 SPKI SHA-256 | DER 编码的 SubjectPublicKeyInfo | argosbx 链接 `pinSHA256`（NekoBox/sing-box 惯例）；sing-box `certificate_public_key_sha256` | `rbj3e5lR5E3k/OWwIUx/dy/ukoXAMdluH9LQUCCvOks=` |
| hex 整证书 DER SHA-256 | 完整证书 DER | Xray 26.x `pinnedPeerCertSha256`；v2rayN 从 PEM 自产的导出指纹 | `00224430D875DE6AC295A11E06F9B24956A5885B35CCD3398695DC96C7F81F4C` |
| base64 整证书 DER SHA-256 | 完整证书 DER（仅编码不同） | sing-box `certificate_sha256`，本补丁不使用 | `ACJEMNh13mrClaEeBvmySValiFs1zNM5hpXclsf4H0w=` |

v2rayN 的 `CertPemManager.GetLeafCertSha256Thumbprint` 调用 `GetCertHashString(SHA256)`，
所以从 PEM 导出的 hy2 链接可能带 hex。hex 由 64 个合法 base64 字符组成，盲解会得到 48 字节，
不是 SHA-256 的 32 字节。本补丁只能检查格式与长度，不能从任意 32 字节哈希判断它是否来自 SPKI；
因此 base64 整证书哈希也不能填入公钥 pin 字段。

### Xray 26.9.9 证据

- [固定版本源码 `transport/internet/tls/config.go`](https://github.com/XTLS/Xray-core/blob/v26.9.9/transport/internet/tls/config.go)：
  `verifyChain` 对证书原始 DER 做 SHA-256，再与解码后的证书 pin 比较；配置使用 hex 解码。
- 本次任务给定的真实配置实测：同一 vps8 证书，hex pin → HTTP 204；base64 公钥 pin →
  `Failed to build TLS config > encoding/hex: invalid byte: U+0072 'r'`，在加载阶段失败。
- 本次二进制核对：Xray 26.9.9 只有 `pinnedPeerCertSha256` 这一 pin 字段，没有 base64 公钥 pin 字段。
- 客户端原核心映射：Hysteria2（ConfigType 7）→ Xray（CoreType 2）；TUIC（8）节点显式指定 sing_box（24）。
  本补丁只改 sing-box 生成器，hy2 必须把核心映射切到 sing_box；该路径此前实测返回 HTTP 204。

### zvpin2 行为与第 4 处补丁

- T1 模型、T3 TUIC 导入不变。T2 在 PEM 优先之后，仅接受 trim、补齐 padding 后能 base64 解出
  32 字节的单个 pin，规范化为 base64 再输出，且强制 `insecure=false`。
- hex、非法 base64、错误长度、逗号列表不输出公钥 pin，保留节点原有 `insecure`。
  **这不把 hex 转成公钥指纹，也不保证所有非法 pin 都能连接**：显式保持 `insecure=false` 时仍做常规证书验证。
- 第 4 处锚点在 `Hysteria2Fmt.ResolveHy2UriQuery`：有效 base64 SPKI pin 不再自动赋值
  `AllowInsecure=true`，避免新节点 UI 显示误导性的“跳过证书验证”；链接显式 `insecure=1` 仍保留，
  最终公钥 pin 仍强制真实校验。
- 与原建议的差异：不能完全删除自动赋值，否则新导入 hex 链接的 `hy2_hexpin` 兼容用例无法通过。
  对 hex 等非公钥格式保留上游自动 insecure 回退；这条兼容路径**没有 pin 身份校验**，应重导脚本的有效公钥链接。
- 补丁器识别 zvpin1 完整旧片段并原位升级；zvpin2 完整片段才算 ALREADY；未知修改或锚点漂移即失败。
- `ClientProbe` 验证真实 DLL 的导入状态、空白/缺 padding 的规范化、非法格式不降级显式验证、PEM 优先及旧 hex 回退。
  `tests/run.sh` 为原 8 项加 `hy2_hexpin`（SOCKS 1088）的 9 项真连接测试。
