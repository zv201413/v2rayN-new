# v2rayN-new (TLS Pin 补丁云端构建仓库)

维护集成 **TLS Pin 补丁**的 v2rayN 客户端（用于 Linux amd64），通过 GitHub Actions 云端全自动编译、打包、测试并发布 Releases。

## 为什么需要此补丁

服务端对 Hysteria2 / TUIC 使用自签证书并提供 `pinSHA256`（base64 公钥 SHA256 指纹）。
官方 v2rayN 存在以下问题：
1. `Hysteria2Fmt` 导入 `pinSHA256` 后存入 `CertSha`，但 sing-box 配置生成器 `SingboxOutboundService.FillOutboundTls` 只认 `_node.Cert`（整段 PEM 文本）或 `AllowInsecure`，从不读取 `CertSha`，导致必须手工在客户端粘贴完整 PEM 证书。
2. `TuicFmt` 不读取链接中的 `pinSHA256`。

本补丁通过四处源码锚点注入（位于 `ServiceLib`）：
- 模型定义：新增 `certificate_public_key_sha256` 字段；
- 出站生成：PEM 优先；仅将 base64 解码为 32 字节的 `CertSha` 映射为 sing-box 1.13+ 的 `certificate_public_key_sha256`，并置 `insecure=false`；
- TUIC 导入：解析 URL 查询参数 `pinSHA256` 存入 `CertSha`；
- Hy2 导入：有效公钥 pin 不再自动勾选跳过验证，hex 旧格式保留兼容回退。

**有效公钥 pin 的效果**：实现自签证书下**零 PEM 证书链粘贴**，同时保持严格的公钥指纹真实校验（既非跳过验证，也无需维护本地证书文件）。

## 云端构建与产物

本项目通过 GitHub Actions 在 Ubuntu 24.04 runner 上基于 .NET 10 SDK 自动构建：
1. 自动拉取上游 `2dust/v2rayN` 指定 tag 源码与子模块；
2. 自动化锚点注入补丁；
3. 编译 `v2rayN.Desktop`、`AmazTool` 与独立测试工具 `ClientProbe`；
4. 基于官方同版本 deb 提取内核与系统桌面配置，合并生成 `v2rayn_<ver>+zvpin2_amd64.deb`；
5. 在 Actions 内使用 `sing-box` 执行 9 项端到端连通性测试（涵盖 pin 正确、无 pin、错 pin、insecure、错端口等用例）；
6. 测试全通后自动创建 GitHub Release 并上传安装包及验证工具。

## 本地安装与验收

在已安装 `v2rayN` 的 Ubuntu 系统上：
```bash
# 下载 Release 中的 deb 与 client-probe
sudo dpkg -i v2rayn_<版本>+zvpin2_amd64.deb

# 验证补丁标记
strings -a /opt/v2rayN/ServiceLib.dll | grep certificate_public_key_sha256

# 验证包完整性
dpkg --verify v2rayn
```

## 客户端适配

| 节点 / 核心 | 使用要求 |
|---|---|
| hy2 / sing_box | 建议在核心映射中把 Hysteria2 设为 sing_box（24），内核 ≥1.13；脚本的 base64 SPKI pin 可免 PEM 验证 |
| hy2 / Xray 26.x | `pinnedPeerCertSha256` 只认 hex 整证书指纹（v2rayN 从 PEM 导出的链接即此格式）；脚本的 base64 公钥 pin 会导致配置加载失败 |
| TUIC / sing_box | 使用 base64 SPKI pin，正确 pin 真校验，错 pin 拒绝 |
| hy2 旧 hex / sing_box | 不再把 hex 喂给公钥字段；保留旧 insecure 回退，建议重导脚本链接以恢复 pin 校验 |

格式对照、Xray 26.9.9 实测及第 4 处补丁动机见 [pin-patch.md](docs/pin-patch.md)。
