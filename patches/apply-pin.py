#!/usr/bin/env python3
"""锚点式给 v2rayN 源码打 TLS pin 补丁（幂等，锚点漂移即报错）。

用法：python3 apply-pin.py <v2rayN 源码根目录>

三处改动（全在 ServiceLib）：
  1. Models/CoreConfigs/SingboxConfig.cs        —— Tls4Sbox 增 certificate_public_key_sha256
  2. Services/CoreConfig/Singbox/SingboxOutboundService.cs
                                                —— FillOutboundTls：CertSha → pin，且与 PEM 二选一
  3. Handler/Fmt/TuicFmt.cs                     —— Resolve：解析 pinSHA256 写入 CertSha

设计要点：
  - 只做「插入/替换固定锚点片段」，不做模糊匹配；找不到锚点 = 上游结构变了 = 立即失败
  - 幂等：已有目标内容（含标记串 certificate_public_key_sha256）则跳过该处
  - 退出码：0 全部就位（含已就位）；1 任一锚点失败
"""

import re
import sys
from pathlib import Path

MARKER = "certificate_public_key_sha256"

# ---------------------------------------------------------------- 改动 1：模型字段

T1_REL = "ServiceLib/Models/CoreConfigs/SingboxConfig.cs"
T1_ANCHOR = "public List<string>? certificate { get; set; }"
T1_INSERT = "    public List<string>? certificate_public_key_sha256 { get; set; }"


def patch_model(root: Path) -> str:
    path = root / T1_REL
    text = path.read_text(encoding="utf-8")
    if MARKER in text:
        return "ALREADY"
    if T1_ANCHOR not in text:
        return f"FAILED: 锚点缺失 -> {T1_ANCHOR!r}"
    text = text.replace(T1_ANCHOR, f"{T1_ANCHOR}\n{T1_INSERT}", 1)
    path.write_text(text, encoding="utf-8")
    return "APPLIED"


# ------------------------------------------------- 改动 2：生成端 CertSha -> pin

T2_REL = "ServiceLib/Services/CoreConfig/Singbox/SingboxOutboundService.cs"
T2_OLD = """                var certs = CertPemManager.ParsePemChain(_node.Cert);
                if (certs.Count > 0)
                {
                    tls.certificate = certs;
                    tls.insecure = false;
                }"""
T2_NEW = """                var certs = CertPemManager.ParsePemChain(_node.Cert);
                if (certs.Count > 0)
                {
                    tls.certificate = certs;
                    tls.insecure = false;
                }
                else if (!_node.CertSha.IsNullOrEmpty() && !_node.CertSha.Contains(','))
                {
                    // zv pin 补丁：CertSha（来自链接的 pinSHA256，base64 公钥指纹）映射为 sing-box
                    // certificate_public_key_sha256。sing-box 侧设置该字段即跳过链校验、改为比对公钥指纹，
                    // 故自签证书可通且仍是真校验。必须与 certificate 二选一（同时给会报 conflict）。
                    // 注意：需要内核 sing-box >= 1.13.0，且 pin 优先于 AllowInsecure（覆盖 Hysteria2Fmt
                    // 导入时自动置的 AllowInsecure=true）。
                    tls.certificate_public_key_sha256 = [_node.CertSha.TrimEx()];
                    tls.insecure = false;
                }"""


def patch_outbound(root: Path) -> str:
    path = root / T2_REL
    text = path.read_text(encoding="utf-8")
    if MARKER in text:
        return "ALREADY"
    if T2_OLD not in text:
        return "FAILED: FillOutboundTls 的证书分支锚点片段缺失（上游可能改了这段）"
    text = text.replace(T2_OLD, T2_NEW, 1)
    path.write_text(text, encoding="utf-8")
    return "APPLIED"


# ------------------------------------------------- 改动 3：TuicFmt 认 pinSHA256

T3_REL = "ServiceLib/Handler/Fmt/TuicFmt.cs"
T3_ANCHOR = """        if (GetQueryValue(query, "allow_insecure") == "1")
        {
            item.AllowInsecure = Global.StringTrue;
        }"""
T3_INSERT = """
        // zv pin 补丁：TUIC 没有官方钉扎约定，但服务端链接带 pinSHA256 时按同样语义收进 CertSha，
        // 生成配置时映射为 certificate_public_key_sha256。此处不置 AllowInsecure —— 由生成端 pin 优先决定。
        if (item.CertSha.IsNullOrEmpty())
        {
            item.CertSha = GetQueryDecoded(query, "pinSHA256");
        }"""


def patch_tuic(root: Path) -> str:
    path = root / T3_REL
    text = path.read_text(encoding="utf-8")
    if MARKER in text:
        return "ALREADY"
    if T3_ANCHOR not in text:
        return "FAILED: TuicFmt.Resolve 的 allow_insecure 锚点缺失（上游可能改了这段）"
    text = text.replace(T3_ANCHOR, f"{T3_ANCHOR}{T3_INSERT}", 1)
    path.write_text(text, encoding="utf-8")
    return "APPLIED"


def main():
    if len(sys.argv) < 2:
        print("用法: apply-pin.py <v2rayN 源码根目录>", file=sys.stderr)
        sys.exit(2)
    root = Path(sys.argv[1]).resolve()
    if not (root / "ServiceLib").is_dir():
        print(f"错误: {root} 不是有效的 v2rayN 源码根（找不到 ServiceLib/）", file=sys.stderr)
        sys.exit(2)

    results = {
        "1_model": patch_model(root),
        "2_outbound": patch_outbound(root),
        "3_tuic": patch_tuic(root),
    }

    ok = True
    for name, res in results.items():
        print(f"[{res:7s}] {name}")
        if res.startswith("FAILED"):
            ok = False

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
