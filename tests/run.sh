#!/usr/bin/env bash
# tests/run.sh — pin 语义回归测试（自签证书 + certificate_public_key_sha256）
# 用真实 sing-box 起一对 hy2/tuic 服务端与客户端，验证：
#   pin 通 / 无 pin 失败 / 错 pin 失败 / insecure 通 / 错端口失败（证明没被直连绕过）
# 依赖：sing-box（默认取客户端内置内核）、openssl、python3、curl
# 目标地址故意取本机非回环 IP —— 回环目标会被直连放行，测不出代理链路（实测教训）。
set -u
ROOT=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/v2rayN-patch"
WORK="$STATE/tests-work"
SB="${SINGBOX:-}"
[ -z "$SB" ] && { [ -f /opt/v2rayN/bin/sing_box/sing-box ] && SB=/opt/v2rayN/bin/sing_box/sing-box; }
[ -z "$SB" ] && SB=$(command -v sing-box || true)
[ -n "$SB" ] && [ -f "$SB" ] || { echo "✗ 找不到 sing-box（用 SINGBOX=/path 指定）"; exit 2; }

# deb 里内核可能没有执行位（属 root）：可读就复制到状态目录再 chmod +x
if [ ! -x "$SB" ]; then
  probe="$STATE/core-probe/sing-box"
  mkdir -p "$(dirname "$probe")" 2>/dev/null
  cp "$SB" "$probe" && chmod +x "$probe" && SB="$probe" \
    || { echo "✗ 内核不可读，无法复制执行：$SB"; exit 2; }
fi

echo "sing-box: $SB"; "$SB" version | head -2
ver=$("$SB" version 2>/dev/null | awk '/version/{print $NF}' | head -1)
[ -n "$ver" ] && [ "$(printf '%s\n1.13.0\n' "$ver" | sort -V | head -1)" = "1.13.0" ] \
  || { echo "✗ 内核 $ver < 1.13.0，不支持 certificate_public_key_sha256"; exit 2; }

rm -rf "$WORK"; mkdir -p "$WORK/pki" "$WORK/www"
cd "$WORK"

# 与 argosbx.sh 相同的证书参数
openssl ecparam -genkey -name prime256v1 -out pki/private.key >/dev/null 2>&1
openssl req -new -x509 -days 3650 -key pki/private.key -out pki/cert.crt \
  -subj "/CN=www.bing.com" -addext "subjectAltName=DNS:www.bing.com" >/dev/null 2>&1
PIN=$(openssl x509 -in pki/cert.crt -pubkey -noout | openssl pkey -pubin -outform der \
      | openssl dgst -sha256 -binary | openssl enc -base64)
echo "pin(base64 pubkey sha256)=$PIN"

LANIP=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}')
[ -z "$LANIP" ] && LANIP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
[ -z "$LANIP" ] && LANIP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -n "$LANIP" ] || { echo "✗ 取不到本机非回环 IP"; exit 2; }
echo "LANIP=$LANIP"
echo "MARKER-OK" > www/marker.txt
URL="http://$LANIP:8091/marker.txt"

cat > server.json <<EOF
{ "log": { "level": "warn" },
  "inbounds": [
    { "type": "hysteria2", "tag": "hy2-in", "listen": "127.0.0.1", "listen_port": 24443,
      "users": [{ "password": "testpw" }],
      "tls": { "enabled": true, "alpn": ["h3"],
               "certificate_path": "$WORK/pki/cert.crt", "key_path": "$WORK/pki/private.key" } },
    { "type": "tuic", "tag": "tuic-in", "listen": "127.0.0.1", "listen_port": 24444,
      "users": [{ "uuid": "11111111-1111-1111-1111-111111111111", "password": "testpw" }],
      "congestion_control": "bbr",
      "tls": { "enabled": true, "alpn": ["h3"],
               "certificate_path": "$WORK/pki/cert.crt", "key_path": "$WORK/pki/private.key" } }
  ],
  "outbounds": [{ "type": "direct", "tag": "direct" }] }
EOF

mk_hy2() { # $1=文件 $2=端口 $3=tls 片段
  cat > "$1" <<EOF
{ "log": { "level": "warn" },
  "inbounds": [{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": $2 }],
  "outbounds": [ { "type": "hysteria2", "tag": "proxy", "server": "127.0.0.1", "server_port": ${4:-24443},
      "password": "testpw",
      "tls": { "enabled": true, "server_name": "www.bing.com", "alpn": ["h3"], $3 } } ] }
EOF
}
mk_tuic() { # $1=文件 $2=端口 $3=tls 片段
  cat > "$1" <<EOF
{ "log": { "level": "warn" },
  "inbounds": [{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": $2 }],
  "outbounds": [ { "type": "tuic", "tag": "proxy", "server": "127.0.0.1", "server_port": 24444,
      "uuid": "11111111-1111-1111-1111-111111111111", "password": "testpw", "congestion_control": "bbr",
      "tls": { "enabled": true, "server_name": "www.bing.com", "alpn": ["h3"], $3 } } ] }
EOF
}
mk_hy2 c_pin.json      1081 "\"insecure\": false, \"certificate_public_key_sha256\": [\"$PIN\"]"
mk_hy2 c_nopin.json    1082 "\"insecure\": false"
mk_hy2 c_wrongpin.json 1083 "\"insecure\": false, \"certificate_public_key_sha256\": [\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"]"
mk_hy2 c_insec.json    1085 "\"insecure\": true"
mk_hy2 c_deadport.json 1086 "\"insecure\": true" 24499
mk_tuic t_pin.json     1084 "\"insecure\": false, \"certificate_public_key_sha256\": [\"$PIN\"]"
mk_tuic t_nopin.json   1087 "\"insecure\": false"
mk_tuic t_wrongpin.json 1089 "\"insecure\": false, \"certificate_public_key_sha256\": [\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"]"

if [ -n "${V2RAYN_APP_DIR:-}" ]; then
  bash "$ROOT/client-probe.sh" "$V2RAYN_APP_DIR" "$WORK" "$PIN" || exit 1
fi
for config in server.json c_*.json t_*.json; do
  "$SB" check -c "$config" || { echo "✗ 配置不可用: $config"; exit 1; }
done

python3 -m http.server 8091 --bind 0.0.0.0 --directory www >/dev/null 2>&1 & HTTP_PID=$!
"$SB" run -c server.json > server.log 2>&1 & SRV_PID=$!
sleep 2
trap 'kill $SRV_PID $HTTP_PID 2>/dev/null' EXIT
kill -0 "$HTTP_PID" "$SRV_PID" 2>/dev/null || { echo "✗ 本地测试服务启动失败"; exit 1; }

fails=0
run_case() { # $1=名字 $2=客户端配置 $3=端口 $4=期望(pass|fail)
  "$SB" run -c "$2" > "c_$1.log" 2>&1 & local p=$!
  sleep 2.5
  kill -0 "$p" 2>/dev/null || { echo "FAIL   $1 客户端启动失败"; fails=$((fails+1)); return; }
  local out; out=$(curl -s --noproxy '' --max-time 8 --socks5-hostname "127.0.0.1:$3" "$URL" 2>&1)
  kill $p 2>/dev/null; wait $p 2>/dev/null
  local got=fail; [[ "$out" == MARKER-OK* ]] && got=pass
  if [ "$got" = "$4" ]; then printf 'PASS   %-14s (期望%s)\n' "$1" "$4"
  else printf 'FAIL   %-14s 期望%s 得到%s  curl:%s\n' "$1" "$4" "$got" "${out:0:50}"; fails=$((fails+1)); fi
}

run_case hy2_pin      c_pin.json      1081 pass
run_case hy2_nopin    c_nopin.json    1082 fail
run_case hy2_wrongpin c_wrongpin.json 1083 fail
run_case tuic_pin     t_pin.json      1084 pass
run_case tuic_nopin   t_nopin.json    1087 fail
run_case tuic_wrongpin t_wrongpin.json 1089 fail
run_case hy2_insec    c_insec.json    1085 pass
run_case hy2_deadport c_deadport.json 1086 fail

echo
if [ "$fails" -eq 0 ]; then echo "全部符合预期（$WORK）"; exit 0
else echo "有 $fails 项不符合预期，详见 $WORK/c_*.log"; exit 1; fi
