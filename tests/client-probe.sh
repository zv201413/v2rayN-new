#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
APP=${1:?client directory required}
WORK=${2:?test work directory required}
PIN=${3:?pin required}
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/v2rayN-patch"
mkdir -p "$STATE/client-probe-src" "$STATE/client-probe-data"

# 1. 优先使用预编译的独立可执行文件（免除 .NET SDK 依赖）
if [ -x "$ROOT/bin/ClientProbe" ]; then
  XDG_DATA_HOME="$STATE/client-probe-data" "$ROOT/bin/ClientProbe" "$APP" "$WORK" "$PIN"
elif [ -x "$STATE/client-probe-bin/ClientProbe" ]; then
  XDG_DATA_HOME="$STATE/client-probe-data" "$STATE/client-probe-bin/ClientProbe" "$APP" "$WORK" "$PIN"
else
  # 2. 回退到 dotnet build 本地编译
  cp "$ROOT/ClientProbe/"* "$STATE/client-probe-src/"
  dotnet build "$STATE/client-probe-src/ClientProbe.csproj" -p:ClientDir="$APP" \
    -o "$STATE/client-probe-bin" --nologo -v:q
  XDG_DATA_HOME="$STATE/client-probe-data" dotnet "$STATE/client-probe-bin/ClientProbe.dll" "$APP" "$WORK" "$PIN"
fi
