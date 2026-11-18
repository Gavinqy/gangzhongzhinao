#!/bin/bash
# 解封一个 IP：从黑名单移除并重新生成 Caddy 片段。
# 用法: ./unban-ip.sh 203.0.113.7
set -e
cd "$(dirname "$0")"
IP="${1:-}"
[ -n "$IP" ] || { echo "用法: $0 <IP地址>" >&2; exit 2; }
LIST="${BLACKLIST_FILE:-./ip-blacklist.txt}"
SNIPPET="${SNIPPET_FILE:-./blocked_ips.caddy}"
grep -vx "$IP" "$LIST" > "$LIST.tmp" && mv "$LIST.tmp" "$LIST"
IPS=$(grep -v '^\s*#' "$LIST" | grep -v '^\s*$' | tr '\n' ' ')
if [ -n "${IPS// /}" ]; then
  { echo "@blocked remote_ip $IPS"; echo 'respond @blocked "Forbidden" 403'; } > "$SNIPPET"
else
  echo "# 当前黑名单为空" > "$SNIPPET"
fi
echo "已解封: $IP（Caddy reload 后生效）"
