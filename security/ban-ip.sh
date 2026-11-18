#!/bin/bash
# 封禁一个 IP：写入黑名单并重新生成 Caddy 片段；设了 CADDY_RELOAD=1 时顺带 reload Caddy。
# 用法: ./ban-ip.sh 203.0.113.7 [备注]
# 环境变量: BLACKLIST_FILE（默认与脚本同目录 ip-blacklist.txt）、SNIPPET_FILE（默认同目录 blocked_ips.caddy）
set -e
cd "$(dirname "$0")"
IP="${1:-}"
if ! echo "$IP" | grep -Eq '^[0-9a-fA-F.:]+$' || [ -z "$IP" ]; then
  echo "用法: $0 <IP地址> [备注]" >&2; exit 2
fi
LIST="${BLACKLIST_FILE:-./ip-blacklist.txt}"
SNIPPET="${SNIPPET_FILE:-./blocked_ips.caddy}"
touch "$LIST"
if grep -qx "$IP" "$LIST"; then echo "已在黑名单里: $IP"; else
  echo "$IP" >> "$LIST"
  echo "已封禁: $IP ${2:-}"
fi
# 重新生成 Caddy 片段：站点块里 import 这个文件即可生效
IPS=$(grep -v '^\s*#' "$LIST" | grep -v '^\s*$' | tr '\n' ' ')
if [ -n "${IPS// /}" ]; then
  { echo "@blocked remote_ip $IPS"; echo 'respond @blocked "Forbidden" 403'; } > "$SNIPPET"
else
  echo "# 当前黑名单为空" > "$SNIPPET"
fi
echo "片段已更新: $SNIPPET"
if [ "${CADDY_RELOAD:-0}" = "1" ]; then
  caddy reload --config /etc/caddy/Caddyfile && echo "Caddy 已 reload"
else
  echo "提示: 在服务器上执行 caddy reload（或设 CADDY_RELOAD=1）后生效。"
fi
