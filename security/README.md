# IP 黑名单（Caddy 层）

思路：在日志里发现某个 IP 疯狂发送无效请求时，直接在反向代理层封掉，不让请求进应用。

- `ip-blacklist.txt`：名单本体，一行一个 IP，由脚本维护。
- `ban-ip.sh <IP> [备注]`：把 IP 写进名单，并重新生成 Caddy 片段 `blocked_ips.caddy`。
- `unban-ip.sh <IP>`：移除并重新生成片段。
- Caddy 站点块里加一行 `import /路径/security/blocked_ips.caddy`，片段内容是：

```caddy
@blocked remote_ip 203.0.113.7
respond @blocked "Forbidden" 403
```

改完名单后 reload / restart Caddy 生效。脚本支持用环境变量 `BLACKLIST_FILE`、`SNIPPET_FILE` 改文件位置，`CADDY_RELOAD=1` 时会顺带执行 `caddy reload`。
