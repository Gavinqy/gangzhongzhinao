"""本地自测：限流 / 长度 / 刷屏禁言 / 封禁解封 / WebSocket 连接数与心跳。
用法: HUB_DB=/tmp/gz_sec.db python -m uvicorn app:app --port 8877 先起服务，再跑本脚本。
"""
import asyncio
import json
import sqlite3
import sys
import urllib.request

BASE = "http://127.0.0.1:8877"
DB = "/tmp/gz_sec.db"
fails = []


def req(method, path, body=None, token=None, raw=False):
    data = json.dumps(body or {}).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(r) as resp:
            out = resp.read().decode()
            return resp.status, (out if raw else json.loads(out or "{}"))
    except urllib.error.HTTPError as e:
        out = e.read().decode()
        try:
            return e.code, json.loads(out or "{}")
        except ValueError:
            return e.code, {"detail": out}


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name, extra)
    if not cond:
        fails.append(name)


def make_user(name, admin=False):
    s, _ = req("POST", "/auth/register", {"username": name, "password": "test1234", "nickname": name})
    conn = sqlite3.connect(DB)
    conn.execute("UPDATE users SET status='approved', is_admin=? WHERE username=?", (1 if admin else 0, name))
    conn.commit(); conn.close()
    s, out = req("POST", "/auth/login", {"username": name, "password": "test1234"})
    return out["token"], out["user_id"]


async def ws_test(tok_admin_target):
    import websockets
    uri = BASE.replace("http", "ws") + "/ws?token=" + tok_admin_target
    conns = []
    try:
        for _ in range(2):
            conns.append(await websockets.connect(uri))
        check("ws_first_two_ok", len(conns) == 2)
        try:
            third = await websockets.connect(uri)
            await third.recv()  # 若没被拒会挂住，走到 timeout 之外另判
            check("ws_third_rejected", False, "third connected")
            await third.close()
        except Exception as e:
            check("ws_third_rejected", True, type(e).__name__)
        # 心跳：发 ping 应回 pong
        await conns[0].send("ping")
        pong = await asyncio.wait_for(conns[0].recv(), 3)
        check("ws_ping_pong", pong == "pong", str(pong))
    finally:
        for c in conns:
            await c.close()


def main():
    admin_tok, admin_id = make_user("secadmin", admin=True)
    user_tok, user_id = make_user("secuser")
    other_tok, other_id = make_user("secother")
    # 建群并拉 other 进来（房主直接建群后，用邀请码路径太长，这里走管理员加人接口简化）
    s, room = req("POST", "/rooms", {"name": "sectest"}, token=admin_tok)
    rid = room.get("room_id") or room.get("id")
    # admin 自己发消息需是成员：建群者默认成员？若不是，下面第一条会 403，自测会暴露
    s, m = req("POST", f"/rooms/{rid}/messages", {"content": "hello"}, token=user_tok)
    if s == 403:  # user 不在房间：用邀请码加入流程
        s, inv = req("POST", f"/rooms/{rid}/invitations", {}, token=admin_tok)
        code = inv.get("code") or inv.get("invitation", {}).get("code")
        s, j = req("POST", f"/invitations/{code}/join", {}, token=user_tok)
        s, m = req("POST", f"/rooms/{rid}/messages", {"content": "hello"}, token=user_tok)
    check("send_normal", s == 200, f"status={s} {m}")

    # 长度：3001 字被拒，3000 字可过（用 other 账号避免污染限流计数前先测长度）
    s, m = req("POST", f"/rooms/{rid}/messages", {"content": "x" * 3001}, token=user_tok)
    check("length_3001_rejected", s == 400 and "3000" in str(m.get("detail", "")), f"status={s} {m}")

    # 限流：user 已发 1 条，再连发到第 11 条应 429
    codes = []
    for i in range(12):
        s, m = req("POST", f"/rooms/{rid}/messages", {"content": f"msg{i} 内容各不相同 {i}"}, token=user_tok)
        codes.append(s)
    check("rate_limit_429", 429 in codes, str(codes))

    # 刷屏禁言：other 发重复字符 -> 403 禁言，随后正常消息也被禁言拦
    s, inv = req("POST", f"/rooms/{rid}/invitations", {}, token=admin_tok)
    code = inv.get("code")
    if code:
        req("POST", f"/invitations/{code}/join", {}, token=other_tok)
    s, m = req("POST", f"/rooms/{rid}/messages", {"content": "啊" * 30}, token=other_tok)
    check("spam_muted", s == 403 and "禁言" in str(m.get("detail", "")), f"status={s} {m}")
    s, m = req("POST", f"/rooms/{rid}/messages", {"content": "正常一句话"}, token=other_tok)
    check("mute_blocks_normal", s == 403 and "禁言" in str(m.get("detail", "")), f"status={s} {m}")

    # 封禁/解封：admin 封 other -> 其 token 立即失效(403)；解封后可重新登录
    s, users = req("GET", "/admin/users", token=admin_tok)
    check("admin_users_list", s == 200 and any(u["id"] == other_id for u in users["users"]), f"status={s}")
    s, _ = req("POST", f"/admin/users/{other_id}/ban", {}, token=admin_tok)
    check("ban_ok", s == 200, f"status={s}")
    s, m = req("GET", "/me", token=other_tok)
    # 封禁时会话已删除，旧 token 表现为 401 bad token；若会话还在则应为 403 封禁。两者都算立即失效。
    check("banned_token_rejected", s in (401, 403), f"status={s} {m}")
    s, m = req("POST", "/auth/login", {"username": "secother", "password": "test1234"})
    check("banned_login_rejected", s == 403, f"status={s}")
    s, _ = req("POST", f"/admin/users/{other_id}/unban", {}, token=admin_tok)
    check("unban_ok", s == 200, f"status={s}")
    s, m = req("POST", "/auth/login", {"username": "secother", "password": "test1234"})
    check("unbanned_login_ok", s == 200, f"status={s}")
    # 不能封管理员/自己
    s, _ = req("POST", f"/admin/users/{admin_id}/ban", {}, token=admin_tok)
    check("ban_self_rejected", s == 400, f"status={s}")
    # 普通用户无权封人
    s, _ = req("POST", f"/admin/users/{other_id}/ban", {}, token=user_tok)
    check("nonadmin_ban_rejected", s in (401, 403), f"status={s}")

    asyncio.run(ws_test(user_tok))
    print("FAILS:", fails)
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
