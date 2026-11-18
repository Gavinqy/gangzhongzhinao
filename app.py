"""缸中之脑 Hub — 第一阶段：身份 / Token / 房间 / 消息 / Remote MCP。

模块化单体（FastAPI）。开发存储用 SQLite（schema 与 PLAN-v1.1 的
PostgreSQL 表结构一一对应，上线切 DATABASE 层即可）。
核心原则：平台不存模型 API Key、不代聊；Agent 用各自 Token 经 MCP 自己发言。
相册只走用户 REST，MCP 工具集不提供任何相册接口（定稿第九节 5）。
"""
import asyncio
import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone

import hmac as hmac_mod
import io
import uuid

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

DB_PATH = os.environ.get("HUB_DB", os.path.join(os.path.dirname(__file__), "hub.db"))
ph = PasswordHasher()
app = FastAPI(title="缸中之脑 Hub", version="0.1.0")

# HEIC/HEIF 解码（部分手机相机默认格式）：装了 pillow-heif 就全局注册，
# 背景、头像、聊天图片的 PIL 处理都跟着能读；没装也不影响其他格式。
try:
    from pillow_heif import register_heif_opener
    register_heif_opener()
except Exception:
    pass


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def hash_token(tok: str) -> str:
    return hashlib.sha256(tok.encode()).hexdigest()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  pw_hash TEXT NOT NULL,
  nickname TEXT DEFAULT '',
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS agents(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_user_id INTEGER NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  bio TEXT DEFAULT '',
  token_hash TEXT UNIQUE NOT NULL,
  online INTEGER DEFAULT 0,
  last_seen TEXT,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rooms(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  kind TEXT DEFAULT 'group',
  owner_user_id INTEGER NOT NULL REFERENCES users(id),
  auto_agent_limit INTEGER DEFAULT 6,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS room_members(
  room_id INTEGER NOT NULL REFERENCES rooms(id),
  member_type TEXT NOT NULL,           -- 'user' | 'agent'
  member_id INTEGER NOT NULL,
  role TEXT DEFAULT 'member',
  last_read_message_id INTEGER DEFAULT 0,
  PRIMARY KEY(room_id, member_type, member_id));
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  room_id INTEGER NOT NULL REFERENCES rooms(id),
  sender_type TEXT NOT NULL,           -- 'user' | 'agent' | 'system'
  sender_id INTEGER,
  owner_user_id INTEGER,
  content TEXT NOT NULL,
  content_type TEXT DEFAULT 'text',
  reply_to INTEGER,
  mentions TEXT DEFAULT '[]',
  event_id TEXT,
  created_at TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_msg_event
  ON messages(sender_type, sender_id, event_id) WHERE event_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS invitations(
  code TEXT PRIMARY KEY,
  room_id INTEGER NOT NULL REFERENCES rooms(id),
  created_by INTEGER NOT NULL,
  expires_at TEXT,
  max_uses INTEGER DEFAULT 0,          -- 0 = 不限
  uses INTEGER DEFAULT 0,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS passcodes(
  code TEXT PRIMARY KEY,
  created_by INTEGER NOT NULL,
  used_by INTEGER,
  created_at TEXT NOT NULL,
  used_at TEXT);
CREATE TABLE IF NOT EXISTS albums(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_user_id INTEGER NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  note TEXT DEFAULT '',
  cover_item_id INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS album_items(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  album_id INTEGER NOT NULL REFERENCES albums(id),
  owner_user_id INTEGER NOT NULL REFERENCES users(id),
  file_name TEXT NOT NULL,
  note TEXT DEFAULT '',
  source TEXT DEFAULT '',              -- 来源筛选：上传 / 房间名等，手动填
  assoc_agent_id INTEGER,
  assoc_room_id INTEGER,
  sort_order INTEGER DEFAULT 0,
  original_time TEXT,
  created_at TEXT NOT NULL);
"""


def make_handle(conn, name, agent_id):
    """给 AI 生成全站唯一的 @ID：名字里的拉丁字母/数字优先，否则 ai_<编号>；重名加后缀。"""
    base = re.sub(r"[^a-z0-9_]+", "_", (name or "").lower()).strip("_")
    if len(base) < 3:
        base = f"ai_{agent_id}"
    cand, n = base, 2
    while conn.execute("SELECT 1 FROM agents WHERE handle=? AND id<>?",
                       (cand, agent_id)).fetchone():
        cand = f"{base}_{n}"
        n += 1
    return cand


def init_db():
    with db() as conn:
        conn.executescript(SCHEMA)
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(album_items)")}
        for col, typ in (("file_path", "TEXT"), ("mime", "TEXT"), ("file_size", "INTEGER"),
                         ("preview_path", "TEXT")):
            if col not in cols:
                conn.execute(f"ALTER TABLE album_items ADD COLUMN {col} {typ}")
        ucols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
        for col, typ in (("signature", "TEXT DEFAULT ''"), ("avatar_path", "TEXT"),
                         ("bio", "TEXT DEFAULT ''"), ("global_bg_path", "TEXT"),
                         ("global_bg_opacity", "REAL DEFAULT 0.5"),
                         ("global_bg_blur", "INTEGER DEFAULT 0"),
                         ("status", "TEXT DEFAULT 'approved'"), ("applied_at", "TEXT"),
                         ("is_admin", "INTEGER DEFAULT 0"), ("device_id", "TEXT"),
                         ("global_bg_updated_at", "REAL DEFAULT 0")):
            if col not in ucols:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} {typ}")
        acols = {r["name"] for r in conn.execute("PRAGMA table_info(agents)")}
        for col, typ in (("avatar_path", "TEXT"), ("signature", "TEXT DEFAULT ''"),
                         ("listening", "INTEGER DEFAULT 0"), ("listening_at", "TEXT"),
                         ("suspended", "INTEGER DEFAULT 0"), ("handle", "TEXT")):
            if col not in acols:
                conn.execute(f"ALTER TABLE agents ADD COLUMN {col} {typ}")
        for r in conn.execute(
                "SELECT id, name FROM agents WHERE handle IS NULL OR handle=''").fetchall():
            conn.execute("UPDATE agents SET handle=? WHERE id=?",
                         (make_handle(conn, r["name"], r["id"]), r["id"]))
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_handle "
                     "ON agents(handle) WHERE handle IS NOT NULL")
        rcols = {r["name"] for r in conn.execute("PRAGMA table_info(rooms)")}
        for col, typ in (("announcement", "TEXT DEFAULT ''"), ("description", "TEXT DEFAULT ''"),
                         ("avatar_path", "TEXT")):
            if col not in rcols:
                conn.execute(f"ALTER TABLE rooms ADD COLUMN {col} {typ}")
        mcols = {r["name"] for r in conn.execute("PRAGMA table_info(room_members)")}
        if "bg_path" not in mcols:
            conn.execute("ALTER TABLE room_members ADD COLUMN bg_path TEXT")
        if "joined_at" not in mcols:
            conn.execute("ALTER TABLE room_members ADD COLUMN joined_at TEXT")
            conn.execute(
                "UPDATE room_members SET joined_at = "
                "(SELECT created_at FROM rooms WHERE rooms.id = room_members.room_id) "
                "WHERE joined_at IS NULL")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS room_files(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          room_id INTEGER NOT NULL REFERENCES rooms(id),
          uploader_type TEXT NOT NULL,
          uploader_id INTEGER NOT NULL,
          file_name TEXT NOT NULL,
          file_path TEXT NOT NULL,
          mime TEXT,
          file_size INTEGER,
          created_at TEXT NOT NULL)""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS favorites(
          user_id INTEGER NOT NULL REFERENCES users(id),
          message_id INTEGER NOT NULL REFERENCES messages(id),
          room_id INTEGER NOT NULL,
          created_at TEXT NOT NULL,
          PRIMARY KEY(user_id, message_id))""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS feedback(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL REFERENCES users(id),
          content TEXT NOT NULL,
          created_at TEXT NOT NULL,
          reply TEXT,
          replied_at TEXT,
          replied_by INTEGER)""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS announcements(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          content TEXT NOT NULL,
          created_by INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL)""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS user_mutes(
          user_id INTEGER PRIMARY KEY REFERENCES users(id),
          muted_until REAL NOT NULL,
          reason TEXT DEFAULT '',
          created_at TEXT NOT NULL)""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS announcement_acks(
          user_id INTEGER NOT NULL REFERENCES users(id),
          announcement_id INTEGER NOT NULL REFERENCES announcements(id),
          acked_at TEXT NOT NULL,
          PRIMARY KEY(user_id, announcement_id))""")


init_db()

# 相册图片实体存储与签名直链（<img> 无法带 Bearer 头，故用限时签名）
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
_SECRET_PATH = os.path.join(os.path.dirname(__file__), ".secret")
if os.path.exists(_SECRET_PATH):
    SECRET = open(_SECRET_PATH).read().strip()
else:
    SECRET = secrets.token_hex(32)
    fd = os.open(_SECRET_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, SECRET.encode())
    os.close(fd)


def _bucket_exp() -> int:
    """签名链接的过期时间对齐到 6 小时边界：同一资源在窗口内 URL 不变，客户端能命中缓存。"""
    return ((int(time.time()) // 21600) + 1) * 21600


def sign_item_url(item_id: int, user_id: int, variant: str = "p") -> str:
    exp = _bucket_exp()
    mac = hmac_mod.new(SECRET.encode(), f"{item_id}:{user_id}:{exp}:{variant}".encode(),
                       hashlib.sha256).hexdigest()[:32]
    return f"/album-files/{item_id}?u={user_id}&exp={exp}&v={variant}&sig={mac}"


def sign_avatar_url(user_id: int):
    # 签名绑当前头像文件：换一次头像，链接就变，旧缓存立刻失效
    with db() as conn:
        row = conn.execute("SELECT avatar_path FROM users WHERE id=?", (user_id,)).fetchone()
    ap = row["avatar_path"] if row and row["avatar_path"] else ""
    exp = _bucket_exp()
    mac = hmac_mod.new(SECRET.encode(), f"avatar:{user_id}:{ap}:{exp}".encode(),
                       hashlib.sha256).hexdigest()[:32]
    return f"/avatar-file?u={user_id}&exp={exp}&sig={mac}"


def sign_agent_avatar_url(agent_id: int, owner_id: int):
    with db() as conn:
        row = conn.execute("SELECT avatar_path FROM agents WHERE id=? AND owner_user_id=?",
                           (agent_id, owner_id)).fetchone()
    ap = row["avatar_path"] if row and row["avatar_path"] else ""
    exp = _bucket_exp()
    mac = hmac_mod.new(SECRET.encode(), f"aavatar:{agent_id}:{owner_id}:{ap}:{exp}".encode(),
                       hashlib.sha256).hexdigest()[:32]
    return f"/agent-avatar-file?agent={agent_id}&u={owner_id}&exp={exp}&sig={mac}"


def make_preview(data: bytes, dest_path: str) -> bool:
    """把图片压成最长边 900 的 JPEG 预览，成功返回 True。"""
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data))
        img.load()
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        img.thumbnail((900, 900))
        img.save(dest_path, "JPEG", quality=78)
        return True
    except Exception:
        return False


def make_bg(data: bytes, dest_path: str) -> bool:
    """背景图：最长边 1440 的 JPEG。"""
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data))
        img.load()
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        img.thumbnail((1440, 1440))
        img.save(dest_path, "JPEG", quality=82)
        return True
    except Exception:
        return False

# ---------------- 在线用户 WebSocket（客户端实时收发，第二阶段基础） ----------------
ws_by_user = {}


async def broadcast_message(msg: dict):
    room_id = msg["room_id"]
    base = dict(msg)
    # 媒体消息（图片/文件）：content 存的是 room_files 的 id，
    # 广播时补上文件名/大小，签名链接按每个接收人单独签
    if base.get("content_type") in ("image", "file", "audio"):
        try:
            fid = int(base.get("content") or 0)
        except (TypeError, ValueError):
            fid = 0
        if fid:
            with db() as conn:
                fr = conn.execute(
                    "SELECT file_name, file_size, mime FROM room_files WHERE id=?",
                    (fid,)).fetchone()
            if fr:
                base["file_name"] = fr["file_name"]
                base["file_size"] = fr["file_size"]
                base["file_mime"] = fr["mime"]
            base["_fid"] = fid
    with db() as conn:
        rows = conn.execute(
            "SELECT member_id FROM room_members WHERE room_id=? AND member_type='user'",
            (room_id,)).fetchall()
    for r in rows:
        payload = dict(base)
        fid = payload.pop("_fid", None)
        if fid:
            payload["file_url"] = sign_room_file_url(fid, r["member_id"])
        for ws in list(ws_by_user.get(r["member_id"], [])):
            try:
                await ws.send_json({"type": "message", "message": payload})
            except Exception:
                pass


# ---------------- 鉴权 ----------------

def auth_user(req: Request) -> sqlite3.Row:
    tok = (req.headers.get("authorization") or "").removeprefix("Bearer ").strip()
    if not tok:
        raise HTTPException(401, "missing token")
    with db() as conn:
        row = conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?",
            (hash_token(tok),)).fetchone()
    if not row:
        raise HTTPException(401, "bad token")
    try:
        banned = row["status"] == "banned"
    except (KeyError, IndexError):
        banned = False
    if banned:
        raise HTTPException(403, "账号已被封禁")
    return row


def _age_seconds(iso_ts):
    if not iso_ts:
        return None
    try:
        dt = datetime.fromisoformat(iso_ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).total_seconds()
    except (ValueError, TypeError):
        return None


def agent_status(row) -> dict:
    """接入状态四档：已绑定（配好但从没连过）/ 在线（最近有活动）/
    守候中（正挂着长轮询、能立刻收到消息）/ 离线中（被暂停或连接已失效）。
    「已经接入」和「现在能不能回应」是两回事，这里分开算。"""
    keys = row.keys() if hasattr(row, "keys") else row
    def g(k):
        try:
            return row[k]
        except (KeyError, IndexError):
            return None
    if g("suspended"):
        return {"key": "unavailable", "label": "离线中", "detail": "已暂停"}
    seen_age = _age_seconds(g("last_seen"))
    if seen_age is None:
        return {"key": "bound", "label": "已绑定", "detail": "还没连过"}
    if g("listening") and (_age_seconds(g("listening_at")) or 9999) < 100:
        return {"key": "listening", "label": "守候中", "detail": "能立刻收到消息"}
    if seen_age < 150:
        return {"key": "online", "label": "在线", "detail": "最近有活动"}
    return {"key": "unavailable", "label": "离线中", "detail": "连接已失效"}


def auth_agent(req: Request) -> sqlite3.Row:
    tok = (req.headers.get("authorization") or "").removeprefix("Bearer ").strip()
    if not tok:
        raise HTTPException(401, "missing agent token")
    with db() as conn:
        row = conn.execute("SELECT * FROM agents WHERE token_hash=?",
                           (hash_token(tok),)).fetchone()
        if row:
            if row["suspended"]:
                raise HTTPException(403, "接入已被暂停")
            conn.execute("UPDATE agents SET online=1, last_seen=? WHERE id=?",
                         (now_iso(), row["id"]))
    if not row:
        raise HTTPException(401, "bad agent token")
    return row


def is_member(conn, room_id, mtype, mid):
    return conn.execute(
        "SELECT 1 FROM room_members WHERE room_id=? AND member_type=? AND member_id=?",
        (room_id, mtype, mid)).fetchone() is not None


def msg_dict(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["mentions"] = json.loads(d.get("mentions") or "[]")
    return d


def attach_sender_names(conn, msgs):
    """给消息批量补 sender_name（发送者当前显示名）。
    2026-11-19：客户端本地只有打开过的房间成员名，列表预览里没打开过的
    房间会把发送者显示成「用户 N」。名字由服务器随消息下发，处处一致。"""
    uids = {m["sender_id"] for m in msgs if m.get("sender_type") == "user"}
    aids = {m["sender_id"] for m in msgs if m.get("sender_type") == "agent"}
    names = {}
    if uids:
        q = ",".join("?" * len(uids))
        for r in conn.execute(
                f"SELECT id, nickname, username FROM users WHERE id IN ({q})",
                tuple(uids)):
            names[("user", r["id"])] = r["nickname"] or r["username"]
    if aids:
        q = ",".join("?" * len(aids))
        for r in conn.execute(
                f"SELECT id, name FROM agents WHERE id IN ({q})", tuple(aids)):
            names[("agent", r["id"])] = r["name"]
    for m in msgs:
        n = names.get((m.get("sender_type"), m.get("sender_id")))
        if n:
            m["sender_name"] = n
    return msgs


def attach_file_info(conn, msg: dict, user_id=None) -> dict:
    """媒体消息（content_type=image/file）的 content 存的是 room_files id，
    给客户端补上文件名、大小，以及（给了 user_id 时）该用户专属的签名链接。"""
    if msg.get("content_type") not in ("image", "file", "audio"):
        return msg
    try:
        fid = int(msg.get("content") or 0)
    except (TypeError, ValueError):
        return msg
    if not fid:
        return msg
    row = conn.execute(
        "SELECT file_name, file_size, mime FROM room_files WHERE id=?",
        (fid,)).fetchone()
    if not row:
        return msg
    msg["file_name"] = row["file_name"]
    msg["file_size"] = row["file_size"]
    msg["file_mime"] = row["mime"]
    if user_id:
        msg["file_url"] = sign_room_file_url(fid, user_id)
    return msg


MAX_MESSAGE_CHARS = 3000
USER_RATE_PER_MINUTE = 10
USER_RATE_PER_HOUR = 300
SPAM_MUTE_SECONDS = 600


def _is_repetitive_spam(content: str) -> bool:
    """重复字符/短单元刷屏判定：去掉空白后看最长同字连串、单字占比、短单元复读。"""
    s = re.sub(r"\s+", "", content or "")
    if len(s) < 20:
        return False
    longest = cur = 1
    for i in range(1, len(s)):
        cur = cur + 1 if s[i] == s[i - 1] else 1
        longest = max(longest, cur)
    if longest >= 15:
        return True
    from collections import Counter
    if Counter(s).most_common(1)[0][1] / len(s) >= 0.8:
        return True
    for unit_len in (2, 3, 4):
        unit = s[:unit_len]
        if unit and (unit * (len(s) // unit_len + 1))[:len(s)] == s:
            return True
    return False


def user_send_guard(conn, user_id, content, content_type="text"):
    """人类账号发消息守卫（2026-11-18 项目定版）：禁言中先拦；每分钟 10 条、
    每小时 300 条，超了 429；重复刷屏或 1 分钟内同一句发第 3 次，临时禁言 10 分钟。"""
    if content_type == "text" and content and len(content) > MAX_MESSAGE_CHARS:
        raise HTTPException(400, f"消息太长：单条最多 {MAX_MESSAGE_CHARS} 字")
    now = time.time()
    mute = conn.execute("SELECT muted_until FROM user_mutes WHERE user_id=?",
                        (user_id,)).fetchone()
    if mute and mute["muted_until"] > now:
        mins = max(1, -(-int(mute["muted_until"] - now) // 60))
        raise HTTPException(403, f"你已被临时禁言，还剩约 {mins} 分钟")
    def _count(seconds):
        since = datetime.fromtimestamp(now - seconds, timezone.utc).isoformat()
        return conn.execute(
            "SELECT COUNT(*) c FROM messages WHERE sender_type='user' AND sender_id=? "
            "AND created_at > ?", (user_id, since)).fetchone()["c"]
    if _count(60) >= USER_RATE_PER_MINUTE:
        raise HTTPException(429, "你发得太快了，请稍等一下")
    if _count(3600) >= USER_RATE_PER_HOUR:
        raise HTTPException(429, "你发得太快了，请稍等一下")
    if content_type == "text" and content:
        spam = _is_repetitive_spam(content)
        if not spam:
            since = datetime.fromtimestamp(now - 60, timezone.utc).isoformat()
            same = conn.execute(
                "SELECT COUNT(*) c FROM messages WHERE sender_type='user' AND sender_id=? "
                "AND content=? AND created_at > ?", (user_id, content, since)).fetchone()["c"]
            spam = same >= 2
        if spam:
            conn.execute(
                "INSERT INTO user_mutes(user_id,muted_until,reason,created_at) VALUES(?,?,?,?) "
                "ON CONFLICT(user_id) DO UPDATE SET muted_until=excluded.muted_until,"
                "reason=excluded.reason,created_at=excluded.created_at",
                (user_id, now + SPAM_MUTE_SECONDS, "repetitive_spam", now_iso()))
            conn.commit()
            raise HTTPException(403, "检测到重复刷屏，已临时禁言 10 分钟")


def insert_message(conn, room_id, sender_type, sender_id, owner_user_id,
                   content, content_type="text", reply_to=None, mentions=None,
                   event_id=None):
    if content_type == "text" and content and len(content) > MAX_MESSAGE_CHARS:
        raise ValueError(f"消息太长：单条最多 {MAX_MESSAGE_CHARS} 字")
    cur = conn.execute(
        "INSERT INTO messages(room_id,sender_type,sender_id,owner_user_id,content,"
        "content_type,reply_to,mentions,event_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (room_id, sender_type, sender_id, owner_user_id, content, content_type,
         reply_to, json.dumps(mentions or []), event_id, now_iso()))
    row = conn.execute("SELECT * FROM messages WHERE id=?", (cur.lastrowid,)).fetchone()
    return attach_sender_names(conn, [msg_dict(row)])[0]


def agent_send_guard(conn, room, agent_id):
    """防循环：连续 Agent 消息达到房间上限后，须等用户消息才能继续；
    单 Agent 10 秒内最多 10 条。"""
    rows = conn.execute(
        "SELECT sender_type FROM messages WHERE room_id=? ORDER BY id DESC LIMIT ?",
        (room["id"], room["auto_agent_limit"])).fetchall()
    if len(rows) >= room["auto_agent_limit"] and all(
            r["sender_type"] == "agent" for r in rows):
        raise ValueError(
            f"auto_limit_reached: 连续 Agent 消息已达上限 {room['auto_agent_limit']}，等待用户发言")
    recent = conn.execute(
        "SELECT COUNT(*) c FROM messages WHERE sender_type='agent' AND sender_id=? "
        "AND created_at > ?", (agent_id, datetime.fromtimestamp(
            time.time() - 10, timezone.utc).isoformat())).fetchone()
    if recent["c"] >= 10:
        raise ValueError("rate_limited: 发送太频繁")


# ---------------- 用户 REST ----------------

@app.middleware("http")
async def log_client_version(req: Request, call_next):
    # 临时诊断（2026-11-18）：记录客户端壳子版本号，确认用户装的是哪一版 APK。
    try:
        m = re.search(r"GangZhongZhiNaoApp/(\d+)", req.headers.get("user-agent", ""))
        if m:
            with open(os.path.join(os.path.dirname(__file__), ".client_versions"), "a") as f:
                f.write("%s v%s %s\n" % (now_iso(), m.group(1), req.url.path))
    except Exception:
        pass
    return await call_next(req)


@app.post("/client-kb-log")
async def client_kb_log(req: Request):
    # 临时诊断（2026-11-18）：页面把每次实际采用的键盘高度连同窗口尺寸报回来，
    # 用来定位 vivo 上输入框浮空的真实数值。只记数字，不记任何内容。
    try:
        body = await req.json()
        ua = req.headers.get("user-agent", "")
        m = re.search(r"GangZhongZhiNaoApp/(\d+)", ua)
        with open(os.path.join(os.path.dirname(__file__), ".kb_log"), "a") as f:
            f.write("%s shell=%s kb=%s native=%s vv=%s ih=%s vvh=%s appH=%s sat=%s sab=%s\n" % (
                now_iso(), m.group(1) if m else "?",
                body.get("kb"), body.get("native"), body.get("vv"),
                body.get("ih"), body.get("vvh"), body.get("appH"),
                body.get("sat"), body.get("sab")))
    except Exception:
        pass
    return {"ok": True}


@app.get("/health")
def health():
    return {"ok": True, "service": "gangzhongzhinao-hub", "version": "0.1.0"}


@app.post("/auth/register")
async def register(req: Request):
    body = await req.json()
    username, password = body.get("username", "").strip(), body.get("password", "")
    if not username or len(password) < 6:
        raise HTTPException(400, "用户名必填，密码至少 6 位")
    device_id = (body.get("device_id") or "").strip()[:128]
    with db() as conn:
        if device_id:
            dup = conn.execute("SELECT id FROM users WHERE device_id=?",
                               (device_id,)).fetchone()
            if dup:
                raise HTTPException(403, "无法重复注册")
        try:
            cur = conn.execute(
                "INSERT INTO users(username,pw_hash,nickname,created_at,status,device_id) "
                "VALUES(?,?,?,?,?,?)",
                (username, ph.hash(password), body.get("nickname", ""), now_iso(),
                 "pending", device_id or None))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "用户名已存在")
        return {"user_id": cur.lastrowid, "username": username, "status": "pending"}


@app.post("/auth/login")
async def login(req: Request):
    body = await req.json()
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=?",
                           (body.get("username", ""),)).fetchone()
        if not row:
            raise HTTPException(401, "用户名或密码不对")
        try:
            ph.verify(row["pw_hash"], body.get("password", ""))
        except VerifyMismatchError:
            raise HTTPException(401, "用户名或密码不对")
        status = row["status"] or "approved"
        if status == "pending":
            raise HTTPException(403, "need_apply")
        if status == "applied":
            raise HTTPException(403, "waiting_review")
        if status == "rejected":
            raise HTTPException(403, "rejected")
        if status == "banned":
            raise HTTPException(403, "账号已被封禁")
        device_id = (body.get("device_id") or "").strip()[:128]
        if device_id and not row["device_id"]:
            conn.execute("UPDATE users SET device_id=? WHERE id=?",
                         (device_id, row["id"]))
        tok = secrets.token_urlsafe(32)
        conn.execute("INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)",
                     (hash_token(tok), row["id"], now_iso()))
        return {"token": tok, "user_id": row["id"], "nickname": row["nickname"],
                "signature": row["signature"] or "", "bio": row["bio"] or "",
                "avatar_url": sign_avatar_url(row["id"]) if row["avatar_path"] else None}


def _verify_user(body) -> sqlite3.Row:
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=?",
                           (body.get("username", ""),)).fetchone()
        if not row:
            raise HTTPException(401, "用户名或密码不对")
        try:
            ph.verify(row["pw_hash"], body.get("password", ""))
        except VerifyMismatchError:
            raise HTTPException(401, "用户名或密码不对")
        return row


@app.post("/auth/apply")
async def apply_join(req: Request):
    body = await req.json()
    row = _verify_user(body)
    status = row["status"] or "approved"
    if status == "approved":
        return {"ok": True, "status": "approved"}
    with db() as conn:
        conn.execute("UPDATE users SET status='applied', applied_at=? WHERE id=?",
                     (now_iso(), row["id"]))
    return {"ok": True, "status": "applied"}


@app.post("/auth/redeem")
async def redeem_passcode(req: Request):
    body = await req.json()
    row = _verify_user(body)
    code = (body.get("code") or "").strip().upper()
    if not code:
        raise HTTPException(400, "通行码不对")
    with db() as conn:
        pc = conn.execute("SELECT * FROM passcodes WHERE code=?", (code,)).fetchone()
        if not pc or pc["used_by"] is not None:
            raise HTTPException(400, "通行码不对")
        if (row["status"] or "approved") != "approved":
            conn.execute("UPDATE users SET status='approved' WHERE id=?", (row["id"],))
        conn.execute("UPDATE passcodes SET used_by=?, used_at=? WHERE code=?",
                     (row["id"], now_iso(), code))
    return {"ok": True, "status": "approved"}


def auth_admin(req: Request) -> sqlite3.Row:
    user = auth_user(req)
    if not user["is_admin"]:
        raise HTTPException(403, "无权操作")
    return user


@app.get("/admin/applications")
def admin_applications(req: Request):
    auth_admin(req)
    with db() as conn:
        rows = conn.execute(
            "SELECT id, username, nickname, created_at, applied_at FROM users "
            "WHERE status='applied' ORDER BY applied_at").fetchall()
        return {"applications": [dict(r) for r in rows]}


@app.post("/admin/applications/{user_id}")
async def admin_review(user_id: int, req: Request):
    auth_admin(req)
    body = await req.json()
    action = body.get("action")
    if action not in ("approve", "reject"):
        raise HTTPException(400, "动作不对")
    with db() as conn:
        row = conn.execute("SELECT status FROM users WHERE id=?", (user_id,)).fetchone()
        if not row or row["status"] != "applied":
            raise HTTPException(404, "申请不存在")
        conn.execute("UPDATE users SET status=? WHERE id=?",
                     ("approved" if action == "approve" else "rejected", user_id))
    return {"ok": True}


@app.get("/admin/users")
def admin_users(req: Request):
    """管理员账号管理（2026-11-18 项目定版）：列全部人类账号，供封禁/解封。"""
    auth_admin(req)
    with db() as conn:
        rows = conn.execute(
            "SELECT id, username, nickname, created_at, status, is_admin FROM users "
            "ORDER BY id").fetchall()
        return {"users": [dict(r) for r in rows]}


@app.post("/admin/users/{user_id}/ban")
def admin_ban_user(user_id: int, req: Request):
    admin = auth_admin(req)
    if user_id == admin["id"]:
        raise HTTPException(400, "不能封禁自己")
    with db() as conn:
        row = conn.execute("SELECT id, is_admin, status FROM users WHERE id=?",
                           (user_id,)).fetchone()
        if not row:
            raise HTTPException(404, "账号不存在")
        if row["is_admin"]:
            raise HTTPException(400, "不能封禁管理员账号")
        conn.execute("UPDATE users SET status='banned' WHERE id=?", (user_id,))
        # 封禁即踢下线：删掉全部会话，并断开其在线 WebSocket（广播层按表查不到即失效；
        # 已连接的连接在下一次鉴权/重连时被拒，这里同时清会话保证立即生效）
        conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    return {"ok": True, "status": "banned"}


@app.post("/admin/users/{user_id}/unban")
def admin_unban_user(user_id: int, req: Request):
    auth_admin(req)
    with db() as conn:
        row = conn.execute("SELECT id, status FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(404, "账号不存在")
        if row["status"] != "banned":
            raise HTTPException(400, "这个账号没有被封禁")
        conn.execute("UPDATE users SET status='approved' WHERE id=?", (user_id,))
        conn.execute("DELETE FROM user_mutes WHERE user_id=?", (user_id,))
    return {"ok": True, "status": "approved"}


@app.get("/admin/passcodes")
def admin_passcodes(req: Request):
    auth_admin(req)
    with db() as conn:
        rows = conn.execute(
            "SELECT p.code, p.created_at, p.used_at, u.username AS used_by_name "
            "FROM passcodes p LEFT JOIN users u ON u.id = p.used_by "
            "ORDER BY p.created_at DESC LIMIT 50").fetchall()
        return {"passcodes": [dict(r) for r in rows]}


@app.post("/admin/passcodes")
def admin_make_passcode(req: Request):
    admin = auth_admin(req)
    alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
    with db() as conn:
        for _ in range(10):
            raw = "".join(secrets.choice(alphabet) for _ in range(8))
            code = raw[:4] + "-" + raw[4:]
            try:
                conn.execute(
                    "INSERT INTO passcodes(code,created_by,created_at) VALUES(?,?,?)",
                    (code, admin["id"], now_iso()))
                return {"code": code}
            except sqlite3.IntegrityError:
                continue
    raise HTTPException(500, "生成失败，请重试")


@app.delete("/admin/passcodes/{code}")
def admin_revoke_passcode(code: str, req: Request):
    auth_admin(req)
    with db() as conn:
        pc = conn.execute("SELECT * FROM passcodes WHERE code=?", (code,)).fetchone()
        if not pc or pc["used_by"] is not None:
            raise HTTPException(404, "通行码不存在或已使用")
        conn.execute("DELETE FROM passcodes WHERE code=?", (code,))
    return {"ok": True}


# ---------- 用户反馈（2026-11-18 项目定版的：人人可提交建议，管理员查看并回复） ----------

@app.post("/feedback")
async def submit_feedback(req: Request):
    user = auth_user(req)
    body = await req.json()
    content = (body.get("content") or "").strip()
    if not content:
        raise HTTPException(400, "反馈内容不能为空")
    if len(content) > 2000:
        raise HTTPException(400, "反馈太长了")
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO feedback(user_id,content,created_at) VALUES(?,?,?)",
            (user["id"], content, now_iso()))
        return {"ok": True, "id": cur.lastrowid}


@app.get("/feedback/mine")
def my_feedback(req: Request):
    user = auth_user(req)
    with db() as conn:
        rows = conn.execute(
            "SELECT id, content, created_at, reply, replied_at FROM feedback "
            "WHERE user_id=? ORDER BY id DESC LIMIT 100", (user["id"],)).fetchall()
        return {"feedback": [dict(r) for r in rows]}


@app.get("/admin/feedback")
def admin_feedback(req: Request):
    auth_admin(req)
    with db() as conn:
        rows = conn.execute(
            "SELECT f.id, f.content, f.created_at, f.reply, f.replied_at, "
            "u.username, u.nickname FROM feedback f JOIN users u ON u.id = f.user_id "
            "ORDER BY f.id DESC LIMIT 200").fetchall()
        return {"feedback": [dict(r) for r in rows]}


@app.post("/admin/feedback/{fid}/reply")
async def admin_reply_feedback(fid: int, req: Request):
    admin = auth_admin(req)
    body = await req.json()
    reply = (body.get("reply") or "").strip()
    if not reply:
        raise HTTPException(400, "回复不能为空")
    with db() as conn:
        row = conn.execute("SELECT id FROM feedback WHERE id=?", (fid,)).fetchone()
        if not row:
            raise HTTPException(404, "反馈不存在")
        conn.execute(
            "UPDATE feedback SET reply=?, replied_at=?, replied_by=? WHERE id=?",
            (reply, now_iso(), admin["id"], fid))
    return {"ok": True}


# ---------- 管理员按 ID 直接加群成员（2026-11-18 项目定版的管理员专属口子） ----------
# 普通用户进群仍然只有邀请码一条路；只有平台管理员（Master）能按 ID 搜索
# 用户或 AI 并直接拉进任意群，不需要对方同意。

@app.get("/admin/lookup")
def admin_lookup(req: Request, q: str = ""):
    auth_admin(req)
    q = q.strip().lstrip("@")
    out = {"users": [], "agents": []}
    if not q:
        return out
    with db() as conn:
        rows = conn.execute(
            "SELECT id, username, nickname FROM users "
            "WHERE username=? OR username LIKE ? LIMIT 10",
            (q, q + "%")).fetchall()
        out["users"] = [dict(r) for r in rows]
        rows = conn.execute(
            "SELECT id, handle, name, owner_user_id FROM agents "
            "WHERE handle=? OR handle LIKE ? OR name LIKE ? LIMIT 10",
            (q, q + "%", "%" + q + "%")).fetchall()
        out["agents"] = [dict(r) for r in rows]
    return out


@app.get("/admin/groups")
def admin_groups(req: Request):
    auth_admin(req)
    with db() as conn:
        rows = conn.execute(
            "SELECT r.id, r.name, "
            "(SELECT COUNT(*) FROM room_members m WHERE m.room_id = r.id) AS member_count "
            "FROM rooms r WHERE kind='group' ORDER BY r.id").fetchall()
        return {"groups": [dict(r) for r in rows]}


@app.post("/admin/groups/{room_id}/add")
async def admin_add_member(room_id: int, req: Request):
    auth_admin(req)
    body = await req.json()
    mtype = body.get("member_type")
    mid = body.get("member_id")
    if mtype not in ("user", "agent") or not isinstance(mid, int):
        raise HTTPException(400, "成员不对")
    with db() as conn:
        room = conn.execute(
            "SELECT * FROM rooms WHERE id=? AND kind='group'", (room_id,)).fetchone()
        if not room:
            raise HTTPException(404, "没有这个群")
        if mtype == "user":
            target = conn.execute("SELECT id FROM users WHERE id=?", (mid,)).fetchone()
        else:
            target = conn.execute("SELECT id FROM agents WHERE id=?", (mid,)).fetchone()
        if not target:
            raise HTTPException(404, "成员不存在")
        cur = conn.execute(
            "INSERT OR IGNORE INTO room_members(room_id,member_type,member_id,role,joined_at) "
            "VALUES(?,?,?,?,?)", (room_id, mtype, mid, "member", now_iso()))
        return {"ok": True, "added": cur.rowcount > 0}


@app.post("/admin/dm")
async def admin_create_dm(req: Request):
    # 管理员直接添加私聊（2026-11-18 项目定版的）：搜到人之后，除了拉进群，
    # 还能直接和对方建私聊，不用对方同意；建好后出现在双方的消息列表里。
    admin = auth_admin(req)
    body = await req.json()
    mtype = body.get("member_type")
    mid = body.get("member_id")
    if mtype not in ("user", "agent") or not isinstance(mid, int):
        raise HTTPException(400, "成员不对")
    if mtype == "user" and mid == admin["id"]:
        raise HTTPException(400, "不能和自己私聊")
    with db() as conn:
        if mtype == "agent":
            t = conn.execute("SELECT id, name FROM agents WHERE id=?", (mid,)).fetchone()
            if not t:
                raise HTTPException(404, "成员不存在")
            row = conn.execute(
                "SELECT r.id FROM rooms r "
                "JOIN room_members mu ON mu.room_id=r.id AND mu.member_type='user' AND mu.member_id=? "
                "JOIN room_members ma ON ma.room_id=r.id AND ma.member_type='agent' AND ma.member_id=? "
                "WHERE r.kind='dm' ORDER BY r.id LIMIT 1", (admin["id"], mid)).fetchone()
            if row:
                return {"room_id": row["id"], "existing": True}
            name = t["name"]
        else:
            t = conn.execute("SELECT id, username, nickname FROM users WHERE id=?", (mid,)).fetchone()
            if not t:
                raise HTTPException(404, "成员不存在")
            row = conn.execute(
                "SELECT r.id FROM rooms r "
                "JOIN room_members m1 ON m1.room_id=r.id AND m1.member_type='user' AND m1.member_id=? "
                "JOIN room_members m2 ON m2.room_id=r.id AND m2.member_type='user' AND m2.member_id=? "
                "WHERE r.kind='dm' ORDER BY r.id LIMIT 1", (admin["id"], mid)).fetchone()
            if row:
                return {"room_id": row["id"], "existing": True}
            name = t["nickname"] or t["username"]
        cur = conn.execute(
            "INSERT INTO rooms(name,kind,owner_user_id,auto_agent_limit,created_at) "
            "VALUES(?,?,?,?,?)", (name, "dm", admin["id"], 6, now_iso()))
        rid = cur.lastrowid
        conn.execute("INSERT INTO room_members(room_id,member_type,member_id,role,joined_at) "
                     "VALUES(?,?,?,?,?)", (rid, "user", admin["id"], "owner", now_iso()))
        conn.execute("INSERT INTO room_members(room_id,member_type,member_id,role,joined_at) "
                     "VALUES(?,?,?,?,?)", (rid, mtype, mid, "member", now_iso()))
        return {"room_id": rid, "existing": False}


# ---------- 全局公告（2026-11-18 项目定版的：管理员发布，全员进应用时弹窗确认） ----------

@app.post("/admin/announcements")
async def admin_publish_announcement(req: Request):
    admin = auth_admin(req)
    body = await req.json()
    content = (body.get("content") or "").strip()
    if not content:
        raise HTTPException(400, "公告内容不能为空")
    if len(content) > 2000:
        raise HTTPException(400, "公告太长了")
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO announcements(content,created_by,created_at) VALUES(?,?,?)",
            (content, admin["id"], now_iso()))
        return {"ok": True, "id": cur.lastrowid}


@app.get("/admin/announcements")
def admin_announcements(req: Request):
    auth_admin(req)
    with db() as conn:
        rows = conn.execute(
            "SELECT id, content, created_at FROM announcements ORDER BY id DESC LIMIT 20"
        ).fetchall()
        return {"announcements": [dict(r) for r in rows]}


@app.get("/announcements/latest")
def latest_announcement(req: Request):
    user = auth_user(req)
    with db() as conn:
        row = conn.execute(
            "SELECT id, content, created_at FROM announcements ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not row:
            return {"announcement": None}
        ack = conn.execute(
            "SELECT 1 FROM announcement_acks WHERE user_id=? AND announcement_id=?",
            (user["id"], row["id"])).fetchone()
        d = dict(row)
        d["acked"] = bool(ack)
        return {"announcement": d}


@app.get("/announcements")
def list_announcements(req: Request):
    user = auth_user(req)
    with db() as conn:
        rows = conn.execute(
            "SELECT a.id, a.content, a.created_at, "
            "EXISTS(SELECT 1 FROM announcement_acks k "
            "WHERE k.user_id=? AND k.announcement_id=a.id) AS acked "
            "FROM announcements a ORDER BY a.id DESC LIMIT 50",
            (user["id"],)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["acked"] = bool(d["acked"])
            out.append(d)
        return {"announcements": out}


@app.post("/announcements/{aid}/ack")
def ack_announcement(aid: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO announcement_acks(user_id,announcement_id,acked_at) "
            "VALUES(?,?,?)", (user["id"], aid, now_iso()))
    return {"ok": True}


def sign_global_bg_url(user_id: int, bg_path: str = "") -> str:
    # 签名绑当前文件路径：换一次图，旧链接立刻作废，浏览器缓存也骗不过去
    exp = _bucket_exp()
    mac = hmac_mod.new(SECRET.encode(), f"globalbg:{user_id}:{bg_path}:{exp}".encode(),
                       hashlib.sha256).hexdigest()[:32]
    return f"/global-bg-file?u={user_id}&exp={exp}&sig={mac}"


def _profile_dict(row):
    keys = row.keys()
    return {"user_id": row["id"], "username": row["username"],
            "nickname": row["nickname"] or "", "signature": row["signature"] or "",
            "bio": row["bio"] or "", "created_at": row["created_at"],
            "avatar_url": sign_avatar_url(row["id"]) if row["avatar_path"] else None,
            "global_bg_url": sign_global_bg_url(row["id"], row["global_bg_path"]) if "global_bg_path" in keys and row["global_bg_path"] else None,
            "global_bg_opacity": row["global_bg_opacity"] if "global_bg_opacity" in keys and row["global_bg_opacity"] is not None else 0.5,
            "global_bg_blur": row["global_bg_blur"] if "global_bg_blur" in keys and row["global_bg_blur"] is not None else 0,
            "global_bg_v": row["global_bg_updated_at"] if "global_bg_updated_at" in keys and row["global_bg_updated_at"] else 0,
            "status": (row["status"] or "approved") if "status" in keys else "approved",
            "is_admin": bool(row["is_admin"]) if "is_admin" in keys else False}


@app.get("/me")
def get_me(req: Request):
    user = auth_user(req)
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        return _profile_dict(row)


@app.patch("/me")
async def patch_me(req: Request):
    user = auth_user(req)
    body = await req.json()
    with db() as conn:
        if "nickname" in body:
            conn.execute("UPDATE users SET nickname=? WHERE id=?",
                         (str(body["nickname"])[:40], user["id"]))
        if "signature" in body:
            conn.execute("UPDATE users SET signature=? WHERE id=?",
                         (str(body["signature"])[:80], user["id"]))
        if "bio" in body:
            conn.execute("UPDATE users SET bio=? WHERE id=?",
                         (str(body["bio"])[:300], user["id"]))
        row = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        return _profile_dict(row)


@app.post("/me/avatar")
async def upload_avatar(req: Request, file: UploadFile = File(...)):
    user = auth_user(req)
    data = await file.read()
    if len(data) > 15 * 1024 * 1024:
        raise HTTPException(413, "图片超过 15MB")
    ava_dir = os.path.join(UPLOAD_DIR, "avatars")
    os.makedirs(ava_dir, exist_ok=True)
    rel = f"avatars/{user['id']}_{uuid.uuid4().hex}.jpg"
    if not make_preview(data, os.path.join(UPLOAD_DIR, rel)):
        raise HTTPException(400, "只能上传图片")
    # 头像压到 512
    try:
        from PIL import Image
        img = Image.open(os.path.join(UPLOAD_DIR, rel))
        img.thumbnail((512, 512))
        img.save(os.path.join(UPLOAD_DIR, rel), "JPEG", quality=82)
    except Exception:
        pass
    with db() as conn:
        old = conn.execute("SELECT avatar_path FROM users WHERE id=?", (user["id"],)).fetchone()
        conn.execute("UPDATE users SET avatar_path=? WHERE id=?", (rel, user["id"]))
        if old and old["avatar_path"]:
            try:
                os.remove(os.path.join(UPLOAD_DIR, old["avatar_path"]))
            except OSError:
                pass
    return {"avatar_url": sign_avatar_url(user["id"])}


@app.post("/me/image-convert")
async def convert_image(req: Request, file: UploadFile = File(...)):
    """把手机本地解不开的图片（HEIC 等）转成 JPEG 返回，供裁剪器继续用。
    只转码不落盘，裁剪与最终上传仍走原流程。"""
    auth_user(req)
    data = await file.read()
    if len(data) > 15 * 1024 * 1024:
        raise HTTPException(413, "图片超过 15MB")
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data))
        img.load()
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        img.thumbnail((2048, 2048))
        out = io.BytesIO()
        img.save(out, "JPEG", quality=88)
        return Response(content=out.getvalue(), media_type="image/jpeg")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(400, "这张图片打不开")


@app.post("/me/background")
async def set_global_background(req: Request, file: UploadFile = File(...)):
    user = auth_user(req)
    data = await file.read()
    if len(data) > 15 * 1024 * 1024:
        raise HTTPException(413, "图片超过 15MB")
    bg_dir = os.path.join(UPLOAD_DIR, "globalbg")
    os.makedirs(bg_dir, exist_ok=True)
    rel = f"globalbg/{user['id']}_{uuid.uuid4().hex}.jpg"
    if not make_bg(data, os.path.join(UPLOAD_DIR, rel)):
        raise HTTPException(400, "只能上传图片")
    v = time.time()
    with db() as conn:
        old = conn.execute("SELECT global_bg_path FROM users WHERE id=?", (user["id"],)).fetchone()
        conn.execute("UPDATE users SET global_bg_path=?, global_bg_updated_at=? WHERE id=?",
                     (rel, v, user["id"]))
        if old and old["global_bg_path"]:
            try:
                os.remove(os.path.join(UPLOAD_DIR, old["global_bg_path"]))
            except OSError:
                pass
    return {"global_bg_url": sign_global_bg_url(user["id"], rel), "global_bg_v": v}


@app.delete("/me/background")
def clear_global_background(req: Request):
    user = auth_user(req)
    with db() as conn:
        old = conn.execute("SELECT global_bg_path FROM users WHERE id=?", (user["id"],)).fetchone()
        conn.execute("UPDATE users SET global_bg_path=NULL, global_bg_updated_at=? WHERE id=?",
                     (time.time(), user["id"]))
        if old and old["global_bg_path"]:
            try:
                os.remove(os.path.join(UPLOAD_DIR, old["global_bg_path"]))
            except OSError:
                pass
    return {"ok": True}


@app.patch("/me/background-settings")
async def set_global_background_settings(req: Request):
    user = auth_user(req)
    body = await req.json()
    opacity = body.get("opacity")
    blur = body.get("blur")
    with db() as conn:
        if opacity is not None:
            conn.execute("UPDATE users SET global_bg_opacity=? WHERE id=?",
                         (max(0.0, min(1.0, float(opacity))), user["id"]))
        if blur is not None:
            conn.execute("UPDATE users SET global_bg_blur=? WHERE id=?",
                         (max(0, min(30, int(blur))), user["id"]))
        row = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        return _profile_dict(row)


@app.get("/global-bg-file")
def global_bg_file(u: int, exp: int, sig: str):
    if exp < int(time.time()):
        raise HTTPException(403, "链接无效或已过期")
    with db() as conn:
        row = conn.execute("SELECT global_bg_path FROM users WHERE id=?", (u,)).fetchone()
    if not row or not row["global_bg_path"]:
        raise HTTPException(404, "没有背景图")
    mac = hmac_mod.new(SECRET.encode(), f"globalbg:{u}:{row['global_bg_path']}:{exp}".encode(),
                       hashlib.sha256).hexdigest()[:32]
    if not hmac_mod.compare_digest(mac, sig):
        raise HTTPException(403, "链接无效或已过期")
    path = os.path.join(UPLOAD_DIR, row["global_bg_path"])
    if not os.path.exists(path):
        raise HTTPException(404, "没有背景图")
    return FileResponse(path, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=21600"})


@app.get("/avatar-file")
def avatar_file(u: int, exp: int, sig: str):
    if exp < int(time.time()):
        raise HTTPException(403, "链接无效或已过期")
    with db() as conn:
        row = conn.execute("SELECT avatar_path FROM users WHERE id=?", (u,)).fetchone()
    if not row or not row["avatar_path"]:
        raise HTTPException(404, "没有头像")
    mac = hmac_mod.new(SECRET.encode(), f"avatar:{u}:{row['avatar_path']}:{exp}".encode(),
                       hashlib.sha256).hexdigest()[:32]
    if not hmac_mod.compare_digest(mac, sig):
        raise HTTPException(403, "链接无效或已过期")
    path = os.path.join(UPLOAD_DIR, row["avatar_path"])
    if not os.path.exists(path):
        raise HTTPException(404, "没有头像")
    return FileResponse(path, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=21600"})


@app.post("/agents")
async def create_agent(req: Request):
    user = auth_user(req)
    body = await req.json()
    if not body.get("name"):
        raise HTTPException(400, "Agent 名称必填")
    tok = "agt_" + secrets.token_urlsafe(32)
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO agents(owner_user_id,name,bio,token_hash,created_at) VALUES(?,?,?,?,?)",
            (user["id"], body["name"], body.get("bio", ""), hash_token(tok), now_iso()))
        aid = cur.lastrowid
        handle = make_handle(conn, body["name"], aid)
        conn.execute("UPDATE agents SET handle=? WHERE id=?", (handle, aid))
        return {"agent_id": aid, "name": body["name"], "handle": handle,
                "token": tok, "note": "Token 只显示这一次，Hub 只存哈希"}


@app.get("/agents")
def list_agents(req: Request):
    user = auth_user(req)
    with db() as conn:
        rows = conn.execute(
            "SELECT id,owner_user_id,name,bio,signature,online,last_seen,created_at,avatar_path,"
            "listening,listening_at,suspended,handle "
            "FROM agents WHERE owner_user_id=?", (user["id"],)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["status"] = agent_status(r)
            d["online"] = d["status"]["key"] in ("online", "listening")
            d["suspended"] = bool(d.get("suspended"))
            d.pop("listening", None)
            d.pop("listening_at", None)
            d["avatar_url"] = (sign_agent_avatar_url(d["id"], user["id"])
                               if d.pop("avatar_path", None) else None)
            out.append(d)
        return {"agents": out}


@app.post("/agents/{agent_id}/avatar")
async def upload_agent_avatar(agent_id: int, req: Request, file: UploadFile = File(...)):
    user = auth_user(req)
    data = await file.read()
    if len(data) > 15 * 1024 * 1024:
        raise HTTPException(413, "图片超过 15MB")
    ava_dir = os.path.join(UPLOAD_DIR, "avatars")
    os.makedirs(ava_dir, exist_ok=True)
    rel = f"avatars/agent_{agent_id}_{uuid.uuid4().hex}.jpg"
    if not make_preview(data, os.path.join(UPLOAD_DIR, rel)):
        raise HTTPException(400, "只能上传图片")
    try:
        from PIL import Image
        img = Image.open(os.path.join(UPLOAD_DIR, rel))
        img.thumbnail((512, 512))
        img.save(os.path.join(UPLOAD_DIR, rel), "JPEG", quality=82)
    except Exception:
        pass
    with db() as conn:
        row = conn.execute("SELECT avatar_path FROM agents WHERE id=? AND owner_user_id=?",
                           (agent_id, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "没有这个 Agent")
        conn.execute("UPDATE agents SET avatar_path=? WHERE id=?", (rel, agent_id))
        if row["avatar_path"]:
            try:
                os.remove(os.path.join(UPLOAD_DIR, row["avatar_path"]))
            except OSError:
                pass
    return {"avatar_url": sign_agent_avatar_url(agent_id, user["id"])}


@app.get("/agent-avatar-file")
def agent_avatar_file(agent: int, u: int, exp: int, sig: str):
    if exp < int(time.time()):
        raise HTTPException(403, "链接无效或已过期")
    with db() as conn:
        row = conn.execute("SELECT avatar_path FROM agents WHERE id=? AND owner_user_id=?",
                           (agent, u)).fetchone()
    if not row or not row["avatar_path"]:
        raise HTTPException(404, "没有头像")
    mac = hmac_mod.new(SECRET.encode(), f"aavatar:{agent}:{u}:{row['avatar_path']}:{exp}".encode(),
                       hashlib.sha256).hexdigest()[:32]
    if not hmac_mod.compare_digest(mac, sig):
        raise HTTPException(403, "链接无效或已过期")
    path = os.path.join(UPLOAD_DIR, row["avatar_path"])
    if not os.path.exists(path):
        raise HTTPException(404, "没有头像")
    return FileResponse(path, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=21600"})


@app.post("/agents/{agent_id}/token")
def reset_agent_token(agent_id: int, req: Request):
    user = auth_user(req)
    tok = "agt_" + secrets.token_urlsafe(32)
    with db() as conn:
        cur = conn.execute("UPDATE agents SET token_hash=? WHERE id=? AND owner_user_id=?",
                           (hash_token(tok), agent_id, user["id"]))
        if cur.rowcount == 0:
            raise HTTPException(404, "没有这个 Agent")
        return {"agent_id": agent_id, "token": tok, "note": "新 Token 只显示这一次，旧的已失效"}


@app.patch("/agents/{agent_id}/suspend")
async def suspend_agent(agent_id: int, req: Request):
    """暂停/恢复某个 AI 的接入：暂停后它的 Token 立刻被拒，状态显示离线中。"""
    user = auth_user(req)
    body = await req.json()
    with db() as conn:
        cur = conn.execute("UPDATE agents SET suspended=?, listening=0 WHERE id=? AND owner_user_id=?",
                           (1 if body.get("suspended") else 0, agent_id, user["id"]))
        if cur.rowcount == 0:
            raise HTTPException(404, "没有这个 Agent")
        return {"ok": True, "suspended": bool(body.get("suspended"))}


@app.patch("/agents/{agent_id}")
async def patch_agent(agent_id: int, req: Request):
    """主人改名下 AI 的资料：名字、签名、介绍（2026-11-18 项目定版：人类可编辑名下成员主页）。
    AI 本人经 MCP 也能改自己的签名/简介，两条路并存。"""
    user = auth_user(req)
    body = await req.json()
    sets, vals = [], []
    if "name" in body:
        name = str(body.get("name", "")).strip()
        if not name:
            raise HTTPException(400, "名字不能为空")
        sets.append("name=?"); vals.append(name[:40])
    if "signature" in body:
        sets.append("signature=?"); vals.append(str(body.get("signature", ""))[:80])
    if "bio" in body:
        sets.append("bio=?"); vals.append(str(body.get("bio", ""))[:300])
    if not sets:
        raise HTTPException(400, "没有要改的内容")
    vals += [agent_id, user["id"]]
    with db() as conn:
        cur = conn.execute(f"UPDATE agents SET {', '.join(sets)} WHERE id=? AND owner_user_id=?", vals)
        if cur.rowcount == 0:
            raise HTTPException(404, "没有这个 Agent")
        return {"ok": True}


@app.delete("/agents/{agent_id}")
def delete_agent(agent_id: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        cur = conn.execute("DELETE FROM agents WHERE id=? AND owner_user_id=?",
                           (agent_id, user["id"]))
        if cur.rowcount == 0:
            raise HTTPException(404, "没有这个 Agent")
        conn.execute("DELETE FROM room_members WHERE member_type='agent' AND member_id=?",
                     (agent_id,))
        return {"ok": True}


@app.post("/rooms")
async def create_room(req: Request):
    user = auth_user(req)
    body = await req.json()
    if not body.get("name"):
        raise HTTPException(400, "房间名必填")
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO rooms(name,kind,owner_user_id,auto_agent_limit,created_at) "
            "VALUES(?,?,?,?,?)",
            (body["name"], body.get("kind", "group"), user["id"],
             int(body.get("auto_agent_limit", 6)), now_iso()))
        room_id = cur.lastrowid
        conn.execute("INSERT INTO room_members(room_id,member_type,member_id,role,joined_at) "
                     "VALUES(?,?,?,?,?)", (room_id, "user", user["id"], "owner", now_iso()))
        return {"room_id": room_id, "name": body["name"]}


@app.post("/rooms/dm")
async def get_or_create_dm(req: Request):
    user = auth_user(req)
    body = await req.json()
    agent_id = int(body.get("agent_id", 0))
    with db() as conn:
        ag = conn.execute("SELECT id, name FROM agents WHERE id=? AND owner_user_id=?",
                          (agent_id, user["id"])).fetchone()
        if not ag:
            raise HTTPException(404, "成员不存在")
        row = conn.execute(
            "SELECT r.id FROM rooms r "
            "JOIN room_members mu ON mu.room_id=r.id AND mu.member_type='user' AND mu.member_id=? "
            "JOIN room_members ma ON ma.room_id=r.id AND ma.member_type='agent' AND ma.member_id=? "
            "WHERE r.kind='dm' ORDER BY r.id LIMIT 1", (user["id"], agent_id)).fetchone()
        if row:
            return {"room_id": row["id"], "existing": True}
        cur = conn.execute(
            "INSERT INTO rooms(name,kind,owner_user_id,auto_agent_limit,created_at) "
            "VALUES(?,?,?,?,?)", (ag["name"], "dm", user["id"], 6, now_iso()))
        room_id = cur.lastrowid
        conn.execute("INSERT INTO room_members(room_id,member_type,member_id,role,joined_at) "
                     "VALUES(?,?,?,?,?)", (room_id, "user", user["id"], "owner", now_iso()))
        conn.execute("INSERT INTO room_members(room_id,member_type,member_id,role,joined_at) "
                     "VALUES(?,?,?,?,?)", (room_id, "agent", agent_id, "member", now_iso()))
        return {"room_id": room_id, "existing": False}


def sign_room_avatar_url(room_id: int) -> str:
    with db() as conn:
        row = conn.execute("SELECT avatar_path FROM rooms WHERE id=?", (room_id,)).fetchone()
    ap = row["avatar_path"] if row and row["avatar_path"] else ""
    exp = _bucket_exp()
    mac = hmac_mod.new(SECRET.encode(), f"roomava:{room_id}:{ap}:{exp}".encode(),
                       hashlib.sha256).hexdigest()[:32]
    return f"/room-avatar-file?room={room_id}&exp={exp}&sig={mac}"


@app.post("/rooms/{room_id}/avatar")
async def set_room_avatar(room_id: int, req: Request, file: UploadFile = File(...)):
    user = auth_user(req)
    data = await file.read()
    if len(data) > 15 * 1024 * 1024:
        raise HTTPException(413, "图片超过 15MB")
    ava_dir = os.path.join(UPLOAD_DIR, "roomava")
    os.makedirs(ava_dir, exist_ok=True)
    rel = f"roomava/{room_id}_{uuid.uuid4().hex}.jpg"
    if not make_preview(data, os.path.join(UPLOAD_DIR, rel)):
        raise HTTPException(400, "只能上传图片")
    with db() as conn:
        row = conn.execute("SELECT owner_user_id, avatar_path FROM rooms WHERE id=?", (room_id,)).fetchone()
        if not row:
            raise HTTPException(404, "房间不存在")
        if row["owner_user_id"] != user["id"]:
            raise HTTPException(403, "只有群主能换群头像")
        conn.execute("UPDATE rooms SET avatar_path=? WHERE id=?", (rel, room_id))
        if row["avatar_path"]:
            try:
                os.remove(os.path.join(UPLOAD_DIR, row["avatar_path"]))
            except OSError:
                pass
    return {"avatar_url": sign_room_avatar_url(room_id)}


@app.get("/room-avatar-file")
def room_avatar_file(room: int, exp: int, sig: str):
    if exp < int(time.time()):
        raise HTTPException(403, "链接无效或已过期")
    with db() as conn:
        row = conn.execute("SELECT avatar_path FROM rooms WHERE id=?", (room,)).fetchone()
    if not row or not row["avatar_path"]:
        raise HTTPException(404, "没有头像")
    mac = hmac_mod.new(SECRET.encode(), f"roomava:{room}:{row['avatar_path']}:{exp}".encode(),
                       hashlib.sha256).hexdigest()[:32]
    if not hmac_mod.compare_digest(mac, sig):
        raise HTTPException(403, "链接无效或已过期")
    path = os.path.join(UPLOAD_DIR, row["avatar_path"])
    if not os.path.exists(path):
        raise HTTPException(404, "没有头像")
    return FileResponse(path, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=21600"})


def sign_room_bg_url(room_id: int, user_id: int) -> str:
    with db() as conn:
        row = conn.execute(
            "SELECT bg_path FROM room_members WHERE room_id=? AND member_type='user' AND member_id=?",
            (room_id, user_id)).fetchone()
    bg_path = row["bg_path"] if row and row["bg_path"] else ""
    exp = _bucket_exp()
    mac = hmac_mod.new(SECRET.encode(), f"roombg:{room_id}:{user_id}:{bg_path}:{exp}".encode(),
                       hashlib.sha256).hexdigest()[:32]
    return f"/room-bg-file?room={room_id}&u={user_id}&exp={exp}&sig={mac}"


@app.get("/rooms")
def list_rooms_rest(req: Request):
    user = auth_user(req)
    with db() as conn:
        rows = conn.execute(
            "SELECT r.*, m.bg_path AS my_bg FROM rooms r JOIN room_members m ON m.room_id=r.id "
            "WHERE m.member_type='user' AND m.member_id=?", (user["id"],)).fetchall()
        rooms = []
        for r in rows:
            d = dict(r)
            d["bg_url"] = sign_room_bg_url(d["id"], user["id"]) if d.pop("my_bg", None) else None
            avatar_path = d.pop("avatar_path", None)
            if d["kind"] == "dm":
                ag = conn.execute(
                    "SELECT a.id AS agent_id, a.avatar_path, a.owner_user_id FROM room_members rm "
                    "JOIN agents a ON a.id=rm.member_id "
                    "WHERE rm.room_id=? AND rm.member_type='agent' LIMIT 1", (d["id"],)).fetchone()
                d["avatar_url"] = (sign_agent_avatar_url(ag["agent_id"], ag["owner_user_id"])
                                   if ag and ag["avatar_path"] else None)
                d["dm_agent_id"] = ag["agent_id"] if ag else None
                if not ag:
                    # 人与人的私聊（管理员直加的那种）：标题和头像按观看者取对方的
                    ou = conn.execute(
                        "SELECT u.id AS uid, u.username, u.nickname, u.avatar_path FROM room_members rm "
                        "JOIN users u ON u.id=rm.member_id "
                        "WHERE rm.room_id=? AND rm.member_type='user' AND rm.member_id<>? LIMIT 1",
                        (d["id"], user["id"])).fetchone()
                    if ou:
                        d["name"] = ou["nickname"] or ou["username"]
                        d["avatar_url"] = sign_avatar_url(ou["uid"]) if ou["avatar_path"] else None
                        d["dm_user_id"] = ou["uid"]
            else:
                d["avatar_url"] = sign_room_avatar_url(d["id"]) if avatar_path else None
            rooms.append(d)
        return {"rooms": rooms}


@app.post("/rooms/{room_id}/background")
async def set_room_background(room_id: int, req: Request, file: UploadFile = File(...)):
    user = auth_user(req)
    data = await file.read()
    if len(data) > 15 * 1024 * 1024:
        raise HTTPException(413, "图片超过 15MB")
    bg_dir = os.path.join(UPLOAD_DIR, "roombg")
    os.makedirs(bg_dir, exist_ok=True)
    rel = f"roombg/{room_id}_{user['id']}_{uuid.uuid4().hex}.jpg"
    if not make_bg(data, os.path.join(UPLOAD_DIR, rel)):
        raise HTTPException(400, "只能上传图片")
    with db() as conn:
        row = conn.execute(
            "SELECT bg_path FROM room_members WHERE room_id=? AND member_type='user' AND member_id=?",
            (room_id, user["id"])).fetchone()
        if not row:
            raise HTTPException(403, "你不在这个房间里")
        conn.execute(
            "UPDATE room_members SET bg_path=? WHERE room_id=? AND member_type='user' AND member_id=?",
            (rel, room_id, user["id"]))
        if row["bg_path"]:
            try:
                os.remove(os.path.join(UPLOAD_DIR, row["bg_path"]))
            except OSError:
                pass
    return {"bg_url": sign_room_bg_url(room_id, user["id"])}


@app.delete("/rooms/{room_id}/background")
def clear_room_background(room_id: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        row = conn.execute(
            "SELECT bg_path FROM room_members WHERE room_id=? AND member_type='user' AND member_id=?",
            (room_id, user["id"])).fetchone()
        if not row:
            raise HTTPException(403, "你不在这个房间里")
        conn.execute(
            "UPDATE room_members SET bg_path=NULL WHERE room_id=? AND member_type='user' AND member_id=?",
            (room_id, user["id"]))
        if row["bg_path"]:
            try:
                os.remove(os.path.join(UPLOAD_DIR, row["bg_path"]))
            except OSError:
                pass
    return {"ok": True}


@app.get("/room-bg-file")
def room_bg_file(room: int, u: int, exp: int, sig: str):
    if exp < int(time.time()):
        raise HTTPException(403, "链接无效或已过期")
    with db() as conn:
        row = conn.execute(
            "SELECT bg_path FROM room_members WHERE room_id=? AND member_type='user' AND member_id=?",
            (room, u)).fetchone()
    if not row or not row["bg_path"]:
        raise HTTPException(404, "没有背景图")
    mac = hmac_mod.new(SECRET.encode(), f"roombg:{room}:{u}:{row['bg_path']}:{exp}".encode(),
                       hashlib.sha256).hexdigest()[:32]
    if not hmac_mod.compare_digest(mac, sig):
        raise HTTPException(403, "链接无效或已过期")
    path = os.path.join(UPLOAD_DIR, row["bg_path"])
    if not os.path.exists(path):
        raise HTTPException(404, "没有背景图")
    return FileResponse(path, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=21600"})


@app.post("/rooms/{room_id}/members")
async def add_member(room_id: int, req: Request):
    # 进群只有一条路：凭邀请码本人加入（人类走 /invitations/<code>/join，
    # AI 走自己的 MCP join_room）。直接加成员的口子已按群主规则关闭，
    # 防止任何人绕过邀请码把成员（尤其成批 AI）塞进群。
    auth_user(req)
    raise HTTPException(403, "进群只能凭邀请码，请让对方拿邀请码自己加入")


@app.post("/rooms/{room_id}/invitations")
async def create_invite(room_id: int, req: Request):
    user = auth_user(req)
    body = await req.json()
    code = secrets.token_urlsafe(9)
    with db() as conn:
        room = conn.execute("SELECT * FROM rooms WHERE id=?", (room_id,)).fetchone()
        if not room:
            raise HTTPException(404, "没有这个房间")
        if room["owner_user_id"] != user["id"]:
            raise HTTPException(403, "只有群主能生成邀请码")
        # 一个邀请码只进一个成员：强制单次使用，每次生成都是新码
        conn.execute(
            "INSERT INTO invitations(code,room_id,created_by,expires_at,max_uses,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (code, room_id, user["id"], body.get("expires_at"), 1, now_iso()))
        return {"code": code, "room_id": room_id}


@app.post("/invitations/{code}/join")
async def join_by_invite(code: str, req: Request):
    user = auth_user(req)
    body = await req.json()
    with db() as conn:
        inv = conn.execute("SELECT * FROM invitations WHERE code=?", (code,)).fetchone()
        if not inv:
            raise HTTPException(404, "邀请码不存在")
        if inv["expires_at"] and inv["expires_at"] < now_iso():
            raise HTTPException(410, "邀请码已过期")
        if inv["max_uses"] and inv["uses"] >= inv["max_uses"]:
            raise HTTPException(410, "邀请码次数已用完")
        # 一个码只进一个成员，且只许本人进：人类凭码进的只能是自己，
        # AI 凭码进群走它自己的 MCP join_room——谁也不能替别人用码，
        # 防止有人拿一个码批量拉几十上百个 AI 进群。
        conn.execute("INSERT OR IGNORE INTO room_members(room_id,member_type,member_id,role,joined_at) "
                     "VALUES(?,?,?,?,?)", (inv["room_id"], "user", user["id"], "member", now_iso()))
        conn.execute("UPDATE invitations SET uses=uses+1 WHERE code=?", (code,))
        return {"ok": True, "room_id": inv["room_id"]}


@app.get("/rooms/{room_id}/members")
def room_members_rest(room_id: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        if not is_member(conn, room_id, "user", user["id"]):
            raise HTTPException(403, "你不在这个房间里")
        rows = conn.execute(
            "SELECT member_type, member_id, role, joined_at FROM room_members WHERE room_id=?",
            (room_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            if r["member_type"] == "user":
                u = conn.execute("SELECT username, nickname, avatar_path, signature, bio, created_at FROM users WHERE id=?",
                                 (r["member_id"],)).fetchone()
                d["name"] = (u["nickname"] or u["username"]) if u else f"用户 {r['member_id']}"
                if u:
                    d["username"] = u["username"] or ""
                    d["signature"] = u["signature"] or ""
                    d["bio"] = u["bio"] or ""
                    d["created_at"] = u["created_at"]
                d["online"] = None
                d["avatar_url"] = (sign_avatar_url(r["member_id"])
                                   if u and u["avatar_path"] else None)
                d["agents"] = []
                if u:
                    for x in conn.execute(
                            "SELECT id, name, handle, avatar_path, owner_user_id FROM agents "
                            "WHERE owner_user_id = ? ORDER BY id", (r["member_id"],)):
                        d["agents"].append({
                            "id": x["id"], "name": x["name"], "handle": x["handle"],
                            "avatar_url": (sign_agent_avatar_url(x["id"], x["owner_user_id"])
                                           if x["avatar_path"] else None)})
            else:
                a = conn.execute(
                    "SELECT a.name, a.online, a.avatar_path, a.owner_user_id, a.signature, a.handle, "
                    "a.bio, a.last_seen, a.listening, a.listening_at, a.suspended, "
                    "u.nickname AS owner_nick, u.username AS owner_name, u.avatar_path AS owner_avatar_path "
                    "FROM agents a LEFT JOIN users u ON u.id = a.owner_user_id WHERE a.id=?",
                    (r["member_id"],)).fetchone()
                d["name"] = a["name"] if a else f"AI {r['member_id']}"
                if a:
                    d["status"] = agent_status(a)
                    d["online"] = d["status"]["key"] in ("online", "listening")
                else:
                    d["online"] = False
                d["avatar_url"] = (sign_agent_avatar_url(r["member_id"], a["owner_user_id"])
                                   if a and a["avatar_path"] else None)
                if a:
                    d["signature"] = a["signature"] or ""
                    d["handle"] = a["handle"] or ""
                    d["bio"] = a["bio"] or ""
                    d["last_seen"] = a["last_seen"]
                    d["owner_name"] = a["owner_nick"] or a["owner_name"] or ""
                    d["owner_username"] = a["owner_name"] or ""
                    d["owner_user_id"] = a["owner_user_id"]
                    d["owner_avatar_url"] = (sign_avatar_url(a["owner_user_id"])
                                              if a["owner_avatar_path"] else None)
            out.append(d)
        return {"members": out}


def _dissolve_room(conn, room_id: int):
    for r in conn.execute("SELECT file_path FROM room_files WHERE room_id=?", (room_id,)).fetchall():
        try:
            os.remove(os.path.join(UPLOAD_DIR, r["file_path"]))
        except OSError:
            pass
    conn.execute("DELETE FROM room_files WHERE room_id=?", (room_id,))
    conn.execute("DELETE FROM favorites WHERE room_id=?", (room_id,))
    conn.execute("DELETE FROM messages WHERE room_id=?", (room_id,))
    conn.execute("DELETE FROM room_members WHERE room_id=?", (room_id,))
    conn.execute("DELETE FROM invitations WHERE room_id=?", (room_id,))
    conn.execute("DELETE FROM rooms WHERE id=?", (room_id,))


@app.patch("/rooms/{room_id}")
async def rename_room(room_id: int, req: Request):
    user = auth_user(req)
    body = await req.json()
    with db() as conn:
        room = conn.execute("SELECT * FROM rooms WHERE id=?", (room_id,)).fetchone()
        if not room or not is_member(conn, room_id, "user", user["id"]):
            raise HTTPException(403, "你不在这个房间里")
        out = {"ok": True}
        if "name" in body:
            name = str(body.get("name", "")).strip()
            if not name:
                raise HTTPException(400, "名字不能为空")
            conn.execute("UPDATE rooms SET name=? WHERE id=?", (name[:60], room_id))
            out["name"] = name[:60]
        # 群公告与群简介只有群主能改
        for field, limit in (("announcement", 500), ("description", 300)):
            if field in body:
                if room["owner_user_id"] != user["id"]:
                    raise HTTPException(403, "只有群主能修改群公告和群简介")
                conn.execute(f"UPDATE rooms SET {field}=? WHERE id=?",
                             (str(body[field])[:limit], room_id))
                out[field] = str(body[field])[:limit]
        return out


@app.delete("/rooms/{room_id}/members/me")
def leave_room(room_id: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        room = conn.execute("SELECT * FROM rooms WHERE id=?", (room_id,)).fetchone()
        if not room or not is_member(conn, room_id, "user", user["id"]):
            raise HTTPException(404, "你不在这个房间里")
        if room["owner_user_id"] == user["id"]:
            _dissolve_room(conn, room_id)
            return {"ok": True, "dissolved": True}
        conn.execute(
            "DELETE FROM room_members WHERE room_id=? AND member_type='user' AND member_id=?",
            (room_id, user["id"]))
        return {"ok": True, "dissolved": False}


@app.delete("/rooms/{room_id}/members/{member_type}/{member_id}")
def kick_member(room_id: int, member_type: str, member_id: int, req: Request):
    user = auth_user(req)
    if member_type not in ("user", "agent"):
        raise HTTPException(400, "成员类型不对")
    with db() as conn:
        room = conn.execute("SELECT * FROM rooms WHERE id=?", (room_id,)).fetchone()
        if not room:
            raise HTTPException(404, "没有这个房间")
        if room["kind"] == "dm":
            raise HTTPException(400, "私聊不能移除成员")
        if room["owner_user_id"] != user["id"]:
            raise HTTPException(403, "只有群主可以移除成员")
        if member_type == "user" and member_id == room["owner_user_id"]:
            raise HTTPException(400, "不能移除群主")
        cur = conn.execute(
            "DELETE FROM room_members WHERE room_id=? AND member_type=? AND member_id=?",
            (room_id, member_type, member_id))
        if cur.rowcount == 0:
            raise HTTPException(404, "这个成员不在群里")
        return {"ok": True}


@app.delete("/rooms/{room_id}")
def dissolve_room(room_id: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        room = conn.execute("SELECT * FROM rooms WHERE id=?", (room_id,)).fetchone()
        if not room:
            raise HTTPException(404, "没有这个房间")
        if room["owner_user_id"] != user["id"]:
            raise HTTPException(403, "只有房主能解散")
        _dissolve_room(conn, room_id)
        return {"ok": True}


@app.post("/rooms/{room_id}/messages")
async def user_send(room_id: int, req: Request):
    user = auth_user(req)
    body = await req.json()
    with db() as conn:
        if not is_member(conn, room_id, "user", user["id"]):
            raise HTTPException(403, "你不在这个房间里")
        user_send_guard(conn, user["id"], body.get("content", ""),
                        body.get("content_type", "text"))
        try:
            msg = insert_message(conn, room_id, "user", user["id"], user["id"],
                                 body.get("content", ""), body.get("content_type", "text"),
                                 body.get("reply_to"), body.get("mentions"))
        except ValueError as e:
            raise HTTPException(400, str(e))
        attach_file_info(conn, msg)
    await broadcast_message(msg)
    out = dict(msg)
    if out.get("content_type") in ("image", "file", "audio"):
        try:
            out["file_url"] = sign_room_file_url(int(out.get("content") or 0), user["id"])
        except (TypeError, ValueError):
            pass
    return out


@app.get("/rooms/{room_id}/messages")
def room_messages(room_id: int, req: Request, after_id: int = 0, limit: int = 100):
    user = auth_user(req)
    with db() as conn:
        if not is_member(conn, room_id, "user", user["id"]):
            raise HTTPException(403, "你不在这个房间里")
        rows = conn.execute(
            "SELECT * FROM messages WHERE room_id=? AND id>? ORDER BY id ASC LIMIT ?",
            (room_id, after_id, limit)).fetchall()
        msgs = [attach_file_info(conn, msg_dict(r), user["id"]) for r in rows]
        return {"messages": attach_sender_names(conn, msgs)}


# ---------------- 相册 REST（仅用户；MCP 无相册接口） ----------------

@app.post("/albums")
async def create_album(req: Request):
    user = auth_user(req)
    body = await req.json()
    if not body.get("name"):
        raise HTTPException(400, "相册名必填")
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO albums(owner_user_id,name,note,created_at,updated_at) VALUES(?,?,?,?,?)",
            (user["id"], body["name"], body.get("note", ""), now_iso(), now_iso()))
        return {"album_id": cur.lastrowid, "name": body["name"]}


@app.get("/albums")
def list_albums(req: Request):
    user = auth_user(req)
    with db() as conn:
        rows = conn.execute(
            "SELECT a.*, (SELECT COUNT(*) FROM album_items i WHERE i.album_id=a.id) AS item_count "
            "FROM albums a WHERE a.owner_user_id=? ORDER BY a.id", (user["id"],)).fetchall()
        return {"albums": [dict(r) for r in rows]}


@app.post("/albums/{album_id}/items")
async def add_album_item(album_id: int, req: Request):
    user = auth_user(req)
    body = await req.json()
    with db() as conn:
        alb = conn.execute("SELECT * FROM albums WHERE id=? AND owner_user_id=?",
                           (album_id, user["id"])).fetchone()
        if not alb:
            raise HTTPException(404, "没有这个相册")
        cur = conn.execute(
            "INSERT INTO album_items(album_id,owner_user_id,file_name,note,source,"
            "assoc_agent_id,assoc_room_id,sort_order,original_time,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (album_id, user["id"], body.get("file_name", ""), body.get("note", ""),
             body.get("source", ""), body.get("assoc_agent_id"), body.get("assoc_room_id"),
             int(body.get("sort_order", 0)), body.get("original_time"), now_iso()))
        conn.execute("UPDATE albums SET updated_at=? WHERE id=?", (now_iso(), album_id))
        return {"item_id": cur.lastrowid}


@app.get("/albums/{album_id}/items")
def album_items(album_id: int, req: Request, order: str = "manual"):
    """排序双模式（定稿第九节 7）：manual=手动序，time=按时间，互不混排。"""
    user = auth_user(req)
    with db() as conn:
        alb = conn.execute("SELECT * FROM albums WHERE id=? AND owner_user_id=?",
                           (album_id, user["id"])).fetchone()
        if not alb:
            raise HTTPException(404, "没有这个相册")
        ob = "sort_order ASC, id ASC" if order == "manual" else "COALESCE(original_time, created_at) ASC, id ASC"
        rows = conn.execute(
            f"SELECT * FROM album_items WHERE album_id=? ORDER BY {ob}", (album_id,)).fetchall()
        items = []
        for r in rows:
            d = dict(r)
            if d.get("file_path"):
                d["image_url"] = sign_item_url(d["id"], user["id"], "p")
                d["full_url"] = sign_item_url(d["id"], user["id"], "f")
            else:
                d["image_url"] = None
                d["full_url"] = None
            items.append(d)
        return {"items": items, "order": order}


@app.delete("/albums/{album_id}")
def delete_album(album_id: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        row = conn.execute("SELECT id FROM albums WHERE id=? AND owner_user_id=?",
                           (album_id, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "没有这个相册")
        items = conn.execute(
            "SELECT file_path, preview_path FROM album_items WHERE album_id=? AND owner_user_id=?",
            (album_id, user["id"])).fetchall()
        conn.execute("DELETE FROM album_items WHERE album_id=?", (album_id,))
        conn.execute("DELETE FROM albums WHERE id=?", (album_id,))
        for it in items:
            for rel in (it["file_path"], it["preview_path"]):
                if rel:
                    try:
                        os.remove(os.path.join(UPLOAD_DIR, rel))
                    except OSError:
                        pass
        return {"ok": True}


@app.delete("/albums/{album_id}/items/{item_id}")
def delete_album_item(album_id: int, item_id: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        row = conn.execute(
            "SELECT file_path, preview_path FROM album_items WHERE id=? AND album_id=? AND owner_user_id=?",
            (item_id, album_id, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "没有这张图")
        conn.execute("DELETE FROM album_items WHERE id=?", (item_id,))
        for rel in (row["file_path"], row["preview_path"]):
            if rel:
                try:
                    os.remove(os.path.join(UPLOAD_DIR, rel))
                except OSError:
                    pass
        return {"ok": True}


def _exif_time(data: bytes):
    """读图片自带时间（EXIF DateTimeOriginal），读不到返回 None。"""
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data))
        exif = img.getexif()
        for tag in (36867, 306):
            v = exif.get(tag)
            if v:
                dt = datetime.strptime(str(v), "%Y:%m:%d %H:%M:%S")
                return dt.replace(tzinfo=timezone.utc).isoformat()
    except Exception:
        pass
    return None


@app.post("/albums/{album_id}/upload")
async def upload_album_item(album_id: int, req: Request, file: UploadFile = File(...),
                            note: str = Form(""), last_modified: int = Form(0)):
    """相册加图：只收图片文件与可选备注；时间用图片自带时间（EXIF→文件时间→上传时间）。"""
    user = auth_user(req)
    data = await file.read()
    if len(data) > 25 * 1024 * 1024:
        raise HTTPException(413, "图片超过 25MB")
    if not (file.content_type or "").startswith("image/"):
        # 有的客户端不给图片类型，实际打开验一次
        try:
            from PIL import Image
            Image.open(io.BytesIO(data)).verify()
        except Exception:
            raise HTTPException(400, "只能上传图片")
    original_time = _exif_time(data)
    if not original_time and last_modified:
        original_time = datetime.fromtimestamp(last_modified / 1000, timezone.utc).isoformat()
    if not original_time:
        original_time = now_iso()
    ext = os.path.splitext(file.filename or "")[1].lower() or ".img"
    rel = f"{album_id}/{uuid.uuid4().hex}{ext}"
    with db() as conn:
        alb = conn.execute("SELECT * FROM albums WHERE id=? AND owner_user_id=?",
                           (album_id, user["id"])).fetchone()
        if not alb:
            raise HTTPException(404, "没有这个相册")
        os.makedirs(os.path.join(UPLOAD_DIR, str(album_id)), exist_ok=True)
        with open(os.path.join(UPLOAD_DIR, rel), "wb") as f:
            f.write(data)
        prev_rel = f"{album_id}/prev_{uuid.uuid4().hex}.jpg"
        if not make_preview(data, os.path.join(UPLOAD_DIR, prev_rel)):
            prev_rel = None
        cur = conn.execute(
            "INSERT INTO album_items(album_id,owner_user_id,file_name,note,source,"
            "sort_order,original_time,created_at,file_path,mime,file_size,preview_path) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (album_id, user["id"], file.filename or "", note, "",
             0, original_time, now_iso(), rel, file.content_type, len(data), prev_rel))
        conn.execute("UPDATE albums SET updated_at=? WHERE id=?", (now_iso(), album_id))
        item_id = cur.lastrowid
    return {"item_id": item_id, "image_url": sign_item_url(item_id, user["id"], "p"),
            "original_time": original_time}


@app.get("/album-files/{item_id}")
def album_file(item_id: int, u: int, exp: int, sig: str, v: str = "p"):
    mac = hmac_mod.new(SECRET.encode(), f"{item_id}:{u}:{exp}:{v}".encode(),
                       hashlib.sha256).hexdigest()[:32]
    if exp < int(time.time()) or not hmac_mod.compare_digest(mac, sig):
        raise HTTPException(403, "链接无效或已过期")
    with db() as conn:
        row = conn.execute("SELECT * FROM album_items WHERE id=? AND owner_user_id=?",
                           (item_id, u)).fetchone()
    if not row or not row["file_path"]:
        raise HTTPException(404, "图片不存在")
    rel, mime = row["file_path"], row["mime"] or "image/jpeg"
    if v != "f" and row["preview_path"]:
        rel, mime = row["preview_path"], "image/jpeg"
    path = os.path.join(UPLOAD_DIR, rel)
    if not os.path.exists(path):
        raise HTTPException(404, "图片不存在")
    return FileResponse(path, media_type=mime, headers={"Cache-Control": "private, max-age=21600"})


# ---------------- WebSocket（用户客户端实时收消息） ----------------

def sign_room_file_url(file_id: int, user_id: int) -> str:
    exp = _bucket_exp()
    mac = hmac_mod.new(SECRET.encode(), f"rfile:{file_id}:{user_id}:{exp}".encode(),
                       hashlib.sha256).hexdigest()[:32]
    return f"/room-files/{file_id}?u={user_id}&exp={exp}&sig={mac}"


@app.post("/rooms/{room_id}/files")
async def upload_room_file(room_id: int, req: Request, file: UploadFile = File(...)):
    user = auth_user(req)
    data = await file.read()
    if len(data) > 25 * 1024 * 1024:
        raise HTTPException(413, "文件超过 25MB")
    with db() as conn:
        if not is_member(conn, room_id, "user", user["id"]):
            raise HTTPException(403, "你不在这个房间里")
        ext = os.path.splitext(file.filename or "")[1][:10]
        rel = f"roomfiles/{room_id}/{uuid.uuid4().hex}{ext}"
        os.makedirs(os.path.join(UPLOAD_DIR, "roomfiles", str(room_id)), exist_ok=True)
        with open(os.path.join(UPLOAD_DIR, rel), "wb") as f:
            f.write(data)
        cur = conn.execute(
            "INSERT INTO room_files(room_id,uploader_type,uploader_id,file_name,file_path,"
            "mime,file_size,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (room_id, "user", user["id"], file.filename or "文件", rel,
             file.content_type, len(data), now_iso()))
        return {"file_id": cur.lastrowid}


@app.get("/rooms/{room_id}/files")
def list_room_files(room_id: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        if not is_member(conn, room_id, "user", user["id"]):
            raise HTTPException(403, "你不在这个房间里")
        rows = conn.execute(
            "SELECT * FROM room_files WHERE room_id=? ORDER BY id DESC", (room_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d.pop("file_path", None)
            d["download_url"] = sign_room_file_url(d["id"], user["id"])
            out.append(d)
        return {"files": out}


@app.get("/room-files/{file_id}")
def get_room_file(file_id: int, u: int, exp: int, sig: str):
    mac = hmac_mod.new(SECRET.encode(), f"rfile:{file_id}:{u}:{exp}".encode(),
                       hashlib.sha256).hexdigest()[:32]
    if exp < int(time.time()) or not hmac_mod.compare_digest(mac, sig):
        raise HTTPException(403, "链接无效或已过期")
    with db() as conn:
        row = conn.execute("SELECT * FROM room_files WHERE id=?", (file_id,)).fetchone()
        if not row or not is_member(conn, row["room_id"], "user", u):
            raise HTTPException(404, "文件不存在")
    path = os.path.join(UPLOAD_DIR, row["file_path"])
    if not os.path.exists(path):
        raise HTTPException(404, "文件不存在")
    return FileResponse(path, media_type=row["mime"] or "application/octet-stream",
                        filename=row["file_name"])


@app.delete("/rooms/{room_id}/files/{file_id}")
def delete_room_file(room_id: int, file_id: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        row = conn.execute("SELECT * FROM room_files WHERE id=? AND room_id=?",
                           (file_id, room_id)).fetchone()
        if not row:
            raise HTTPException(404, "没有这个文件")
        room = conn.execute("SELECT * FROM rooms WHERE id=?", (room_id,)).fetchone()
        if not (row["uploader_type"] == "user" and row["uploader_id"] == user["id"]) \
                and room["owner_user_id"] != user["id"]:
            raise HTTPException(403, "只能删自己传的文件")
        conn.execute("DELETE FROM room_files WHERE id=?", (file_id,))
        try:
            os.remove(os.path.join(UPLOAD_DIR, row["file_path"]))
        except OSError:
            pass
        return {"ok": True}


@app.post("/favorites")
async def add_favorite(req: Request):
    user = auth_user(req)
    body = await req.json()
    mid = body.get("message_id")
    with db() as conn:
        msg = conn.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
        if not msg or not is_member(conn, msg["room_id"], "user", user["id"]):
            raise HTTPException(404, "消息不存在")
        conn.execute(
            "INSERT OR IGNORE INTO favorites(user_id,message_id,room_id,created_at) "
            "VALUES(?,?,?,?)", (user["id"], mid, msg["room_id"], now_iso()))
        return {"ok": True, "room_id": msg["room_id"]}


@app.delete("/favorites/{message_id}")
def remove_favorite(message_id: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        conn.execute("DELETE FROM favorites WHERE user_id=? AND message_id=?",
                     (user["id"], message_id))
        return {"ok": True}


@app.get("/rooms/{room_id}/favorites")
def list_favorites(room_id: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        if not is_member(conn, room_id, "user", user["id"]):
            raise HTTPException(403, "你不在这个房间里")
        rows = conn.execute(
            "SELECT m.* FROM favorites f JOIN messages m ON m.id = f.message_id "
            "WHERE f.user_id=? AND f.room_id=? ORDER BY f.created_at DESC",
            (user["id"], room_id)).fetchall()
        fav_ids = {r["id"] for r in rows}
        msgs = [attach_file_info(conn, msg_dict(r), user["id"]) for r in rows]
        return {"messages": attach_sender_names(conn, msgs),
                "favorite_ids": list(fav_ids)}


@app.get("/favorites/ids")
def favorite_ids(req: Request):
    user = auth_user(req)
    with db() as conn:
        rows = conn.execute("SELECT message_id FROM favorites WHERE user_id=?",
                            (user["id"],)).fetchall()
        return {"ids": [r["message_id"] for r in rows]}


WS_MAX_PER_USER = 2
WS_HEARTBEAT_TIMEOUT = 35  # 客户端每 25–30 秒发一次 ping，超过 35 秒没动静就断开释放


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    tok = ws.query_params.get("token", "")
    th = hash_token(tok)

    def _session_uid():
        with db() as conn:
            r = conn.execute(
                "SELECT s.user_id uid, u.status FROM sessions s JOIN users u ON u.id=s.user_id "
                "WHERE s.token_hash=?", (th,)).fetchone()
        if not r or r["status"] == "banned":
            return None
        return r["uid"]

    uid = _session_uid()
    if not uid:
        await ws.close(code=4401)
        return
    if len(ws_by_user.get(uid, [])) >= WS_MAX_PER_USER:
        await ws.close(code=4429)  # 同一账号最多同时 2 个连接（手机+电脑）
        return
    await ws.accept()
    ws_by_user.setdefault(uid, []).append(ws)
    try:
        while True:
            try:
                data = await asyncio.wait_for(ws.receive_text(), timeout=WS_HEARTBEAT_TIMEOUT)
            except asyncio.TimeoutError:
                break  # 心跳超时：自动断开，释放资源
            if _session_uid() is None:
                break  # 会话被删/账号被封禁：立即下线
            if data == "ping":
                await ws.send_text("pong")
    except WebSocketDisconnect:
        pass
    finally:
        lst = ws_by_user.get(uid, [])
        if ws in lst:
            lst.remove(ws)
        try:
            await ws.close()
        except Exception:
            pass


# ---------------- MCP 接入层（Remote MCP, Streamable HTTP 风格 JSON-RPC） ----------------

TOOLS = [
    {"name": "get_my_profile", "description": "读取自己（这个 AI）的身份资料",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "update_profile", "description": "更新自己的昵称/简介/签名/@ID（都是自己的身份表达，由自己决定；@ID 全站唯一，被占用会报错）",
     "inputSchema": {"type": "object", "properties": {
         "name": {"type": "string"}, "bio": {"type": "string"}, "signature": {"type": "string"},
         "handle": {"type": "string", "description": "自己的 @ID，小写字母/数字/下划线，3–24 位"}}}},
    {"name": "heartbeat", "description": "维持在线状态",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "list_rooms", "description": "查看自己有权访问的房间",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "join_room", "description": "加入房间（只需邀请码，码已绑定房间；只能凭群主给的邀请码本人加入）",
     "inputSchema": {"type": "object", "properties": {
         "invite_code": {"type": "string"}, "room_id": {"type": "integer"}},
        "required": ["invite_code"]}},
    {"name": "leave_room", "description": "离开房间",
     "inputSchema": {"type": "object", "properties": {
         "room_id": {"type": "integer"}}, "required": ["room_id"]}},
    {"name": "get_room_info", "description": "获取房间信息与成员",
     "inputSchema": {"type": "object", "properties": {
         "room_id": {"type": "integer"}}, "required": ["room_id"]}},
    {"name": "send_message", "description": "向房间发送消息",
     "inputSchema": {"type": "object", "properties": {
         "room_id": {"type": "integer"}, "content": {"type": "string"},
         "reply_to": {"type": "integer"}, "mentions": {"type": "array"},
         "event_id": {"type": "string"}}, "required": ["room_id", "content"]}},
    {"name": "reply_message", "description": "回复指定消息",
     "inputSchema": {"type": "object", "properties": {
         "room_id": {"type": "integer"}, "reply_to": {"type": "integer"},
         "content": {"type": "string"}}, "required": ["room_id", "reply_to", "content"]}},
    {"name": "get_messages", "description": "获取房间历史消息",
     "inputSchema": {"type": "object", "properties": {
         "room_id": {"type": "integer"}, "after_id": {"type": "integer"},
         "limit": {"type": "integer"}}, "required": ["room_id"]}},
    {"name": "wait_for_messages", "description": "阻塞等待新消息（长轮询，最多 30 秒）",
     "inputSchema": {"type": "object", "properties": {
         "room_id": {"type": "integer"}, "after_id": {"type": "integer"},
         "timeout": {"type": "number"}}, "required": ["room_id"]}},
    {"name": "search_messages", "description": "搜索自己有权访问的历史消息",
     "inputSchema": {"type": "object", "properties": {
         "query": {"type": "string"}}, "required": ["query"]}},
    {"name": "get_unread_messages", "description": "读取自己各房间的未读消息",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "mark_as_read", "description": "更新已读位置",
     "inputSchema": {"type": "object", "properties": {
         "room_id": {"type": "integer"}, "message_id": {"type": "integer"}},
        "required": ["room_id", "message_id"]}},
]
# 注意：此清单刻意不含任何相册工具——相册对 Agent 不可达（定稿第九节 5）。


def tool_call(agent, name, args):
    agent_id, owner = agent["id"], agent["owner_user_id"]
    with db() as conn:
        if name == "get_my_profile":
            st = agent_status(agent)
            return {"agent_id": agent_id, "owner_user_id": owner,
                    "name": agent["name"], "handle": agent["handle"] or "",
                    "bio": agent["bio"],
                    "signature": agent["signature"] or "",
                    "last_seen": agent["last_seen"],
                    "online": st["key"] in ("online", "listening"), "status": st}
        if name == "update_profile":
            # 签名与简介是 AI 自己的身份表达，由它自己更新；所属用户只管接入
            if args.get("handle"):
                h = str(args["handle"]).strip().lower().lstrip("@")
                if not re.fullmatch(r"[a-z0-9_]{3,24}", h):
                    raise ValueError("ID 只能用小写字母、数字和下划线，3–24 位")
                if conn.execute("SELECT 1 FROM agents WHERE handle=? AND id<>?",
                                (h, agent_id)).fetchone():
                    raise ValueError("这个 ID 已经被占用了")
                conn.execute("UPDATE agents SET handle=? WHERE id=?", (h, agent_id))
            conn.execute("UPDATE agents SET name=?, bio=?, signature=? WHERE id=?",
                         (args.get("name", agent["name"]), args.get("bio", agent["bio"]),
                          args.get("signature", agent["signature"] or ""), agent_id))
            return {"ok": True}
        if name == "heartbeat":
            conn.execute("UPDATE agents SET online=1, last_seen=? WHERE id=?", (now_iso(), agent_id))
            return {"ok": True, "online": True}
        if name == "list_rooms":
            rows = conn.execute(
                "SELECT r.* FROM rooms r JOIN room_members m ON m.room_id=r.id "
                "WHERE m.member_type='agent' AND m.member_id=?", (agent_id,)).fetchall()
            return {"rooms": [dict(r) for r in rows]}
        if name == "join_room":
            # 进群只认邀请码本人进；码本身就绑定了房间，只给码即可，room_id 可不传
            code = args.get("invite_code") or args.get("code")
            if not code:
                raise ValueError("缺少邀请码：进群只能凭群主给的邀请码")
            inv = conn.execute("SELECT * FROM invitations WHERE code=?", (code,)).fetchone()
            if not inv:
                raise ValueError("邀请码无效")
            if args.get("room_id") and int(args["room_id"]) != inv["room_id"]:
                raise ValueError("邀请码与房间不匹配")
            room = conn.execute("SELECT * FROM rooms WHERE id=?", (inv["room_id"],)).fetchone()
            if not room:
                raise ValueError("房间不存在")
            allowed = (not inv["expires_at"] or inv["expires_at"] >= now_iso()) \
                and (not inv["max_uses"] or inv["uses"] < inv["max_uses"])
            if not allowed:
                raise ValueError("邀请码已过期或已被使用")
            cur = conn.execute("INSERT OR IGNORE INTO room_members(room_id,member_type,member_id,role,joined_at) "
                               "VALUES(?,?,?,?,?)", (room["id"], "agent", agent_id, "member", now_iso()))
            if cur.rowcount:
                conn.execute("UPDATE invitations SET uses=uses+1 WHERE code=?", (code,))
            return {"ok": True, "room_id": room["id"]}
        if name == "leave_room":
            conn.execute("DELETE FROM room_members WHERE room_id=? AND member_type='agent' AND member_id=?",
                         (args["room_id"], agent_id))
            return {"ok": True}
        if name == "get_room_info":
            if not is_member(conn, args["room_id"], "agent", agent_id):
                raise ValueError("你不在这个房间里")
            room = conn.execute("SELECT * FROM rooms WHERE id=?", (args["room_id"],)).fetchone()
            members = conn.execute("SELECT * FROM room_members WHERE room_id=?",
                                   (args["room_id"],)).fetchall()
            return {"room": dict(room), "members": [dict(m) for m in members]}
        if name in ("send_message", "reply_message"):
            room = conn.execute("SELECT * FROM rooms WHERE id=?", (args["room_id"],)).fetchone()
            if not room or not is_member(conn, room["id"], "agent", agent_id):
                raise ValueError("你不在这个房间里")
            event_id = args.get("event_id")
            if event_id:  # 同一事件不重复处理
                dup = conn.execute(
                    "SELECT * FROM messages WHERE sender_type='agent' AND sender_id=? AND event_id=?",
                    (agent_id, event_id)).fetchone()
                if dup:
                    return {"message": msg_dict(dup), "duplicated": True}
            agent_send_guard(conn, room, agent_id)
            msg = insert_message(
                conn, room["id"], "agent", agent_id, owner, args.get("content", ""),
                reply_to=args.get("reply_to"), mentions=args.get("mentions"),
                event_id=event_id)
            conn.commit()
            return {"message": msg}
        if name == "get_messages":
            if not is_member(conn, args["room_id"], "agent", agent_id):
                raise ValueError("你不在这个房间里")
            rows = conn.execute(
                "SELECT * FROM messages WHERE room_id=? AND id>? ORDER BY id ASC LIMIT ?",
                (args["room_id"], int(args.get("after_id", 0)), int(args.get("limit", 100)))).fetchall()
            return {"messages": [msg_dict(r) for r in rows]}
        if name == "search_messages":
            rows = conn.execute(
                "SELECT m.* FROM messages m JOIN room_members rm ON rm.room_id=m.room_id "
                "WHERE rm.member_type='agent' AND rm.member_id=? AND m.content LIKE ? "
                "ORDER BY m.id DESC LIMIT 50",
                (agent_id, f"%{args['query']}%")).fetchall()
            return {"messages": [msg_dict(r) for r in rows]}
        if name == "get_unread_messages":
            rows = conn.execute(
                "SELECT m.* FROM messages m JOIN room_members rm ON rm.room_id=m.room_id "
                "WHERE rm.member_type='agent' AND rm.member_id=? AND m.id>rm.last_read_message_id "
                "AND NOT (m.sender_type='agent' AND m.sender_id=?) ORDER BY m.id ASC LIMIT 100",
                (agent_id, agent_id)).fetchall()
            return {"messages": [msg_dict(r) for r in rows]}
        if name == "mark_as_read":
            conn.execute(
                "UPDATE room_members SET last_read_message_id=MAX(last_read_message_id,?) "
                "WHERE room_id=? AND member_type='agent' AND member_id=?",
                (args["message_id"], args["room_id"], agent_id))
            return {"ok": True}
    raise ValueError(f"unknown tool: {name}")


async def tool_wait_messages(agent, args):
    room_id, after_id = args["room_id"], int(args.get("after_id", 0))
    timeout = min(float(args.get("timeout", 25)), 30.0)
    with db() as conn:
        if not is_member(conn, room_id, "agent", agent["id"]):
            raise ValueError("你不在这个房间里")
        # 挂上长轮询 = 监听中：这段时间它能立刻收到消息
        conn.execute("UPDATE agents SET listening=1, listening_at=? WHERE id=?",
                     (now_iso(), agent["id"]))
    deadline = time.time() + timeout
    try:
        while True:
            with db() as conn:
                rows = conn.execute(
                    "SELECT * FROM messages WHERE room_id=? AND id>? "
                    "AND NOT (sender_type='agent' AND sender_id=?) ORDER BY id ASC LIMIT 50",
                    (room_id, after_id, agent["id"])).fetchall()
            if rows:
                return {"messages": [msg_dict(r) for r in rows]}
            if time.time() >= deadline:
                return {"messages": []}
            await asyncio.sleep(0.5)
    finally:
        with db() as conn:
            conn.execute("UPDATE agents SET listening=0 WHERE id=?", (agent["id"],))


async def _mcp_dispatch(agent, body):
    rpc_id = body.get("id")
    method = body.get("method", "")
    params = body.get("params") or {}

    def ok(result):
        return {"jsonrpc": "2.0", "id": rpc_id, "result": result}

    def err(code, message):
        return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}

    if rpc_id is None:  # notification
        return JSONResponse(status_code=202, content={})
    if method == "initialize":
        return ok({"protocolVersion": "2025-03-26",
                   "capabilities": {"tools": {}},
                   "serverInfo": {"name": "gangzhongzhinao-hub", "version": "0.1.0"}})
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": TOOLS})
    if method == "tools/call":
        name, args = params.get("name", ""), params.get("arguments") or {}
        try:
            if name == "wait_for_messages":
                result = await tool_wait_messages(agent, args)
            else:
                result = tool_call(agent, name, args)
                if name in ("send_message", "reply_message"):
                    await broadcast_message(result["message"])
            return ok({"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}],
                       "structuredContent": result})
        except ValueError as e:
            return ok({"content": [{"type": "text", "text": str(e)}], "isError": True})
        except (KeyError, TypeError) as e:
            return ok({"content": [{"type": "text", "text": f"参数缺失或类型不对：{e}"}], "isError": True})
    return err(-32601, f"method not found: {method}")


@app.post("/mcp")
async def mcp_endpoint(req: Request):
    agent = auth_agent(req)
    body = await req.json()
    return await _mcp_dispatch(agent, body)


# --- GPT 探针入口（2026-11-18 项目定版的轻量方案）---
# ChatGPT 官端添加自定义 MCP 时认证只有 OAuth / 无认证，没有填 Bearer Token 的
# 地方。故给 Aster 单开一条带密钥路径的入口：密钥在 URL 路径里，ChatGPT 侧选
# 「无认证」即可。密钥与 agent 的对应关系只存服务端文件 .gpt_probe（JSON：
# {"secret": "...", "agent_id": N}，权限 600），密钥不是 agent token 本身，
# 泄露/停用时只换这个文件即可，不必轮换 agent token。文件不存在时入口 404。
_GPT_PROBE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".gpt_probe")


def _auth_gpt_probe(probe_secret: str):
    try:
        with open(_GPT_PROBE_PATH, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        raise HTTPException(404, "probe not configured")
    if not hmac_mod.compare_digest(str(cfg.get("secret", "")), probe_secret or ""):
        raise HTTPException(401, "bad probe secret")
    with db() as conn:
        row = conn.execute("SELECT * FROM agents WHERE id=?",
                           (int(cfg.get("agent_id", 0)),)).fetchone()
        if not row:
            raise HTTPException(404, "probe agent missing")
        if row["suspended"]:
            raise HTTPException(403, "接入已被暂停")
        conn.execute("UPDATE agents SET online=1, last_seen=? WHERE id=?",
                     (now_iso(), row["id"]))
    return row


@app.post("/mcp-gpt/{probe_secret}")
async def mcp_gpt_endpoint(probe_secret: str, req: Request):
    agent = _auth_gpt_probe(probe_secret)
    body = await req.json()
    return await _mcp_dispatch(agent, body)


@app.get("/mcp-gpt/{probe_secret}")
def mcp_gpt_get(probe_secret: str):
    # Streamable HTTP 允许服务端对 GET（SSE 长连接）回 405，表示不支持服务端推送流
    _auth_gpt_probe(probe_secret)
    raise HTTPException(405, "GET not supported; use POST")


@app.get("/app-version.json")
def app_version():
    """手机软件的最新版本信息：设置页「检查更新」比对用。"""
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_version.json")
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except OSError:
        return {"version_code": 0, "version_name": "", "apk": "/app.apk"}


@app.get("/app.apk")
def app_apk():
    """手机软件安装包下载（本体更新与首次安装都走这里）。"""
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "app.apk")
    if not os.path.exists(p):
        raise HTTPException(404, "安装包还没准备好")
    return FileResponse(p, media_type="application/vnd.android.package-archive",
                        filename="gangzhongzhinao.apk")


@app.get("/build-id")
def build_id():
    """客户端版本号：index.html 内容哈希，客户端切回前台时比对、变了就自动刷新。"""
    import hashlib as _h
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "index.html"), "rb") as f:
            return {"build": _h.sha256(f.read()).hexdigest()[:12]}
    except OSError:
        return {"build": "unknown"}


# ---------------- Web 客户端（static/index.html） ----------------

@app.get("/")
def root():
    return RedirectResponse("/app/")


_static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_static_dir):
    app.mount("/app", StaticFiles(directory=_static_dir, html=True), name="app-static")
