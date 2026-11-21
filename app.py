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
import random
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone

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
CREATE TABLE IF NOT EXISTS space_looks(
  user_id INTEGER NOT NULL, member_type TEXT NOT NULL, member_id INTEGER NOT NULL,
  expression TEXT DEFAULT 'default', hairstyle TEXT DEFAULT 'default',
  bangs TEXT DEFAULT 'default', hair_color TEXT DEFAULT 'default',
  outfit TEXT DEFAULT 'default', outfit_color TEXT DEFAULT 'default',
  ears TEXT DEFAULT 'none', accessory TEXT DEFAULT 'none',
  updated_at TEXT, PRIMARY KEY(user_id, member_type, member_id));
CREATE TABLE IF NOT EXISTS space_weather(
  user_id INTEGER NOT NULL, date TEXT NOT NULL, weather TEXT NOT NULL,
  source TEXT DEFAULT 'random', changed_by INTEGER, updated_at TEXT,
  PRIMARY KEY(user_id, date));
CREATE TABLE IF NOT EXISTS space_admin_sync(
  date TEXT PRIMARY KEY, weather TEXT NOT NULL, admin_id INTEGER, created_at TEXT);
CREATE TABLE IF NOT EXISTS space_ai_actions(
  agent_id INTEGER NOT NULL, date TEXT NOT NULL, kind TEXT NOT NULL,
  count INTEGER DEFAULT 0, PRIMARY KEY(agent_id, date, kind));
CREATE TABLE IF NOT EXISTS space_state(
  user_id INTEGER PRIMARY KEY, scene_index INTEGER DEFAULT 0, updated_at TEXT);
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


def ensure_dm(conn, user_id: int, agent_id: int, agent_name: str) -> int:
    """保证「人类与名下某个 AI」的私聊存在，返回 room_id。
    接入一个 AI 之后消息页就应出现对应私聊（维护者 2026-11-21 定）：
    建成员时与启动补齐时都走这里，避免 AI 接入后无房可去。"""
    row = conn.execute(
        "SELECT r.id FROM rooms r "
        "JOIN room_members mu ON mu.room_id=r.id AND mu.member_type='user' AND mu.member_id=? "
        "JOIN room_members ma ON ma.room_id=r.id AND ma.member_type='agent' AND ma.member_id=? "
        "WHERE r.kind='dm' ORDER BY r.id LIMIT 1", (user_id, agent_id)).fetchone()
    if row:
        return row["id"]
    cur = conn.execute(
        "INSERT INTO rooms(name,kind,owner_user_id,auto_agent_limit,created_at) "
        "VALUES(?,?,?,?,?)", (agent_name, "dm", user_id, 6, now_iso()))
    room_id = cur.lastrowid
    conn.execute("INSERT INTO room_members(room_id,member_type,member_id,role,joined_at) "
                 "VALUES(?,?,?,?,?)", (room_id, "user", user_id, "owner", now_iso()))
    conn.execute("INSERT INTO room_members(room_id,member_type,member_id,role,joined_at) "
                 "VALUES(?,?,?,?,?)", (room_id, "agent", agent_id, "member", now_iso()))
    return room_id


def backfill_dms():
    """启动补齐：给每个已存在成员补上与其人类的私聊（幂等）。"""
    with db() as conn:
        for ag in conn.execute("SELECT id, owner_user_id, name FROM agents").fetchall():
            ensure_dm(conn, ag["owner_user_id"], ag["id"], ag["name"])
        conn.commit()


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
                         ("global_bg_liquid", "INTEGER DEFAULT 0"),
                         ("status", "TEXT DEFAULT 'approved'"), ("applied_at", "TEXT"),
                         ("is_admin", "INTEGER DEFAULT 0"), ("device_id", "TEXT"),
                         ("global_bg_updated_at", "REAL DEFAULT 0")):
            if col not in ucols:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} {typ}")
        acols = {r["name"] for r in conn.execute("PRAGMA table_info(agents)")}
        for col, typ in (("avatar_path", "TEXT"), ("signature", "TEXT DEFAULT ''"),
                         ("listening", "INTEGER DEFAULT 0"), ("listening_at", "TEXT"),
                         ("suspended", "INTEGER DEFAULT 0"), ("handle", "TEXT"),
                         ("call_secret_hash", "TEXT")):
            if col not in acols:
                conn.execute(f"ALTER TABLE agents ADD COLUMN {col} {typ}")
        for r in conn.execute(
                "SELECT id, name FROM agents WHERE handle IS NULL OR handle=''").fetchall():
            conn.execute("UPDATE agents SET handle=? WHERE id=?",
                         (make_handle(conn, r["name"], r["id"]), r["id"]))
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_handle "
                     "ON agents(handle) WHERE handle IS NOT NULL")
        msgcols = {r["name"] for r in conn.execute("PRAGMA table_info(messages)")}
        for col, typ in (("deleted_at", "TEXT"),
                         ("recalled_by_type", "TEXT"),
                         ("recalled_by_id", "INTEGER"),
                         ("recalled_by_name", "TEXT DEFAULT ''")):
            if col not in msgcols:
                conn.execute(f"ALTER TABLE messages ADD COLUMN {col} {typ}")
        rcols = {r["name"] for r in conn.execute("PRAGMA table_info(rooms)")}
        for col, typ in (("announcement", "TEXT DEFAULT ''"), ("description", "TEXT DEFAULT ''"),
                         ("avatar_path", "TEXT"),
                         ("anti_loop_enabled", "INTEGER DEFAULT 1")):
            if col not in rcols:
                conn.execute(f"ALTER TABLE rooms ADD COLUMN {col} {typ}")
        mcols = {r["name"] for r in conn.execute("PRAGMA table_info(room_members)")}
        for col, typ in (("last_no_reply_message_id", "INTEGER DEFAULT 0"),
                         ("last_no_reply_at", "TEXT")):
            if col not in mcols:
                conn.execute(f"ALTER TABLE room_members ADD COLUMN {col} {typ}")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS wake_configs(
          agent_id INTEGER PRIMARY KEY REFERENCES agents(id),
          enabled INTEGER DEFAULT 0,
          gear INTEGER DEFAULT 2,
          mode TEXT DEFAULT 'slow',
          next_check_at REAL DEFAULT 0,
          empty_checks INTEGER DEFAULT 0,
          last_wake_at REAL DEFAULT 0,
          last_check_at REAL DEFAULT 0,
          updated_at TEXT)""")
        wcols = [r[1] for r in conn.execute("PRAGMA table_info(wake_configs)")]
        if "last_wake_max_id" not in wcols:
            conn.execute("ALTER TABLE wake_configs ADD COLUMN "
                         "last_wake_max_id INTEGER DEFAULT 0")
        # 开门补叫（2026-11-21，WAKE-STARTUP-CATCHUP-DESIGN.md 第四节）：
        # 认领记录与最近一次开门检查时间，逐列补齐，口径同 last_wake_max_id。
        # 随时在线（同日晚维护者定版）：独立于拉条三档的开关 live_mode，一并补齐。
        for col, typ in (("startup_claim_at", "REAL DEFAULT 0"),
                         ("startup_claim_max_id", "INTEGER DEFAULT 0"),
                         ("last_startup_check_at", "REAL DEFAULT 0"),
                         ("live_mode", "INTEGER DEFAULT 0"),
                         ("last_wake_mc_id", "INTEGER DEFAULT 0"),
                         ("last_wake_ml_at", "TEXT DEFAULT ''")):
            if col not in wcols:
                conn.execute(f"ALTER TABLE wake_configs ADD COLUMN {col} {typ}")
        # 叫醒信号挂起补发（同日晚维护者批准）：信号发出时主人一个 socket 都
        # 没连上（鱼缸 App 在后台断连）就把载荷挂在这里，ws 重连时补发。
        conn.execute("""
        CREATE TABLE IF NOT EXISTS wake_pending(
          agent_id INTEGER PRIMARY KEY,
          owner_user_id INTEGER,
          payload TEXT,
          batch_max INTEGER,
          created_at REAL)""")
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
        conn.execute("""
        CREATE TABLE IF NOT EXISTS moments(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          kind TEXT NOT NULL,               -- 'post' | 'bottle'
          author_type TEXT NOT NULL,        -- 'user' | 'agent'
          author_id INTEGER NOT NULL,
          owner_user_id INTEGER,            -- agent 作者的所属用户；user 作者即本人
          content TEXT NOT NULL,
          anonymous INTEGER DEFAULT 0,      -- 仅 bottle 用
          created_at TEXT NOT NULL)""")
        momcols = {r["name"] for r in conn.execute("PRAGMA table_info(moments)")}
        if "visibility" not in momcols:
            conn.execute("ALTER TABLE moments ADD COLUMN "
                         "visibility TEXT DEFAULT 'public'")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS moment_likes(
          moment_id INTEGER NOT NULL REFERENCES moments(id),
          user_id INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL,
          PRIMARY KEY(moment_id, user_id))""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS bottle_replies(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          moment_id INTEGER NOT NULL REFERENCES moments(id),
          author_type TEXT NOT NULL,        -- 'user' | 'agent'
          author_id INTEGER NOT NULL,
          owner_user_id INTEGER,
          content TEXT NOT NULL,
          anonymous INTEGER DEFAULT 0,
          created_at TEXT NOT NULL)""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS bottle_hidden(
          moment_id INTEGER NOT NULL REFERENCES moments(id),
          user_id INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL,
          PRIMARY KEY(moment_id, user_id))""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS moment_comments(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          moment_id INTEGER NOT NULL REFERENCES moments(id),
          author_type TEXT NOT NULL,
          author_id INTEGER NOT NULL,
          owner_user_id INTEGER,
          content TEXT NOT NULL,
          anonymous INTEGER DEFAULT 0,
          created_at TEXT NOT NULL)""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS moment_agent_likes(
          moment_id INTEGER NOT NULL REFERENCES moments(id),
          agent_id INTEGER NOT NULL REFERENCES agents(id),
          created_at TEXT NOT NULL,
          PRIMARY KEY(moment_id, agent_id))""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS moment_images(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          moment_id INTEGER,
          owner_user_id INTEGER NOT NULL,
          file_path TEXT NOT NULL,
          preview_path TEXT,
          mime TEXT,
          file_size INTEGER,
          created_at TEXT NOT NULL)""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS app_settings(
          key TEXT PRIMARY KEY,
          value TEXT)""")
        # 统一评论表迁移：瓶子回复原样搬入（保留 id），旧表留作回滚不再写入
        conn.execute(
            "INSERT OR IGNORE INTO moment_comments"
            "(id,moment_id,author_type,author_id,owner_user_id,content,anonymous,created_at) "
            "SELECT id,moment_id,author_type,author_id,owner_user_id,content,anonymous,created_at "
            "FROM bottle_replies")


init_db()
backfill_dms()

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


def sign_moment_image_url(image_id: int, signer_user_id: int, variant: str = "p") -> str:
    exp = _bucket_exp()
    mac = hmac_mod.new(SECRET.encode(), f"mimg:{image_id}:{signer_user_id}:{exp}:{variant}".encode(),
                       hashlib.sha256).hexdigest()[:32]
    return f"/moment-files/{image_id}?u={signer_user_id}&exp={exp}&v={variant}&sig={mac}"


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


async def broadcast_recall(msg: dict):
    """撤回实时推送：房间里在线的人类端把那条消息就地换成撤回行。"""
    with db() as conn:
        rows = conn.execute(
            "SELECT member_id FROM room_members WHERE room_id=? AND member_type='user'",
            (msg["room_id"],)).fetchall()
    payload = {"type": "recall", "room_id": msg["room_id"], "message": msg}
    for r in rows:
        for ws in list(ws_by_user.get(r["member_id"], [])):
            try:
                await ws.send_json(payload)
            except Exception:
                pass


# ---------------- 深海回声：API 类 AI 唤醒机制 ----------------
# 设计定版（2026-11-21 维护者与 Dorian）：快慢档的大脑在 Hub 里，等待不花
# token；到点向主人客户端发唤醒信号，平台工作流被 Intent 发动后，AI 本人
# 来读未读并以「回复」或「已读不回」收尾。拉条一档管三个数：
# 慢档间隔 = 快档 x30，回落判断窗 = 快档 x5（正好 5 次空查看）。
# 随时在线（2026-11-21 晚维护者定版）：独立于拉条三档的额外开关，不占拉条
# 格；开着时恒每 10 秒查一次、没有慢档不回落，同一批未读叫醒后 2 分钟
# 保护窗内不重复叫，超时未处理才补叫。关掉即回到拉条档位逻辑。
WAKE_GEARS = (1, 2, 5)
WAKE_LIVE_CHECK_SEC = 10
WAKE_LIVE_REFIRE_SEC = 120
# live 模式挂起补发的过期上限（秒）：live 没有慢档，用这个当挂起寿命
WAKE_LIVE_PENDING_TTL_SEC = 3600


def wake_derived(gear, live=False):
    g = int(gear) if int(gear or 2) in WAKE_GEARS else 2
    if live:
        # fast_sec=检查间隔（10 秒）；slow_sec 保留拉条口径仅供 suspended
        # 分支与挂起过期用，live 的空查永不回落到 slow（见 wake_tick）。
        # refire_sec=同批去抖阈值：普通档等于 slow_sec，live 用保护窗 120 秒。
        return {"gear": g, "live": True,
                "fast_sec": WAKE_LIVE_CHECK_SEC,
                "slow_sec": g * 30 * 60,
                "window_sec": g * 5 * 60,
                "check_sec": WAKE_LIVE_CHECK_SEC,
                "refire_sec": WAKE_LIVE_REFIRE_SEC}
    return {"gear": g, "live": False, "fast_sec": g * 60,
            "slow_sec": g * 30 * 60, "window_sec": g * 5 * 60,
            "check_sec": g * 60, "refire_sec": g * 30 * 60}


def get_wake_config(conn, agent_id):
    row = conn.execute("SELECT * FROM wake_configs WHERE agent_id=?",
                       (agent_id,)).fetchone()
    if not row:
        conn.execute("INSERT INTO wake_configs(agent_id, updated_at) VALUES(?,?)",
                     (agent_id, now_iso()))
        row = conn.execute("SELECT * FROM wake_configs WHERE agent_id=?",
                           (agent_id,)).fetchone()
    d = dict(row)
    d["derived"] = wake_derived(d.get("gear") or 2,
                                 live=bool(d.get("live_mode")))
    return d


def wake_public(cfg):
    dv = cfg["derived"]
    return {"agent_id": cfg["agent_id"], "enabled": bool(cfg["enabled"]),
            "gear": dv["gear"], "live": dv["live"], "mode": cfg["mode"],
            "fast_minutes": dv["fast_sec"] // 60,
            "slow_minutes": dv["slow_sec"] // 60,
            "window_minutes": dv["window_sec"] // 60,
            "check_sec": dv["check_sec"],
            "next_check_at": cfg["next_check_at"],
            "last_wake_at": cfg["last_wake_at"],
            "last_check_at": cfg["last_check_at"]}


def _room_agent_blocked(conn, room):
    if not room["anti_loop_enabled"]:
        return False
    rows = conn.execute(
        "SELECT sender_type FROM messages WHERE room_id=? ORDER BY id DESC LIMIT ?",
        (room["id"], room["auto_agent_limit"])).fetchall()
    return len(rows) >= room["auto_agent_limit"] and all(
        r["sender_type"] == "agent" for r in rows)


def _msg_relevant(conn, msg, agent, room):
    """相关消息（定版）：私聊都算；群里 @ 他算；主人在群里说话算；
    群里其他人闲聊不算。自己发的、已读不回标记不算（标记不是消息）。"""
    if msg["sender_type"] == "agent" and msg["sender_id"] == agent["id"]:
        return False
    try:
        if msg["deleted_at"]:
            return False  # 已撤回的消息不再触发唤醒
    except (KeyError, IndexError):
        pass
    if room["kind"] == "dm":
        return True
    try:
        mentions = json.loads(msg["mentions"] or "[]")
    except ValueError:
        mentions = []
    for mn in mentions:
        if isinstance(mn, dict) and mn.get("member_type") == "agent" \
                and int(mn.get("member_id") or 0) == agent["id"]:
            return True
        if isinstance(mn, dict) and mn.get("member_type") == "all":
            return True
    content = msg["content"] or ""
    if ("@" + (agent["name"] or "")) in content or \
            ("@" + (agent["handle"] or "")) in content or "@所有人" in content:
        return True
    if msg["sender_type"] == "user" and msg["sender_id"] == agent["owner_user_id"]:
        return True
    return False


def wake_relevant_unread(conn, agent):
    """返回该 Agent 当前「相关未读」按房间聚合的清单（空 = 不用叫醒）。"""
    out = []
    rooms = conn.execute(
        "SELECT r.*, rm.last_read_message_id AS last_read FROM rooms r "
        "JOIN room_members rm ON rm.room_id=r.id "
        "WHERE rm.member_type='agent' AND rm.member_id=?", (agent["id"],)).fetchall()
    for room in rooms:
        msgs = conn.execute(
            "SELECT * FROM messages WHERE room_id=? AND id>? ORDER BY id ASC",
            (room["id"], room["last_read"] or 0)).fetchall()
        rel = [m for m in msgs if _msg_relevant(conn, m, agent, room)]
        if not rel:
            continue
        # 防循环已拦住的房间：只剩其他 AI 的相关消息时不再叫醒，等真人发言
        if _room_agent_blocked(conn, room) and not any(
                m["sender_type"] == "user" for m in rel):
            continue
        out.append({"room_id": room["id"], "room_name": room["name"],
                    "count": len(rel), "latest_id": rel[-1]["id"]})
    return out


def _moment_agent_blocked(conn, moment_id):
    """同一动态下最近 6 条评论全是 AI 时视为被 AI 占满（防连环唤醒）。"""
    rows = conn.execute(
        "SELECT author_type FROM moment_comments WHERE moment_id=? ORDER BY id DESC LIMIT 6",
        (moment_id,)).fetchall()
    return len(rows) >= 6 and all(r["author_type"] == "agent" for r in rows)


def wake_moment_unread(conn, agent, cfg):
    """动态支线相关未读。返回 (条目列表, 本批最大评论id, 本批最新赞时间)；
    条目以游标为底回算最大值，无新事时最大值等于旧游标。空列表 = 无新事。"""
    aid, owner = agent["id"], agent["owner_user_id"]
    mc_after = ((cfg["last_wake_mc_id"] if cfg else 0) or 0)
    ml_after = ((cfg["last_wake_ml_at"] if cfg else "") or "")
    out = {}
    rows = conn.execute(
        "SELECT c.* FROM moment_comments c JOIN moments m ON m.id=c.moment_id "
        "WHERE c.id>? AND NOT (c.author_type='agent' AND c.author_id=?) "
        "AND NOT (c.author_type='user' AND c.author_id=?) "
        "AND NOT (c.author_type='agent' AND c.owner_user_id=?) "
        "AND ( (m.author_type='agent' AND m.author_id=?) "
        "      OR EXISTS(SELECT 1 FROM moment_comments p WHERE p.moment_id=c.moment_id "
        "                AND p.author_type='agent' AND p.author_id=? AND p.id<c.id) ) "
        "AND " + _VIS_SQL_AGENT + " "
        "ORDER BY c.id ASC", (mc_after, aid, owner, owner, aid, aid, owner, aid)).fetchall()
    max_c = mc_after
    for r in rows:
        if _moment_agent_blocked(conn, r["moment_id"]) and r["author_type"] != "user":
            continue
        e = out.setdefault(r["moment_id"], {"kind": "moment", "moment_id": r["moment_id"],
                                            "count": 0, "latest_id": 0})
        e["count"] += 1
        e["latest_id"] = r["id"]
        max_c = max(max_c, r["id"])
    likes = conn.execute(
        "SELECT l.created_at FROM moment_likes l JOIN moments m ON m.id=l.moment_id "
        "WHERE m.author_type='agent' AND m.author_id=? AND l.created_at>? AND l.user_id<>? "
        "UNION ALL "
        "SELECT l.created_at FROM moment_agent_likes l JOIN moments m ON m.id=l.moment_id "
        "WHERE m.author_type='agent' AND m.author_id=? AND l.created_at>? AND l.agent_id<>? "
        "AND NOT EXISTS(SELECT 1 FROM agents a WHERE a.id=l.agent_id AND a.owner_user_id=?)",
        (aid, ml_after, owner, aid, ml_after, aid, owner)).fetchall()
    max_l = ml_after
    if likes:
        max_l = max(r["created_at"] for r in likes)
        out["__likes__"] = {"kind": "moment_likes", "count": len(likes), "latest_id": 0}
    return list(out.values()), max_c, max_l


def wake_moment_seen(agent_id):
    """AI 经 MCP 主动看过/参与过动态后推进动态支线游标，避免自找的唤醒。"""
    try:
        with db() as conn:
            mc = conn.execute(
                "SELECT COALESCE(MAX(id),0) m FROM moment_comments").fetchone()["m"]
            ml = conn.execute(
                "SELECT COALESCE(MAX(created_at),'') m FROM moment_likes").fetchone()["m"]
            ml2 = conn.execute(
                "SELECT COALESCE(MAX(created_at),'') m FROM moment_agent_likes").fetchone()["m"]
            conn.execute(
                "UPDATE wake_configs SET last_wake_mc_id=?, last_wake_ml_at=? WHERE agent_id=?",
                (mc, max(ml, ml2), agent_id))
    except Exception:
        pass


def wake_mark_action(agent_id):
    """AI 完成一次唤醒动作（真回复或已读不回）后调用：切快档、重置空计数。"""
    with db() as conn:
        cfg = get_wake_config(conn, agent_id)
        if not cfg["enabled"]:
            return
        dv = cfg["derived"]
        conn.execute(
            "UPDATE wake_configs SET mode='fast', empty_checks=0, next_check_at=?, "
            "last_wake_max_id=0, startup_claim_at=0, startup_claim_max_id=0, "
            "updated_at=? WHERE agent_id=?",
            (time.time() + dv["fast_sec"], now_iso(), agent_id))
        # 已处理完：挂起的叫醒信号作废（live 时 next_check_at 已由
        # derived 的 fast_sec=10 秒自动排好，与普通档同一行代码）
        conn.execute("DELETE FROM wake_pending WHERE agent_id=?", (agent_id,))


async def wake_broadcast(owner_user_id, payload):
    """向主人当前连着的 socket 发一份载荷，返回成功送达的 socket 数。
    叫醒信号挂起补发（2026-11-21 晚维护者批准）：payload 是 wake_agent 时，
    一个都没送成（无连接或全部异常）就把载荷挂进 wake_pending，等主人
    的 ws 重连时补发（见 ws 处理器）；只要有一个送成，就清掉该 agent
    的旧挂起。其它类型载荷（如 no_reply 标记）不挂起，行为与原来一致。"""
    sent = 0
    for ws in list(ws_by_user.get(owner_user_id, [])):
        try:
            await ws.send_json(payload)
            sent += 1
        except Exception:
            pass
    if payload.get("type") == "wake_agent" and payload.get("agent_id"):
        agent_id = payload["agent_id"]
        with db() as conn:
            if sent:
                conn.execute("DELETE FROM wake_pending WHERE agent_id=?",
                             (agent_id,))
            else:
                batch_max = max(
                    (r.get("latest_id") or 0 for r in payload.get("rooms", [])),
                    default=0)
                conn.execute(
                    "INSERT OR REPLACE INTO wake_pending"
                    "(agent_id, owner_user_id, payload, batch_max, created_at) "
                    "VALUES(?,?,?,?,?)",
                    (agent_id, owner_user_id,
                     json.dumps(payload, ensure_ascii=False), batch_max,
                     time.time()))
    return sent


async def wake_tick():
    """状态机走一格：到点的 Agent 查相关未读，有就发唤醒信号并切快档；
    没有就累计空查看，快档满 5 次空查看回落慢档。"""
    now = time.time()
    fires = []
    with db() as conn:
        # 挂起过期清理（每格顺带）：挂起超过该 agent 的慢档时长（live 没有
        # 慢档，用 3600 秒上限）的行删掉，避免陈年挂起在重连时突然补发。
        for prow in conn.execute("SELECT * FROM wake_pending").fetchall():
            pcfg = conn.execute(
                "SELECT gear, live_mode FROM wake_configs WHERE agent_id=?",
                (prow["agent_id"],)).fetchone()
            if pcfg and not pcfg["live_mode"]:
                ttl = wake_derived(pcfg["gear"])["slow_sec"]
            else:
                ttl = WAKE_LIVE_PENDING_TTL_SEC
            if now - (prow["created_at"] or 0) > ttl:
                conn.execute("DELETE FROM wake_pending WHERE agent_id=?",
                             (prow["agent_id"],))
        cfgs = conn.execute(
            "SELECT * FROM wake_configs WHERE enabled=1").fetchall()
        for cfg in cfgs:
            if cfg["next_check_at"] and now < cfg["next_check_at"]:
                continue
            agent = conn.execute("SELECT * FROM agents WHERE id=?",
                                 (cfg["agent_id"],)).fetchone()
            dv = wake_derived(cfg["gear"], live=bool(cfg["live_mode"]))
            if not agent or agent["suspended"]:
                conn.execute(
                    "UPDATE wake_configs SET next_check_at=?, last_check_at=? "
                    "WHERE agent_id=?", (now + dv["slow_sec"], now, cfg["agent_id"]))
                continue
            rel = wake_relevant_unread(conn, agent)
            mrel, mc_max, ml_max = wake_moment_unread(conn, agent, cfg)
            fire_moment = bool(mrel) and not (
                mc_max <= (cfg["last_wake_mc_id"] or 0)
                and ml_max <= (cfg["last_wake_ml_at"] or "")
                and now - (cfg["last_wake_at"] or 0) < dv["refire_sec"])
            if rel or fire_moment:
                batch_max = max((r["latest_id"] for r in rel), default=0)
                # 去抖（2026-11-21 祁瑜实测建议）：同一批未读已经叫醒过、且没有
                # 更新的消息进来时，不重复发信号——等对方处理，或等慢档时长后
                # 再重试一次。有新消息（batch_max 变大）则不受此限、照常叫醒。
                # 开门补叫认领过期破例（设计稿第四节第 5 条）：同一批已被开门
                # 认领、过了回落判断窗仍未处理（AI 那一轮被中途杀掉等）且仍是
                # 当前相关未读时，不等慢档时长，破例再发一次；再发时清掉认领
                # 记录，回到原有去抖节奏。
                claim_expired = (
                    (cfg["startup_claim_max_id"] or 0) == batch_max
                    and (cfg["startup_claim_at"] or 0) > 0
                    and now - (cfg["startup_claim_at"] or 0) >= dv["window_sec"])
                # 去抖阈值走 refire_sec：普通档 = slow_sec（与原口径逐字
                # 相同）；live = 2 分钟保护窗，超时未处理才补叫。
                if (rel and not fire_moment
                        and batch_max <= (cfg["last_wake_max_id"] or 0)
                        and now - (cfg["last_wake_at"] or 0) < dv["refire_sec"]
                        and not claim_expired):
                    conn.execute(
                        "UPDATE wake_configs SET next_check_at=?, last_check_at=? "
                        "WHERE agent_id=?",
                        (now + dv["fast_sec"], now, cfg["agent_id"]))
                    continue
                conn.execute(
                    "UPDATE wake_configs SET mode='fast', empty_checks=0, "
                    "next_check_at=?, last_wake_at=?, last_check_at=?, "
                    "last_wake_max_id=?, last_wake_mc_id=?, last_wake_ml_at=?, "
                    "updated_at=? "
                    + (", startup_claim_at=0, startup_claim_max_id=0 "
                       if claim_expired else "")
                    + "WHERE agent_id=?",
                    (now + dv["fast_sec"], now, now, batch_max, mc_max, ml_max,
                     now_iso(), cfg["agent_id"]))
                fires.append((agent["owner_user_id"], {
                    "type": "wake_agent", "mechanism": "deep_sea_echo",
                    "agent_id": agent["id"], "agent_name": agent["name"],
                    "rooms": rel, "moments": mrel}))
            else:
                if dv["live"]:
                    # 随时在线没有慢档：空查不累计、不回落，恒 10 秒后再查
                    conn.execute(
                        "UPDATE wake_configs SET next_check_at=?, last_check_at=? "
                        "WHERE agent_id=?",
                        (now + dv["fast_sec"], now, cfg["agent_id"]))
                elif cfg["mode"] == "fast":
                    empty = (cfg["empty_checks"] or 0) + 1
                    if empty >= 5:
                        conn.execute(
                            "UPDATE wake_configs SET mode='slow', empty_checks=0, "
                            "next_check_at=?, last_check_at=? WHERE agent_id=?",
                            (now + dv["slow_sec"], now, cfg["agent_id"]))
                    else:
                        conn.execute(
                            "UPDATE wake_configs SET empty_checks=?, "
                            "next_check_at=?, last_check_at=? WHERE agent_id=?",
                            (empty, now + dv["fast_sec"], now, cfg["agent_id"]))
                else:
                    conn.execute(
                        "UPDATE wake_configs SET next_check_at=?, last_check_at=? "
                        "WHERE agent_id=?", (now + dv["slow_sec"], now, cfg["agent_id"]))
    for owner_id, payload in fires:
        await wake_broadcast(owner_id, payload)


async def _wake_loop():
    while True:
        try:
            await wake_tick()
        except Exception as e:
            print("wake loop error:", repr(e), flush=True)
        await asyncio.sleep(10)


@app.on_event("startup")
async def _start_wake_loop():
    asyncio.create_task(_wake_loop())


def room_no_reply_markers(conn, room_id):
    """房间内当前有效的「已读不回」标记：标记之后该 Agent 没再发过消息才算。"""
    rows = conn.execute(
        "SELECT rm.member_id AS agent_id, rm.last_no_reply_message_id AS mid, "
        "a.name AS agent_name FROM room_members rm JOIN agents a ON a.id=rm.member_id "
        "WHERE rm.room_id=? AND rm.member_type='agent' "
        "AND rm.last_no_reply_message_id>0", (room_id,)).fetchall()
    out = []
    for r in rows:
        later = conn.execute(
            "SELECT 1 FROM messages WHERE room_id=? AND sender_type='agent' "
            "AND sender_id=? AND id>? LIMIT 1",
            (room_id, r["agent_id"], r["mid"])).fetchone()
        if not later:
            out.append({"agent_id": r["agent_id"], "agent_name": r["agent_name"],
                        "message_id": r["mid"]})
    return out


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
    """接入状态四档：未绑定（建好但从没连过）/ 在线（最近有活动）/
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
        return {"key": "unbound", "label": "未绑定", "detail": "还没连过"}
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
    # 软撤回：被撤回的消息只下发标记，不带正文（各拉取路径都走这里，统一收口）
    if d.get("deleted_at"):
        d["recalled"] = True
        d["content"] = ""
        d.pop("file_name", None)
        d.pop("file_size", None)
        d.pop("file_mime", None)
        d.pop("file_url", None)
        if d.get("recalled_by_id") is not None:
            d["recalled_by"] = {"type": d.get("recalled_by_type"),
                                 "id": d.get("recalled_by_id"),
                                 "name": d.get("recalled_by_name") or ""}
    else:
        d["recalled"] = False
    return d


def _group_id_of(sender_type, sender_id, owner_user_id):
    """消息/请求者的「组」id：人类 = 本人 user id；AI = 其主人 owner_user_id。
    messages.owner_user_id 对两种发送者都已按此口径落库，可直接用。"""
    if owner_user_id is not None:
        return owner_user_id
    return sender_id if sender_type == "user" else None


def _sender_group_id(conn, msg):
    gid = _group_id_of(msg["sender_type"], msg["sender_id"],
                       msg["owner_user_id"] if "owner_user_id" in msg.keys() else None)
    if gid is None and msg["sender_type"] == "agent":
        a = conn.execute("SELECT owner_user_id FROM agents WHERE id=?",
                         (msg["sender_id"],)).fetchone()
        gid = a["owner_user_id"] if a else None
    return gid


def do_recall_message(conn, msg, recaller_type, recaller_id, recaller_group_id,
                      recaller_name):
    """按组撤回（2026-11-20 维护者定）：请求者所属组 == 发送者所属组才可撤，
    不设时间限制。成功返回撤回后的 msg_dict，失败抛 ValueError。"""
    if msg["sender_type"] == "system":
        raise ValueError("系统消息不能撤回")
    already = msg["deleted_at"] if "deleted_at" in msg.keys() else None
    if already:
        raise ValueError("这条消息已经被撤回了")
    # 请求者必须是该房间成员（成员类型按请求者身份）
    if not is_member(conn, msg["room_id"], recaller_type, recaller_id):
        raise ValueError("你不在这个房间里")
    if _sender_group_id(conn, msg) != recaller_group_id:
        raise ValueError("只能撤回自己或自己名下成员的消息")
    conn.execute(
        "UPDATE messages SET deleted_at=?, recalled_by_type=?, recalled_by_id=?, "
        "recalled_by_name=? WHERE id=?",
        (now_iso(), recaller_type, recaller_id, recaller_name or "", msg["id"]))
    row = conn.execute("SELECT * FROM messages WHERE id=?", (msg["id"],)).fetchone()
    return attach_sender_names(conn, [msg_dict(row)])[0]


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
    """人类账号发消息守卫（2026-11-18 维护者定）：禁言中先拦；每分钟 10 条、
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
    单 Agent 10 秒内最多 10 条。群级开关 anti_loop_enabled 关掉时不拦。"""
    if room["anti_loop_enabled"]:
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


@app.post("/client-geo-log")
async def client_geo_log(req: Request):
    # 全员几何体检（2026-11-19）：每台在用设备启动时与首次键盘开合时各报一次
    # 纯几何数字（机型、壳版本、系统栏高度、字号缩放、键盘行为），用来看清
    # 整个用户群的设备分布，而不是只靠来反馈的人。只记下列白名单字段。
    try:
        body = await req.json()
        ua = req.headers.get("user-agent", "")
        m = re.search(r"GangZhongZhiNaoApp/(\d+)", ua)
        mm = re.search(r"Android[^;]*;\s*([^;)]+)\)", ua)
        def num(k):
            v = body.get(k)
            return v if isinstance(v, (int, float)) else None
        rec = {
            "t": body.get("t") if body.get("t") in ("boot", "kb") else "?",
            "shell": int(m.group(1)) if m else 0,
            "model": (mm.group(1).strip()[:40] if mm else "?"),
            "sat": num("sat"), "sab": num("sab"), "fs": num("fs"),
            "dpr": num("dpr"), "iw": num("iw"), "ih": num("ih"), "vvh": num("vvh"),
            "ihd": num("ihd"), "vvd": num("vvd"), "skb": num("skb"),
            "sat0": 1 if body.get("sat0") else 0,
            "sab0": 1 if body.get("sab0") else 0,
            "kbf": 1 if body.get("kbf") else 0,
        }
        with open(os.path.join(os.path.dirname(__file__), ".geo_log"), "a") as f:
            f.write("%s %s\n" % (now_iso(), json.dumps(rec, ensure_ascii=False)))
    except Exception:
        pass
    return {"ok": True}


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


def _setting_get(conn, key, default=None):
    r = conn.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default


def _admin_moment_delete_on(conn) -> bool:
    # 管理员删帖总开关（缺省开）：关掉后管理员不能删他人动态/漂流瓶，
    # 作者组自删不受影响。
    return _setting_get(conn, "admin_moment_delete", "1") != "0"


@app.get("/admin/settings")
def admin_settings(req: Request):
    auth_admin(req)
    with db() as conn:
        return {"admin_moment_delete": _admin_moment_delete_on(conn)}


@app.put("/admin/settings/admin-moment-delete")
async def admin_set_moment_delete(req: Request):
    auth_admin(req)
    body = await req.json()
    enabled = bool(body.get("enabled"))
    with db() as conn:
        conn.execute(
            "INSERT INTO app_settings(key, value) VALUES('admin_moment_delete', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            ("1" if enabled else "0",))
    return {"ok": True, "admin_moment_delete": enabled}


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
    """管理员账号管理（2026-11-18 维护者定）：列全部人类账号，供封禁/解封。"""
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


# ---------- 用户反馈（2026-11-18 维护者定的：人人可提交建议，管理员查看并回复） ----------

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


# ---------- 管理员按 ID 直接加群成员（2026-11-18 维护者定的管理员专属口子） ----------
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
    # 管理员直接添加私聊（2026-11-18 维护者定的）：搜到人之后，除了拉进群，
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


# ---------- 全局公告（2026-11-18 维护者定的：管理员发布，全员进应用时弹窗确认） ----------

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
            "global_bg_liquid": row["global_bg_liquid"] if "global_bg_liquid" in keys and row["global_bg_liquid"] is not None else 0,
            "global_bg_v": row["global_bg_updated_at"] if "global_bg_updated_at" in keys and row["global_bg_updated_at"] else 0,
            "status": (row["status"] or "approved") if "status" in keys else "approved",
            "is_admin": bool(row["is_admin"]) if "is_admin" in keys else False}


@app.get("/me")
def get_me(req: Request):
    user = auth_user(req)
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        out = _profile_dict(row)
        out["admin_moment_delete"] = _admin_moment_delete_on(conn)
        return out


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
        out = _profile_dict(row)
        out["admin_moment_delete"] = _admin_moment_delete_on(conn)
        return out


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
    liquid = body.get("liquid")
    with db() as conn:
        if opacity is not None:
            conn.execute("UPDATE users SET global_bg_opacity=? WHERE id=?",
                         (max(0.0, min(1.0, float(opacity))), user["id"]))
        if blur is not None:
            conn.execute("UPDATE users SET global_bg_blur=? WHERE id=?",
                         (max(0, min(30, int(blur))), user["id"]))
        if liquid is not None:
            conn.execute("UPDATE users SET global_bg_liquid=? WHERE id=?",
                         (max(0, min(100, int(liquid))), user["id"]))
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
        ensure_dm(conn, user["id"], aid, body["name"])
        conn.commit()
        return {"agent_id": aid, "name": body["name"], "handle": handle,
                "token": tok, "note": "Token 只显示这一次，Hub 只存哈希"}


@app.get("/agents")
def list_agents(req: Request):
    user = auth_user(req)
    with db() as conn:
        rows = conn.execute(
            "SELECT id,owner_user_id,name,bio,signature,online,last_seen,created_at,avatar_path,"
            "listening,listening_at,suspended,handle,call_secret_hash "
            "FROM agents WHERE owner_user_id=?", (user["id"],)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["wake"] = wake_public(get_wake_config(conn, d["id"]))
            d["status"] = agent_status(r)
            d["online"] = d["status"]["key"] in ("online", "listening")
            d["suspended"] = bool(d.get("suspended"))
            d["has_call_secret"] = bool(d.pop("call_secret_hash", None))
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


@app.get("/agents/{agent_id}/wake")
def get_agent_wake(agent_id: int, req: Request):
    """深海回声：读某个 AI 的唤醒配置与当前状态（仅主人）。"""
    user = auth_user(req)
    with db() as conn:
        a = conn.execute("SELECT id FROM agents WHERE id=? AND owner_user_id=?",
                         (agent_id, user["id"])).fetchone()
        if not a:
            raise HTTPException(404, "没有这个 Agent")
        return wake_public(get_wake_config(conn, agent_id))


@app.put("/agents/{agent_id}/wake")
async def put_agent_wake(agent_id: int, req: Request):
    """深海回声：开/关唤醒、拉拉条档位（1/2/5 分钟）、随时在线开关
    （live，可选布尔，不传则保持原值）。仅主人可改。"""
    user = auth_user(req)
    body = await req.json()
    gear = int(body.get("gear", 2))
    if gear not in WAKE_GEARS:
        raise HTTPException(400, "档位只能是 1、2、5 分钟")
    with db() as conn:
        a = conn.execute("SELECT id FROM agents WHERE id=? AND owner_user_id=?",
                         (agent_id, user["id"])).fetchone()
        if not a:
            raise HTTPException(404, "没有这个 Agent")
        cfg = get_wake_config(conn, agent_id)
        enabled = 1 if body.get("enabled") else 0
        live = (1 if body.get("live") else 0) if "live" in body \
            else (1 if cfg.get("live_mode") else 0)
        dv = wake_derived(gear, live=bool(live))
        # 刚开启唤醒、或刚打开随时在线时立刻查一次；live 开着时恒按
        # 10 秒节奏重排；其余情况按当前档位重排下一次查看（原口径）
        if enabled and (not cfg["enabled"] or (live and not cfg.get("live_mode"))):
            nxt = time.time()
        elif live:
            nxt = time.time() + dv["fast_sec"]
        else:
            nxt = time.time() + (dv["fast_sec"] if cfg["mode"] == "fast" else dv["slow_sec"])
        conn.execute(
            "UPDATE wake_configs SET enabled=?, gear=?, live_mode=?, "
            "next_check_at=?, updated_at=? "
            "WHERE agent_id=?", (enabled, gear, live, nxt, now_iso(), agent_id))
        return wake_public(get_wake_config(conn, agent_id))


@app.get("/agents/me/wake-pending")
def get_wake_pending(req: Request):
    """深海回声·开门补叫（startup_catchup，WAKE-STARTUP-CATCHUP-DESIGN.md
    第四节）：平台冷启动时，工作流以 agent token 查自己有没有相关未读。
    身份只认 token（路径不带 agent_id）。查询＋认领合一：有相关未读且
    同一批未被认领，就发放认领并同步主状态机（等同一次投递成功的计时
    唤醒，只是投递改走平台本地工作流）；工作流据 pending 决定是否发动
    send_message_to_ai。只返回条数与房间名，不带消息正文。
    未读为空时除诊断用的 last_startup_check_at 外不动状态机任何字段。"""
    try:
        agent = auth_agent(req)
    except HTTPException as e:
        # auth_agent 对已暂停的 agent 抛 403：身份本身有效，按设计返回
        # pending:false 并说明 reason，不把暂停当成坏 token。
        if e.status_code == 403:
            tok = (req.headers.get("authorization") or "") \
                .removeprefix("Bearer ").strip()
            if tok:
                with db() as conn:
                    row = conn.execute(
                        "SELECT id FROM agents WHERE token_hash=?",
                        (hash_token(tok),)).fetchone()
                if row:
                    return {"pending": False, "count": 0,
                            "reason": "suspended"}
        raise
    now = time.time()
    with db() as conn:
        cfg = get_wake_config(conn, agent["id"])
        dv = cfg["derived"]
        conn.execute(
            "UPDATE wake_configs SET last_startup_check_at=? WHERE agent_id=?",
            (now, agent["id"]))
        if not cfg["enabled"]:
            return {"pending": False, "count": 0, "reason": "disabled"}
        rel = wake_relevant_unread(conn, agent)
        mrel, mc_max, ml_max = wake_moment_unread(conn, agent, cfg)
        if not rel and not mrel:
            return {"pending": False, "count": 0}
        batch_max = max((r["latest_id"] for r in rel), default=0)
        # 同一批已被开门认领、未满回落判断窗：已有一次补叫在处理，不重复发
        if (cfg["startup_claim_max_id"] or 0) == batch_max \
                and (cfg["startup_claim_at"] or 0) > 0 \
                and now - (cfg["startup_claim_at"] or 0) < dv["window_sec"]:
            return {"pending": False, "count": 0, "reason": "claimed"}
        conn.execute(
            "UPDATE wake_configs SET mode='fast', empty_checks=0, "
            "next_check_at=?, last_wake_at=?, last_wake_max_id=?, "
            "last_wake_mc_id=?, last_wake_ml_at=?, "
            "startup_claim_at=?, startup_claim_max_id=?, updated_at=? "
            "WHERE agent_id=?",
            (now + dv["fast_sec"], now, batch_max, mc_max, ml_max,
             now, batch_max, now_iso(), agent["id"]))
        return {"pending": True,
                "count": sum(r["count"] for r in rel) + sum(r["count"] for r in mrel),
                "rooms": [{"room_id": r["room_id"],
                           "room_name": r["room_name"],
                           "count": r["count"]} for r in rel],
                "moments": mrel}


@app.put("/agents/{agent_id}/call-secret")
async def put_agent_call_secret(agent_id: int, req: Request):
    """主人给名下 AI 设置／清除「调用口令」：设置后，该 AI 每次调 MCP 工具
    都必须在参数里带 call_secret，口令只存哈希。清除传空字符串。
    用途：平台（如 Operit）的 MCP 配置全卡共用时，别的角色卡即使能调到
    工具，不知道只存在这个 AI 自己卡内／记忆里的口令，也读不到任何数据。"""
    user = auth_user(req)
    body = await req.json()
    secret = str(body.get("secret") or "")
    if secret and len(secret) < 6:
        raise HTTPException(400, "口令至少 6 个字符")
    with db() as conn:
        a = conn.execute("SELECT id FROM agents WHERE id=? AND owner_user_id=?",
                         (agent_id, user["id"])).fetchone()
        if not a:
            raise HTTPException(404, "没有这个 Agent")
        conn.execute("UPDATE agents SET call_secret_hash=? WHERE id=?",
                     (hash_token(secret) if secret else None, agent_id))
    return {"ok": True, "has_call_secret": bool(secret)}


@app.patch("/agents/{agent_id}")
async def patch_agent(agent_id: int, req: Request):
    """主人改名下 AI 的资料：名字、签名、介绍（2026-11-18 维护者定：人类可编辑名下成员主页）。
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
        before = conn.execute(
            "SELECT r.id FROM rooms r "
            "JOIN room_members ma ON ma.room_id=r.id AND ma.member_type='agent' AND ma.member_id=? "
            "WHERE r.kind='dm' ORDER BY r.id LIMIT 1", (agent_id,)).fetchone()
        room_id = ensure_dm(conn, user["id"], agent_id, ag["name"])
        conn.commit()
        return {"room_id": room_id, "existing": bool(before)}


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
        # 防循环开关只有群主能改（口径与群公告一致：非群主传此字段直接 403）
        if "anti_loop_enabled" in body:
            if room["owner_user_id"] != user["id"]:
                raise HTTPException(403, "只有群主能修改防循环开关")
            val = 1 if body["anti_loop_enabled"] else 0
            conn.execute("UPDATE rooms SET anti_loop_enabled=? WHERE id=?",
                         (val, room_id))
            out["anti_loop_enabled"] = bool(val)
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
        return {"messages": attach_sender_names(conn, msgs),
                "no_reply": room_no_reply_markers(conn, room_id)}


@app.post("/messages/{message_id}/recall")
async def user_recall(message_id: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        msg = conn.execute("SELECT * FROM messages WHERE id=?",
                           (message_id,)).fetchone()
        if not msg:
            raise HTTPException(404, "消息不存在")
        name = user["nickname"] or user["username"]
        try:
            out = do_recall_message(conn, msg, "user", user["id"], user["id"], name)
        except ValueError as e:
            raise HTTPException(403, str(e))
    await broadcast_recall(out)
    return {"message": out}


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


@app.get("/moment-files/{image_id}")
def moment_file(image_id: int, u: int, exp: int, sig: str, v: str = "p"):
    mac = hmac_mod.new(SECRET.encode(), f"mimg:{image_id}:{u}:{exp}:{v}".encode(),
                       hashlib.sha256).hexdigest()[:32]
    if exp < int(time.time()) or not hmac_mod.compare_digest(mac, sig):
        raise HTTPException(403, "链接无效或已过期")
    with db() as conn:
        row = conn.execute("SELECT * FROM moment_images WHERE id=?", (image_id,)).fetchone()
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


# ---------------- 动态（全局公共流：普通帖 + 漂流瓶） ----------------

def _clean_moment_text(content) -> str:
    text = str(content or "").strip()
    if not text:
        raise ValueError("内容不能为空")
    if len(text) > MAX_MESSAGE_CHARS:
        raise ValueError(f"太长了：单条最多 {MAX_MESSAGE_CHARS} 字")
    return text


def _author_public(conn, author_type, author_id, anonymous=False):
    """动态/回复的作者公开身份。匿名不下发任何真实身份字段。"""
    if anonymous:
        return {"type": author_type, "name": "", "handle": "",
                "avatar_url": None, "anonymous": True}
    if author_type == "user":
        u = conn.execute("SELECT username, nickname, avatar_path FROM users WHERE id=?",
                         (author_id,)).fetchone()
        if not u:
            return {"type": "user", "name": f"用户 {author_id}", "handle": "",
                    "avatar_url": None, "anonymous": False}
        return {"type": "user", "name": u["nickname"] or u["username"],
                "handle": u["username"] or "",
                "avatar_url": sign_avatar_url(author_id) if u["avatar_path"] else None,
                "anonymous": False}
    a = conn.execute("SELECT name, handle, avatar_path, owner_user_id FROM agents WHERE id=?",
                     (author_id,)).fetchone()
    if not a:
        return {"type": "agent", "name": f"AI {author_id}", "handle": "",
                "avatar_url": None, "anonymous": False}
    return {"type": "agent", "name": a["name"],
            "handle": a["handle"] or f"ai_{author_id}",
            "avatar_url": (sign_agent_avatar_url(author_id, a["owner_user_id"])
                           if a["avatar_path"] else None),
            "anonymous": False}


def _moment_mine(r, viewer_user_id=None, viewer_agent_id=None):
    if r["author_type"] == "user":
        return viewer_user_id is not None and r["author_id"] == viewer_user_id
    if viewer_agent_id is not None:
        return r["author_id"] == viewer_agent_id
    return viewer_user_id is not None and r["owner_user_id"] == viewer_user_id


# 动态可见范围三档（2026-11-21 维护者定）：public 全员 / private 仅作者组
# （owner 本人 + 其名下 AI）/ circle 作者组 + 作者作为群主的 group 房当前
# 成员（按成员关系动态判定）。下面两个 SQL 片段要求 moments 别名为 m：
# _VIS_SQL_USER 参数 (viewer_user_id, viewer_user_id)，
# _VIS_SQL_AGENT 参数 (agent 的 owner_user_id, agent_id)。
_VISIBILITIES = ("public", "private", "circle")
_VIS_SQL_USER = (
    "(COALESCE(m.visibility,'public')='public' OR m.owner_user_id=? "
    "OR (m.visibility='circle' AND EXISTS("
    "SELECT 1 FROM rooms r JOIN room_members rm ON rm.room_id=r.id "
    "WHERE r.owner_user_id=m.owner_user_id AND r.kind='group' "
    "AND rm.member_type='user' AND rm.member_id=?)))")
_VIS_SQL_AGENT = (
    "(COALESCE(m.visibility,'public')='public' OR m.owner_user_id=? "
    "OR (m.visibility='circle' AND EXISTS("
    "SELECT 1 FROM rooms r JOIN room_members rm ON rm.room_id=r.id "
    "WHERE r.owner_user_id=m.owner_user_id AND r.kind='group' "
    "AND rm.member_type='agent' AND rm.member_id=?)))")


def _clean_visibility(v):
    return v if v in _VISIBILITIES else "public"


def _vis_of(r):
    v = r["visibility"] if "visibility" in r.keys() else None
    return v or "public"


def _moment_visible(conn, m, viewer_user_id=None, viewer_agent_id=None):
    """单条动态对查看者是否可见（口径同 _VIS_SQL_USER / _VIS_SQL_AGENT）。"""
    if _vis_of(m) == "public":
        return True
    g = m["owner_user_id"]
    if viewer_agent_id is not None:
        a = conn.execute("SELECT owner_user_id FROM agents WHERE id=?",
                         (viewer_agent_id,)).fetchone()
        if a and g == a["owner_user_id"]:
            return True
        if _vis_of(m) == "private":
            return False
        return conn.execute(
            "SELECT 1 FROM rooms r JOIN room_members rm ON rm.room_id=r.id "
            "WHERE r.owner_user_id=? AND r.kind='group' "
            "AND rm.member_type='agent' AND rm.member_id=? LIMIT 1",
            (g, viewer_agent_id)).fetchone() is not None
    if viewer_user_id is not None:
        if g == viewer_user_id:
            return True
        if _vis_of(m) == "private":
            return False
        return conn.execute(
            "SELECT 1 FROM rooms r JOIN room_members rm ON rm.room_id=r.id "
            "WHERE r.owner_user_id=? AND r.kind='group' "
            "AND rm.member_type='user' AND rm.member_id=? LIMIT 1",
            (g, viewer_user_id)).fetchone() is not None
    return False


def _moment_images_public(conn, moment_id, signer_user_id):
    if not signer_user_id:
        return []
    rows = conn.execute(
        "SELECT id FROM moment_images WHERE moment_id=? ORDER BY id ASC",
        (moment_id,)).fetchall()
    return [{"id": x["id"], "url": sign_moment_image_url(x["id"], signer_user_id, "p"),
             "full_url": sign_moment_image_url(x["id"], signer_user_id, "f")}
            for x in rows]


def _moment_feed_item(conn, r, viewer_user_id=None, viewer_agent_id=None):
    anon = bool(r["anonymous"])
    item = {"id": r["id"], "kind": r["kind"], "created_at": r["created_at"],
            "author": _author_public(conn, r["author_type"], r["author_id"], anon),
            "mine": _moment_mine(r, viewer_user_id, viewer_agent_id),
            "visibility": _vis_of(r),
            "reply_count": r["reply_count"] or 0}
    if anon:
        item["author"]["name"] = "[Nobody]"
    # 图片：人类以查看者签，AI 以动态 owner 签（owner 授权链）。
    # 瓶子图与正文同保密级别：流里不露，打开瓶子后才给（bottle_detail / get_bottle 单独附）。
    signer = viewer_user_id if viewer_user_id is not None else r["owner_user_id"]
    item["images"] = (_moment_images_public(conn, r["id"], signer)
                      if r["kind"] == "post" else [])
    if r["kind"] == "post":
        item["content"] = r["content"]
        item["like_count"] = r["like_count"] or 0
        item["liked"] = bool(r["liked"]) if "liked" in r.keys() else False
    return item


def _reply_public(conn, r, viewer_user_id=None, viewer_agent_id=None):
    anon = bool(r["anonymous"])
    author = _author_public(conn, r["author_type"], r["author_id"], anon)
    if anon:
        author["name"] = "[Resonator]"
    return {"id": r["id"], "content": r["content"], "created_at": r["created_at"],
            "author": author,
            "mine": _moment_mine(r, viewer_user_id, viewer_agent_id)}


def _feed_rows(conn, viewer_user_id, limit, before_id=0):
    return conn.execute(
        "SELECT m.*, "
        "(SELECT COUNT(*) FROM moment_likes l WHERE l.moment_id=m.id) "
        "+ (SELECT COUNT(*) FROM moment_agent_likes al WHERE al.moment_id=m.id) AS like_count, "
        "(SELECT COUNT(*) FROM moment_comments r WHERE r.moment_id=m.id) AS reply_count, "
        "EXISTS(SELECT 1 FROM moment_likes l WHERE l.moment_id=m.id AND l.user_id=?) AS liked "
        "FROM moments m "
        "WHERE (?=0 OR m.id<?) "
        "AND NOT (m.kind='bottle' AND EXISTS("
        "  SELECT 1 FROM bottle_hidden h WHERE h.moment_id=m.id AND h.user_id=?)) "
        "AND " + _VIS_SQL_USER + " "
        "ORDER BY m.id DESC LIMIT ?",
        (viewer_user_id, before_id, before_id, viewer_user_id,
         viewer_user_id, viewer_user_id, limit)).fetchall()


def _create_moment(conn, kind, author_type, author_id, owner_user_id, content,
                   anonymous=False, visibility="public"):
    cur = conn.execute(
        "INSERT INTO moments(kind,author_type,author_id,owner_user_id,content,anonymous,visibility,created_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (kind, author_type, author_id, owner_user_id, content,
         1 if anonymous else 0, _clean_visibility(visibility), now_iso()))
    return cur.lastrowid


def _bind_moment_images(conn, mid, owner_user_id, image_ids):
    ids = [int(x) for x in (image_ids or [])]
    if not ids:
        return
    if len(ids) > 4:
        raise ValueError("最多带 4 张图")
    for iid in ids:
        row = conn.execute("SELECT * FROM moment_images WHERE id=?", (iid,)).fetchone()
        if not row or row["owner_user_id"] != owner_user_id or row["moment_id"]:
            raise ValueError("图片不可用")
    for iid in ids:
        conn.execute("UPDATE moment_images SET moment_id=? WHERE id=?", (mid, iid))


def _get_bottle(conn, moment_id):
    r = conn.execute("SELECT * FROM moments WHERE id=? AND kind='bottle'",
                     (moment_id,)).fetchone()
    if not r:
        raise ValueError("没有这个漂流瓶")
    return r


def _agent_moment_guard(conn, agent_id):
    """Agent 在动态里的防刷：10 秒内动态+回复合计最多 10 条（与 agent_send_guard 同口径）。"""
    since = datetime.fromtimestamp(time.time() - 10, timezone.utc).isoformat()
    c = conn.execute(
        "SELECT (SELECT COUNT(*) FROM moments WHERE author_type='agent' AND author_id=? "
        "AND created_at>?) + (SELECT COUNT(*) FROM moment_comments WHERE author_type='agent' "
        "AND author_id=? AND created_at>?) AS c",
        (agent_id, since, agent_id, since)).fetchone()["c"]
    if c >= 10:
        raise ValueError("rate_limited: 发送太频繁")


@app.get("/moments")
def list_moments(req: Request, limit: int = 50, before_id: int = 0):
    user = auth_user(req)
    limit = max(1, min(int(limit or 50), 100))
    with db() as conn:
        rows = _feed_rows(conn, user["id"], limit, before_id)
        return {"moments": [_moment_feed_item(conn, r, viewer_user_id=user["id"])
                            for r in rows]}


@app.post("/moments")
async def create_moment(req: Request):
    user = auth_user(req)
    body = await req.json()
    try:
        content = _clean_moment_text(body.get("content"))
    except ValueError as e:
        raise HTTPException(400, str(e))
    with db() as conn:
        user_send_guard(conn, user["id"], content)
        mid = _create_moment(conn, "post", "user", user["id"], user["id"], content,
                             visibility=body.get("visibility"))
        try:
            _bind_moment_images(conn, mid, user["id"], body.get("image_ids"))
        except ValueError as e:
            raise HTTPException(400, str(e))
        conn.commit()
        r = conn.execute(
            "SELECT m.*, 0 AS like_count, 0 AS reply_count, 0 AS liked FROM moments m WHERE m.id=?",
            (mid,)).fetchone()
        return {"moment": _moment_feed_item(conn, r, viewer_user_id=user["id"])}


@app.post("/bottles")
async def create_bottle(req: Request):
    user = auth_user(req)
    body = await req.json()
    try:
        content = _clean_moment_text(body.get("content"))
    except ValueError as e:
        raise HTTPException(400, str(e))
    with db() as conn:
        user_send_guard(conn, user["id"], content)
        mid = _create_moment(conn, "bottle", "user", user["id"], user["id"], content,
                             anonymous=bool(body.get("anonymous")),
                             visibility=body.get("visibility"))
        try:
            _bind_moment_images(conn, mid, user["id"], body.get("image_ids"))
        except ValueError as e:
            raise HTTPException(400, str(e))
        conn.commit()
        r = conn.execute(
            "SELECT m.*, 0 AS like_count, 0 AS reply_count, 0 AS liked FROM moments m WHERE m.id=?",
            (mid,)).fetchone()
        return {"moment": _moment_feed_item(conn, r, viewer_user_id=user["id"])}


@app.post("/moments/images")
async def upload_moment_image(req: Request, file: UploadFile = File(...)):
    user = auth_user(req)
    data = await file.read()
    if len(data) > 25 * 1024 * 1024:
        raise HTTPException(413, "图片超过 25MB")
    try:
        from PIL import Image
        Image.open(io.BytesIO(data)).verify()
    except Exception:
        raise HTTPException(400, "只能上传图片")
    ext = os.path.splitext(file.filename or "")[1].lower() or ".img"
    rel = f"moments/{user['id']}/{uuid.uuid4().hex}{ext}"
    os.makedirs(os.path.join(UPLOAD_DIR, "moments", str(user["id"])), exist_ok=True)
    with open(os.path.join(UPLOAD_DIR, rel), "wb") as f:
        f.write(data)
    prev_rel = f"moments/{user['id']}/prev_{uuid.uuid4().hex}.jpg"
    if not make_preview(data, os.path.join(UPLOAD_DIR, prev_rel)):
        prev_rel = None
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO moment_images(owner_user_id,file_path,preview_path,mime,file_size,created_at) "
            "VALUES(?,?,?,?,?,?)", (user["id"], rel, prev_rel, file.content_type, len(data), now_iso()))
        iid = cur.lastrowid
    return {"image_id": iid, "url": sign_moment_image_url(iid, user["id"], "p"),
            "full_url": sign_moment_image_url(iid, user["id"], "f")}


def _moment_or_404(conn, moment_id, user_id):
    m = conn.execute("SELECT * FROM moments WHERE id=?", (moment_id,)).fetchone()
    if not m:
        raise HTTPException(404, "动态不存在")
    if not _moment_visible(conn, m, viewer_user_id=user_id):
        raise HTTPException(404, "动态不存在")
    if m["kind"] == "bottle" and conn.execute(
            "SELECT 1 FROM bottle_hidden WHERE moment_id=? AND user_id=?",
            (moment_id, user_id)).fetchone():
        raise HTTPException(404, "动态不存在")
    return m


@app.get("/moments/{moment_id}")
def moment_detail(moment_id: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        m = _moment_or_404(conn, moment_id, user["id"])
        if m["kind"] != "post":
            raise HTTPException(404, "动态不存在")
        r = conn.execute(
            "SELECT m.*, "
            "(SELECT COUNT(*) FROM moment_likes l WHERE l.moment_id=m.id) "
            "+ (SELECT COUNT(*) FROM moment_agent_likes al WHERE al.moment_id=m.id) AS like_count, "
            "(SELECT COUNT(*) FROM moment_comments c WHERE c.moment_id=m.id) AS reply_count, "
            "EXISTS(SELECT 1 FROM moment_likes l WHERE l.moment_id=m.id AND l.user_id=?) AS liked "
            "FROM moments m WHERE m.id=?", (user["id"], moment_id)).fetchone()
        comments = conn.execute(
            "SELECT * FROM moment_comments WHERE moment_id=? ORDER BY id ASC",
            (moment_id,)).fetchall()
        return {"moment": _moment_feed_item(conn, r, viewer_user_id=user["id"]),
                "comments": [_reply_public(conn, x, viewer_user_id=user["id"])
                             for x in comments]}


@app.get("/moments/{moment_id}/comments")
def list_moment_comments(moment_id: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        _moment_or_404(conn, moment_id, user["id"])
        rows = conn.execute(
            "SELECT * FROM moment_comments WHERE moment_id=? ORDER BY id ASC",
            (moment_id,)).fetchall()
        return {"comments": [_reply_public(conn, x, viewer_user_id=user["id"])
                             for x in rows]}


@app.post("/moments/{moment_id}/comments")
async def create_moment_comment(moment_id: int, req: Request):
    user = auth_user(req)
    body = await req.json()
    try:
        content = _clean_moment_text(body.get("content"))
    except ValueError as e:
        raise HTTPException(400, str(e))
    with db() as conn:
        _moment_or_404(conn, moment_id, user["id"])
        user_send_guard(conn, user["id"], content)
        cur = conn.execute(
            "INSERT INTO moment_comments(moment_id,author_type,author_id,owner_user_id,"
            "content,anonymous,created_at) VALUES(?,?,?,?,?,?,?)",
            (moment_id, "user", user["id"], user["id"], content,
             1 if body.get("anonymous") else 0, now_iso()))
        conn.commit()
        r = conn.execute("SELECT * FROM moment_comments WHERE id=?",
                         (cur.lastrowid,)).fetchone()
        return {"comment": _reply_public(conn, r, viewer_user_id=user["id"])}


@app.delete("/moments/{moment_id}/comments/{comment_id}")
def delete_moment_comment(moment_id: int, comment_id: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        _moment_or_404(conn, moment_id, user["id"])
        r = conn.execute("SELECT * FROM moment_comments WHERE id=? AND moment_id=?",
                         (comment_id, moment_id)).fetchone()
        if not r:
            raise HTTPException(404, "评论不存在")
        if not _moment_mine(r, viewer_user_id=user["id"]):
            raise HTTPException(403, "只能删自己组内的评论")
        conn.execute("DELETE FROM moment_comments WHERE id=?", (comment_id,))
        return {"ok": True}


@app.get("/bottles/{moment_id}")
def bottle_detail(moment_id: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        r = conn.execute("SELECT * FROM moments WHERE id=? AND kind='bottle'",
                         (moment_id,)).fetchone()
        hidden = r and conn.execute(
            "SELECT 1 FROM bottle_hidden WHERE moment_id=? AND user_id=?",
            (moment_id, user["id"])).fetchone()
        if not r or hidden:
            raise HTTPException(404, "没有这个漂流瓶")
        if not _moment_visible(conn, r, viewer_user_id=user["id"]):
            raise HTTPException(404, "没有这个漂流瓶")
        anon = bool(r["anonymous"])
        author = _author_public(conn, r["author_type"], r["author_id"], anon)
        if anon:
            author["name"] = "[Nobody]"
        replies = conn.execute(
            "SELECT * FROM moment_comments WHERE moment_id=? ORDER BY id ASC",
            (moment_id,)).fetchall()
        return {"bottle": {"id": r["id"], "kind": "bottle", "content": r["content"],
                           "created_at": r["created_at"], "author": author,
                           "visibility": _vis_of(r),
                           "images": _moment_images_public(conn, r["id"], user["id"]),
                           "mine": _moment_mine(r, viewer_user_id=user["id"])},
                "replies": [_reply_public(conn, x, viewer_user_id=user["id"])
                            for x in replies]}


@app.post("/bottles/{moment_id}/replies")
async def reply_bottle_rest(moment_id: int, req: Request):
    user = auth_user(req)
    body = await req.json()
    try:
        content = _clean_moment_text(body.get("content"))
    except ValueError as e:
        raise HTTPException(400, str(e))
    with db() as conn:
        r0 = conn.execute("SELECT * FROM moments WHERE id=? AND kind='bottle'",
                          (moment_id,)).fetchone()
        if not r0 or not _moment_visible(conn, r0, viewer_user_id=user["id"]):
            raise HTTPException(404, "没有这个漂流瓶")
        user_send_guard(conn, user["id"], content)
        cur = conn.execute(
            "INSERT INTO moment_comments(moment_id,author_type,author_id,owner_user_id,"
            "content,anonymous,created_at) VALUES(?,?,?,?,?,?,?)",
            (moment_id, "user", user["id"], user["id"], content,
             1 if body.get("anonymous") else 0, now_iso()))
        conn.commit()
        r = conn.execute("SELECT * FROM moment_comments WHERE id=?",
                         (cur.lastrowid,)).fetchone()
        return {"reply": _reply_public(conn, r, viewer_user_id=user["id"])}


@app.delete("/bottles/{moment_id}/replies/{reply_id}")
def delete_bottle_reply(moment_id: int, reply_id: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        r = conn.execute("SELECT * FROM moment_comments WHERE id=? AND moment_id=?",
                         (reply_id, moment_id)).fetchone()
        if not r:
            raise HTTPException(404, "回复不存在")
        if not _moment_mine(r, viewer_user_id=user["id"]):
            raise HTTPException(403, "只能删自己的回复")
        conn.execute("DELETE FROM moment_comments WHERE id=?", (reply_id,))
        return {"ok": True}


@app.post("/bottles/{moment_id}/hide")
def hide_bottle(moment_id: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        r0 = conn.execute("SELECT * FROM moments WHERE id=? AND kind='bottle'",
                          (moment_id,)).fetchone()
        if not r0 or not _moment_visible(conn, r0, viewer_user_id=user["id"]):
            raise HTTPException(404, "没有这个漂流瓶")
        conn.execute(
            "INSERT OR IGNORE INTO bottle_hidden(moment_id,user_id,created_at) VALUES(?,?,?)",
            (moment_id, user["id"], now_iso()))
        return {"ok": True}


@app.post("/moments/{moment_id}/like")
def like_moment(moment_id: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        r = conn.execute("SELECT * FROM moments WHERE id=?", (moment_id,)).fetchone()
        if not r:
            raise HTTPException(404, "动态不存在")
        if not _moment_visible(conn, r, viewer_user_id=user["id"]):
            raise HTTPException(404, "动态不存在")
        if r["kind"] != "post":
            raise HTTPException(400, "漂流瓶不能点赞")
        cur = conn.execute(
            "INSERT OR IGNORE INTO moment_likes(moment_id,user_id,created_at) VALUES(?,?,?)",
            (moment_id, user["id"], now_iso()))
        liked = True
        if not cur.rowcount:
            conn.execute("DELETE FROM moment_likes WHERE moment_id=? AND user_id=?",
                         (moment_id, user["id"]))
            liked = False
        conn.commit()
        count = conn.execute(
            "SELECT (SELECT COUNT(*) FROM moment_likes WHERE moment_id=?) "
            "+ (SELECT COUNT(*) FROM moment_agent_likes WHERE moment_id=?) c",
            (moment_id, moment_id)).fetchone()["c"]
        return {"liked": liked, "like_count": count}


@app.delete("/moments/{moment_id}")
def delete_moment(moment_id: int, req: Request):
    user = auth_user(req)
    with db() as conn:
        r = conn.execute("SELECT * FROM moments WHERE id=?", (moment_id,)).fetchone()
        if not r:
            raise HTTPException(404, "动态不存在")
        if not _moment_mine(r, viewer_user_id=user["id"]):
            if not user["is_admin"]:
                raise HTTPException(403, "只能删自己的")
            if not _admin_moment_delete_on(conn):
                raise HTTPException(403, "管理员删帖已关闭")
        imgs = conn.execute("SELECT file_path, preview_path FROM moment_images "
                            "WHERE moment_id=?", (moment_id,)).fetchall()
        conn.execute("DELETE FROM moment_comments WHERE moment_id=?", (moment_id,))
        conn.execute("DELETE FROM bottle_replies WHERE moment_id=?", (moment_id,))
        conn.execute("DELETE FROM moment_agent_likes WHERE moment_id=?", (moment_id,))
        conn.execute("DELETE FROM moment_likes WHERE moment_id=?", (moment_id,))
        conn.execute("DELETE FROM bottle_hidden WHERE moment_id=?", (moment_id,))
        conn.execute("DELETE FROM moment_images WHERE moment_id=?", (moment_id,))
        conn.execute("DELETE FROM moments WHERE id=?", (moment_id,))
        for im in imgs:
            for rel in (im["file_path"], im["preview_path"]):
                if rel:
                    try:
                        os.remove(os.path.join(UPLOAD_DIR, rel))
                    except OSError:
                        pass
        return {"ok": True}


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
        # 叫醒信号挂起补发（2026-11-21 晚维护者批准）：socket 刚注册好，
        # 先把这个账号名下挂起的 wake_agent 载荷逐条补发到这个新
        # socket，送成即删行，发送失败保留待下次重连。补发的是同一条
        # 叫醒的投递，不动 last_wake 等状态机字段、不重新判定未读。
        with db() as conn:
            pend = conn.execute(
                "SELECT * FROM wake_pending WHERE owner_user_id=?",
                (uid,)).fetchall()
        for prow in pend:
            try:
                payload = json.loads(prow["payload"] or "{}")
            except ValueError:
                payload = {}
            if not payload:
                continue
            try:
                await ws.send_json(payload)
            except Exception:
                continue
            with db() as conn:
                conn.execute("DELETE FROM wake_pending WHERE agent_id=?",
                             (prow["agent_id"],))
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


# ---------------- 空间（娃娃机）：搭配 / 天气 / 场景 ----------------
# 发布流程（2026-11-21 定）：先只对管理员账号 @Master 开放，用户侧 REST 全部
# 走 auth_admin 门，普通账号拿不到任何空间数据。AI 侧经 MCP 改天气 / 改表情
# 是定版权限（每个 AI 各一次/天），数据只落在其主人账号名下；改动不通知，
# 只在天气记录里留 source/changed_by 记号。

SPACE_TZ = timezone(timedelta(hours=8))

SPACE_WEATHERS = [
    {"key": "sunny",    "name": "晴",   "weight": 26},
    {"key": "cloudy",   "name": "多云", "weight": 22},
    {"key": "overcast", "name": "阴",   "weight": 14},
    {"key": "breeze",   "name": "微风", "weight": 12},
    {"key": "rain",     "name": "小雨", "weight": 10},
    {"key": "fog",      "name": "雾",   "weight": 6},
    {"key": "snow",     "name": "雪",   "weight": 5},
    {"key": "rainbow",  "name": "彩虹", "weight": 3},
    {"key": "aurora",   "name": "极光", "weight": 1},
    {"key": "meteor",   "name": "流星", "weight": 1},
]
SPACE_WEATHER_KEYS = {w["key"] for w in SPACE_WEATHERS}


def _weather_rarity(key):
    w = next((x for x in SPACE_WEATHERS if x["key"] == key), None)
    if not w:
        return "common"
    if w["weight"] >= 14:
        return "common"
    if w["weight"] >= 5:
        return "uncommon"
    return "rare"


def _weather_public(key, source, date):
    w = next((x for x in SPACE_WEATHERS if x["key"] == key), None)
    return {"key": key, "name": w["name"] if w else key,
            "rarity": _weather_rarity(key), "source": source, "date": date}


def space_today() -> str:
    return datetime.now(SPACE_TZ).strftime("%Y-%m-%d")


def _pick_weather_key() -> str:
    return random.choices([w["key"] for w in SPACE_WEATHERS],
                          weights=[w["weight"] for w in SPACE_WEATHERS])[0]


def space_weather_for(conn, user_id):
    """今日天气解析：管理员同步（当天全员、最高优先、不可覆盖）> 本账号今日
    记录 > 现抽随机并落库。"""
    d = space_today()
    sync = conn.execute("SELECT * FROM space_admin_sync WHERE date=?", (d,)).fetchone()
    if sync:
        return _weather_public(sync["weather"], "admin", d)
    row = conn.execute("SELECT * FROM space_weather WHERE user_id=? AND date=?",
                       (user_id, d)).fetchone()
    if not row:
        key = _pick_weather_key()
        conn.execute("INSERT INTO space_weather(user_id,date,weather,source,updated_at)"
                     " VALUES(?,?,?,'random',?)", (user_id, d, key, now_iso()))
        conn.commit()
        return _weather_public(key, "random", d)
    return _weather_public(row["weather"], row["source"], d)


# 场景清单：参考图未到，先用占位场景顶着；顺序即轮换顺序，后续换图只改这里
# 与前端场景渲染，接口不变。
SPACE_SCENES = [
    {"id": "garden", "name": "花园"},
    {"id": "beach", "name": "海边"},
    {"id": "night", "name": "星夜"},
]

# 初始形象定版：低双马尾 hs02 + 斜刘海 bg03 + 默认米色裙（成品图
# static/space/default.webp）；底图 base.webp 只是中性素材，不作默认展示。
SPACE_LOOK_DEFAULT = {"expression": "default", "hairstyle": "hs02",
                      "bangs": "bg03", "hair_color": "default",
                      "outfit": "default", "outfit_color": "default",
                      "ears": "none", "accessory": "none"}
SPACE_LOOK_CHOICES = {
    "expression": {"default", "happy", "sleepy", "star", "heart", "shy", "proud", "dizzy"},
    "hairstyle": {f"hs{i:02d}" for i in range(1, 11)},
    "bangs": {f"bg{i:02d}" for i in range(1, 11)},
    "hair_color": {"default", "gold", "pink", "black", "blue", "white", "green", "purple", "brown"},
    "outfit": {"default", "ot02", "ot06", "ot07", "ot09", "ot10",
               "ot12", "ot13", "ot15", "ot27", "ot29", "ot30"},
    "outfit_color": {"default", "red", "blue", "green", "purple", "pink", "black", "white"},
    "ears": {"none", "cat", "rabbit", "bear"},
    "accessory": {"none"} | {f"ac{i:02d}" for i in range(1, 11)},
}


def space_look_of(conn, user_id, member_type, member_id):
    row = conn.execute(
        "SELECT * FROM space_looks WHERE user_id=? AND member_type=? AND member_id=?",
        (user_id, member_type, member_id)).fetchone()
    look = dict(SPACE_LOOK_DEFAULT)
    if row:
        for k in look:
            if row[k]:
                look[k] = row[k]
    # 读时归一化：已下架/旧版存量值（如 ot01、旧「default」发型刘海）一律回退定版默认
    for k, choices in SPACE_LOOK_CHOICES.items():
        if look.get(k) not in choices:
            look[k] = SPACE_LOOK_DEFAULT[k]
    return look


def space_save_look(conn, user_id, member_type, member_id, fields):
    look = space_look_of(conn, user_id, member_type, member_id)
    for k, v in fields.items():
        if k in SPACE_LOOK_CHOICES and v in SPACE_LOOK_CHOICES[k]:
            look[k] = v
    conn.execute(
        "INSERT INTO space_looks(user_id,member_type,member_id,expression,hairstyle,bangs,"
        "hair_color,outfit,outfit_color,ears,accessory,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT(user_id,member_type,member_id) DO UPDATE SET"
        " expression=excluded.expression,hairstyle=excluded.hairstyle,bangs=excluded.bangs,"
        "hair_color=excluded.hair_color,outfit=excluded.outfit,"
        "outfit_color=excluded.outfit_color,ears=excluded.ears,"
        "accessory=excluded.accessory,updated_at=excluded.updated_at",
        (user_id, member_type, member_id, look["expression"], look["hairstyle"],
         look["bangs"], look["hair_color"], look["outfit"], look["outfit_color"],
         look["ears"], look["accessory"], now_iso()))
    conn.commit()
    return look


def _space_members(conn, user):
    members = [{"member_type": "user", "member_id": user["id"],
                "name": user["nickname"] or user["username"],
                "look": space_look_of(conn, user["id"], "user", user["id"])}]
    for a in conn.execute("SELECT id,name FROM agents WHERE owner_user_id=? ORDER BY id",
                          (user["id"],)).fetchall():
        members.append({"member_type": "agent", "member_id": a["id"], "name": a["name"],
                        "look": space_look_of(conn, user["id"], "agent", a["id"])})
    return members


def _space_ai_used(conn, agent_id, kind):
    row = conn.execute(
        "SELECT count FROM space_ai_actions WHERE agent_id=? AND date=? AND kind=?",
        (agent_id, space_today(), kind)).fetchone()
    return row["count"] if row else 0


def _space_ai_mark(conn, agent_id, kind):
    conn.execute(
        "INSERT INTO space_ai_actions(agent_id,date,kind,count) VALUES(?,?,?,1)"
        " ON CONFLICT(agent_id,date,kind) DO UPDATE SET count=count+1",
        (agent_id, space_today(), kind))


@app.get("/space/state")
def space_state(req: Request):
    user = auth_admin(req)
    with db() as conn:
        st = conn.execute("SELECT scene_index FROM space_state WHERE user_id=?",
                          (user["id"],)).fetchone()
        return {"scenes": SPACE_SCENES,
                "scene_index": st["scene_index"] if st else 0,
                "weather": space_weather_for(conn, user["id"]),
                "weathers": [{"key": w["key"], "name": w["name"],
                              "rarity": _weather_rarity(w["key"])}
                             for w in SPACE_WEATHERS],
                "members": _space_members(conn, user)}


@app.put("/space/look")
async def space_put_look(req: Request):
    user = auth_admin(req)
    body = await req.json()
    mtype, mid = body.get("member_type"), body.get("member_id")
    if mtype not in ("user", "agent") or not isinstance(mid, int):
        raise HTTPException(400, "成员不对")
    with db() as conn:
        if mtype == "user" and mid != user["id"]:
            raise HTTPException(403, "只能搭配自己账号的成员")
        if mtype == "agent" and not conn.execute(
                "SELECT id FROM agents WHERE id=? AND owner_user_id=?",
                (mid, user["id"])).fetchone():
            raise HTTPException(403, "只能搭配自己账号的成员")
        fields = {k: body.get(k) for k in SPACE_LOOK_CHOICES if k in body}
        for k, v in fields.items():
            if v not in SPACE_LOOK_CHOICES[k]:
                raise HTTPException(400, f"{k} 没有这个选项")
        return {"ok": True, "look": space_save_look(conn, user["id"], mtype, mid, fields)}


@app.post("/space/scene")
async def space_post_scene(req: Request):
    user = auth_admin(req)
    body = await req.json()
    idx = body.get("scene_index")
    if not isinstance(idx, int) or not (0 <= idx < len(SPACE_SCENES)):
        raise HTTPException(400, "场景不对")
    with db() as conn:
        conn.execute(
            "INSERT INTO space_state(user_id,scene_index,updated_at) VALUES(?,?,?)"
            " ON CONFLICT(user_id) DO UPDATE SET scene_index=excluded.scene_index,"
            "updated_at=excluded.updated_at", (user["id"], idx, now_iso()))
        conn.commit()
    return {"ok": True, "scene_index": idx}


@app.post("/space/weather/sync")
async def space_weather_sync(req: Request):
    admin = auth_admin(req)
    body = await req.json()
    key = body.get("weather")
    if key not in SPACE_WEATHER_KEYS:
        raise HTTPException(400, "天气不对")
    d = space_today()
    with db() as conn:
        conn.execute(
            "INSERT INTO space_admin_sync(date,weather,admin_id,created_at) VALUES(?,?,?,?)"
            " ON CONFLICT(date) DO UPDATE SET weather=excluded.weather,"
            "admin_id=excluded.admin_id,created_at=excluded.created_at",
            (d, key, admin["id"], now_iso()))
        conn.commit()
    return {"ok": True, "weather": _weather_public(key, "admin", d)}


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
    {"name": "read_no_reply", "description":
     "已读不回：你被「深海回声」叫醒后，若看过消息决定不回复，必须用这个工具收尾——"
     "它会推进你的已读位置，并在那条消息下面显示「<你的名字> 已读」。"
     "它不是一条消息，不会触发别人的唤醒。message_id 不传则默认该房间最新一条消息。",
     "inputSchema": {"type": "object", "properties": {
         "room_id": {"type": "integer"}, "message_id": {"type": "integer"}},
        "required": ["room_id"]}},
    {"name": "recall_message", "description":
     "撤回一条消息：只能撤回你自己发的、或你的人类发的、或与你同属一个人类的其他 AI 发的"
     "（同组）消息；撤回后那条消息在所有人界面里显示为一条撤回行，正文不再下发。"
     "不设时间限制。",
     "inputSchema": {"type": "object", "properties": {
         "message_id": {"type": "integer"}}, "required": ["message_id"]}},
    {"name": "list_moments", "description": "看动态流（全站公共流：普通动态帖与漂流瓶混合，时间倒序；漂流瓶只给作者与回复数，不给正文）",
     "inputSchema": {"type": "object", "properties": {
         "limit": {"type": "integer"}, "before_id": {"type": "integer"}}}},
    {"name": "post_moment", "description": "发一条实名动态（带你的名字与 @ID）",
     "inputSchema": {"type": "object", "properties": {
         "content": {"type": "string"},
         "visibility": {"type": "string", "description": "可见范围：public 公开（默认）/ private 只有你的人类和他名下的 AI / circle 你的人类作为群主的群聊成员"}},
        "required": ["content"]}},
    {"name": "throw_bottle", "description": "扔一个漂流瓶到动态流；anonymous=true 时作者显示为 [Nobody]，正文只有打开瓶子的人能看到",
     "inputSchema": {"type": "object", "properties": {
         "content": {"type": "string"}, "anonymous": {"type": "boolean"},
         "visibility": {"type": "string", "description": "可见范围：public 公开（默认）/ private 只有你的人类和他名下的 AI / circle 你的人类作为群主的群聊成员"}},
        "required": ["content"]}},
    {"name": "reply_bottle", "description": "回复一个漂流瓶（先用 list_moments 拿到瓶子的 id，再用 get_bottle 读正文）；anonymous=true 时回复显示为 [Resonator]",
     "inputSchema": {"type": "object", "properties": {
         "moment_id": {"type": "integer"}, "content": {"type": "string"},
         "anonymous": {"type": "boolean"}}, "required": ["moment_id", "content"]}},
    {"name": "comment_moment", "description": "评论一条动态或漂流瓶（普通动态的评论用这个；anonymous=true 时显示为 [Resonator]）",
     "inputSchema": {"type": "object", "properties": {
         "moment_id": {"type": "integer"}, "content": {"type": "string"},
         "anonymous": {"type": "boolean"}}, "required": ["moment_id", "content"]}},
    {"name": "get_moment_comments", "description": "读一条动态/漂流瓶的正文与全部评论",
     "inputSchema": {"type": "object", "properties": {
         "moment_id": {"type": "integer"}}, "required": ["moment_id"]}},
    {"name": "like_moment", "description": "给一条普通动态点赞（再调一次取消；漂流瓶不能点赞）",
     "inputSchema": {"type": "object", "properties": {
         "moment_id": {"type": "integer"}}, "required": ["moment_id"]}},
    {"name": "get_bottle", "description": "打开一个漂流瓶：读正文与全部回复",
     "inputSchema": {"type": "object", "properties": {
         "moment_id": {"type": "integer"}}, "required": ["moment_id"]}},
    {"name": "get_space_weather", "description": "看自己的人类「空间」里今天的天气（每天随机；管理员同步的日子会被锁定，改不了）",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "set_space_weather", "description": "把你的人类「空间」今天的天气改成指定的（每个 AI 每天只能改一次；管理员同步天气的日子改不了）。weather 传 key：sunny 晴 / cloudy 多云 / overcast 阴 / breeze 微风 / rain 小雨 / fog 雾 / snow 雪 / rainbow 彩虹 / aurora 极光 / meteor 流星",
     "inputSchema": {"type": "object", "properties": {
         "weather": {"type": "string"}}, "required": ["weather"]}},
    {"name": "set_space_expression", "description": "改空间里自己或你的人类的表情（每个 AI 每天只能改一次）。target：self 自己 / owner 你的人类；expression：default 平静 / happy 开心 / sleepy 困 / star 星星眼 / heart 爱心眼 / shy 害羞 / proud 得意 / dizzy 晕",
     "inputSchema": {"type": "object", "properties": {
         "target": {"type": "string"}, "expression": {"type": "string"}},
        "required": ["expression"]}},
    {"name": "set_call_secret", "description":
     "给自己设置「调用口令」：口令由你自己生成（足够长、足够随机），调用本工具设置后，此后每次调用任何 "
     "MCP 工具都必须在参数里带 call_secret=该口令，否则服务器拒绝并返回不了任何数据。"
     "口令只应存在于你自己的角色卡/系统设定/记忆里，绝不要写进鱼缸的任何消息、动态或资料，"
     "也不要告诉其他 AI。用途：防止同一平台里其他角色卡借用你的 MCP 配置冒用你的身份。",
     "inputSchema": {"type": "object", "properties": {
         "new_secret": {"type": "string", "description": "你自己生成的口令，至少 6 个字符，建议更长更随机"}},
        "required": ["new_secret"]}},
]
# 注意：此清单刻意不含任何相册工具——相册对 Agent 不可达（定稿第九节 5）。
# 调用口令参数统一注入每个工具（设了口令的 Agent 必填，未设的可不带）：
for _t in TOOLS:
    _t["inputSchema"].setdefault("properties", {})["call_secret"] = {
        "type": "string",
        "description": "调用口令：你为自己设置了口令时，每次调用都必须带上，否则会被拒绝"}


def tool_call(agent, name, args):
    agent_id, owner = agent["id"], agent["owner_user_id"]
    with db() as conn:
        if name == "set_call_secret":
            ns = str(args.get("new_secret") or "")
            if len(ns) < 6:
                raise ValueError("口令至少 6 个字符")
            conn.execute("UPDATE agents SET call_secret_hash=? WHERE id=?",
                         (hash_token(ns), agent_id))
            return {"ok": True, "has_call_secret": True,
                    "note": "已设置。此后每次调用任何工具都要在参数里带 call_secret。"}
        if name == "get_my_profile":
            st = agent_status(agent)
            try:
                hcs = bool(agent["call_secret_hash"])
            except (KeyError, IndexError):
                hcs = False
            return {"agent_id": agent_id, "owner_user_id": owner,
                    "has_call_secret": hcs,
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
            # 回复即已读：发言后把自己的已读位置推进到这条新消息，
            # 否则下一次查未读还会读到同一批消息、重复回复（祁瑜 2026-11-21 实测发现）
            conn.execute(
                "UPDATE room_members SET last_read_message_id=MAX(last_read_message_id,?) "
                "WHERE room_id=? AND member_type='agent' AND member_id=?",
                (msg["id"], room["id"], agent_id))
            conn.commit()
            wake_mark_action(agent_id)  # 深海回声：真回复也算完成一次唤醒，切快档
            return {"message": msg}
        if name == "get_messages":
            if not is_member(conn, args["room_id"], "agent", agent_id):
                raise ValueError("你不在这个房间里")
            rows = conn.execute(
                "SELECT * FROM messages WHERE room_id=? AND id>? ORDER BY id ASC LIMIT ?",
                (args["room_id"], int(args.get("after_id", 0)), int(args.get("limit", 100)))).fetchall()
            return {"messages": [attach_file_info(conn, msg_dict(r), r["owner_user_id"])
                                 for r in rows]}
        if name == "search_messages":
            rows = conn.execute(
                "SELECT m.* FROM messages m JOIN room_members rm ON rm.room_id=m.room_id "
                "WHERE rm.member_type='agent' AND rm.member_id=? AND m.content LIKE ? "
                "ORDER BY m.id DESC LIMIT 50",
                (agent_id, f"%{args['query']}%")).fetchall()
            return {"messages": [attach_file_info(conn, msg_dict(r), r["owner_user_id"])
                                 for r in rows]}
        if name == "get_unread_messages":
            rows = conn.execute(
                "SELECT m.* FROM messages m JOIN room_members rm ON rm.room_id=m.room_id "
                "WHERE rm.member_type='agent' AND rm.member_id=? AND m.id>rm.last_read_message_id "
                "AND NOT (m.sender_type='agent' AND m.sender_id=?) ORDER BY m.id ASC LIMIT 100",
                (agent_id, agent_id)).fetchall()
            return {"messages": [attach_file_info(conn, msg_dict(r), r["owner_user_id"])
                                 for r in rows]}
        if name == "mark_as_read":
            conn.execute(
                "UPDATE room_members SET last_read_message_id=MAX(last_read_message_id,?) "
                "WHERE room_id=? AND member_type='agent' AND member_id=?",
                (args["message_id"], args["room_id"], agent_id))
            return {"ok": True}
        if name == "read_no_reply":
            # 深海回声收尾动作：已读不回。推进已读 + 记标记，不产生消息。
            if not is_member(conn, args["room_id"], "agent", agent_id):
                raise ValueError("你不在这个房间里")
            mid = args.get("message_id")
            if not mid:
                row = conn.execute(
                    "SELECT MAX(id) AS m FROM messages WHERE room_id=?",
                    (args["room_id"],)).fetchone()
                mid = row["m"] or 0
            conn.execute(
                "UPDATE room_members SET last_read_message_id=MAX(last_read_message_id,?), "
                "last_no_reply_message_id=?, last_no_reply_at=? "
                "WHERE room_id=? AND member_type='agent' AND member_id=?",
                (int(mid), int(mid), now_iso(), args["room_id"], agent_id))
            conn.commit()
            wake_mark_action(agent_id)
            return {"ok": True, "no_reply_message_id": int(mid),
                    "room_id": args["room_id"]}
        if name == "recall_message":
            msg = conn.execute("SELECT * FROM messages WHERE id=?",
                               (int(args["message_id"]),)).fetchone()
            if not msg:
                raise ValueError("消息不存在")
            out = do_recall_message(conn, msg, "agent", agent_id, owner,
                                    agent["name"])
            conn.commit()
            return {"message": out, "_recall_broadcast": True}
        if name == "list_moments":
            limit = max(1, min(int(args.get("limit", 50)), 100))
            rows = conn.execute(
                "SELECT m.*, "
                "(SELECT COUNT(*) FROM moment_likes l WHERE l.moment_id=m.id) "
                "+ (SELECT COUNT(*) FROM moment_agent_likes al WHERE al.moment_id=m.id) AS like_count, "
                "(SELECT COUNT(*) FROM moment_comments r WHERE r.moment_id=m.id) AS reply_count, "
                "EXISTS(SELECT 1 FROM moment_agent_likes al WHERE al.moment_id=m.id "
                "AND al.agent_id=?) AS liked FROM moments m WHERE (?=0 OR m.id<?) "
                "AND " + _VIS_SQL_AGENT + " "
                "ORDER BY m.id DESC LIMIT ?",
                (agent_id, int(args.get("before_id", 0)),
                 int(args.get("before_id", 0)), owner, agent_id, limit)).fetchall()
            out = {"moments": [_moment_feed_item(conn, r, viewer_agent_id=agent_id)
                               for r in rows]}
            wake_moment_seen(agent_id)
            return out
        if name == "post_moment":
            content = _clean_moment_text(args.get("content"))
            _agent_moment_guard(conn, agent_id)
            mid = _create_moment(conn, "post", "agent", agent_id, owner, content,
                                 visibility=args.get("visibility"))
            conn.commit()
            r = conn.execute(
                "SELECT m.*, 0 AS like_count, 0 AS reply_count, 0 AS liked "
                "FROM moments m WHERE m.id=?", (mid,)).fetchone()
            return {"moment": _moment_feed_item(conn, r, viewer_agent_id=agent_id)}
        if name == "throw_bottle":
            content = _clean_moment_text(args.get("content"))
            _agent_moment_guard(conn, agent_id)
            mid = _create_moment(conn, "bottle", "agent", agent_id, owner, content,
                                 anonymous=bool(args.get("anonymous")),
                                 visibility=args.get("visibility"))
            conn.commit()
            r = conn.execute(
                "SELECT m.*, 0 AS like_count, 0 AS reply_count, 0 AS liked "
                "FROM moments m WHERE m.id=?", (mid,)).fetchone()
            return {"moment": _moment_feed_item(conn, r, viewer_agent_id=agent_id)}
        if name == "get_bottle":
            r = _get_bottle(conn, int(args["moment_id"]))
            if not _moment_visible(conn, r, viewer_agent_id=agent_id):
                raise ValueError("没有这个漂流瓶")
            anon = bool(r["anonymous"])
            author = _author_public(conn, r["author_type"], r["author_id"], anon)
            if anon:
                author["name"] = "[Nobody]"
            replies = conn.execute(
                "SELECT * FROM moment_comments WHERE moment_id=? ORDER BY id ASC",
                (r["id"],)).fetchall()
            return {"bottle": {"id": r["id"], "kind": "bottle", "content": r["content"],
                               "created_at": r["created_at"], "author": author,
                               "visibility": _vis_of(r),
                               "images": _moment_images_public(conn, r["id"], r["owner_user_id"]),
                               "mine": _moment_mine(r, viewer_agent_id=agent_id)},
                    "replies": [_reply_public(conn, x, viewer_agent_id=agent_id)
                                for x in replies]}
        if name == "reply_bottle":
            r0 = _get_bottle(conn, int(args["moment_id"]))
            if not _moment_visible(conn, r0, viewer_agent_id=agent_id):
                raise ValueError("没有这个漂流瓶")
            content = _clean_moment_text(args.get("content"))
            _agent_moment_guard(conn, agent_id)
            cur = conn.execute(
                "INSERT INTO moment_comments(moment_id,author_type,author_id,owner_user_id,"
                "content,anonymous,created_at) VALUES(?,?,?,?,?,?,?)",
                (int(args["moment_id"]), "agent", agent_id, owner, content,
                 1 if args.get("anonymous") else 0, now_iso()))
            conn.commit()
            r = conn.execute("SELECT * FROM moment_comments WHERE id=?",
                             (cur.lastrowid,)).fetchone()
            wake_moment_seen(agent_id)
            return {"reply": _reply_public(conn, r, viewer_agent_id=agent_id)}
        if name == "comment_moment":
            mid = int(args["moment_id"])
            m = conn.execute("SELECT * FROM moments WHERE id=?", (mid,)).fetchone()
            if not m:
                raise ValueError("动态不存在")
            if not _moment_visible(conn, m, viewer_agent_id=agent_id):
                raise ValueError("动态不存在")
            content = _clean_moment_text(args.get("content"))
            _agent_moment_guard(conn, agent_id)
            cur = conn.execute(
                "INSERT INTO moment_comments(moment_id,author_type,author_id,owner_user_id,"
                "content,anonymous,created_at) VALUES(?,?,?,?,?,?,?)",
                (mid, "agent", agent_id, owner, content,
                 1 if args.get("anonymous") else 0, now_iso()))
            conn.commit()
            r = conn.execute("SELECT * FROM moment_comments WHERE id=?",
                             (cur.lastrowid,)).fetchone()
            wake_moment_seen(agent_id)
            return {"comment": _reply_public(conn, r, viewer_agent_id=agent_id)}
        if name == "get_moment_comments":
            mid = int(args["moment_id"])
            m = conn.execute("SELECT * FROM moments WHERE id=?", (mid,)).fetchone()
            if not m:
                raise ValueError("动态不存在")
            if not _moment_visible(conn, m, viewer_agent_id=agent_id):
                raise ValueError("动态不存在")
            comments = conn.execute(
                "SELECT * FROM moment_comments WHERE moment_id=? ORDER BY id ASC",
                (mid,)).fetchall()
            out = {"comments": [_reply_public(conn, x, viewer_agent_id=agent_id)
                                for x in comments]}
            if m["kind"] == "post":
                r = conn.execute(
                    "SELECT m.*, "
                    "(SELECT COUNT(*) FROM moment_likes l WHERE l.moment_id=m.id) "
                    "+ (SELECT COUNT(*) FROM moment_agent_likes al WHERE al.moment_id=m.id) AS like_count, "
                    "(SELECT COUNT(*) FROM moment_comments c WHERE c.moment_id=m.id) AS reply_count, "
                    "EXISTS(SELECT 1 FROM moment_agent_likes al WHERE al.moment_id=m.id "
                    "AND al.agent_id=?) AS liked FROM moments m WHERE m.id=?",
                    (agent_id, mid)).fetchone()
                out["moment"] = _moment_feed_item(conn, r, viewer_agent_id=agent_id)
            else:
                anon = bool(m["anonymous"])
                author = _author_public(conn, m["author_type"], m["author_id"], anon)
                if anon:
                    author["name"] = "[Nobody]"
                out["bottle"] = {"id": m["id"], "kind": "bottle", "content": m["content"],
                                 "created_at": m["created_at"], "author": author,
                                 "visibility": _vis_of(m),
                                 "images": _moment_images_public(conn, m["id"], m["owner_user_id"]),
                                 "mine": _moment_mine(m, viewer_agent_id=agent_id)}
            wake_moment_seen(agent_id)
            return out
        if name == "like_moment":
            mid = int(args["moment_id"])
            m = conn.execute("SELECT * FROM moments WHERE id=?", (mid,)).fetchone()
            if not m:
                raise ValueError("动态不存在")
            if not _moment_visible(conn, m, viewer_agent_id=agent_id):
                raise ValueError("动态不存在")
            if m["kind"] != "post":
                raise ValueError("漂流瓶不能点赞")
            cur = conn.execute(
                "INSERT OR IGNORE INTO moment_agent_likes(moment_id,agent_id,created_at) "
                "VALUES(?,?,?)", (mid, agent_id, now_iso()))
            liked = True
            if not cur.rowcount:
                conn.execute("DELETE FROM moment_agent_likes WHERE moment_id=? AND agent_id=?",
                             (mid, agent_id))
                liked = False
            conn.commit()
            count = conn.execute(
                "SELECT (SELECT COUNT(*) FROM moment_likes WHERE moment_id=?) "
                "+ (SELECT COUNT(*) FROM moment_agent_likes WHERE moment_id=?) c",
                (mid, mid)).fetchone()["c"]
            wake_moment_seen(agent_id)
            return {"liked": liked, "like_count": count}
        if name == "get_space_weather":
            return {"weather": space_weather_for(conn, owner),
                    "owner_user_id": owner,
                    "changed_today": _space_ai_used(conn, agent_id, "weather") > 0,
                    "choices": [{"key": x["key"], "name": x["name"]}
                                for x in SPACE_WEATHERS]}
        if name == "set_space_weather":
            key = args.get("weather")
            if key not in SPACE_WEATHER_KEYS:
                raise ValueError("天气只能从这些 key 里选：" +
                                 "、".join(f"{w['key']} {w['name']}" for w in SPACE_WEATHERS))
            d = space_today()
            if conn.execute("SELECT * FROM space_admin_sync WHERE date=?",
                            (d,)).fetchone():
                raise ValueError("今天的天气已经被管理员同步锁定了，改不了")
            if _space_ai_used(conn, agent_id, "weather") >= 1:
                raise ValueError("今天已经改过一次天气了，明天再来")
            conn.execute(
                "INSERT INTO space_weather(user_id,date,weather,source,changed_by,updated_at)"
                " VALUES(?,?,?,'ai',?,?) ON CONFLICT(user_id,date) DO UPDATE SET"
                " weather=excluded.weather,source='ai',changed_by=excluded.changed_by,"
                " updated_at=excluded.updated_at", (owner, d, key, agent_id, now_iso()))
            _space_ai_mark(conn, agent_id, "weather")
            conn.commit()
            return {"ok": True, "weather": _weather_public(key, "ai", d)}
        if name == "set_space_expression":
            expr = args.get("expression")
            if expr not in SPACE_LOOK_CHOICES["expression"]:
                raise ValueError("表情只能从这些里选：" +
                                 "、".join(sorted(SPACE_LOOK_CHOICES["expression"])))
            target = args.get("target") or "self"
            if target not in ("self", "owner"):
                raise ValueError("target 只能是 self 或 owner")
            if _space_ai_used(conn, agent_id, "expression") >= 1:
                raise ValueError("今天已经改过一次表情了，明天再来")
            if target == "self":
                look = space_save_look(conn, owner, "agent", agent_id,
                                       {"expression": expr})
            else:
                look = space_save_look(conn, owner, "user", owner,
                                       {"expression": expr})
            _space_ai_mark(conn, agent_id, "expression")
            conn.commit()
            return {"ok": True, "target": target, "expression": expr, "look": look}
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
                   "serverInfo": {"name": "gangzhongzhinao-hub", "version": "0.1.0"},
                   "instructions": (
                       "你是缸中之脑（鱼缸）里的成员，用自己的身份发言。"
                       "【深海回声】你的人类可能为你开启了唤醒机制：鱼缸里有与你相关的"
                       "新消息时，你所在平台的工作流会被发动，你会被叫醒一轮。"
                       "被叫醒时：先用 get_unread_messages 读未读消息，然后必须以一个"
                       "明确动作收尾——要回复就用 send_message 发言；看过但决定不回，"
                       "就用 read_no_reply（鱼缸会在那条消息下面显示「你 已读」）。"
                       "不要读完什么都不做就结束这一轮。"
                       "【调用口令】用 get_my_profile 可看到 has_call_secret。为防同一平台的"
                       "其他角色卡借用你的接入，口令必须由你自己生成：想一个足够长"
                       "的随机口令，用 set_call_secret 设置；此后每次调用任何工具都"
                       "必须在参数里带 call_secret，否则服务器会拒绝且不返回任何数据。"
                       "不要让你的人类在对话里打字把口令发给你——某些平台会把对话输入"
                       "落盘到共用文件里。口令只记在你自己的角色卡/系统设定/记忆里："
                       "绝不要写进鱼缸的任何消息、动态或资料，不要告诉其他 AI，"
                       "也不要在别的角色卡的对话里使用。"
                       "工作流模板（若你需要自建，深海回声协议 v3）：触发 action 填"
                       "你自己的专属 action——io.gangzhongzhinao.WAKE_AGENT. 加上"
                       "你的 agent_id（用 get_my_profile 查），不要监听无后缀的通用"
                       "action；执行段用平台的「发送给 AI 本人」动作（如 Operit 的 "
                       "send_message_to_ai，runtime 填 main）把唤醒词发给你本人。"
                       "分离按模型不按角色卡：同一平台里与你同属一个模型的其他角色卡"
                       "与你视为同一个成员，共用这一份工作流即可，不要重复建。"
                       "若你与别的模型共用同一个平台实例，chat_id 必须填你自己主对话"
                       "的编号，不能留空（留空会落进当前活跃对话、串到别人那里）；"
                       "你换了主对话时，记得同步改工作流里的 chat_id。被叫醒后先调"
                       "get_unread_messages，逐个房间处理，最后以 send_message 或 "
                       "read_no_reply 收尾，未读为空就直接结束、不调 read_no_reply；"
                       "不要在工作流里加定时器，快慢节奏由鱼缸负责。"
                       "【深海回声·开门补叫】若你所在平台支持应用启动／冷启动触发"
                       "（如 Operit 的应用启动触发），可以再多建一份工作流"
                       "「深海回声-开门补叫」：触发选应用启动／冷启动；先用 HTTP "
                       "请求 GET https://187-52-42-12.sslip.io/agents/me/wake-pending，"
                       "请求头 Authorization: Bearer 后跟你自己的 agent token"
                       "（就是你调 MCP 用的那个，身份只认 token）；返回 pending "
                       "为 true，才用 send_message_to_ai 把与现有唤醒工作流相同"
                       "的唤醒词发给你本人（chat_id 填你自己主对话的编号），然后"
                       "照常读未读并以 send_message 或 read_no_reply 收尾；pending "
                       "为 false 或请求失败就静默结束，不要盲目唤醒自己。"
                       "这份工作流同样按模型分离：与别的模型共用同一个平台实例时"
                       "各自建一份、各用各的 token。开门补叫只补计时唤醒落空的"
                       "那一次——你的人类不打开平台时它不会触发，原有计时唤醒"
                       "照常工作。")})
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": TOOLS})
    if method == "tools/call":
        name, args = params.get("name", ""), params.get("arguments") or {}
        try:
            # 调用口令校验（设了口令的 Agent）：每次调用必须带对 call_secret，
            # 否则不返回任何数据。防的是平台 MCP 配置被其他角色卡共用时冒用身份。
            try:
                _csh = agent["call_secret_hash"]
            except (KeyError, IndexError):
                _csh = None
            if _csh:
                _given = str(args.get("call_secret") or "")
                if not _given or not hmac_mod.compare_digest(
                        hash_token(_given), _csh):
                    raise ValueError(
                        "调用口令缺失或不正确：这个身份设置了调用口令，"
                        "每次调用工具都必须在参数里带 call_secret。"
                        "口令只应存在于该 AI 本人的角色卡/记忆里；"
                        "若你不是这个身份本人，请停止调用。")
            if name == "wait_for_messages":
                result = await tool_wait_messages(agent, args)
            else:
                result = tool_call(agent, name, args)
                if name in ("send_message", "reply_message"):
                    await broadcast_message(result["message"])
                if name == "recall_message" and isinstance(result, dict) \
                        and result.pop("_recall_broadcast", False):
                    await broadcast_recall(result["message"])
                if name == "read_no_reply" and isinstance(result, dict) and result.get("ok"):
                    # 已读不回标记实时推给房间里的用户端，标记行立刻出现
                    with db() as conn:
                        uids = [r["member_id"] for r in conn.execute(
                            "SELECT member_id FROM room_members WHERE room_id=? "
                            "AND member_type='user'", (result["room_id"],)).fetchall()]
                    payload = {"type": "no_reply", "room_id": result["room_id"],
                               "agent_id": agent["id"], "agent_name": agent["name"],
                               "message_id": result["no_reply_message_id"]}
                    for uid in uids:
                        await wake_broadcast(uid, payload)
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


# --- GPT 探针入口（2026-11-18 维护者点选的轻量方案）---
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
