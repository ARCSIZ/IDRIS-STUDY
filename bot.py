import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import struct
import threading
import time
import zlib
from collections import deque
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import requests


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("DATA_DIR", str(BASE_DIR)))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.getenv("BOT_DB_PATH", DATA_DIR / "idris_study.sqlite3"))
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
BOT_USERNAME = os.getenv("BOT_USERNAME", "").lstrip("@").strip()
APP_URL = os.getenv("APP_URL", "https://IdrisStudy.bothost.tech").rstrip("/")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "").strip()
TELEGRAM_MODE = os.getenv("TELEGRAM_MODE", "polling").strip().lower()
PORT = int(os.getenv("PORT", "5000"))
RUN_WEB = os.getenv("RUN_WEB", "1") == "1"
SESSION_TTL = 30 * 24 * 60 * 60
QUIZ_TTL = 4 * 60 * 60
LINK_TTL = 20 * 60
TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"
# Преподаватели обладают теми же правами, что и сотрудники IDRIS.
AUTHOR_ROLES = {"teacher", "staff", "dev"}

if not WEBHOOK_SECRET and BOT_TOKEN:
    WEBHOOK_SECRET = hashlib.sha256(BOT_TOKEN.encode()).hexdigest()[:48]

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("idris-study")


# ---------------- realtime ----------------

EVENT_COND = threading.Condition()
EVENTS = deque(maxlen=200)
EVENT_ID = 0


def emit_event(kind="sync", payload=None):
    global EVENT_ID
    with EVENT_COND:
        EVENT_ID += 1
        EVENTS.append((EVENT_ID, kind, payload or {}))
        EVENT_COND.notify_all()


# ---------------- database ----------------

def db_connect():
    db = sqlite3.connect(DB_PATH, timeout=20)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 240_000)
    return f"pbkdf2_sha256$240000${salt.hex()}${digest.hex()}"


def verify_password(password, encoded):
    try:
        name, rounds, salt, expected = encoded.split("$", 3)
        if name != "pbkdf2_sha256":
            return False
        got = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt), int(rounds)
        ).hex()
        return hmac.compare_digest(got, expected)
    except Exception:
        return False


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('student','teacher','staff','dev')),
    group_name TEXT NOT NULL DEFAULT '',
    employee_id TEXT COLLATE NOCASE,
    initials TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    accepted_terms INTEGER NOT NULL DEFAULT 0,
    subject TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS employee_ids (
    code TEXT PRIMARY KEY COLLATE NOCASE,
    active INTEGER NOT NULL DEFAULT 1,
    used_by INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    user_agent TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS tests (
    id TEXT PRIMARY KEY,
    author_id INTEGER NOT NULL REFERENCES users(id),
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    content_json TEXT NOT NULL,
    points INTEGER NOT NULL DEFAULT 0,
    question_count INTEGER NOT NULL DEFAULT 0,
    access_mode TEXT NOT NULL DEFAULT 'open',
    access_hash TEXT NOT NULL DEFAULT '',
    qr_code TEXT NOT NULL UNIQUE,
    published INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS quiz_sessions (
    token_hash TEXT PRIMARY KEY,
    test_id TEXT NOT NULL REFERENCES tests(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id TEXT NOT NULL REFERENCES tests(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    student_name TEXT NOT NULL,
    group_name TEXT NOT NULL,
    score INTEGER NOT NULL,
    total INTEGER NOT NULL,
    grade INTEGER NOT NULL,
    percent INTEGER NOT NULL,
    review_json TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_links (
    code TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL,
    chat_id INTEGER,
    telegram_user_id INTEGER,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS telegram_links (
    account_id TEXT PRIMARY KEY,
    chat_id INTEGER NOT NULL UNIQUE,
    phone TEXT NOT NULL,
    telegram_user_id INTEGER NOT NULL,
    telegram_username TEXT NOT NULL DEFAULT '',
    linked_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT 'info',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_reads (
    notification_id INTEGER NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY(notification_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_attempt_test ON attempts(test_id, created_at);
CREATE INDEX IF NOT EXISTS idx_session_expiry ON sessions(expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_employee ON users(employee_id) WHERE employee_id IS NOT NULL;
"""


def table_exists(db, name):
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE name=? AND type='table'", (name,)
    ).fetchone() is not None


def full_fk_rebuild(_ignored=None):
    """Восстанавливает схему после старых RENAME-миграций.
    Работает на отдельном соединении: PRAGMA foreign_keys не действует внутри транзакции."""
    db = sqlite3.connect(DB_PATH, timeout=30)
    db.row_factory = sqlite3.Row
    db.isolation_level = None          # автокоммит, чтобы PRAGMA применилась
    db.execute("PRAGMA foreign_keys=OFF")
    preserved = {}
    for table in ("users", "users_old", "tests", "attempts", "employee_ids",
                  "notifications", "settings", "telegram_links", "pending_links"):
        preserved[table] = (
            [dict(r) for r in db.execute(f"SELECT * FROM {table}")]
            if table_exists(db, table) else []
        )
    for table in ("sessions", "quiz_sessions", "notification_reads", "notifications",
                  "attempts", "tests", "employee_ids", "users_old", "users"):
        db.execute(f"DROP TABLE IF EXISTS {table}")
    db.executescript(SCHEMA)

    merged_users = {r["id"]: r for r in preserved["users_old"] + preserved["users"]}
    used_eid = set()
    for r in merged_users.values():
        eid = r.get("employee_id") or None
        if eid and eid in used_eid:
            eid = None
        if eid:
            used_eid.add(eid)
        db.execute(
            "INSERT INTO users(id,name,password_hash,role,group_name,subject,employee_id,"
            "initials,title,created_at,must_change_password,accepted_terms) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (r["id"], r["name"], r["password_hash"], r.get("role", "student"),
             r.get("group_name", "") or "", r.get("subject", "") or "", eid,
             r.get("initials", "") or "", r.get("title", "") or "",
             r.get("created_at", 0), r.get("must_change_password", 0),
             r.get("accepted_terms", 0)),
        )
    for r in preserved["employee_ids"]:
        db.execute("INSERT OR IGNORE INTO employee_ids(code,active,used_by) VALUES(?,?,?)",
                   (r["code"], r.get("active", 1), r.get("used_by")))
    test_cols = ("id", "author_id", "title", "description", "content_json", "points",
                 "question_count", "access_mode", "access_hash", "qr_code", "published",
                 "created_at", "updated_at")
    for r in preserved["tests"]:
        db.execute(f"INSERT INTO tests({','.join(test_cols)}) VALUES({','.join(['?'] * len(test_cols))})",
                   tuple(r.get(c) for c in test_cols))
    attempt_cols = ("id", "test_id", "user_id", "student_name", "group_name", "score",
                    "total", "grade", "percent", "review_json", "created_at")
    for r in preserved["attempts"]:
        db.execute(f"INSERT INTO attempts({','.join(attempt_cols)}) VALUES({','.join(['?'] * len(attempt_cols))})",
                   tuple(r.get(c) for c in attempt_cols))
    for r in preserved["notifications"]:
        db.execute("INSERT INTO notifications(id,user_id,title,body,kind,created_at) VALUES(?,?,?,?,?,?)",
                   (r["id"], r.get("user_id"), r["title"], r.get("body", ""),
                    r.get("kind", "info"), r.get("created_at", 0)))
    db.execute("PRAGMA foreign_keys=ON")
    db.close()
    log.warning("Database schema rebuilt: foreign keys repaired, data preserved")


# ---------------- link preview banner ----------------

_FONT = {
    "A": "01110 10001 10001 11111 10001 10001 10001", "B": "11110 10001 10001 11110 10001 10001 11110",
    "C": "01110 10001 10000 10000 10000 10001 01110", "D": "11110 10001 10001 10001 10001 10001 11110",
    "E": "11111 10000 10000 11110 10000 10000 11111", "F": "11111 10000 10000 11110 10000 10000 10000",
    "G": "01110 10001 10000 10111 10001 10001 01111", "H": "10001 10001 10001 11111 10001 10001 10001",
    "I": "11111 00100 00100 00100 00100 00100 11111", "J": "00111 00010 00010 00010 00010 10010 01100",
    "K": "10001 10010 10100 11000 10100 10010 10001", "L": "10000 10000 10000 10000 10000 10000 11111",
    "M": "10001 11011 10101 10101 10001 10001 10001", "N": "10001 11001 10101 10011 10001 10001 10001",
    "O": "01110 10001 10001 10001 10001 10001 01110", "P": "11110 10001 10001 11110 10000 10000 10000",
    "Q": "01110 10001 10001 10001 10101 10010 01101", "R": "11110 10001 10001 11110 10100 10010 10001",
    "S": "01111 10000 10000 01110 00001 00001 11110", "T": "11111 00100 00100 00100 00100 00100 00100",
    "U": "10001 10001 10001 10001 10001 10001 01110", "V": "10001 10001 10001 10001 10001 01010 00100",
    "W": "10001 10001 10001 10101 10101 11011 10001", "X": "10001 10001 01010 00100 01010 10001 10001",
    "Y": "10001 10001 01010 00100 00100 00100 00100", "Z": "11111 00001 00010 00100 01000 10000 11111",
    "0": "01110 10001 10011 10101 11001 10001 01110", "1": "00100 01100 00100 00100 00100 00100 01110",
    "2": "01110 10001 00001 00010 00100 01000 11111", "3": "11111 00010 00100 00010 00001 10001 01110",
    "4": "00010 00110 01010 10010 11111 00010 00010", "5": "11111 10000 11110 00001 00001 10001 01110",
    "6": "00110 01000 10000 11110 10001 10001 01110", "7": "11111 00001 00010 00100 01000 01000 01000",
    "8": "01110 10001 10001 01110 10001 10001 01110", "9": "01110 10001 10001 01111 00001 00010 01100",
    "-": "00000 00000 00000 11111 00000 00000 00000", ".": "00000 00000 00000 00000 00000 01100 01100",
    "/": "00001 00010 00010 00100 01000 01000 10000", ":": "00000 01100 01100 00000 01100 01100 00000",
    " ": "00000 00000 00000 00000 00000 00000 00000",
}


def _draw_text(rows, text, x, y, scale, color, width, height):
    cursor = x
    for char in text.upper():
        glyph = _FONT.get(char)
        if glyph is None:
            cursor += 6 * scale
            continue
        for gy, line in enumerate(glyph.split()):
            for gx, bit in enumerate(line):
                if bit != "1":
                    continue
                for sy in range(scale):
                    py = y + gy * scale + sy
                    if not (0 <= py < height):
                        continue
                    row = rows[py]
                    for sx in range(scale):
                        px = cursor + gx * scale + sx
                        if 0 <= px < width:
                            row[px * 3:px * 3 + 3] = color
        cursor += 6 * scale
    return cursor


def _text_width(text, scale):
    return len(text) * 6 * scale


def render_banner():
    """Баннер 1200x630 для превью ссылок: PNG собирается вручную, без зависимостей."""
    width, height = 1200, 630
    rows = []
    for y in range(height):
        t = y / height
        row = bytearray()
        for x in range(width):
            u = x / width
            mix = (t * 0.68) + (u * 0.32)
            r = int(20 + 26 * (1 - mix))
            g = int(96 + 74 * (1 - mix))
            b = int(80 + 58 * (1 - mix))
            row += bytes((max(0, min(255, r)), max(0, min(255, g)), max(0, min(255, b))))
        rows.append(row)

    white = bytes((255, 255, 255))
    mint = bytes((150, 232, 208))
    soft = bytes((198, 228, 220))

    title, sub, host = "IDRIS STUDY", "ONLINE TESTING PLATFORM", "IDRISSTUDY.BOTHOST.TECH"
    ts, ss, hs = 13, 4, 3
    _draw_text(rows, title, (width - _text_width(title, ts)) // 2, 214, ts, white, width, height)
    _draw_text(rows, sub, (width - _text_width(sub, ss)) // 2, 350, ss, mint, width, height)
    _draw_text(rows, host, (width - _text_width(host, hs)) // 2, 470, hs, soft, width, height)

    # акцентная линия под заголовком
    for y in range(322, 328):
        for x in range((width - 420) // 2, (width + 420) // 2):
            rows[y][x * 3:x * 3 + 3] = mint

    raw = b"".join(b"\x00" + bytes(r) for r in rows)

    def chunk(tag, data):
        head = struct.pack(">I", len(data)) + tag + data
        return head + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 6))
        + chunk(b"IEND", b"")
    )


_BANNER_CACHE = {}


def banner_bytes():
    custom = BASE_DIR / "baner.png"
    if custom.exists():
        return custom.read_bytes()
    stored = DATA_DIR / "baner.png"
    if stored.exists():
        return stored.read_bytes()
    if "data" not in _BANNER_CACHE:
        _BANNER_CACHE["data"] = render_banner()
        try:
            stored.write_bytes(_BANNER_CACHE["data"])
        except OSError:
            pass
    return _BANNER_CACHE["data"]


def schema_is_broken(db):
    """Старые миграции могли оставить ссылки FK на удалённую users_old."""
    row = db.execute("SELECT sql FROM sqlite_master WHERE name='users'").fetchone()
    users_sql = row["sql"] if row and row["sql"] else ""
    for dep in ("sessions", "employee_ids", "tests", "attempts", "notifications", "notification_reads"):
        s = db.execute("SELECT sql FROM sqlite_master WHERE name=?", (dep,)).fetchone()
        if s and s["sql"] and "users_old" in s["sql"]:
            return True
    return (
        table_exists(db, "users_old")
        or "'teacher'" not in users_sql
        or "employee_id TEXT UNIQUE" in users_sql
    )


def init_db():
    with db_connect() as db:
        db.execute("PRAGMA journal_mode=WAL")
        # Актуальная схема применяется первой; блок ниже остаётся для старых баз.
        db.executescript(SCHEMA)
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('student','staff','dev')),
                group_name TEXT NOT NULL DEFAULT '',
                employee_id TEXT UNIQUE COLLATE NOCASE,
                initials TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS employee_ids (
                code TEXT PRIMARY KEY COLLATE NOCASE,
                active INTEGER NOT NULL DEFAULT 1,
                used_by INTEGER REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tests (
                id TEXT PRIMARY KEY,
                author_id INTEGER NOT NULL REFERENCES users(id),
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                content_json TEXT NOT NULL,
                points INTEGER NOT NULL DEFAULT 0,
                question_count INTEGER NOT NULL DEFAULT 0,
                access_mode TEXT NOT NULL DEFAULT 'open',
                access_hash TEXT NOT NULL DEFAULT '',
                qr_code TEXT NOT NULL UNIQUE,
                published INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS quiz_sessions (
                token_hash TEXT PRIMARY KEY,
                test_id TEXT NOT NULL REFERENCES tests(id) ON DELETE CASCADE,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                test_id TEXT NOT NULL REFERENCES tests(id) ON DELETE CASCADE,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                student_name TEXT NOT NULL,
                group_name TEXT NOT NULL,
                score INTEGER NOT NULL,
                total INTEGER NOT NULL,
                grade INTEGER NOT NULL,
                percent INTEGER NOT NULL,
                review_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pending_links (
                code TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                display_name TEXT NOT NULL DEFAULT '',
                phone TEXT NOT NULL,
                chat_id INTEGER,
                telegram_user_id INTEGER,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS telegram_links (
                account_id TEXT PRIMARY KEY,
                chat_id INTEGER NOT NULL UNIQUE,
                phone TEXT NOT NULL,
                telegram_user_id INTEGER NOT NULL,
                telegram_username TEXT NOT NULL DEFAULT '',
                linked_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                body TEXT NOT NULL DEFAULT '',
                kind TEXT NOT NULL DEFAULT 'info',
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notification_reads (
                notification_id INTEGER NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                PRIMARY KEY(notification_id, user_id)
            );

            CREATE INDEX IF NOT EXISTS idx_attempt_test ON attempts(test_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_session_expiry ON sessions(expires_at);
            """
        )

        for table, column, ddl in (
            ("sessions", "user_agent", "ALTER TABLE sessions ADD COLUMN user_agent TEXT NOT NULL DEFAULT ''"),
            ("users", "must_change_password", "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0"),
            ("users", "accepted_terms", "ALTER TABLE users ADD COLUMN accepted_terms INTEGER NOT NULL DEFAULT 0"),
            ("users", "subject", "ALTER TABLE users ADD COLUMN subject TEXT NOT NULL DEFAULT ''"),
        ):
            columns = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
            if column not in columns:
                db.execute(ddl)

        db.commit()
        needs_rebuild = schema_is_broken(db)
    if needs_rebuild:
        full_fk_rebuild()
    with db_connect() as db:

        dev_name = os.getenv("DEV_NAME", "Самир Гамидов").strip()
        dev_password = os.getenv("DEV_PASSWORD", "Fakiza2015")
        if dev_name and not db.execute(
            "SELECT 1 FROM users WHERE name=? COLLATE NOCASE", (dev_name,)
        ).fetchone():
            db.execute(
                "INSERT INTO users(name,password_hash,role,employee_id,initials,title,created_at) VALUES(?,?,?,?,?,?,?)",
                (dev_name, hash_password(dev_password), "dev", "IDR-0001", "СГ", "Разработчик", int(time.time())),
            )

        staff_name = os.getenv("STAFF_NAME", "").strip()
        staff_password = os.getenv("STAFF_PASSWORD", "EkaterinaL26")
        if staff_name and not db.execute(
            "SELECT 1 FROM users WHERE name=? COLLATE NOCASE", (staff_name,)
        ).fetchone():
            db.execute(
                "INSERT INTO users(name,password_hash,role,employee_id,initials,title,created_at) VALUES(?,?,?,?,?,?,?)",
                (staff_name, hash_password(staff_password), "staff", "IDR-1001", make_initials(staff_name), "Преподаватель", int(time.time())),
            )

        db.execute("INSERT OR IGNORE INTO employee_ids(code) VALUES('IDR-1001')")
        db.execute(
            "UPDATE employee_ids SET used_by=(SELECT id FROM users WHERE employee_id='IDR-1001') "
            "WHERE code='IDR-1001' AND EXISTS(SELECT 1 FROM users WHERE employee_id='IDR-1001')"
        )
        db.execute(
            "INSERT OR IGNORE INTO settings(key,value) VALUES('maintenance',?)",
            (json.dumps({"on": False, "text": "Ведутся технические работы. Скоро вернёмся!"}, ensure_ascii=False),),
        )
        now = int(time.time())
        db.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        db.execute("DELETE FROM quiz_sessions WHERE expires_at < ?", (now,))


def make_initials(name):
    return "".join(p[0] for p in name.split() if p)[:2].upper()


def user_json(row):
    if not row:
        return None
    keys = row.keys()
    return {
        "id": row["id"], "user": row["name"], "role": row["role"],
        "group": row["group_name"], "sid": row["employee_id"] or "",
        "short": row["initials"], "title": row["title"],
        "subject": row["subject"] if "subject" in keys else "",
        "mustChange": bool(row["must_change_password"]) if "must_change_password" in keys else False,
    }


def create_session(db, user_id, user_agent=""):
    token = secrets.token_urlsafe(36)
    now = int(time.time())
    db.execute(
        "INSERT INTO sessions(token_hash,user_id,created_at,last_seen,expires_at,user_agent) VALUES(?,?,?,?,?,?)",
        (hashlib.sha256(token.encode()).hexdigest(), user_id, now, now, now + SESSION_TTL, (user_agent or "")[:200]),
    )
    return token


def describe_agent(agent):
    agent = agent or ""
    device = "Телефон" if any(k in agent for k in ("Android", "iPhone", "iPad", "Mobile")) else "Компьютер"
    for key, name in (("Edg", "Edge"), ("OPR", "Opera"), ("YaBrowser", "Яндекс"), ("Chrome", "Chrome"), ("Firefox", "Firefox"), ("Safari", "Safari")):
        if key in agent:
            return f"{device} · {name}"
    return device


def push_notification(db, user_id, title, body, kind="info"):
    db.execute(
        "INSERT INTO notifications(user_id,title,body,kind,created_at) VALUES(?,?,?,?,?)",
        (user_id, str(title)[:160], str(body)[:600], kind, int(time.time())),
    )


def notifications_for(db, user):
    if user:
        rows = db.execute(
            "SELECT n.*, (r.user_id IS NOT NULL) AS seen FROM notifications n "
            "LEFT JOIN notification_reads r ON r.notification_id=n.id AND r.user_id=? "
            "WHERE n.user_id IS NULL OR n.user_id=? ORDER BY n.created_at DESC LIMIT 40",
            (user["id"], user["id"]),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT *, 0 AS seen FROM notifications WHERE user_id IS NULL ORDER BY created_at DESC LIMIT 40"
        ).fetchall()
    return [
        {
            "id": row["id"], "title": row["title"], "body": row["body"], "kind": row["kind"],
            "seen": bool(row["seen"]),
            "date": time.strftime("%d.%m.%Y %H:%M", time.localtime(row["created_at"])),
        }
        for row in rows
    ]


def get_setting(db, key, fallback):
    row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    try:
        return json.loads(row["value"]) if row else fallback
    except Exception:
        return fallback


# ---------------- tests and grading ----------------

def test_content(row):
    try:
        return json.loads(row["content_json"])
    except Exception:
        return {"blocks": [], "scale": None}


def attempt_json(row):
    return {
        "name": row["student_name"], "group": row["group_name"],
        "score": row["score"], "pts": row["total"], "grade": row["grade"],
        "pct": row["percent"],
        "date": time.strftime("%d.%m.%Y %H:%M", time.localtime(row["created_at"])),
    }


def fetch_test(db, test_id):
    return db.execute(
        "SELECT t.*,u.name author_name FROM tests t JOIN users u ON u.id=t.author_id WHERE t.id=?",
        (test_id,),
    ).fetchone()


def serialize_test(db, row, owner=False):
    content = test_content(row)
    out = {
        "id": row["id"], "title": row["title"], "desc": row["description"],
        "author": row["author_name"], "authorId": str(row["author_id"]),
        "count": row["question_count"], "pts": row["points"],
        "acc": row["access_mode"],
        "date": time.strftime("%d.%m.%Y", time.localtime(row["updated_at"])),
    }
    if owner:
        records = [
            attempt_json(a) for a in db.execute(
                "SELECT * FROM attempts WHERE test_id=? ORDER BY created_at DESC", (row["id"],)
            ).fetchall()
        ]
        out.update(
            blocks=content.get("blocks", []), scale=content.get("scale"),
            code=row["qr_code"], records=records, runs=len(records),
            sum=sum(a["score"] for a in records),
            best=max((a["score"] for a in records), default=0),
        )
    return out


def public_blocks(blocks):
    result = []
    for block in blocks:
        item = {
            "id": block.get("id"), "type": block.get("type"),
            "q": block.get("q", ""), "pts": int(block.get("pts") or 0),
            "img": block.get("img"), "req": bool(block.get("req")),
        }
        if item["type"] != "text":
            item["opts"] = [{"t": opt.get("t", "")} for opt in block.get("opts", [])]
        result.append(item)
    return result


def grade_for(score, total, scale):
    if scale:
        if score >= int(scale.get("g5", total + 1)):
            return 5
        if score >= int(scale.get("g4", total + 1)):
            return 4
        if score >= int(scale.get("g3", total + 1)):
            return 3
        return 2
    pct = score / total * 100 if total else 0
    return 5 if pct >= 90 else 4 if pct >= 75 else 3 if pct >= 50 else 2


def calculate_result(content, answers):
    score = 0
    review = []
    for block in content.get("blocks", []):
        bid = str(block.get("id"))
        answer = answers.get(bid, answers.get(block.get("id")))
        ok, yours, right = False, "—", ""
        if block.get("type") == "text":
            expected = str(block.get("answer", "")).strip()
            yours = str(answer or "").strip() or "—"
            right = expected
            ok = bool(expected) and yours.casefold() == expected.casefold()
        else:
            opts = block.get("opts", [])
            correct = [i for i, opt in enumerate(opts) if opt.get("ok")]
            got = sorted(int(i) for i in (answer or []) if str(i).isdigit())
            yours = ", ".join(opts[i].get("t", f"Вариант {i + 1}") for i in got if i < len(opts)) or "—"
            right = ", ".join(opts[i].get("t", f"Вариант {i + 1}") for i in correct)
            ok = bool(correct) and got == sorted(correct)
        pts = int(block.get("pts") or 0)
        if ok:
            score += pts
        review.append({
            "id": block.get("id"), "q": block.get("q", ""), "ok": ok,
            "yours": yours, "right": right, "pts": pts, "expl": block.get("expl", ""),
        })
    total = sum(int(b.get("pts") or 0) for b in content.get("blocks", []))
    percent = round(score / total * 100) if total else 0
    grade = grade_for(score, total, content.get("scale"))
    return score, total, percent, grade, review


# ---------------- Telegram ----------------

def normalize_phone(value):
    digits = re.sub(r"\D", "", str(value or ""))
    if len(digits) == 11 and digits.startswith("8"):
        digits = "7" + digits[1:]
    return digits


def telegram(method, payload=None):
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN is not configured")
    response = requests.post(f"{TELEGRAM_API}/{method}", json=payload or {}, timeout=45)
    response.raise_for_status()
    data = response.json()
    if not data.get("ok"):
        raise RuntimeError(data.get("description", "Telegram API error"))
    return data.get("result")


def send_message(chat_id, text, reply_markup=None):
    payload = {"chat_id": chat_id, "text": text}
    if reply_markup is not None:
        payload["reply_markup"] = reply_markup
    return telegram("sendMessage", payload)


def current_bot_username():
    global BOT_USERNAME
    if not BOT_USERNAME and BOT_TOKEN:
        BOT_USERNAME = telegram("getMe").get("username", "")
    return BOT_USERNAME


def configure_webhook():
    telegram("setWebhook", {"url": f"{APP_URL}/telegram/webhook", "secret_token": WEBHOOK_SECRET, "allowed_updates": ["message"]})


def handle_update(update):
    message = update.get("message") or {}
    if not message or message.get("chat", {}).get("type") != "private":
        return
    chat_id = message["chat"]["id"]
    sender_id = message.get("from", {}).get("id")
    contact = message.get("contact")
    if contact:
        if contact.get("user_id") and contact.get("user_id") != sender_id:
            send_message(chat_id, "Нужно отправить именно свой номер телефона.")
            return
        now = int(time.time())
        with db_connect() as db:
            row = db.execute("SELECT * FROM pending_links WHERE chat_id=? AND status='pending' AND created_at>=? ORDER BY created_at DESC LIMIT 1", (chat_id, now - LINK_TTL)).fetchone()
            if not row:
                send_message(chat_id, "Активной привязки нет. Создайте новую ссылку в профиле.", {"remove_keyboard": True})
                return
            got = normalize_phone(contact.get("phone_number"))
            if normalize_phone(row["phone"])[-10:] != got[-10:]:
                send_message(chat_id, "Номер не совпадает с указанным на сайте.", {"remove_keyboard": True})
                return
            db.execute("DELETE FROM telegram_links WHERE chat_id=? OR account_id=?", (chat_id, row["account_id"]))
            db.execute("INSERT INTO telegram_links(account_id,chat_id,phone,telegram_user_id,telegram_username,linked_at) VALUES(?,?,?,?,?,?)", (row["account_id"], chat_id, got, sender_id, message.get("from", {}).get("username", ""), now))
            db.execute("UPDATE pending_links SET status='confirmed' WHERE code=?", (row["code"],))
        send_message(chat_id, "Telegram подключён. Уведомления IDRIS STUDY включены.", {"remove_keyboard": True})
        emit_event("telegram")
        return

    text = (message.get("text") or "").strip()
    if text.startswith("/start"):
        parts = text.split(maxsplit=1)
        code = parts[1].upper() if len(parts) == 2 else ""
        with db_connect() as db:
            row = db.execute("SELECT * FROM pending_links WHERE code=? AND created_at>=?", (code, int(time.time()) - LINK_TTL)).fetchone()
            if not row or row["status"] == "confirmed":
                send_message(chat_id, "Ссылка истекла. Получите новую в профиле IDRIS STUDY.")
                return
            db.execute("UPDATE pending_links SET chat_id=?,telegram_user_id=? WHERE code=?", (chat_id, sender_id, code))
        send_message(chat_id, "Подтвердите свой номер телефона.", {"keyboard": [[{"text": "Поделиться номером", "request_contact": True}]], "resize_keyboard": True, "one_time_keyboard": True})
    elif text == "/status":
        with db_connect() as db:
            linked = db.execute("SELECT 1 FROM telegram_links WHERE chat_id=?", (chat_id,)).fetchone()
        send_message(chat_id, "Аккаунт подключён." if linked else "Аккаунт не подключён.")
    elif text == "/unlink":
        with db_connect() as db:
            db.execute("DELETE FROM telegram_links WHERE chat_id=?", (chat_id,))
        send_message(chat_id, "Привязка удалена.", {"remove_keyboard": True})
    else:
        send_message(chat_id, "Команды: /status и /unlink")


def polling_loop():
    log.info("Telegram long polling started")
    try:
        telegram("deleteWebhook", {"drop_pending_updates": False})
    except Exception as exc:
        log.warning("deleteWebhook: %s", exc)
    offset = None
    while True:
        try:
            updates = telegram("getUpdates", {"timeout": 25, "offset": offset, "allowed_updates": ["message"]})
            for update in updates:
                offset = update["update_id"] + 1
                try:
                    handle_update(update)
                except Exception:
                    log.exception("Telegram update error")
        except Exception as exc:
            log.warning("Polling error: %s", exc)
            time.sleep(4)


def notify_author(account_id, text):
    if not BOT_TOKEN:
        return
    with db_connect() as db:
        row = db.execute("SELECT chat_id FROM telegram_links WHERE account_id=?", (str(account_id),)).fetchone()
    if row:
        try:
            send_message(row["chat_id"], text)
        except Exception:
            log.exception("Telegram notification failed")


# ---------------- HTTP server ----------------

class Handler(BaseHTTPRequestHandler):
    server_version = "IdrisStudy/2.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        log.info("%s %s", self.address_string(), fmt % args)

    def handle_one_request(self):
        # Соединение переиспользуется, поэтому флаг ответа сбрасываем на каждый запрос.
        self._replied = False
        super().handle_one_request()

    def headers_out(self, status, content_type, length=None, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if length is not None:
            self.send_header("Content-Length", str(length))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()

    def send_json(self, payload, status=200, extra=None):
        # Защита от повторной отправки заголовков после ошибки в обработчике.
        if getattr(self, "_replied", False):
            return
        self._replied = True
        body = json.dumps(payload, ensure_ascii=False).encode()
        try:
            self.headers_out(status, "application/json; charset=utf-8", len(body), extra)
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 12 * 1024 * 1024:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode())
        except Exception:
            return {}

    def cookie_token(self):
        jar = SimpleCookie(self.headers.get("Cookie", ""))
        return jar.get("idris_session").value if jar.get("idris_session") else ""

    def current_user(self, db):
        token = self.cookie_token()
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        row = db.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?",
            (token_hash, int(time.time())),
        ).fetchone()
        if row:
            db.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (int(time.time()), token_hash))
        return row

    def require_user(self, db, roles=None):
        user = self.current_user(db)
        if not user or (roles and user["role"] not in roles):
            self.send_json({"ok": False, "error": "Требуется вход"}, 401)
            return None
        return user

    def route(self):
        return urlparse(self.path).path

    def serve_banner(self):
        if getattr(self, "_replied", False):
            return
        self._replied = True
        try:
            body = banner_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def serve_file(self, filename, head=False):
        path = BASE_DIR / filename
        if not path.exists():
            self.send_json({"detail": "Not Found"}, 404)
            return
        body = path.read_bytes()
        self.headers_out(200, "text/html; charset=utf-8", len(body), {"Cache-Control": "no-cache"})
        if not head:
            self.wfile.write(body)

    def on_terms_host(self):
        host = (self.headers.get("Host") or "").lower()
        return host.startswith("terms.") or host.startswith("legal.")

    def serve_index(self, head=False):
        # Поддомен terms.* отдаёт пользовательское соглашение прямо на корне.
        self.serve_file("terms.html" if self.on_terms_host() else "index.html", head)

    def do_HEAD(self):
        self.serve_index(True)

    def do_GET(self):
        try:
            path = self.route()
            if path in ("/", "/index.html"):
                self.serve_index()
            elif path in ("/baner.png", "/banner.png", "/og.png"):
                self.serve_banner()
            elif path in ("/terms", "/terms.html", "/terms/"):
                self.serve_file("terms.html")
            elif path == "/health":
                self.send_json({"ok": True, "bot": bool(BOT_TOKEN), "mode": TELEGRAM_MODE})
            elif path == "/api/bootstrap":
                self.api_bootstrap()
            elif path == "/api/events":
                self.api_events()
            elif path == "/api/telegram/link-status":
                code = parse_qs(urlparse(self.path).query).get("code", [""])[0].upper()
                with db_connect() as db:
                    row = db.execute("SELECT status,phone FROM pending_links WHERE code=?", (code,)).fetchone()
                self.send_json({"ok": True, "linked": bool(row and row["status"] == "confirmed"), "phone": row["phone"] if row and row["status"] == "confirmed" else None})
            else:
                self.send_json({"detail": "Not Found"}, 404)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            log.exception("GET error")
            try:
                self.send_json({"ok": False, "error": "Server error"}, 500)
            except Exception:
                pass

    def do_POST(self):
        try:
            path = self.route()
            if path == "/telegram/webhook":
                provided = self.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
                if WEBHOOK_SECRET and not secrets.compare_digest(provided, WEBHOOK_SECRET):
                    self.send_json({"ok": False}, 403)
                    return
                handle_update(self.read_json())
                self.send_json({"ok": True})
                return
            routes = {
                "/api/auth/login": self.api_login,
                "/api/auth/register": self.api_register,
                "/api/auth/logout": self.api_logout,
                "/api/tests": self.api_save_test,
                "/api/maintenance": self.api_maintenance,
                "/api/admin/wipe": self.api_admin_wipe,
                "/api/sessions/revoke": self.api_session_revoke,
                "/api/admin/users/role": self.api_user_role,
                "/api/admin/users/password": self.api_user_password,
                "/api/admin/users/delete": self.api_user_delete,
                "/api/admin/notify": self.api_admin_notify,
                "/api/notifications/read": self.api_notifications_read,
                "/api/auth/password": self.api_change_password,
                "/api/tests/resolve": self.api_test_resolve,
                "/api/telegram/link": self.api_telegram_link,
                "/api/telegram/unlink": self.api_telegram_unlink,
                "/api/admin/employee-ids": self.api_employee_id,
            }
            if path in routes:
                routes[path]()
                return
            match = re.fullmatch(r"/api/tests/([^/]+)/(access|open|submit)", path)
            if match:
                getattr(self, f"api_test_{match.group(2)}")(match.group(1))
                return
            self.send_json({"detail": "Not Found"}, 404)
        except Exception:
            log.exception("POST error")
            try:
                self.send_json({"ok": False, "error": "Server error"}, 500)
            except Exception:
                pass

    def do_DELETE(self):
        try:
            match = re.fullmatch(r"/api/tests/([^/]+)", self.route())
            if not match:
                self.send_json({"detail": "Not Found"}, 404)
                return
            with db_connect() as db:
                user = self.require_user(db, AUTHOR_ROLES)
                if not user:
                    return
                row = fetch_test(db, match.group(1))
                if not row or (user["role"] != "dev" and row["author_id"] != user["id"]):
                    self.send_json({"ok": False}, 403)
                    return
                db.execute("DELETE FROM tests WHERE id=?", (row["id"],))
            emit_event("tests")
            self.send_json({"ok": True})
        except Exception:
            log.exception("DELETE error")
            self.send_json({"ok": False}, 500)

    def api_bootstrap(self):
        with db_connect() as db:
            user = self.current_user(db)
            tests = [serialize_test(db, r) for r in db.execute("SELECT t.*,u.name author_name FROM tests t JOIN users u ON u.id=t.author_id WHERE published=1 ORDER BY updated_at DESC").fetchall()]
            owned, attempts = [], []
            if user and user["role"] in AUTHOR_ROLES:
                sql = "SELECT t.*,u.name author_name FROM tests t JOIN users u ON u.id=t.author_id"
                params = ()
                if user["role"] != "dev":
                    sql += " WHERE t.author_id=?"
                    params = (user["id"],)
                sql += " ORDER BY t.updated_at DESC"
                owned = [serialize_test(db, r, True) for r in db.execute(sql, params).fetchall()]
            if user:
                attempts = [
                    {**attempt_json(a), "title": a["test_title"]}
                    for a in db.execute("SELECT a.*,t.title test_title FROM attempts a JOIN tests t ON t.id=a.test_id WHERE a.user_id=? ORDER BY a.created_at DESC", (user["id"],)).fetchall()
                ]
            maintenance = get_setting(db, "maintenance", {"on": False, "text": ""})
            admin = None
            if user and user["role"] == "dev":
                admin = {
                    "accounts": db.execute("SELECT COUNT(*) n FROM users").fetchone()["n"],
                    "tests": db.execute("SELECT COUNT(*) n FROM tests").fetchone()["n"],
                    "attempts": db.execute("SELECT COUNT(*) n FROM attempts").fetchone()["n"],
                }
            me = user_json(user)
            sessions = []
            users = []
            if me:
                link = db.execute("SELECT phone FROM telegram_links WHERE account_id=?", (str(user["id"]),)).fetchone()
                me["tg"] = link["phone"] if link else ""
                token_hash = hashlib.sha256(self.cookie_token().encode()).hexdigest()
                for row in db.execute(
                    "SELECT rowid AS sid, token_hash, created_at, last_seen, user_agent FROM sessions WHERE user_id=? ORDER BY created_at",
                    (user["id"],),
                ).fetchall():
                    current = hmac.compare_digest(row["token_hash"], token_hash)
                    sessions.append({
                        "id": row["sid"],
                        "current": current,
                        "device": describe_agent(row["user_agent"]),
                        "started": time.strftime("%d.%m.%Y %H:%M", time.localtime(row["created_at"])),
                        "active": time.strftime("%d.%m.%Y %H:%M", time.localtime(row["last_seen"])),
                        "createdAt": row["created_at"],
                    })
                current_started = next((s["createdAt"] for s in sessions if s["current"]), None)
                for item in sessions:
                    item["canRevoke"] = item["current"] or (current_started is not None and item["createdAt"] > current_started)
            if user and user["role"] == "dev":
                users = [
                    {
                        "id": row["id"], "user": row["name"], "role": row["role"],
                        "group": row["group_name"], "sid": row["employee_id"] or "",
                        "subject": row["subject"], "short": row["initials"], "title": row["title"],
                        "mustChange": bool(row["must_change_password"]),
                        "created": time.strftime("%d.%m.%Y", time.localtime(row["created_at"])),
                    }
                    for row in db.execute("SELECT * FROM users ORDER BY role, name").fetchall()
                ]
            notes = notifications_for(db, user)
        self.send_json({
            "ok": True, "me": me, "tests": tests, "drafts": owned, "attempts": attempts,
            "maintenance": maintenance, "admin": admin, "sessions": sessions, "users": users,
            "notifications": notes, "version": EVENT_ID,
        })

    def api_events(self):
        try:
            last = int(self.headers.get("Last-Event-ID") or 0)
        except ValueError:
            last = 0
        # Поток событий должен закрывать соединение сам: без Content-Length
        # keep-alive ломает разбор ответа и браузер буферизует данные.
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        try:
            self.wfile.write(b"retry: 2000\n: connected\n\n")
            self.wfile.flush()
            started = time.time()
            while time.time() - started < 50:
                with EVENT_COND:
                    EVENT_COND.wait_for(lambda: EVENT_ID > last, timeout=10)
                    pending = [event for event in EVENTS if event[0] > last]
                if pending:
                    for event_id, kind, payload in pending:
                        self.wfile.write(
                            f"id: {event_id}\nevent: {kind}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n".encode()
                        )
                        last = event_id
                else:
                    self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def api_login(self):
        data = self.read_json()
        with db_connect() as db:
            user = db.execute("SELECT * FROM users WHERE name=? COLLATE NOCASE", (str(data.get("user", "")).strip(),)).fetchone()
            if not user or not verify_password(str(data.get("password", "")), user["password_hash"]):
                self.send_json({"ok": False, "error": "Неверное имя или пароль"}, 401)
                return
            token = create_session(db, user["id"], self.headers.get("User-Agent", ""))
        cookie = f"idris_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}"
        if APP_URL.startswith("https://"):
            cookie += "; Secure"
        self.send_json({"ok": True, "user": user_json(user)}, extra={"Set-Cookie": cookie})

    def api_register(self):
        data = self.read_json()
        name = str(data.get("name", "")).strip()[:120]
        password = str(data.get("password", ""))
        role = str(data.get("role", "student"))
        group = str(data.get("group", "")).strip()[:50]
        subject = str(data.get("subject", "")).strip()[:80]
        sid = str(data.get("employee_id", "")).strip().upper()[:40]
        if role not in ("student", "teacher", "staff") or len(name) < 3 or len(password) < 6:
            self.send_json({"ok": False, "error": "Проверьте поля; пароль от 6 символов"}, 400)
            return
        if role == "student" and not group:
            self.send_json({"ok": False, "error": "Укажите номер группы"}, 400)
            return
        if role == "teacher" and not subject:
            self.send_json({"ok": False, "error": "Укажите предмет, который вы ведёте"}, 400)
            return
        if not data.get("accept_terms"):
            self.send_json({"ok": False, "error": "Примите пользовательское соглашение"}, 400)
            return
        with db_connect() as db:
            if db.execute("SELECT 1 FROM users WHERE name=? COLLATE NOCASE", (name,)).fetchone():
                self.send_json({"ok": False, "error": "Такой пользователь уже существует"}, 409)
                return
            if role == "staff" and not db.execute("SELECT 1 FROM employee_ids WHERE code=? COLLATE NOCASE AND active=1 AND used_by IS NULL", (sid,)).fetchone():
                self.send_json({"ok": False, "error": "ID сотрудника не найден или уже использован"}, 403)
                return
            now = int(time.time())
            titles = {"student": "Студент", "teacher": "Преподаватель", "staff": "Сотрудник IDRIS"}
            employee_id = sid if (role == "staff" and sid) else None
            if employee_id and db.execute(
                "SELECT 1 FROM users WHERE employee_id=? COLLATE NOCASE", (employee_id,)
            ).fetchone():
                self.send_json({"ok": False, "error": "Этот ID сотрудника уже привязан к аккаунту"}, 409)
                return
            try:
                cur = db.execute(
                    "INSERT INTO users(name,password_hash,role,group_name,subject,employee_id,initials,title,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (name, hash_password(password), role, group if role == "student" else "",
                     subject if role == "teacher" else "", employee_id, make_initials(name), titles[role], now),
                )
            except sqlite3.IntegrityError:
                self.send_json({"ok": False, "error": "Такой пользователь или ID уже существует"}, 409)
                return
            user_id = cur.lastrowid
            if role == "staff":
                db.execute("UPDATE employee_ids SET used_by=? WHERE code=? COLLATE NOCASE", (user_id, sid))
            db.execute("UPDATE users SET accepted_terms=1 WHERE id=?", (user_id,))
            push_notification(db, user_id, "Добро пожаловать в IDRIS STUDY",
                              "Аккаунт создан. Проходите тесты и следите за результатами в разделе «Мои тесты».", "info")
            user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            token = create_session(db, user_id, self.headers.get("User-Agent", ""))
        emit_event("accounts")
        cookie = f"idris_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}"
        if APP_URL.startswith("https://"):
            cookie += "; Secure"
        self.send_json({"ok": True, "user": user_json(user)}, 201, {"Set-Cookie": cookie})

    def api_logout(self):
        token = self.cookie_token()
        if token:
            with db_connect() as db:
                db.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
        self.send_json({"ok": True}, extra={"Set-Cookie": "idris_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"})

    def api_save_test(self):
        data = self.read_json()
        with db_connect() as db:
            user = self.require_user(db, AUTHOR_ROLES)
            if not user:
                return
            test_id = str(data.get("id") or secrets.token_urlsafe(9))[:40]
            existing = fetch_test(db, test_id)
            if existing and user["role"] != "dev" and existing["author_id"] != user["id"]:
                self.send_json({"ok": False}, 403)
                return
            blocks = data.get("blocks") if isinstance(data.get("blocks"), list) else []
            points = sum(max(0, int(block.get("pts") or 0)) for block in blocks)
            content = json.dumps({"blocks": blocks, "scale": data.get("scale")}, ensure_ascii=False)
            now = int(time.time())
            if existing:
                db.execute("UPDATE tests SET title=?,description=?,content_json=?,points=?,question_count=?,updated_at=? WHERE id=?", (str(data.get("title") or "Без названия")[:180], str(data.get("desc") or "")[:1000], content, points, len(blocks), now, test_id))
            else:
                db.execute("INSERT INTO tests(id,author_id,title,description,content_json,points,question_count,access_mode,access_hash,qr_code,published,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (test_id, user["id"], str(data.get("title") or "Без названия")[:180], str(data.get("desc") or "")[:1000], content, points, len(blocks), "open", "", secrets.token_hex(4).upper(), 1, now, now))
            payload = serialize_test(db, fetch_test(db, test_id), True)
        emit_event("tests", {"id": test_id})
        self.send_json({"ok": True, "test": payload})

    def api_test_access(self, test_id):
        data = self.read_json()
        mode = str(data.get("mode", "open"))
        if mode not in ("open", "pass", "qr"):
            mode = "open"
        with db_connect() as db:
            user = self.require_user(db, AUTHOR_ROLES)
            if not user:
                return
            row = fetch_test(db, test_id)
            if not row or (user["role"] != "dev" and row["author_id"] != user["id"]):
                self.send_json({"ok": False}, 403)
                return
            encoded = row["access_hash"]
            if mode == "pass" and str(data.get("password", "")):
                encoded = hash_password(str(data["password"]))
            db.execute("UPDATE tests SET access_mode=?,access_hash=?,updated_at=? WHERE id=?", (mode, encoded, int(time.time()), test_id))
            payload = serialize_test(db, fetch_test(db, test_id), True)
        emit_event("tests", {"id": test_id})
        self.send_json({"ok": True, "test": payload})

    def api_test_open(self, test_id):
        data = self.read_json()
        with db_connect() as db:
            row = fetch_test(db, test_id)
            if not row or not row["published"]:
                self.send_json({"ok": False, "error": "Тест не найден"}, 404)
                return
            credential = str(data.get("credential", ""))
            if row["access_mode"] == "pass" and not verify_password(credential, row["access_hash"]):
                self.send_json({"ok": False, "error": "Неверный пароль"}, 403)
                return
            if row["access_mode"] == "qr" and not hmac.compare_digest(credential.upper(), row["qr_code"].upper()):
                self.send_json({"ok": False, "error": "Неверный QR-код"}, 403)
                return
            token = secrets.token_urlsafe(30)
            now = int(time.time())
            db.execute("INSERT INTO quiz_sessions(token_hash,test_id,created_at,expires_at) VALUES(?,?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), test_id, now, now + QUIZ_TTL))
            content = test_content(row)
        self.send_json({"ok": True, "token": token, "blocks": public_blocks(content.get("blocks", []))})

    def api_test_submit(self, test_id):
        data = self.read_json()
        token_hash = hashlib.sha256(str(data.get("token", "")).encode()).hexdigest()
        with db_connect() as db:
            quiz = db.execute("SELECT * FROM quiz_sessions WHERE token_hash=? AND test_id=? AND expires_at>?", (token_hash, test_id, int(time.time()))).fetchone()
            row = fetch_test(db, test_id)
            if not quiz or not row:
                self.send_json({"ok": False, "error": "Сессия теста истекла"}, 403)
                return
            user = self.current_user(db)
            student_name = str(data.get("student_name") or (user["name"] if user else "")).strip()[:120]
            group = str(data.get("group") or (user["group_name"] if user else "")).strip()[:50]
            if not student_name or not group:
                self.send_json({"ok": False, "error": "Укажите имя и группу"}, 400)
                return
            content = test_content(row)
            answers = data.get("answers") or {}
            for index, block in enumerate(content.get("blocks", [])):
                if not block.get("req"):
                    continue
                answer = answers.get(str(block.get("id")), answers.get(block.get("id")))
                missing = not str(answer or "").strip() if block.get("type") == "text" else not answer
                if missing:
                    self.send_json({"ok": False, "error": f"Обязательный вопрос № {index + 1} не отвечен", "question": index + 1}, 400)
                    return
            score, total, percent, grade, review = calculate_result(content, answers)
            now = int(time.time())
            db.execute("INSERT INTO attempts(test_id,user_id,student_name,group_name,score,total,grade,percent,review_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", (test_id, user["id"] if user else None, student_name, group, score, total, grade, percent, json.dumps(review, ensure_ascii=False), now))
            db.execute("DELETE FROM quiz_sessions WHERE token_hash=?", (token_hash,))
        emit_event("attempts", {"test_id": test_id})
        text = f"Новое прохождение теста\n\nТест: {row['title']}\nСтудент: {student_name}\nГруппа: {group}\nРезультат: {score} из {total}\nОценка: {grade}"
        threading.Thread(target=notify_author, args=(row["author_id"], text), daemon=True).start()
        self.send_json({"ok": True, "score": score, "total": total, "percent": percent, "grade": grade, "review": review})

    def api_maintenance(self):
        data = self.read_json()
        with db_connect() as db:
            user = self.require_user(db, {"dev"})
            if not user:
                return
            previous = get_setting(db, "maintenance", {})
            value = {
                "on": bool(data.get("on")),
                "text": str(data.get("text") or "Ведутся технические работы.")[:500],
                "planned": str(data.get("planned") or "")[:40],
                "notice": str(data.get("notice") or "")[:300],
            }
            db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('maintenance',?)", (json.dumps(value, ensure_ascii=False),))
            if value["planned"] and value["planned"] != previous.get("planned"):
                when = value["planned"].replace("T", " ")
                push_notification(db, None, "Плановые технические работы",
                                  f"{when} — {value['notice'] or 'сайт будет временно недоступен.'}", "warning")
            if value["on"] and not previous.get("on"):
                push_notification(db, None, "Технический перерыв начался", value["text"], "warning")
        emit_event("maintenance")
        self.send_json({"ok": True, "maintenance": value})

    def api_session_revoke(self):
        data = self.read_json()
        with db_connect() as db:
            user = self.require_user(db)
            if not user:
                return
            token_hash = hashlib.sha256(self.cookie_token().encode()).hexdigest()
            current = db.execute("SELECT rowid AS sid, created_at FROM sessions WHERE token_hash=?", (token_hash,)).fetchone()
            target = db.execute(
                "SELECT rowid AS sid, created_at, user_id FROM sessions WHERE rowid=?", (int(data.get("id") or 0),)
            ).fetchone()
            if not current or not target or target["user_id"] != user["id"]:
                self.send_json({"ok": False, "error": "Сессия не найдена"}, 404)
                return
            # Более ранняя сессия старше по правам: младшая не может завершить старшую.
            if target["sid"] != current["sid"] and target["created_at"] <= current["created_at"]:
                self.send_json({"ok": False, "error": "Эта сессия старше вашей — завершить её нельзя"}, 403)
                return
            db.execute("DELETE FROM sessions WHERE rowid=?", (target["sid"],))
            closed_self = target["sid"] == current["sid"]
        emit_event("sessions")
        extra = {"Set-Cookie": "idris_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"} if closed_self else None
        self.send_json({"ok": True, "self": closed_self}, extra=extra)

    def api_user_role(self):
        data = self.read_json()
        role = str(data.get("role", ""))
        with db_connect() as db:
            admin = self.require_user(db, {"dev"})
            if not admin:
                return
            target_id = int(data.get("user_id") or 0)
            if role not in ("student", "teacher", "staff", "dev") or target_id == admin["id"]:
                self.send_json({"ok": False, "error": "Некорректная роль"}, 400)
                return
            title = {"student": "Студент", "teacher": "Преподаватель", "staff": "Сотрудник IDRIS", "dev": "Разработчик"}[role]
            db.execute("UPDATE users SET role=?,title=? WHERE id=?", (role, title, target_id))
            push_notification(db, target_id, "Роль изменена", f"Администратор назначил вам роль «{title}».", "info")
        emit_event("accounts")
        self.send_json({"ok": True})

    def api_user_password(self):
        data = self.read_json()
        with db_connect() as db:
            admin = self.require_user(db, {"dev"})
            if not admin:
                return
            target_id = int(data.get("user_id") or 0)
            db.execute("UPDATE users SET must_change_password=1 WHERE id=?", (target_id,))
            push_notification(
                db, target_id, "Требуется смена пароля",
                "Администратор попросил вас обновить пароль. Откройте профиль → «Мой профиль» → «Сменить пароль».",
                "warning",
            )
        emit_event("accounts")
        self.send_json({"ok": True})

    def api_user_delete(self):
        data = self.read_json()
        with db_connect() as db:
            admin = self.require_user(db, {"dev"})
            if not admin:
                return
            target_id = int(data.get("user_id") or 0)
            if target_id == admin["id"]:
                self.send_json({"ok": False, "error": "Нельзя удалить свой аккаунт"}, 400)
                return
            db.execute("DELETE FROM users WHERE id=?", (target_id,))
        emit_event("accounts")
        self.send_json({"ok": True})

    def api_change_password(self):
        data = self.read_json()
        new_password = str(data.get("new_password", ""))
        with db_connect() as db:
            user = self.require_user(db)
            if not user:
                return
            if not verify_password(str(data.get("current_password", "")), user["password_hash"]):
                self.send_json({"ok": False, "error": "Текущий пароль неверен"}, 403)
                return
            if len(new_password) < 6:
                self.send_json({"ok": False, "error": "Новый пароль от 6 символов"}, 400)
                return
            db.execute(
                "UPDATE users SET password_hash=?,must_change_password=0 WHERE id=?",
                (hash_password(new_password), user["id"]),
            )
            token_hash = hashlib.sha256(self.cookie_token().encode()).hexdigest()
            db.execute("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (user["id"], token_hash))
        emit_event("accounts")
        self.send_json({"ok": True})

    def api_admin_notify(self):
        data = self.read_json()
        with db_connect() as db:
            admin = self.require_user(db, {"dev"})
            if not admin:
                return
            target = data.get("user_id")
            push_notification(
                db, int(target) if target else None,
                data.get("title") or "Уведомление",
                data.get("body") or "",
                str(data.get("kind") or "info"),
            )
        emit_event("notifications")
        self.send_json({"ok": True})

    def api_notifications_read(self):
        with db_connect() as db:
            user = self.current_user(db)
            if not user:
                self.send_json({"ok": True})
                return
            db.execute(
                "INSERT OR IGNORE INTO notification_reads(notification_id,user_id) "
                "SELECT id,? FROM notifications WHERE user_id IS NULL OR user_id=?",
                (user["id"], user["id"]),
            )
        self.send_json({"ok": True})

    def api_test_resolve(self):
        data = self.read_json()
        code = str(data.get("code", "")).strip().upper()
        with db_connect() as db:
            row = db.execute(
                "SELECT t.*,u.name author_name FROM tests t JOIN users u ON u.id=t.author_id WHERE UPPER(t.qr_code)=?",
                (code,),
            ).fetchone()
            if not row or not row["published"]:
                self.send_json({"ok": False, "error": "Тест не найден"}, 404)
                return
            token = secrets.token_urlsafe(30)
            now = int(time.time())
            db.execute(
                "INSERT INTO quiz_sessions(token_hash,test_id,created_at,expires_at) VALUES(?,?,?,?)",
                (hashlib.sha256(token.encode()).hexdigest(), row["id"], now, now + QUIZ_TTL),
            )
            payload = serialize_test(db, row)
            content = test_content(row)
        self.send_json({"ok": True, "token": token, "test": payload, "blocks": public_blocks(content.get("blocks", []))})

    def api_admin_wipe(self):
        with db_connect() as db:
            user = self.require_user(db, {"dev"})
            if not user:
                return
            db.execute("DELETE FROM tests")
            db.execute("DELETE FROM sessions WHERE user_id<>?", (user["id"],))
            db.execute("DELETE FROM employee_ids")
            db.execute("DELETE FROM users WHERE role<>'dev'")
            db.execute("INSERT OR IGNORE INTO employee_ids(code) VALUES('IDR-1001')")
        emit_event("sync")
        self.send_json({"ok": True})

    def api_employee_id(self):
        data = self.read_json()
        code = str(data.get("code", "")).strip().upper()
        if not re.fullmatch(r"IDR-[A-Z0-9]{4,12}", code):
            self.send_json({"ok": False, "error": "Формат IDR-XXXX"}, 400)
            return
        with db_connect() as db:
            if not self.require_user(db, {"dev"}):
                return
            db.execute("INSERT OR IGNORE INTO employee_ids(code) VALUES(?)", (code,))
        self.send_json({"ok": True})

    def api_telegram_link(self):
        data = self.read_json()
        phone = normalize_phone(data.get("phone"))
        with db_connect() as db:
            user = self.require_user(db, AUTHOR_ROLES)
            if not user:
                return
            if len(phone) < 10:
                self.send_json({"ok": False, "error": "Некорректный номер"}, 400)
                return
            account_id = str(user["id"])
            code = secrets.token_hex(3).upper()
            db.execute("DELETE FROM pending_links WHERE account_id=?", (account_id,))
            db.execute("INSERT INTO pending_links(code,account_id,display_name,phone,status,created_at) VALUES(?,?,?,?,?,?)", (code, account_id, user["name"], phone, "pending", int(time.time())))
        username = current_bot_username()
        self.send_json({"ok": True, "code": code, "bot_url": f"https://t.me/{username}?start={code}" if username else "", "expires_in": LINK_TTL})

    def api_telegram_unlink(self):
        with db_connect() as db:
            user = self.require_user(db, AUTHOR_ROLES)
            if not user:
                return
            db.execute("DELETE FROM telegram_links WHERE account_id=?", (str(user["id"]),))
        self.send_json({"ok": True})


def run_web():
    servers = []
    for port in dict.fromkeys((PORT, 3000, 8080)):
        try:
            server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
        except OSError:
            continue
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        log.info("IDRIS STUDY web started on 0.0.0.0:%s", port)
    return servers


def main():
    init_db()
    if BOT_TOKEN and TELEGRAM_MODE == "polling":
        threading.Thread(target=polling_loop, daemon=True).start()
    servers = run_web() if RUN_WEB else []
    if BOT_TOKEN and TELEGRAM_MODE == "webhook" and servers:
        threading.Thread(target=configure_webhook, daemon=True).start()
    log.info("Service started: mode=%s, ports=%s", TELEGRAM_MODE, [s.server_port for s in servers])
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()