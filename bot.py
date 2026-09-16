import hashlib
import json
import logging
import os
import re
import secrets
import socket
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import requests


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(
    os.getenv("BOT_DB_PATH")
    or (Path(os.getenv("DATA_DIR", str(BASE_DIR))) / "idris_bot.sqlite3")
)
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
APP_URL = os.getenv("APP_URL", "https://IdrisStudy.bothost.tech").rstrip("/")
PORT = int(os.getenv("PORT", "5000"))
BOT_USERNAME = os.getenv("BOT_USERNAME", "").lstrip("@").strip()
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "").strip()
TELEGRAM_MODE = os.getenv("TELEGRAM_MODE", "polling").strip().lower()  # polling | webhook
RUN_WEB = os.getenv("RUN_WEB", "1") == "1"

if not WEBHOOK_SECRET and BOT_TOKEN:
    WEBHOOK_SECRET = hashlib.sha256(BOT_TOKEN.encode("utf-8")).hexdigest()[:48]

TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"
LINK_TTL = 20 * 60

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("idris-bot")


# ---------------- storage ----------------

def connect_db():
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with connect_db() as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript(
            """
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

            CREATE INDEX IF NOT EXISTS idx_pending_chat
            ON pending_links(chat_id, status, created_at);
            """
        )


# ---------------- telegram helpers ----------------

def normalize_phone(value):
    digits = re.sub(r"\D", "", str(value or ""))
    if len(digits) == 11 and digits.startswith("8"):
        digits = "7" + digits[1:]
    return digits


def telegram(method, payload=None):
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN is not configured")
    response = requests.post(
        f"{TELEGRAM_API}/{method}", json=payload or {}, timeout=45
    )
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
    if BOT_USERNAME:
        return BOT_USERNAME
    try:
        BOT_USERNAME = telegram("getMe").get("username", "")
    except Exception as exc:
        log.warning("Unable to read bot username: %s", exc)
    return BOT_USERNAME


def configure_webhook():
    telegram(
        "setWebhook",
        {
            "url": f"{APP_URL}/telegram/webhook",
            "secret_token": WEBHOOK_SECRET,
            "allowed_updates": ["message"],
            "drop_pending_updates": False,
        },
    )
    log.info("Telegram webhook configured: %s/telegram/webhook", APP_URL)


def remove_keyboard():
    return {"remove_keyboard": True}


def contact_keyboard():
    return {
        "keyboard": [[{"text": "Поделиться номером", "request_contact": True}]],
        "resize_keyboard": True,
        "one_time_keyboard": True,
    }


def start_link(message, code):
    chat_id = message["chat"]["id"]
    user_id = message["from"]["id"]
    now = int(time.time())
    with connect_db() as db:
        row = db.execute(
            "SELECT * FROM pending_links WHERE code = ? AND created_at >= ?",
            (code.upper(), now - LINK_TTL),
        ).fetchone()
        if not row or row["status"] == "confirmed":
            send_message(
                chat_id,
                "Код привязки не найден или уже истёк. Создайте новый код в профиле IDRIS STUDY.",
            )
            return
        db.execute(
            "UPDATE pending_links SET chat_id = ?, telegram_user_id = ? WHERE code = ?",
            (chat_id, user_id, code.upper()),
        )

    send_message(
        chat_id,
        "Почти готово. Подтвердите номер телефона кнопкой ниже. Telegram отправит номер только этому боту.",
        contact_keyboard(),
    )


def confirm_contact(message):
    chat_id = message["chat"]["id"]
    sender_id = message["from"]["id"]
    contact = message.get("contact") or {}
    contact_user_id = contact.get("user_id")

    if contact_user_id and contact_user_id != sender_id:
        send_message(chat_id, "Нужно отправить именно свой номер телефона.")
        return

    now = int(time.time())
    with connect_db() as db:
        row = db.execute(
            """
            SELECT * FROM pending_links
            WHERE chat_id = ? AND status = 'pending' AND created_at >= ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (chat_id, now - LINK_TTL),
        ).fetchone()
        if not row:
            send_message(
                chat_id,
                "Активной привязки нет. Сначала получите новую ссылку в профиле IDRIS STUDY.",
                remove_keyboard(),
            )
            return

        expected = normalize_phone(row["phone"])
        received = normalize_phone(contact.get("phone_number"))
        if not expected or expected[-10:] != received[-10:]:
            send_message(
                chat_id,
                "Этот номер не совпадает с номером, введённым на сайте. Создайте привязку заново.",
                remove_keyboard(),
            )
            return

        username = message.get("from", {}).get("username", "")
        db.execute(
            "DELETE FROM telegram_links WHERE chat_id = ? OR account_id = ?",
            (chat_id, row["account_id"]),
        )
        db.execute(
            """
            INSERT INTO telegram_links
                (account_id, chat_id, phone, telegram_user_id, telegram_username, linked_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (row["account_id"], chat_id, received, sender_id, username, now),
        )
        db.execute(
            "UPDATE pending_links SET status = 'confirmed' WHERE code = ?",
            (row["code"],),
        )

    send_message(
        chat_id,
        "Telegram успешно подключён к аккаунту IDRIS STUDY. Теперь сюда будут приходить уведомления о прохождениях тестов.",
        remove_keyboard(),
    )


def handle_update(update):
    message = update.get("message") or {}
    if not message or message.get("chat", {}).get("type") != "private":
        return

    chat_id = message["chat"]["id"]
    if message.get("contact"):
        confirm_contact(message)
        return

    text = (message.get("text") or "").strip()
    if text.startswith("/start"):
        parts = text.split(maxsplit=1)
        if len(parts) == 2 and re.fullmatch(r"[A-Z0-9]{6}", parts[1].upper()):
            start_link(message, parts[1])
        else:
            send_message(
                chat_id,
                "Я бот уведомлений IDRIS STUDY. Откройте профиль на сайте, укажите номер и перейдите по выданной ссылке.",
            )
        return

    if text == "/status":
        with connect_db() as db:
            row = db.execute(
                "SELECT account_id FROM telegram_links WHERE chat_id = ?", (chat_id,)
            ).fetchone()
        send_message(chat_id, "Аккаунт подключён." if row else "Аккаунт пока не подключён.")
        return

    if text == "/unlink":
        with connect_db() as db:
            db.execute("DELETE FROM telegram_links WHERE chat_id = ?", (chat_id,))
        send_message(chat_id, "Привязка удалена.", remove_keyboard())
        return

    send_message(chat_id, "Доступные команды: /status и /unlink")


# ---------------- long polling ----------------

def polling_loop():
    log.info("Telegram long polling started")
    try:
        telegram("deleteWebhook", {"drop_pending_updates": False})
    except Exception as exc:
        log.warning("deleteWebhook failed: %s", exc)
    offset = None
    while True:
        try:
            updates = telegram(
                "getUpdates",
                {"timeout": 25, "offset": offset, "allowed_updates": ["message"]},
            )
            for upd in updates:
                offset = upd["update_id"] + 1
                try:
                    handle_update(upd)
                except Exception:
                    log.exception("Error while handling update")
        except Exception as exc:
            if "Conflict" in str(exc):
                try:
                    telegram("deleteWebhook", {"drop_pending_updates": False})
                except Exception:
                    pass
            log.warning("Polling error: %s", exc)
            time.sleep(4)


# ---------------- http api (stdlib only) ----------------

def api_create_link(data):
    account_id = str(data.get("account_id", "")).strip()[:80]
    display_name = str(data.get("display_name", "")).strip()[:120]
    phone = normalize_phone(data.get("phone"))
    if not account_id or len(phone) < 10:
        return 400, {"ok": False, "error": "Укажите аккаунт и корректный номер"}

    code = secrets.token_hex(3).upper()
    now = int(time.time())
    with connect_db() as db:
        db.execute("DELETE FROM pending_links WHERE account_id = ?", (account_id,))
        db.execute(
            "INSERT INTO pending_links (code, account_id, display_name, phone, status, created_at) "
            "VALUES (?, ?, ?, ?, 'pending', ?)",
            (code, account_id, display_name, phone, now),
        )
    username = current_bot_username()
    bot_url = f"https://t.me/{username}?start={code}" if username else ""
    return 200, {"ok": True, "code": code, "bot_url": bot_url, "expires_in": LINK_TTL}


def api_link_status(code):
    code = code.strip().upper()
    if not re.fullmatch(r"[A-Z0-9]{6}", code):
        return 400, {"ok": False, "linked": False}
    with connect_db() as db:
        row = db.execute(
            "SELECT status, phone FROM pending_links WHERE code = ?", (code,)
        ).fetchone()
    return 200, {
        "ok": True,
        "linked": bool(row and row["status"] == "confirmed"),
        "phone": row["phone"] if row and row["status"] == "confirmed" else None,
    }


def api_unlink(data):
    account_id = str(data.get("account_id", "")).strip()[:80]
    if not account_id:
        return 400, {"ok": False}
    with connect_db() as db:
        db.execute("DELETE FROM telegram_links WHERE account_id = ?", (account_id,))
        db.execute("DELETE FROM pending_links WHERE account_id = ?", (account_id,))
    return 200, {"ok": True}


def api_notify(data):
    account_id = str(data.get("account_id", "")).strip()[:80]
    if not account_id:
        return 400, {"ok": False, "error": "account_id is required"}
    with connect_db() as db:
        row = db.execute(
            "SELECT chat_id FROM telegram_links WHERE account_id = ?", (account_id,)
        ).fetchone()
    if not row:
        return 200, {"ok": True, "delivered": False}

    text = (
        "Новое прохождение теста\n\n"
        f"Тест: {str(data.get('test', 'Тест'))[:160]}\n"
        f"Студент: {str(data.get('student', 'Студент'))[:120]}\n"
        f"Группа: {str(data.get('group', '—'))[:50]}\n"
        f"Результат: {str(data.get('score', '0'))[:12]} из {str(data.get('total', '0'))[:12]}\n"
        f"Оценка: {str(data.get('grade', '—'))[:4]}"
    )
    try:
        send_message(row["chat_id"], text)
    except Exception:
        log.exception("Unable to deliver notification")
        return 502, {"ok": False, "delivered": False}
    return 200, {"ok": True, "delivered": True}


class Handler(BaseHTTPRequestHandler):
    server_version = "IdrisStudy/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        log.info("%s %s", self.address_string(), fmt % args)

    def _headers(self, status, ctype, length):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.end_headers()

    def _send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if not length or length > 128 * 1024:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _serve_index(self, head=False):
        path = BASE_DIR / "index.html"
        try:
            body = path.read_bytes()
        except Exception:
            self._headers(404, "text/plain; charset=utf-8", 0)
            return
        self._headers(200, "text/html; charset=utf-8", len(body))
        if not head:
            self.wfile.write(body)

    def _hidden_404(self):
        self._send_json({"detail": "Not Found"}, 404)

    def do_HEAD(self):
        self._serve_index(head=True)

    def do_GET(self):
        try:
            url = urlparse(self.path)
            path = url.path
            if path == "/" or path == "/index.html":
                self._serve_index()
            elif path == "/health":
                self._send_json({
                    "ok": True, "bot": bool(BOT_TOKEN), "mode": TELEGRAM_MODE,
                    "webhook": f"{APP_URL}/telegram/webhook",
                })
            elif path == "/api/telegram/link-status":
                code = parse_qs(url.query).get("code", [""])[0]
                status, payload = api_link_status(code)
                self._send_json(payload, status)
            else:
                self._hidden_404()
        except Exception:
            log.exception("GET error")

    def do_POST(self):
        try:
            path = urlparse(self.path).path
            if path == "/telegram/webhook":
                if WEBHOOK_SECRET:
                    provided = self.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
                    if not secrets.compare_digest(provided, WEBHOOK_SECRET):
                        self._send_json({"ok": False}, 403)
                        return
                try:
                    handle_update(self._read_json())
                except Exception:
                    log.exception("Webhook update error")
                self._send_json({"ok": True})
            elif path == "/api/telegram/link":
                status, payload = api_create_link(self._read_json())
                self._send_json(payload, status)
            elif path == "/api/telegram/unlink":
                status, payload = api_unlink(self._read_json())
                self._send_json(payload, status)
            elif path == "/api/telegram/notify":
                status, payload = api_notify(self._read_json())
                self._send_json(payload, status)
            else:
                self._hidden_404()
        except Exception:
            log.exception("POST error")


# ---------------- entry ----------------

def port_busy(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


def run_web():
    servers = []
    candidates = [PORT] + [p for p in (3000, 8080) if p != PORT]
    for p in candidates:
        if port_busy(p):
            log.warning("Порт %s уже занят — пропускаю", p)
            continue
        try:
            srv = ThreadingHTTPServer(("0.0.0.0", p), Handler)
        except OSError as exc:
            log.warning("Не удалось занять порт %s: %s", p, exc)
            continue
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        log.info("IDRIS STUDY web запущен на 0.0.0.0:%s", p)
    return servers


def main():
    init_db()

    if BOT_TOKEN and TELEGRAM_MODE == "polling":
        threading.Thread(target=polling_loop, daemon=True).start()

    servers = run_web() if RUN_WEB else []

    if BOT_TOKEN and TELEGRAM_MODE == "webhook" and servers:
        threading.Thread(target=lambda: [time.sleep(1), configure_webhook()], daemon=True).start()

    log.info(
        "Бот запущен (режим=%s, web=%s)",
        TELEGRAM_MODE,
        ",".join(str(s.server_address[1]) for s in servers) or "off",
    )
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
