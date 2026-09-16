import hashlib
import logging
import os
import re
import secrets
import socket
import sqlite3
import threading
import time
from pathlib import Path

import requests
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("BOT_DB_PATH", BASE_DIR / "idris_bot.sqlite3"))
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

app = FastAPI(title="IDRIS STUDY", docs_url=None, redoc_url=None, openapi_url=None)


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
        "input_field_placeholder": "Нажмите кнопку ниже",
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
        send_message(
            chat_id,
            "Аккаунт подключён." if row else "Аккаунт пока не подключён.",
        )
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
            msg = str(exc)
            if "Conflict" in msg:
                try:
                    telegram("deleteWebhook", {"drop_pending_updates": False})
                except Exception:
                    pass
            log.warning("Polling error: %s", exc)
            time.sleep(4)


# ---------------- web ----------------

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
def index():
    return FileResponse(BASE_DIR / "index.html")


@app.get("/health")
def health():
    return {
        "ok": True,
        "bot": bool(BOT_TOKEN),
        "mode": TELEGRAM_MODE,
        "webhook": f"{APP_URL}/telegram/webhook",
    }


@app.post("/telegram/webhook")
async def telegram_webhook(request: Request):
    if WEBHOOK_SECRET:
        provided = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if not secrets.compare_digest(provided, WEBHOOK_SECRET):
            return JSONResponse({"ok": False}, status_code=403)
    try:
        handle_update(await request.json())
    except Exception:
        log.exception("Error while handling Telegram update")
    return {"ok": True}


@app.post("/api/telegram/link")
async def create_link(request: Request):
    data = await request.json()
    account_id = str(data.get("account_id", "")).strip()[:80]
    display_name = str(data.get("display_name", "")).strip()[:120]
    phone = normalize_phone(data.get("phone"))
    if not account_id or len(phone) < 10:
        return JSONResponse(
            {"ok": False, "error": "Укажите аккаунт и корректный номер"},
            status_code=400,
        )

    code = secrets.token_hex(3).upper()
    now = int(time.time())
    with connect_db() as db:
        db.execute("DELETE FROM pending_links WHERE account_id = ?", (account_id,))
        db.execute(
            """
            INSERT INTO pending_links
                (code, account_id, display_name, phone, status, created_at)
            VALUES (?, ?, ?, ?, 'pending', ?)
            """,
            (code, account_id, display_name, phone, now),
        )

    username = current_bot_username()
    bot_url = f"https://t.me/{username}?start={code}" if username else ""
    return {"ok": True, "code": code, "bot_url": bot_url, "expires_in": LINK_TTL}


@app.get("/api/telegram/link-status")
def link_status(code: str = ""):
    code = code.strip().upper()
    if not re.fullmatch(r"[A-Z0-9]{6}", code):
        return JSONResponse({"ok": False, "linked": False}, status_code=400)
    with connect_db() as db:
        row = db.execute(
            "SELECT status, phone FROM pending_links WHERE code = ?", (code,)
        ).fetchone()
    return {
        "ok": True,
        "linked": bool(row and row["status"] == "confirmed"),
        "phone": row["phone"] if row and row["status"] == "confirmed" else None,
    }


@app.post("/api/telegram/unlink")
async def api_unlink(request: Request):
    data = await request.json()
    account_id = str(data.get("account_id", "")).strip()[:80]
    if not account_id:
        return JSONResponse({"ok": False}, status_code=400)
    with connect_db() as db:
        db.execute("DELETE FROM telegram_links WHERE account_id = ?", (account_id,))
        db.execute("DELETE FROM pending_links WHERE account_id = ?", (account_id,))
    return {"ok": True}


@app.post("/api/telegram/notify")
async def notify(request: Request):
    data = await request.json()
    account_id = str(data.get("account_id", "")).strip()[:80]
    if not account_id:
        return JSONResponse({"ok": False, "error": "account_id is required"}, status_code=400)
    with connect_db() as db:
        row = db.execute(
            "SELECT chat_id FROM telegram_links WHERE account_id = ?", (account_id,)
        ).fetchone()
    if not row:
        return {"ok": True, "delivered": False}

    student = str(data.get("student", "Студент"))[:120]
    group = str(data.get("group", "—"))[:50]
    test = str(data.get("test", "Тест"))[:160]
    score = str(data.get("score", "0"))[:12]
    total = str(data.get("total", "0"))[:12]
    grade = str(data.get("grade", "—"))[:4]
    text = (
        "Новое прохождение теста\n\n"
        f"Тест: {test}\n"
        f"Студент: {student}\n"
        f"Группа: {group}\n"
        f"Результат: {score} из {total}\n"
        f"Оценка: {grade}"
    )
    try:
        send_message(row["chat_id"], text)
    except Exception:
        log.exception("Unable to deliver notification")
        return JSONResponse({"ok": False, "delivered": False}, status_code=502)
    return {"ok": True, "delivered": True}


@app.on_event("startup")
def on_startup():
    init_db()
    if BOT_TOKEN and TELEGRAM_MODE == "webhook":
        try:
            configure_webhook()
        except Exception:
            log.exception("Unable to configure Telegram webhook")


# ---------------- entry ----------------

def port_busy(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


def main():
    init_db()

    if BOT_TOKEN and TELEGRAM_MODE == "polling":
        threading.Thread(target=polling_loop, daemon=True).start()

    if not RUN_WEB:
        log.info("WEB disabled — running bot only (mode=%s)", TELEGRAM_MODE)
        while True:
            time.sleep(3600)

    import uvicorn

    if port_busy(PORT):
        log.warning(
            "Порт %s уже занят веб-сервером хостинга — свой веб-сервер не поднимаю. "
            "Бот продолжает работать (режим %s).",
            PORT, TELEGRAM_MODE,
        )
        while True:
            time.sleep(3600)

    log.info("Starting IDRIS STUDY web on 0.0.0.0:%s", PORT)
    try:
        uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")
    except OSError as exc:
        log.warning("Не удалось занять порт %s: %s. Бот продолжает работать.", PORT, exc)
        while True:
            time.sleep(3600)


if __name__ == "__main__":
    main()
