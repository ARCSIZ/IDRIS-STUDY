import hashlib
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path

import requests
from flask import Flask, jsonify, request, send_from_directory
from waitress import serve


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("BOT_DB_PATH", BASE_DIR / "idris_bot.sqlite3"))
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
APP_URL = os.getenv("APP_URL", "https://IdrisStudy.bothost.tech").rstrip("/")
PORT = int(os.getenv("PORT", "5000"))
BOT_USERNAME = os.getenv("BOT_USERNAME", "").lstrip("@").strip()
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "").strip()

if not WEBHOOK_SECRET and BOT_TOKEN:
    WEBHOOK_SECRET = hashlib.sha256(BOT_TOKEN.encode("utf-8")).hexdigest()[:48]

TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"
LINK_TTL = 20 * 60

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 128 * 1024
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("idris-bot")


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


def normalize_phone(value):
    digits = re.sub(r"\D", "", str(value or ""))
    if len(digits) == 11 and digits.startswith("8"):
        digits = "7" + digits[1:]
    return digits


def telegram(method, payload=None):
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN is not configured")
    response = requests.post(
        f"{TELEGRAM_API}/{method}", json=payload or {}, timeout=20
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
    if not BOT_TOKEN:
        log.warning("BOT_TOKEN is missing. Web server started without Telegram bot.")
        return
    try:
        current_bot_username()
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
    except Exception:
        log.exception("Unable to configure Telegram webhook")


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


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


@app.get("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/health")
def health():
    return jsonify(ok=True, bot=bool(BOT_TOKEN), webhook=f"{APP_URL}/telegram/webhook")


@app.post("/telegram/webhook")
def webhook():
    if WEBHOOK_SECRET:
        provided = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if not secrets.compare_digest(provided, WEBHOOK_SECRET):
            return jsonify(ok=False), 403
    try:
        handle_update(request.get_json(silent=True) or {})
    except Exception:
        log.exception("Error while handling Telegram update")
    return jsonify(ok=True)


@app.post("/api/telegram/link")
def create_link():
    data = request.get_json(silent=True) or {}
    account_id = str(data.get("account_id", "")).strip()[:80]
    display_name = str(data.get("display_name", "")).strip()[:120]
    phone = normalize_phone(data.get("phone"))
    if not account_id or len(phone) < 10:
        return jsonify(ok=False, error="Укажите аккаунт и корректный номер"), 400

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
    return jsonify(
        ok=True,
        code=code,
        bot_url=bot_url,
        expires_in=LINK_TTL,
    )


@app.get("/api/telegram/link-status")
def link_status():
    code = request.args.get("code", "").strip().upper()
    if not re.fullmatch(r"[A-Z0-9]{6}", code):
        return jsonify(ok=False, linked=False), 400
    with connect_db() as db:
        row = db.execute(
            "SELECT status, phone FROM pending_links WHERE code = ?", (code,)
        ).fetchone()
    return jsonify(
        ok=True,
        linked=bool(row and row["status"] == "confirmed"),
        phone=row["phone"] if row and row["status"] == "confirmed" else None,
    )


@app.post("/api/telegram/unlink")
def unlink():
    data = request.get_json(silent=True) or {}
    account_id = str(data.get("account_id", "")).strip()[:80]
    if not account_id:
        return jsonify(ok=False), 400
    with connect_db() as db:
        db.execute("DELETE FROM telegram_links WHERE account_id = ?", (account_id,))
        db.execute("DELETE FROM pending_links WHERE account_id = ?", (account_id,))
    return jsonify(ok=True)


@app.post("/api/telegram/notify")
def notify():
    data = request.get_json(silent=True) or {}
    account_id = str(data.get("account_id", "")).strip()[:80]
    if not account_id:
        return jsonify(ok=False, error="account_id is required"), 400
    with connect_db() as db:
        row = db.execute(
            "SELECT chat_id FROM telegram_links WHERE account_id = ?", (account_id,)
        ).fetchone()
    if not row:
        return jsonify(ok=True, delivered=False)

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
        return jsonify(ok=False, delivered=False), 502
    return jsonify(ok=True, delivered=True)


if __name__ == "__main__":
    init_db()
    threading.Thread(target=configure_webhook, daemon=True).start()
    log.info("Starting IDRIS STUDY on 0.0.0.0:%s", PORT)
    serve(app, host="0.0.0.0", port=PORT, threads=8)