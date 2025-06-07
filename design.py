#!/usr/bin/env python3
"""
Combined Telegram bot + Flask web UI for Netflix-mail fetching,
all served under “/” only (no other routes).
"""

import os
import json
import threading
import logging
import asyncio
import imaplib
import email
import datetime
import re
import io

from email.utils import parsedate_to_datetime
from dotenv import load_dotenv

from flask import (
    Flask, request, session, render_template, flash
)

from telegram import (
    Update, InlineKeyboardMarkup,
    InlineKeyboardButton, InputFile
)
from telegram.ext import (
    ApplicationBuilder, ContextTypes,
    CommandHandler, CallbackQueryHandler,
    MessageHandler, filters
)

from apscheduler.schedulers.background import BackgroundScheduler

# ────────────────────────────────────────────────────────────────
# Configuration & Globals
# ────────────────────────────────────────────────────────────────
load_dotenv()
BOT_TOKEN             = os.getenv("BOT_TOKEN")
OWNER_CHAT_ID         = int(os.getenv("OWNER_CHAT_ID", "0"))
ADMIN_CHAT_ID         = int(os.getenv("ADMIN_CHAT_ID", "0"))
WEB_PORT              = int(os.getenv("PORT", "5000"))
SECRET_KEY            = os.getenv("SECRET_KEY", os.urandom(24).hex())
CONTACT_SELLER_URL    = os.getenv("CONTACT_SELLER_URL", "#")
CONTACT_DEVELOPER_URL = os.getenv("CONTACT_DEVELOPER_URL", "#")

DB_FILE = "db.json"
db_lock = threading.Lock()

telegram_app = None
bot_loop     = None

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = SECRET_KEY

IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993

HOUSEHOLD_PATTERN = re.compile(
    r"https://www\.netflix\.com/(account/update-primary-location|account/travel/verify)\?[^\"'\]\s]+",
    re.IGNORECASE,
)
CODE_PATTERN = re.compile(r">[\s\r\n]*([0-9]{4})[\s\r\n]*<", re.IGNORECASE)
RESET_PATTERN = re.compile(r"https://www\.netflix\.com/password\?[^\"'\]\s]+", re.IGNORECASE)

# ────────────────────────────────────────────────────────────────
# Database Utilities
# ────────────────────────────────────────────────────────────────
def load_db():
    with db_lock:
        if not os.path.exists(DB_FILE):
            initial = {"credentials":[{"mail":"","pass":"","users":[]}]}
            with open(DB_FILE, "w") as f:
                json.dump(initial, f, indent=2)
            return initial
        with open(DB_FILE, "r") as f:
            return json.load(f)

async def send_db_to_owner():
    if not (telegram_app and bot_loop):
        return
    with open(DB_FILE, "rb") as f:
        data_bytes = f.read()
    bio = io.BytesIO(data_bytes)
    bio.name = "db.json"
    bio.seek(0)
    await telegram_app.bot.send_document(
        chat_id=OWNER_CHAT_ID,
        document=InputFile(bio, filename="db.json"),
        caption="📂 Updated database file",
    )

def save_db_and_notify(data):
    with db_lock:
        with open(DB_FILE, "w") as f:
            json.dump(data, f, indent=2)
    if bot_loop:
        asyncio.run_coroutine_threadsafe(send_db_to_owner(), bot_loop)

# ────────────────────────────────────────────────────────────────
# IMAP Helpers
# ────────────────────────────────────────────────────────────────
def connect_to_gmail_imap(mail_addr, app_pass):
    conn = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
    conn.login(mail_addr, app_pass)
    return conn

def search_last_hour(imap_conn, target_email):
    imap_conn.select("INBOX")
    raw_query = f'from:info@account.netflix.com to:{target_email} newer_than:1h'
    status, data = imap_conn.search(None, "X-GM-RAW", f'"{raw_query}"')
    return data[0].split() if status == "OK" else []

def filter_uids_last_15m(imap_conn, uids):
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    cutoff  = now_utc - datetime.timedelta(minutes=15)
    filtered = []
    for uid in uids:
        status, msg_data = imap_conn.fetch(uid, '(BODY.PEEK[HEADER.FIELDS (DATE)])')
        if status != "OK":
            continue
        raw_headers = msg_data[0][1].decode("utf-8", errors="ignore")
        date_header = next(
            (line[len("Date:"):].strip()
             for line in raw_headers.split("\r\n")
             if line.lower().startswith("date:")),
            None
        )
        if not date_header:
            continue
        try:
            msg_dt = parsedate_to_datetime(date_header)
        except Exception:
            continue
        if msg_dt.tzinfo is None:
            msg_dt = msg_dt.replace(tzinfo=datetime.timezone.utc)
        if cutoff <= msg_dt <= now_utc:
            filtered.append(uid)
    return filtered

def fetch_and_extract_household_link(imap_conn, uids):
    results = {}
    for uid in uids:
        status, data = imap_conn.fetch(uid, "(RFC822)")
        if status != "OK":
            continue
        msg = email.message_from_bytes(data[0][1])
        combined = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = part.get("Content-Disposition", "")
                if ctype in ("text/plain", "text/html") and "attachment" not in disp:
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or "utf-8"
                        combined += payload.decode(charset, errors="replace")
                    except Exception:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or "utf-8"
                combined = payload.decode(charset, errors="replace")
            except Exception:
                combined = ""
        m = HOUSEHOLD_PATTERN.search(combined)
        results[uid.decode()] = m.group(0).rstrip("]") if m else None
    return results

def fetch_and_extract_code(imap_conn, uids):
    results = {}
    for uid in uids:
        status, data = imap_conn.fetch(uid, "(RFC822)")
        if status != "OK":
            continue
        msg = email.message_from_bytes(data[0][1])
        combined = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = part.get("Content-Disposition", "")
                if ctype in ("text/plain", "text/html") and "attachment" not in disp:
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or "utf-8"
                        combined += payload.decode(charset, errors="replace")
                    except Exception:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or "utf-8"
                combined = payload.decode(charset, errors="replace")
            except Exception:
                combined = ""
        m = CODE_PATTERN.search(combined)
        results[uid.decode()] = m.group(1) if m else None
    return results

def fetch_and_extract_reset_link(imap_conn, uids):
    results = {}
    for uid in uids:
        status, data = imap_conn.fetch(uid, "(RFC822)")
        if status != "OK":
            continue
        msg = email.message_from_bytes(data[0][1])
        combined = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = part.get("Content-Disposition", "")
                if ctype in ("text/plain", "text/html") and "attachment" not in disp:
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or "utf-8"
                        combined += payload.decode(charset, errors="replace")
                    except Exception:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or "utf-8"
                combined = payload.decode(charset, errors="replace")
            except Exception:
                combined = ""
        mlist = RESET_PATTERN.findall(combined)
        results[uid.decode()] = mlist[0].rstrip("]") if mlist else None
    return results

# ────────────────────────────────────────────────────────────────
# Scheduler: daily decrement at midnight IST
# ────────────────────────────────────────────────────────────────
def decrement_token_days():
    try:
        data = load_db()
        creds = data.get("credentials", [])
        changed = False
        for cred in creds:
            for u in cred.get("users", []):
                if u["days"] > 0:
                    u["days"] -= 1
                    changed = True
                    if u["days"] == 0 and bot_loop:
                        asyncio.run_coroutine_threadsafe(
                            telegram_app.bot.send_message(
                                chat_id=ADMIN_CHAT_ID,
                                text=(
                                    f"🔔 Token `{u['token']}` has expired today. "
                                    "Please extend with /extend if needed."
                                ),
                                parse_mode="Markdown",
                            ),
                            bot_loop,
                        )
        if changed:
            save_db_and_notify(data)
    except Exception as e:
        err = str(e)
        if bot_loop:
            bio = io.BytesIO(err.encode("utf-8"))
            bio.name = "error.txt"
            bio.seek(0)
            asyncio.run_coroutine_threadsafe(
                telegram_app.bot.send_document(
                    chat_id=OWNER_CHAT_ID,
                    document=InputFile(bio, filename="error.txt"),
                    caption="❌ Error",
                ),
                bot_loop,
            )

scheduler = BackgroundScheduler(timezone="Asia/Kolkata")
scheduler.add_job(decrement_token_days, "cron", hour=0, minute=0)
scheduler.start()

# ────────────────────────────────────────────────────────────────
# Telegram Bot Handlers
# ────────────────────────────────────────────────────────────────
async def send_error_to_owner(txt):
    if bot_loop:
        bio = io.BytesIO(txt.encode("utf-8"))
        bio.name = "error.txt"
        bio.seek(0)
        try:
            await telegram_app.bot.send_document(
                chat_id=OWNER_CHAT_ID,
                document=InputFile(bio, filename="error.txt"),
                caption="❌ Error",
            )
        except Exception as e:
            logger.error(f"Failed to send error.txt: {e}")

def is_admin(cid):
    return cid == ADMIN_CHAT_ID

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        cid = update.effective_chat.id
        name = update.effective_user.full_name
        if not is_admin(cid):
            await update.message.reply_text("🚫 You are not authorized to use this bot.")
            return

        data = load_db()
        cred = data["credentials"][0]
        m, p = cred.get("mail", ""), cred.get("pass", "")

        if not m or not p:
            kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("Configure this bot", callback_data="cfg_start")]
            ])
            await update.message.reply_text(
                f"Hey {name},\nYou are the admin of this bot.\nYou didn't configure this bot yet.",
                reply_markup=kb,
            )
        else:
            try:
                await update.message.reply_text("⏳ Checking IMAP connectivity...")
                conn = connect_to_gmail_imap(m, p)
                conn.logout()
                kb = InlineKeyboardMarkup([
                    [InlineKeyboardButton("Reconfigure", callback_data="cfg_reconfigure")]
                ])
                await update.message.reply_text(
                    f"Hey {name},\nYou are the admin.\nYou are already configured.",
                    reply_markup=kb,
                )
            except Exception:
                cred["mail"] = ""
                cred["pass"] = ""
                save_db_and_notify(data)
                kb = InlineKeyboardMarkup([
                    [InlineKeyboardButton("Configure this bot", callback_data="cfg_start")]
                ])
                await update.message.reply_text(
                    f"Hey {name},\nYour stored credentials failed IMAP login.\nPlease configure again.",
                    reply_markup=kb,
                )
    except Exception as e:
        await send_error_to_owner(str(e))

async def cfg_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        q = update.callback_query
        await q.answer()
        data = load_db()
        cred = data["credentials"][0]

        if q.data == "cfg_start":
            await q.message.reply_text("Please send your Gmail address (only Gmail).")
        elif q.data == "cfg_reconfigure":
            cred["mail"] = ""
            cred["pass"] = ""
            save_db_and_notify(data)
            await q.message.reply_text("Credentials cleared. Please send your Gmail address.")
        elif q.data == "cfg_wrong_mail":
            await q.message.reply_text("Okay, please send the correct Gmail address.")
    except Exception as e:
        await send_error_to_owner(str(e))

async def cfg_mail_received(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        cid = update.effective_chat.id
        if not is_admin(cid):
            return
        mail = update.message.text.strip()
        if "@" not in mail or not mail.endswith("gmail.com"):
            kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("Wrong mail", callback_data="cfg_wrong_mail")]
            ])
            await update.message.reply_text(
                "That doesn't look like a Gmail address. Please send a valid Gmail address.",
                reply_markup=kb,
            )
            return
        context.user_data["cfg_mail"] = mail
        kb = InlineKeyboardMarkup([
            [
                InlineKeyboardButton(
                    "How to get app password",
                    url="https://support.google.com/accounts/answer/185833"
                ),
                InlineKeyboardButton("Wrong mail", callback_data="cfg_wrong_mail"),
            ]
        ])
        await update.message.reply_text("Please send your Gmail app password.", reply_markup=kb)
    except Exception as e:
        await send_error_to_owner(str(e))

async def cfg_pass_received(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        cid = update.effective_chat.id
        if not is_admin(cid):
            return
        if "cfg_mail" not in context.user_data:
            return
        mail = context.user_data["cfg_mail"]
        app_pass = update.message.text.strip()

        msg = await update.message.reply_text("⏳ Connecting to your IMAP...")
        try:
            conn = connect_to_gmail_imap(mail, app_pass)
            conn.logout()
        except Exception:
            await msg.edit_text("❌ Wrong credentials. IMAP login failed. Please try again.")
            return

        data = load_db()
        cred = data["credentials"][0]
        cred["mail"] = mail
        cred["pass"] = app_pass
        save_db_and_notify(data)

        await msg.edit_text("✅ Successfully connected to your IMAP.")
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("Commands", url="https://example.com/commands-documentation")]
        ])
        await update.message.reply_text(
            "Click the button below to know all commands:",
            reply_markup=kb,
        )
        context.user_data.pop("cfg_mail", None)
    except Exception as e:
        await send_error_to_owner(str(e))

def generate_random_token(length=10):
    import random, string
    chars = string.ascii_uppercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))

async def gen_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        cid = update.effective_chat.id
        if not is_admin(cid):
            await update.message.reply_text("🚫 You are not authorized to use this command.")
            return
        args = context.args
        if len(args) != 1 or not args[0].isdigit():
            await update.message.reply_text("Usage: /gen <days>")
            return
        days = int(args[0])
        token = generate_random_token(10)
        user_obj = {
            "token": token,
            "days": days,
            "household": True,
            "signin": False,
            "reset": False,
        }
        data = load_db()
        data["credentials"][0]["users"].append(user_obj)
        save_db_and_notify(data)

        kb = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("📍 Household ✅", callback_data=f"tg_{token}_household"),
                InlineKeyboardButton("🔑 Signin Code ❌", callback_data=f"tg_{token}_signin"),
            ],
            [
                InlineKeyboardButton("🛡️ Pass Reset ❌", callback_data=f"tg_{token}_reset"),
                InlineKeyboardButton("Remove Token ⛔️", callback_data=f"tg_{token}_remove"),
            ],
        ])
        await update.message.reply_text(
            f"Generated token: `{token}` for {days} days with access to:",
            reply_markup=kb,
            parse_mode="Markdown",
        )
    except Exception as e:
        await send_error_to_owner(str(e))

async def toggle_access_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        q = update.callback_query
        await q.answer()
        data = load_db()
        users = data["credentials"][0]["users"]
        _, token, action = q.data.split("_", 2)
        u = next((x for x in users if x["token"] == token), None)
        if not u:
            await q.message.edit_text(f"🚫 Token `{token}` not found.", parse_mode="Markdown")
            return
        if action == "remove":
            users.remove(u)
            save_db_and_notify(data)
            await q.message.edit_text(f"✅ Token `{token}` has been removed.")
            return
        u[action] = not u[action]
        save_db_and_notify(data)

        kb_house = f"📍 Household {'✅' if u['household'] else '❌'}"
        kb_sign  = f"🔑 Signin Code {'✅' if u['signin'] else '❌'}"
        kb_reset = f"🛡️ Pass Reset {'✅' if u['reset'] else '❌'}"
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton(kb_house, callback_data=f"tg_{token}_household"),
             InlineKeyboardButton(kb_sign, callback_data=f"tg_{token}_signin")],
            [InlineKeyboardButton(kb_reset, callback_data=f"tg_{token}_reset"),
             InlineKeyboardButton("Remove Token ⛔️", callback_data=f"tg_{token}_remove")],
        ])
        await q.message.edit_text(
            f"Token: `{token}` access updated. Current settings:",
            reply_markup=kb,
            parse_mode="Markdown",
        )
    except Exception as e:
        await send_error_to_owner(str(e))

async def extend_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        cid = update.effective_chat.id
        if not is_admin(cid):
            await update.message.reply_text("🚫 You are not authorized to use this command.")
            return
        args = context.args
        if len(args) != 2 or not args[1].isdigit():
            await update.message.reply_text("Usage: /extend <token> <days_to_add>")
            return
        token, add = args[0], int(args[1])
        data = load_db()
        users = data["credentials"][0]["users"]
        u = next((x for x in users if x["token"] == token), None)
        if not u:
            await update.message.reply_text(f"🚫 Token `{token}` is invalid.", parse_mode="Markdown")
            return
        u["days"] += add
        save_db_and_notify(data)

        kb_house = f"📍 Household {'✅' if u['household'] else '❌'}"
        kb_sign  = f"🔑 Signin Code {'✅' if u['signin'] else '❌'}"
        kb_reset = f"🛡️ Pass Reset {'✅' if u['reset'] else '❌'}"
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton(kb_house, callback_data=f"tg_{token}_household"),
             InlineKeyboardButton(kb_sign, callback_data=f"tg_{token}_signin")],
            [InlineKeyboardButton(kb_reset, callback_data=f"tg_{token}_reset"),
             InlineKeyboardButton("Remove Token ⛔️", callback_data=f"tg_{token}_remove")],
        ])
        await update.message.reply_text(
            f"✅ Extended `{token}` by {add} days. It now has {u['days']} days left.\nAccess:",
            reply_markup=kb,
            parse_mode="Markdown",
        )
    except Exception as e:
        await send_error_to_owner(str(e))

async def remove_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        cid = update.effective_chat.id
        if not is_admin(cid):
            await update.message.reply_text("🚫 You are not authorized to use this command.")
            return
        args = context.args
        if len(args) != 1:
            await update.message.reply_text("Usage: /remove <token>")
            return
        token = args[0]
        data = load_db()
        users = data["credentials"][0]["users"]
        u = next((x for x in users if x["token"] == token), None)
        if not u:
            await update.message.reply_text(f"🚫 Token `{token}` is invalid.", parse_mode="Markdown")
            return
        users.remove(u)
        save_db_and_notify(data)
        await update.message.reply_text(f"✅ Successfully removed `{token}`.")
    except Exception as e:
        await send_error_to_owner(str(e))

async def users_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        cid = update.effective_chat.id
        if not is_admin(cid):
            await update.message.reply_text("🚫 You are not authorized to use this command.")
            return
        data = load_db()
        users = data["credentials"][0]["users"]
        out = {"users": [
            {"token": u["token"], "days": u["days"],
             "household": u["household"], "signin": u["signin"], "reset": u["reset"]}
            for u in users
        ]}
        jb = json.dumps(out, indent=2).encode("utf-8")
        bio = io.BytesIO(jb)
        bio.name = "users.json"
        bio.seek(0)
        await update.message.reply_document(
            document=InputFile(bio, filename="users.json"),
            caption="📜 List of approved users (tokens)."
        )
    except Exception as e:
        await send_error_to_owner(str(e))

async def terminate_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        cid = update.effective_chat.id
        if not is_admin(cid):
            await update.message.reply_text("🚫 You are not authorized to use this command.")
            return
        data = load_db()
        data["credentials"][0]["users"] = []
        save_db_and_notify(data)
        await update.message.reply_text("✅ All tokens have been removed.")
    except Exception as e:
        await send_error_to_owner(str(e))

async def reset_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        cid = update.effective_chat.id
        if not is_admin(cid):
            await update.message.reply_text("🚫 You are not authorized to use this command.")
            return
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)
        await update.message.reply_text("⚙️ Factory reset completed. Please send /start to configure again.")
    except Exception as e:
        await send_error_to_owner(str(e))

async def info_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        cid = update.effective_chat.id
        if not is_admin(cid):
            await update.message.reply_text("🚫 You are not authorized to use this command.")
            return
        args = context.args
        if len(args) != 1:
            await update.message.reply_text("Usage: /info <token>")
            return
        token = args[0]
        data = load_db()
        users = data["credentials"][0]["users"]
        u = next((x for x in users if x["token"] == token), None)
        if not u:
            await update.message.reply_text(f"🚫 Token `{token}` is invalid.", parse_mode="Markdown")
            return
        days = u["days"]
        text = (
            f"*Token:* `{token}`\n"
            f"*Days left:* {days}\n"
            "*Access to:*"
        )
        kb_house = f"📍 Household {'✅' if u['household'] else '❌'}"
        kb_sign  = f"🔑 Signin Code {'✅' if u['signin'] else '❌'}"
        kb_reset = f"🛡️ Pass Reset {'✅' if u['reset'] else '❌'}"
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton(kb_house, callback_data=f"tg_{token}_household"),
             InlineKeyboardButton(kb_sign, callback_data=f"tg_{token}_signin")],
            [InlineKeyboardButton(kb_reset, callback_data=f"tg_{token}_reset"),
             InlineKeyboardButton("Remove Token ⛔️", callback_data=f"tg_{token}_remove")],
        ])
        await update.message.reply_text(text, parse_mode="Markdown", reply_markup=kb)
    except Exception as e:
        await send_error_to_owner(str(e))

async def notify_admin_token_used(token: str, action: str):
    try:
        labels = {
            "household": "Netflix household link",
            "signin":    "Netflix signin code",
            "reset":     "Netflix password reset link",
        }
        at = labels.get(action, "Netflix mail")
        txt = f"🔔 Token `{token}` requested for {at} and was successfully served."
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("Remove Token ⛔️", callback_data=f"tg_{token}_remove")]])
        await telegram_app.bot.send_message(
            chat_id=ADMIN_CHAT_ID,
            text=txt,
            reply_markup=kb,
            parse_mode="Markdown",
        )
    except Exception as e:
        logger.error(f"Failed to notify admin: {e}")

async def invalid_admin_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        cid = update.effective_chat.id
        if not is_admin(cid):
            return
        txt = update.message.text or ""
        if txt.strip().lower().startswith("/command"):
            kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("Read Manual", url="https://example.com/commands-documentation")]
            ])
            await update.message.reply_text(
                "Click the button below to know commands and about this bot:",
                reply_markup=kb
            )
        else:
            await update.message.reply_text(
                "Invalid message/command. Send /commands to know the usable commands."
            )
    except Exception as e:
        await send_error_to_owner(str(e))

def run_telegram():
    global bot_loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    bot_loop = loop
    telegram_app.run_polling(stop_signals=None)

# ────────────────────────────────────────────────────────────────
# Single Flask Route ("/")
# ────────────────────────────────────────────────────────────────
@app.route("/", methods=["GET","POST"])
def index():
    # Logout
    if request.method == "POST" and "logout" in request.form:
        session.clear()
        return render_template(
            "token_form.html",
            contact_seller_url=CONTACT_SELLER_URL,
            contact_developer_url=CONTACT_DEVELOPER_URL,
        )

    # Already logged in & GET → dashboard
    if "token" in session and request.method == "GET":
        token = session["token"]
        data  = load_db()
        u     = next((x for x in data["credentials"][0]["users"] if x["token"] == token), None)
        if not u:
            session.clear()
            flash("Session invalidated. Please log in again.")
            return render_template(
                "token_form.html",
                contact_seller_url=CONTACT_SELLER_URL,
                contact_developer_url=CONTACT_DEVELOPER_URL,
            )
        return render_template(
            "dashboard.html",
            token=token,
            days=u["days"],
            household=u["household"],
            signin=u["signin"],
            reset=u["reset"],
            contact_seller_url=CONTACT_SELLER_URL,
            contact_developer_url=CONTACT_DEVELOPER_URL,
        )

    # POST handling
    if request.method == "POST":
        # 1) Login form
        if "token" in request.form and "action" not in request.form and "logout" not in request.form:
            tok = request.form["token"].strip()
            data = load_db()
            u    = next((x for x in data["credentials"][0]["users"] if x["token"] == tok), None)
            if not u:
                flash("Invalid token. Please try again.")
                return render_template(
                    "token_form.html",
                    contact_seller_url=CONTACT_SELLER_URL,
                    contact_developer_url=CONTACT_DEVELOPER_URL,
                )
            # Allow expired tokens to log in
            if u["days"] == 0:
                flash(f"Token `{tok}` has expired. You may still log in; contact your supplier to extend.")
                session["token"] = tok
                if bot_loop:
                    asyncio.run_coroutine_threadsafe(
                        telegram_app.bot.send_message(
                            chat_id=ADMIN_CHAT_ID,
                            text=(
                                f"🔔 Token `{tok}` was used on the webpage but has expired. "
                                "Please extend with /extend if needed."
                            ),
                            parse_mode="Markdown",
                        ),
                        bot_loop,
                    )
            else:
                session["token"] = tok
            # Render dashboard
            token = session["token"]
            data  = load_db()
            u     = next((x for x in data["credentials"][0]["users"] if x["token"] == token), None)
            return render_template(
                "dashboard.html",
                token=token,
                days=u["days"],
                household=u["household"],
                signin=u["signin"],
                reset=u["reset"],
                contact_seller_url=CONTACT_SELLER_URL,
                contact_developer_url=CONTACT_DEVELOPER_URL,
            )

        # 2) Dashboard action select → mail_request
        if "action" in request.form and "email_addr" not in request.form:
            action = request.form["action"]
            names  = {
                "household":"Household Mail 📍",
                "signin":   "Signin Code 🔑",
                "reset":    "Password Reset Link 🛡️",
            }
            return render_template(
                "mail_request.html",
                action=action,
                action_name=names.get(action, ""),
                contact_seller_url=CONTACT_SELLER_URL,
                contact_developer_url=CONTACT_DEVELOPER_URL,
            )

        # 3) mail_request POST → fetch & result
        if "action" in request.form and "email_addr" in request.form:
            action     = request.form["action"]
            email_addr = request.form["email_addr"].strip()
            names      = {
                "household":"Household Mail 📍",
                "signin":   "Signin Code 🔑",
                "reset":    "Password Reset Link 🛡️",
            }
            action_name=names.get(action, "")
            # Go back?
            if request.form.get("go") == "back":
                token = session["token"]
                data  = load_db()
                u     = next((x for x in data["credentials"][0]["users"] if x["token"] == token), None)
                return render_template(
                    "dashboard.html",
                    token=token,
                    days=u["days"],
                    household=u["household"],
                    signin=u["signin"],
                    reset=u["reset"],
                    contact_seller_url=CONTACT_SELLER_URL,
                    contact_developer_url=CONTACT_DEVELOPER_URL,
                )
            # Otherwise fetch:
            results = []
            data    = load_db()
            cred    = data["credentials"][0]
            try:
                imap_conn = connect_to_gmail_imap(cred["mail"], cred["pass"])
                uids       = search_last_hour(imap_conn, email_addr)
                if uids:
                    recent = filter_uids_last_15m(imap_conn, uids)
                    if recent:
                        if action == "household":
                            fetched = fetch_and_extract_household_link(imap_conn, recent)
                            for _, link in fetched.items():
                                if link:
                                    results.append({"email_addr": email_addr, "link": link})
                        elif action == "signin":
                            fetched = fetch_and_extract_code(imap_conn, recent)
                            for _, code in fetched.items():
                                if code:
                                    results.append({"email_addr": email_addr, "code": code})
                        else:
                            fetched = fetch_and_extract_reset_link(imap_conn, recent)
                            for _, link in fetched.items():
                                if link:
                                    results.append({"email_addr": email_addr, "link": link})
                imap_conn.logout()
            except Exception as e:
                err = str(e)
                if bot_loop:
                    bio = io.BytesIO(err.encode("utf-8"))
                    bio.name = "error.txt"
                    bio.seek(0)
                    asyncio.run_coroutine_threadsafe(
                        telegram_app.bot.send_document(
                            chat_id=OWNER_CHAT_ID,
                            document=InputFile(bio, filename="error.txt"),
                            caption="❌ Error",
                        ),
                        bot_loop,
                    )

            # Notify admin if served
            if results and bot_loop:
                asyncio.run_coroutine_threadsafe(
                    telegram_app.bot.send_message(
                        chat_id=ADMIN_CHAT_ID,
                        text=(
                            f"🔔 Token `{session['token']}` requested for "
                            f"{action_name.lower()} and was successfully served."
                        ),
                        parse_mode="Markdown",
                        reply_markup=InlineKeyboardMarkup([
                            [InlineKeyboardButton("Remove Token ⛔️", callback_data=f"tg_{session['token']}_remove")]
                        ]),
                    ),
                    bot_loop,
                )

            return render_template(
                "result.html",
                action_name=action_name,
                action=action,
                results=results,
                contact_seller_url=CONTACT_SELLER_URL,
                contact_developer_url=CONTACT_DEVELOPER_URL,
            )

    # Default GET → login
    return render_template(
        "token_form.html",
        contact_seller_url=CONTACT_SELLER_URL,
        contact_developer_url=CONTACT_DEVELOPER_URL,
    )

def main():
    global telegram_app, bot_loop

    telegram_app = ApplicationBuilder().token(BOT_TOKEN).build()

    telegram_app.add_handler(CommandHandler("start", start))
    telegram_app.add_handler(CallbackQueryHandler(cfg_callback, pattern=r"^cfg_"))
    telegram_app.add_handler(MessageHandler(filters.Regex(r"^[\w\.-]+@gmail\.com$"), cfg_mail_received))
    telegram_app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), cfg_pass_received))
    telegram_app.add_handler(CommandHandler("gen", gen_command))
    telegram_app.add_handler(CallbackQueryHandler(toggle_access_callback, pattern=r"^tg_"))
    telegram_app.add_handler(CommandHandler("extend", extend_command))
    telegram_app.add_handler(CommandHandler("remove", remove_command))
    telegram_app.add_handler(CommandHandler("users", users_command))
    telegram_app.add_handler(CommandHandler("terminate", terminate_command))
    telegram_app.add_handler(CommandHandler("reset", reset_command))
    telegram_app.add_handler(CommandHandler("info", info_command))
    telegram_app.add_handler(MessageHandler(filters.ALL, invalid_admin_message))

    async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
        await send_error_to_owner(str(context.error))

    telegram_app.add_error_handler(error_handler)

    threading.Thread(target=run_telegram, daemon=True).start()
    app.run(host="0.0.0.0", port=WEB_PORT)

if __name__ == "__main__":
    main()
