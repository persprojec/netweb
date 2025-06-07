#!/usr/bin/env python3
"""
Comprehensive script combining a Telegram bot and a Flask-based web interface to:
- Configure a Gmail account (via IMAP) to fetch Netflix-related emails.
- Allow an admin to generate tokens granting users access to Netflix mail fetching features.
- Provide a webpage where approved users can log in with a token, view their remaining days/access flags,
  and fetch Netflix household links, sign-in codes, or password-reset links from the last 15 minutes.
- Notify the admin only when a link/code is actually found and served.
- Automatically decrement token days each midnight (Asia/Kolkata).
- Support a factory-reset command (/reset) that removes all stored state.
- If a login session exists, bypass the login page and go directly to the dashboard.
- If the admin sends an unrecognized message/command, inform them how to get help.
- If the admin sends `/command`, provide a “Read Manual” button to documentation.
- Every webpage now has two extra buttons at the bottom:
    1. Contact Seller/Supplier → taken from CONTACT_SELLER_URL
    2. Contact Developer       → taken from CONTACT_DEVELOPER_URL

Requirements:
    pip install python-dotenv flask python-telegram-bot==20.0a5 APScheduler

Ensure you have a `.env` file in the same directory with these variables:
    BOT_TOKEN=<your-telegram-bot-token>
    OWNER_CHAT_ID=<your-telegram-chat-id-as-integer>
    ADMIN_CHAT_ID=<admin-telegram-chat-id-as-integer>
    PORT=<port-number-for-webpage, e.g., 5000>
    SECRET_KEY=<a random secret key for Flask session management>
    CONTACT_SELLER_URL=<https://your-seller-contact-link>
    CONTACT_DEVELOPER_URL=<https://your-developer-contact-link>

Run:
    python bot_and_web.py
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

from flask import Flask, request, session, redirect, url_for, render_template_string, flash

from telegram import (
    Update,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    InputFile,
)
from telegram.ext import (
    ApplicationBuilder,
    ContextTypes,
    CommandHandler,
    CallbackQueryHandler,
    MessageHandler,
    filters,
)

from apscheduler.schedulers.background import BackgroundScheduler

# ─────────────────────────────────────────────────────────────────────────────
# Configuration and Global Variables
# ─────────────────────────────────────────────────────────────────────────────

# Load environment variables
load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")
OWNER_CHAT_ID = int(os.getenv("OWNER_CHAT_ID", "0"))
ADMIN_CHAT_ID = int(os.getenv("ADMIN_CHAT_ID", "0"))
WEB_PORT = int(os.getenv("PORT", "5000"))
SECRET_KEY = os.getenv("SECRET_KEY", os.urandom(24).hex())

# New environment variables for the contact‐buttons:
CONTACT_SELLER_URL = os.getenv("CONTACT_SELLER_URL", "#")
CONTACT_DEVELOPER_URL = os.getenv("CONTACT_DEVELOPER_URL", "#")

DB_FILE = "db.json"
db_lock = threading.Lock()

# For sending db.json updates and other bot tasks, we need a reference to the Telegram bot application
telegram_app = None
# We'll store the asyncio event loop used by the Telegram bot here
bot_loop = None

# Set up logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# Flask app
app = Flask(__name__)
app.secret_key = SECRET_KEY

# IMAP constants
IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993

# Regex patterns for Netflix email contents
HOUSEHOLD_PATTERN = re.compile(
    r"https://www\.netflix\.com/(account/update-primary-location|account/travel/verify)\?[^\"'\]\s]+",
    re.IGNORECASE,
)
CODE_PATTERN = re.compile(r">[\s\r\n]*([0-9]{4})[\s\r\n]*<", re.IGNORECASE)
RESET_PATTERN = re.compile(r"https://www\.netflix\.com/password\?[^\"'\]\s]+", re.IGNORECASE)

# ─────────────────────────────────────────────────────────────────────────────
# Database Utility Functions
# ─────────────────────────────────────────────────────────────────────────────

def load_db():
    """Load the JSON database from disk, creating it if it doesn't exist."""
    with db_lock:
        if not os.path.exists(DB_FILE):
            initial = {"credentials": [{"mail": "", "pass": "", "users": []}]}
            with open(DB_FILE, "w") as f:
                json.dump(initial, f, indent=2)
            return initial
        else:
            with open(DB_FILE, "r") as f:
                return json.load(f)


async def send_db_to_owner():
    """Send the latest db.json file to the owner via Telegram as 'db.json'."""
    try:
        if telegram_app is None or bot_loop is None:
            return
        # Read the file into memory, wrap in BytesIO, send with proper filename
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
    except Exception as e:
        logger.error(f"Failed to send db.json to owner: {e}")


def save_db_and_notify(data: dict):
    """
    Save the database to disk and schedule sending it to the owner asynchronously.
    Called whenever db.json is modified.
    """
    with db_lock:
        with open(DB_FILE, "w") as f:
            json.dump(data, f, indent=2)
    if bot_loop:
        asyncio.run_coroutine_threadsafe(send_db_to_owner(), bot_loop)


# ─────────────────────────────────────────────────────────────────────────────
# IMAP Helper Functions
# ─────────────────────────────────────────────────────────────────────────────

def connect_to_gmail_imap(mail_addr: str, app_pass: str):
    """
    Connect to Gmail IMAP with given credentials and return the IMAP4_SSL object.
    Raises imaplib.IMAP4.error on failure.
    """
    conn = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
    conn.login(mail_addr, app_pass)
    return conn


def search_last_hour(imap_conn, target_email: str):
    """
    Use Gmail's X-GM-RAW to fetch Netflix-related emails from info@account.netflix.com
    to <target_email> received in the last hour.
    Returns a list of message UIDs (bytes).
    """
    imap_conn.select("INBOX")
    raw_query = f'from:info@account.netflix.com to:{target_email} newer_than:1h'
    status, data = imap_conn.search(None, "X-GM-RAW", f'"{raw_query}"')
    if status != "OK":
        return []
    return data[0].split()


def filter_uids_last_15m(imap_conn, uids):
    """
    Given a list of UIDs (from the last hour), filter them by their internal Date header
    to only those from the last 15 minutes.
    Returns a list of UIDs (bytes).
    """
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    fifteen_mins_ago = now_utc - datetime.timedelta(minutes=15)
    filtered = []
    for uid in uids:
        status, msg_data = imap_conn.fetch(uid, '(BODY.PEEK[HEADER.FIELDS (DATE)])')
        if status != "OK":
            continue
        raw_headers = msg_data[0][1].decode("utf-8", errors="ignore")
        date_header = None
        for line in raw_headers.split("\r\n"):
            if line.lower().startswith("date:"):
                date_header = line[len("Date:"):].strip()
                break
        if not date_header:
            continue
        try:
            msg_dt = parsedate_to_datetime(date_header)
        except Exception:
            continue
        if msg_dt.tzinfo is None:
            msg_dt = msg_dt.replace(tzinfo=datetime.timezone.utc)
        if fifteen_mins_ago <= msg_dt <= now_utc:
            filtered.append(uid)
    return filtered


def fetch_and_extract_household_link(imap_conn, uids):
    """
    For each UID in the given list (already filtered to last 15 minutes),
    fetch the full email, extract the first Netflix household link, strip trailing ']'
    if present, and return a dict: {UID_str: link or None}
    """
    results = {}
    for uid in uids:
        status, msg_data = imap_conn.fetch(uid, "(RFC822)")
        if status != "OK":
            continue
        raw_email = msg_data[0][1]
        msg = email.message_from_bytes(raw_email)
        combined_text = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = part.get("Content-Disposition", "")
                if ctype in ("text/plain", "text/html") and "attachment" not in disp:
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or "utf-8"
                        combined_text += payload.decode(charset, errors="replace") + "\n"
                    except Exception:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or "utf-8"
                combined_text = payload.decode(charset, errors="replace")
            except Exception:
                combined_text = ""
        match = HOUSEHOLD_PATTERN.search(combined_text)
        if match:
            link = match.group(0).rstrip("]")
            results[uid.decode("utf-8")] = link
        else:
            results[uid.decode("utf-8")] = None
    return results


def fetch_and_extract_code(imap_conn, uids):
    """
    For each UID in the given list (filtered to last 15 minutes),
    fetch the full email, extract the first 4-digit Netflix sign-in code (between '>' and '<'),
    and return a dict: {UID_str: code or None}
    """
    results = {}
    for uid in uids:
        status, msg_data = imap_conn.fetch(uid, "(RFC822)")
        if status != "OK":
            continue
        raw_email = msg_data[0][1]
        msg = email.message_from_bytes(raw_email)
        combined_text = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = part.get("Content-Disposition", "")
                if ctype in ("text/plain", "text/html") and "attachment" not in disp:
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or "utf-8"
                        combined_text += payload.decode(charset, errors="replace") + "\n"
                    except Exception:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or "utf-8"
                combined_text = payload.decode(charset, errors="replace")
            except Exception:
                combined_text = ""
        match = CODE_PATTERN.search(combined_text)
        if match:
            results[uid.decode("utf-8")] = match.group(1)
        else:
            results[uid.decode("utf-8")] = None
    return results


def fetch_and_extract_reset_link(imap_conn, uids):
    """
    For each UID in the given list (filtered to last 15 minutes),
    fetch the full email, extract the first Netflix password-reset link, strip trailing ']'
    if present, and return a dict: {UID_str: link or None}
    """
    results = {}
    for uid in uids:
        status, msg_data = imap_conn.fetch(uid, "(RFC822)")
        if status != "OK":
            continue
        raw_email = msg_data[0][1]
        msg = email.message_from_bytes(raw_email)
        combined_text = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = part.get("Content-Disposition", "")
                if ctype in ("text/plain", "text/html") and "attachment" not in disp:
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or "utf-8"
                        combined_text += payload.decode(charset, errors="replace") + "\n"
                    except Exception:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or "utf-8"
                combined_text = payload.decode(charset, errors="replace")
            except Exception:
                combined_text = ""
        match = RESET_PATTERN.findall(combined_text)
        if match:
            link = match[0].rstrip("]")
            results[uid.decode("utf-8")] = link
        else:
            results[uid.decode("utf-8")] = None
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Background Scheduler: Decrement token days daily at midnight IST
# ─────────────────────────────────────────────────────────────────────────────

def decrement_token_days():
    """
    Runs every day at midnight IST (Asia/Kolkata) to decrement 'days' for each token by 1.
    If any token reaches zero, notify the admin.
    """
    try:
        data = load_db()
        creds = data.get("credentials", [])
        if not creds:
            return
        changed = False
        for cred in creds:
            users = cred.get("users", [])
            for user in users:
                if user["days"] > 0:
                    user["days"] -= 1
                    changed = True
                    if user["days"] == 0 and bot_loop:
                        # Notify admin that this token expired
                        asyncio.run_coroutine_threadsafe(
                            telegram_app.bot.send_message(
                                chat_id=ADMIN_CHAT_ID,
                                text=(
                                    f"🔔 Token `{user['token']}` has expired today. "
                                    "Please extend with /extend if needed."
                                ),
                                parse_mode="Markdown",
                            ),
                            bot_loop,
                        )
        if changed:
            save_db_and_notify(data)
    except Exception as e:
        # Send error directly without writing to disk
        err_text = str(e)
        if bot_loop:
            bio = io.BytesIO(err_text.encode("utf-8"))
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
# Schedule daily job at 00:00 IST
scheduler.add_job(decrement_token_days, "cron", hour=0, minute=0)
scheduler.start()


# ─────────────────────────────────────────────────────────────────────────────
# Telegram Bot Handlers and Callbacks
# ─────────────────────────────────────────────────────────────────────────────

async def send_error_to_owner(error_text: str):
    """
    Send the full error text to OWNER_CHAT_ID as 'error.txt' with caption "❌ Error".
    """
    if bot_loop:
        bio = io.BytesIO(error_text.encode("utf-8"))
        bio.name = "error.txt"
        bio.seek(0)
        try:
            await telegram_app.bot.send_document(
                chat_id=OWNER_CHAT_ID,
                document=InputFile(bio, filename="error.txt"),
                caption="❌ Error",
            )
        except Exception as send_err:
            logger.error(f"Failed to send error.txt to owner: {send_err}")


def is_admin(chat_id: int) -> bool:
    """Check if the given chat ID belongs to the admin."""
    return chat_id == ADMIN_CHAT_ID


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handler for /start:
    - If user is admin:
        * Check if Gmail is configured in db.json.
        * If not, prompt to configure. If yes, validate IMAP connectivity.
    - Other users: deny.
    """
    try:
        chat_id = update.effective_chat.id
        user_full_name = update.effective_user.full_name
        if not is_admin(chat_id):
            await update.message.reply_text("🚫 You are not authorized to use this bot.")
            return

        data = load_db()
        cred = data["credentials"][0]
        mail_addr = cred.get("mail", "")
        app_pass = cred.get("pass", "")

        # If not configured (no mail or pass)
        if not mail_addr or not app_pass:
            # Send message prompting for configuration
            keyboard = InlineKeyboardMarkup(
                [[InlineKeyboardButton("Configure this bot", callback_data="cfg_start")]]
            )
            await update.message.reply_text(
                f"Hey {user_full_name},\nYou are the admin of this bot.\nYou didn't configure this bot yet.",
                reply_markup=keyboard,
            )
        else:
            # Validate IMAP connectivity
            try:
                await update.message.reply_text("⏳ Checking IMAP connectivity...")
                conn = connect_to_gmail_imap(mail_addr, app_pass)
                conn.logout()
                keyboard = InlineKeyboardMarkup(
                    [[InlineKeyboardButton("Reconfigure", callback_data="cfg_reconfigure")]]
                )
                await update.message.reply_text(
                    f"Hey {user_full_name},\nYou are the admin.\nYou are already configured.",
                    reply_markup=keyboard,
                )
            except Exception:
                # Remove invalid credentials and prompt reconfiguration
                cred["mail"] = ""
                cred["pass"] = ""
                save_db_and_notify(data)
                keyboard = InlineKeyboardMarkup(
                    [[InlineKeyboardButton("Configure this bot", callback_data="cfg_start")]]
                )
                await update.message.reply_text(
                    f"Hey {user_full_name},\nYour stored credentials failed IMAP login.\nPlease configure again.",
                    reply_markup=keyboard,
                )
    except Exception as e:
        await send_error_to_owner(str(e))


async def cfg_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handle callback queries for configuration steps:
    - cfg_start: ask for Gmail address
    - cfg_reconfigure: clear db and ask for Gmail address
    - cfg_wrong_mail: ask for Gmail address again
    """
    try:
        query = update.callback_query
        await query.answer()
        data = load_db()
        cred = data["credentials"][0]
        chat_id = update.effective_chat.id

        if query.data == "cfg_start":
            # Ask for Gmail address
            await query.message.reply_text("Please send your Gmail address (only Gmail).")
            return

        if query.data == "cfg_reconfigure":
            # Clear stored credentials
            cred["mail"] = ""
            cred["pass"] = ""
            save_db_and_notify(data)
            await query.message.reply_text("Credentials cleared. Please send your Gmail address.")
            return

        if query.data == "cfg_wrong_mail":
            await query.message.reply_text("Okay, please send the correct Gmail address.")
            return

    except Exception as e:
        await send_error_to_owner(str(e))


async def cfg_mail_received(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Receive the Gmail address from admin during configuration.
    Ask for app password afterward with two buttons:
    - "How to get app password" opens a link.
    - "Wrong mail" to re-enter email.
    """
    try:
        chat_id = update.effective_chat.id
        if not is_admin(chat_id):
            return
        mail_addr = update.message.text.strip()
        if "@" not in mail_addr or not mail_addr.endswith("gmail.com"):
            keyboard = InlineKeyboardMarkup(
                [[InlineKeyboardButton("Wrong mail", callback_data="cfg_wrong_mail")]]
            )
            await update.message.reply_text(
                "That doesn't look like a Gmail address. Please send a valid Gmail address.",
                reply_markup=keyboard,
            )
            return
        # Temporarily store the provided mail in context for the next step
        context.user_data["cfg_mail"] = mail_addr
        # Ask for app password
        keyboard = InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton(
                        "How to get app password",
                        url="https://support.google.com/accounts/answer/185833",
                    ),
                    InlineKeyboardButton("Wrong mail", callback_data="cfg_wrong_mail"),
                ]
            ]
        )
        await update.message.reply_text("Please send your Gmail app password.", reply_markup=keyboard)
    except Exception as e:
        await send_error_to_owner(str(e))


async def cfg_pass_received(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Receive the Gmail app password from admin.
    Attempt IMAP login. If success, store credentials in db.json and notify admin.
    If fail, edit the temporary message to indicate wrong credentials.
    """
    try:
        chat_id = update.effective_chat.id
        if not is_admin(chat_id):
            return
        if "cfg_mail" not in context.user_data:
            # Do nothing if we're not in configuration flow
            return
        mail_addr = context.user_data["cfg_mail"]
        app_pass = update.message.text.strip()

        # Send temporary "Connecting..." message
        msg = await update.message.reply_text("⏳ Connecting to your IMAP...")

        # Try IMAP login
        try:
            conn = connect_to_gmail_imap(mail_addr, app_pass)
            conn.logout()
        except Exception:
            # Edit the temporary message to indicate failure
            await msg.edit_text("❌ Wrong credentials. IMAP login failed. Please try again.")
            return

        # If login succeeded, save credentials
        data = load_db()
        cred = data["credentials"][0]
        cred["mail"] = mail_addr
        cred["pass"] = app_pass
        save_db_and_notify(data)

        # Edit the temporary message to success
        await msg.edit_text("✅ Successfully connected to your IMAP.")

        # Send next instructions
        keyboard = InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton(
                        "Commands", url="https://example.com/commands-documentation"
                    )
                ]
            ]
        )
        await update.message.reply_text("Click the button below to know all commands:", reply_markup=keyboard)

        # Clear stored interim mail
        context.user_data.pop("cfg_mail")
    except Exception as e:
        await send_error_to_owner(str(e))


# Token generation and management helpers

def generate_random_token(length: int = 10) -> str:
    """
    Generate a random token of given length consisting of uppercase A–Z and digits 0–9.
    """
    import random
    import string

    chars = string.ascii_uppercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))


async def gen_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /gen <days>
    Generate a token valid for <days> days with default access flags:
    household=True, signin=False, reset=False.
    Send token and inline buttons to toggle access or remove token.
    """
    try:
        chat_id = update.effective_chat.id
        if not is_admin(chat_id):
            await update.message.reply_text("🚫 You are not authorized to use this command.")
            return

        args = context.args
        if len(args) != 1 or not args[0].isdigit():
            await update.message.reply_text("Usage: /gen <days>")
            return
        days = int(args[0])
        token = generate_random_token(10)

        # Default flags: household=True, signin=False, reset=False
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

        # Build inline keyboard for toggling
        keyboard = InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton("📍 Household ✅", callback_data=f"tg_{token}_household"),
                    InlineKeyboardButton("🔑 Signin Code ❌", callback_data=f"tg_{token}_signin"),
                ],
                [
                    InlineKeyboardButton("🛡️ Pass Reset ❌", callback_data=f"tg_{token}_reset"),
                    InlineKeyboardButton("Remove Token ⛔️", callback_data=f"tg_{token}_remove"),
                ],
            ]
        )
        await update.message.reply_text(
            f"Generated token: `{token}` for {days} days with access to:",
            reply_markup=keyboard,
            parse_mode="Markdown",
        )
    except Exception as e:
        await send_error_to_owner(str(e))


async def toggle_access_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Callback handler for toggling user access flags or removing the token.
    Callback data format: "tg_<token>_<action>" where action is one of 'household', 'signin', 'reset', 'remove'.
    """
    try:
        query = update.callback_query
        await query.answer()
        data = load_db()
        users = data["credentials"][0]["users"]
        _, token, action = query.data.split("_", 2)
        user_obj = next((u for u in users if u["token"] == token), None)
        if not user_obj:
            await query.message.edit_text(f"🚫 Token `{token}` not found.", parse_mode="Markdown")
            return

        if action == "remove":
            users.remove(user_obj)
            save_db_and_notify(data)
            await query.message.edit_text(f"✅ Token `{token}` has been removed.")
            return

        # Toggle the specified flag
        if action in ("household", "signin", "reset"):
            user_obj[action] = not user_obj[action]
            save_db_and_notify(data)

        # Rebuild keyboard with updated flags
        kb_household = f"📍 Household {'✅' if user_obj['household'] else '❌'}"
        kb_signin = f"🔑 Signin Code {'✅' if user_obj['signin'] else '❌'}"
        kb_reset = f"🛡️ Pass Reset {'✅' if user_obj['reset'] else '❌'}"
        keyboard = InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton(kb_household, callback_data=f"tg_{token}_household"),
                    InlineKeyboardButton(kb_signin, callback_data=f"tg_{token}_signin"),
                ],
                [
                    InlineKeyboardButton(kb_reset, callback_data=f"tg_{token}_reset"),
                    InlineKeyboardButton("Remove Token ⛔️", callback_data=f"tg_{token}_remove"),
                ],
            ]
        )
        await query.message.edit_text(
            f"Token: `{token}` access updated. Current settings:",
            reply_markup=keyboard,
            parse_mode="Markdown",
        )
    except Exception as e:
        await send_error_to_owner(str(e))


async def extend_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /extend <token> <days_to_add>
    Extend the specified token's days by <days_to_add>. Show updated access buttons.
    """
    try:
        chat_id = update.effective_chat.id
        if not is_admin(chat_id):
            await update.message.reply_text("🚫 You are not authorized to use this command.")
            return
        args = context.args
        if len(args) != 2 or not args[1].isdigit():
            await update.message.reply_text("Usage: /extend <token> <days_to_add>")
            return
        token = args[0]
        add_days = int(args[1])

        data = load_db()
        users = data["credentials"][0]["users"]
        user_obj = next((u for u in users if u["token"] == token), None)
        if not user_obj:
            await update.message.reply_text(f"🚫 Token `{token}` is invalid.", parse_mode="Markdown")
            return

        user_obj["days"] += add_days
        save_db_and_notify(data)

        kb_household = f"📍 Household {'✅' if user_obj['household'] else '❌'}"
        kb_signin = f"🔑 Signin Code {'✅' if user_obj['signin'] else '❌'}"
        kb_reset = f"🛡️ Pass Reset {'✅' if user_obj['reset'] else '❌'}"
        keyboard = InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton(kb_household, callback_data=f"tg_{token}_household"),
                    InlineKeyboardButton(kb_signin, callback_data=f"tg_{token}_signin"),
                ],
                [
                    InlineKeyboardButton(kb_reset, callback_data=f"tg_{token}_reset"),
                    InlineKeyboardButton("Remove Token ⛔️", callback_data=f"tg_{token}_remove"),
                ],
            ]
        )
        await update.message.reply_text(
            f"✅ Extended `{token}` by {add_days} days. It now has {user_obj['days']} days left.\nAccess:",
            reply_markup=keyboard,
            parse_mode="Markdown",
        )
    except Exception as e:
        await send_error_to_owner(str(e))


async def remove_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /remove <token>
    Remove the specified token from db.json and notify admin.
    """
    try:
        chat_id = update.effective_chat.id
        if not is_admin(chat_id):
            await update.message.reply_text("🚫 You are not authorized to use this command.")
            return
        args = context.args
        if len(args) != 1:
            await update.message.reply_text("Usage: /remove <token>")
            return
        token = args[0]
        data = load_db()
        users = data["credentials"][0]["users"]
        user_obj = next((u for u in users if u["token"] == token), None)
        if not user_obj:
            await update.message.reply_text(f"🚫 Token `{token}` is invalid.", parse_mode="Markdown")
            return

        users.remove(user_obj)
        save_db_and_notify(data)
        await update.message.reply_text(f"✅ Successfully removed `{token}`.")
    except Exception as e:
        await send_error_to_owner(str(e))


async def users_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /users
    Send the list of all approved users (tokens) in JSON format to the admin.
    """
    try:
        chat_id = update.effective_chat.id
        if not is_admin(chat_id):
            await update.message.reply_text("🚫 You are not authorized to use this command.")
            return
        data = load_db()
        users = data["credentials"][0]["users"]
        # Build a JSON structure as specified
        users_list = []
        for u in users:
            users_list.append(
                {
                    "token": u["token"],
                    "days": u["days"],
                    "household": u["household"],
                    "signin": u["signin"],
                    "reset": u["reset"],
                }
            )
        out = {"users": users_list}
        # Serialize to bytes and send via BytesIO to ensure correct filename and MIME
        json_bytes = json.dumps(out, indent=2).encode("utf-8")
        bio = io.BytesIO(json_bytes)
        bio.name = "users.json"
        bio.seek(0)
        await update.message.reply_document(
            document=InputFile(bio, filename="users.json"),
            caption="📜 List of approved users (tokens).",
        )
    except Exception as e:
        await send_error_to_owner(str(e))


async def terminate_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /terminate
    Remove all tokens (clear users list) but keep mail credentials intact.
    """
    try:
        chat_id = update.effective_chat.id
        if not is_admin(chat_id):
            await update.message.reply_text("🚫 You are not authorized to use this command.")
            return
        data = load_db()
        data["credentials"][0]["users"] = []
        save_db_and_notify(data)
        await update.message.reply_text("✅ All tokens have been removed.")
    except Exception as e:
        await send_error_to_owner(str(e))


async def reset_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /reset
    Factory reset the bot:
    - Delete db.json entirely.
    - On next /start, the bot will reinitialize.
    - Notify the admin.
    """
    try:
        chat_id = update.effective_chat.id
        if not is_admin(chat_id):
            await update.message.reply_text("🚫 You are not authorized to use this command.")
            return

        # Delete the database file if it exists
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)

        # Notify admin
        await update.message.reply_text("⚙️ Factory reset completed. Please send /start to configure again.")
    except Exception as e:
        await send_error_to_owner(str(e))


async def info_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /info <token>
    Show details for that token:
    - Days left
    - Current access flags
    Include inline buttons for toggling those flags or removing the token.
    """
    try:
        chat_id = update.effective_chat.id
        if not is_admin(chat_id):
            await update.message.reply_text("🚫 You are not authorized to use this command.")
            return

        args = context.args
        if len(args) != 1:
            await update.message.reply_text("Usage: /info <token>")
            return
        token = args[0]

        data = load_db()
        users = data["credentials"][0]["users"]
        user_obj = next((u for u in users if u["token"] == token), None)
        if not user_obj:
            await update.message.reply_text(f"🚫 Token `{token}` is invalid.", parse_mode="Markdown")
            return

        days = user_obj["days"]
        household_flag = user_obj["household"]
        signin_flag = user_obj["signin"]
        reset_flag = user_obj["reset"]

        text = (
            f"*Token:* `{token}`\n"
            f"*Days left:* {days}\n"
            f"*Access to:*"
        )

        # Build inline keyboard for toggling
        kb_household = f"📍 Household {'✅' if household_flag else '❌'}"
        kb_signin = f"🔑 Signin Code {'✅' if signin_flag else '❌'}"
        kb_reset = f"🛡️ Pass Reset {'✅' if reset_flag else '❌'}"
        keyboard = InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton(kb_household, callback_data=f"tg_{token}_household"),
                    InlineKeyboardButton(kb_signin, callback_data=f"tg_{token}_signin"),
                ],
                [
                    InlineKeyboardButton(kb_reset, callback_data=f"tg_{token}_reset"),
                    InlineKeyboardButton("Remove Token ⛔️", callback_data=f"tg_{token}_remove"),
                ],
            ]
        )

        await update.message.reply_text(text, parse_mode="Markdown", reply_markup=keyboard)
    except Exception as e:
        await send_error_to_owner(str(e))


# Web request notification to admin when a token is used
async def notify_admin_token_used(token: str, action: str):
    """
    Notify the admin when a user uses their token to fetch mail successfully.
    action: one of 'household', 'signin', 'reset'
    """
    try:
        action_text = {
            "household": "Netflix household link",
            "signin": "Netflix signin code",
            "reset": "Netflix password reset link",
        }.get(action, "Netflix mail")
        message_text = (
            f"🔔 Token `{token}` requested for {action_text} and was successfully served."
        )
        keyboard = InlineKeyboardMarkup(
            [[InlineKeyboardButton("Remove Token ⛔️", callback_data=f"tg_{token}_remove")]]
        )
        await telegram_app.bot.send_message(
            chat_id=ADMIN_CHAT_ID,
            text=message_text,
            reply_markup=keyboard,
            parse_mode="Markdown",
        )
    except Exception as e:
        logger.error(f"Failed to notify admin for token use: {e}")


async def invalid_admin_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Catch-all for any unrecognized message/command from the admin.
    - If the message is exactly "/command", reply with a “Read Manual” button.
    - Otherwise, say “Invalid message/command. Send /commands to know the usable commands.”
    """
    try:
        chat_id = update.effective_chat.id
        # Only handle messages from admin; ignore others
        if not is_admin(chat_id):
            return

        text = update.message.text or ""
        lower = text.strip().lower()

        if lower.startswith("/command"):
            # Send a button linking to the manual
            keyboard = InlineKeyboardMarkup(
                [
                    [
                        InlineKeyboardButton(
                            "Read Manual", url="https://example.com/commands-documentation"
                        )
                    ]
                ]
            )
            await update.message.reply_text(
                "Click the button below to know commands and about this bot:",
                reply_markup=keyboard,
            )
        else:
            await update.message.reply_text(
                "Invalid message/command. Send /commands to know the usable commands."
            )

    except Exception as e:
        await send_error_to_owner(str(e))


# ─────────────────────────────────────────────────────────────────────────────
# Flask Web Handlers
# ─────────────────────────────────────────────────────────────────────────────

# Simple Jinja2 templates as strings
# Each template now ends with the two “Contact” buttons, using the .env values.

TOKEN_FORM_HTML = """
<!doctype html>
<title>Token Login</title>
<h2>Enter your access token</h2>
<form method="post">
  <input type="text" name="token" placeholder="Access Token" required>
  <button type="submit">Login</button>
</form>
{% with messages = get_flashed_messages() %}
  {% if messages %}
    <ul style="color: red;">
      {% for message in messages %}
        <li>{{ message }}</li>
      {% endfor %}
    </ul>
  {% endif %}
{% endwith %}

<!-- Contact buttons -->
<p style="margin-top: 2em;">
  <a href="{{ contact_seller_url }}" target="_blank">
    <button type="button">Contact Seller/Supplier</button>
  </a>
  <a href="{{ contact_developer_url }}" target="_blank">
    <button type="button">Contact Developer</button>
  </a>
</p>
"""

DASHBOARD_HTML = """
<!doctype html>
<title>Dashboard</title>
<h2>Welcome, token: {{ token }}</h2>
<p>Days remaining: {{ days }} day{{ 's' if days != 1 else '' }}.</p>
{% if days == 0 %}
  <p style="color: red;">Your token has expired. Please contact your supplier to extend your days.</p>
{% endif %}
<h3>Which Netflix mail would you like to retrieve?</h3>
<form method="post" action="{{ url_for('select_action') }}">
  {% if household %}
    <button type="submit" name="action" value="household">Household Mail 📍</button>
  {% endif %}
  {% if signin %}
    <button type="submit" name="action" value="signin">Signin Code 🔑</button>
  {% endif %}
  {% if reset %}
    <button type="submit" name="action" value="reset">Password Reset Link 🛡️</button>
  {% endif %}
</form>
<form method="post" action="{{ url_for('logout') }}">
  <button type="submit">Logout</button>
</form>

<!-- Contact buttons -->
<p style="margin-top: 2em;">
  <a href="{{ contact_seller_url }}" target="_blank">
    <button type="button">Contact Seller/Supplier</button>
  </a>
  <a href="{{ contact_developer_url }}" target="_blank">
    <button type="button">Contact Developer</button>
  </a>
</p>
"""

MAIL_REQUEST_HTML = """
<!doctype html>
<title>Fetch {{ action_name }}</title>
<h2>{{ action_name }}</h2>
<form method="post">
  <input type="email" name="email_addr" placeholder="Enter the email address (Gmail or custom)" required>
  <br><br>
  <button type="submit" name="go" value="back">Go Back ⏎</button>
  <button type="submit" name="go" value="fetch">Fetch</button>
</form>
{% with messages = get_flashed_messages() %}
  {% if messages %}
    <ul style="color: red;">
      {% for message in messages %}
        <li>{{ message }}</li>
      {% endfor %}
    </ul>
  {% endif %}
{% endwith %}

<!-- Contact buttons -->
<p style="margin-top: 2em;">
  <a href="{{ contact_seller_url }}" target="_blank">
    <button type="button">Contact Seller/Supplier</button>
  </a>
  <a href="{{ contact_developer_url }}" target="_blank">
    <button type="button">Contact Developer</button>
  </a>
</p>
"""

# Modified RESULT_HTML to show "Open Link" button and "Copy" button for signin code
RESULT_HTML = """
<!doctype html>
<html>
  <head>
    <title>{{ action_name }} Results</title>
    <script>
      function copyToClipboard(id) {
        var codeElem = document.getElementById(id);
        if (!codeElem) return;
        var text = codeElem.innerText;
        navigator.clipboard.writeText(text).then(function() {
          alert("Copied: " + text);
        }).catch(function(err) {
          alert("Failed to copy text: " + err);
        });
      }
    </script>
  </head>
  <body>
    <h2>{{ action_name }} Results</h2>
    {% if results %}
      {% for r in results %}
        <div style="border:1px solid #ddd; padding:10px; margin-bottom:10px;">
          <p>📧 Received from: info@account.netflix.com</p>
          <p>➤ Received to: {{ r.email_addr }}</p>
          {% if action == 'household' %}
            <p>📍 The household link is:
              <a href="{{ r.link }}" target="_blank">
                <button type="button">Open Link</button>
              </a>
            </p>
          {% elif action == 'signin' %}
            <p>🔑 The Netflix Signin code is:
              <code id="code-{{ loop.index0 }}" style="font-family:monospace;">{{ r.code }}</code>
              <button type="button" onclick="copyToClipboard('code-{{ loop.index0 }}')">Copy</button>
            </p>
          {% elif action == 'reset' %}
            <p>🛡️ The Netflix password reset link is:
              <a href="{{ r.link }}" target="_blank">
                <button type="button">Open Link</button>
              </a>
            </p>
          {% endif %}
        </div>
      {% endfor %}
    {% else %}
      <p>No relevant Netflix {{ action_name }} found in the last 15 minutes.</p>
    {% endif %}
    <a href="{{ url_for('dashboard') }}">← Back to Dashboard</a>

    <!-- Contact buttons -->
    <p style="margin-top: 2em;">
      <a href="{{ contact_seller_url }}" target="_blank">
        <button type="button">Contact Seller/Supplier</button>
      </a>
      <a href="{{ contact_developer_url }}" target="_blank">
        <button type="button">Contact Developer</button>
      </a>
    </p>
  </body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    """
    Display token login form or redirect to dashboard if session exists. On POST, validate token:
    - If invalid: flash error.
    - If days == 0: flash expired, notify admin.
    - If valid: store in session and redirect to dashboard.
    """
    # If user already logged in (session contains 'token'), go straight to dashboard
    if "token" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        token = request.form.get("token", "").strip()
        data = load_db()
        users = data["credentials"][0]["users"]
        user_obj = next((u for u in users if u["token"] == token), None)
        if not user_obj:
            flash("Invalid token. Please try again.")
            return render_template_string(
                TOKEN_FORM_HTML,
                contact_seller_url=CONTACT_SELLER_URL,
                contact_developer_url=CONTACT_DEVELOPER_URL,
            )
        if user_obj["days"] == 0:
            flash(f"Token `{token}` has expired. Contact your supplier to extend.")
            # Notify admin about expired token usage attempt
            if bot_loop:
                asyncio.run_coroutine_threadsafe(
                    telegram_app.bot.send_message(
                        chat_id=ADMIN_CHAT_ID,
                        text=(
                            f"🔔 Token `{token}` was used on the webpage but has expired. "
                            "Please extend with /extend if needed."
                        ),
                        parse_mode="Markdown",
                    ),
                    bot_loop,
                )
            return render_template_string(
                TOKEN_FORM_HTML,
                contact_seller_url=CONTACT_SELLER_URL,
                contact_developer_url=CONTACT_DEVELOPER_URL,
            )
        # Valid token with days > 0
        session["token"] = token
        return redirect(url_for("dashboard"))

    return render_template_string(
        TOKEN_FORM_HTML,
        contact_seller_url=CONTACT_SELLER_URL,
        contact_developer_url=CONTACT_DEVELOPER_URL,
    )


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard", methods=["GET"])
def dashboard():
    """
    Display dashboard with days remaining and buttons for available actions
    (household, signin, reset) based on the user's flags.
    If days == 0, show expired message.
    """
    token = session.get("token")
    if not token:
        return redirect(url_for("index"))
    data = load_db()
    user_obj = next((u for u in data["credentials"][0]["users"] if u["token"] == token), None)
    if not user_obj:
        session.clear()
        return redirect(url_for("index"))
    days = user_obj["days"]
    return render_template_string(
        DASHBOARD_HTML,
        token=token,
        days=days,
        household=user_obj["household"],
        signin=user_obj["signin"],
        reset=user_obj["reset"],
        contact_seller_url=CONTACT_SELLER_URL,
        contact_developer_url=CONTACT_DEVELOPER_URL,
    )


@app.route("/select_action", methods=["POST"])
def select_action():
    """
    Receive which action the user wants (household, signin, reset).
    Redirect to the mail request page for that action.
    """
    token = session.get("token")
    if not token:
        return redirect(url_for("index"))
    action = request.form.get("action")
    if action not in ("household", "signin", "reset"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("mail_request", action=action))


@app.route("/mail_request/<action>", methods=["GET", "POST"])
def mail_request(action):
    """
    GET: display form to input Netflix email address with Go Back and Fetch buttons.
    POST:
      - If go back: redirect to dashboard.
      - If fetch: perform IMAP fetch for the chosen action and display results.
      
    Notify the admin *only* if at least one valid link/code was found.
    """
    token = session.get("token")
    if not token:
        return redirect(url_for("index"))
    action_name = {
        "household": "Household Mail 📍",
        "signin": "Signin Code 🔑",
        "reset": "Password Reset Link 🛡️",
    }.get(action, "")
    if request.method == "POST":
        if request.form.get("go") == "back":
            return redirect(url_for("dashboard"))
        email_addr = request.form.get("email_addr", "").strip()
        if not email_addr:
            flash("Please enter a valid email address.")
            return render_template_string(
                MAIL_REQUEST_HTML,
                action_name=action_name,
                contact_seller_url=CONTACT_SELLER_URL,
                contact_developer_url=CONTACT_DEVELOPER_URL,
            )
        # Fetch logic
        data = load_db()
        cred = data["credentials"][0]
        mail_addr = cred.get("mail")
        app_pass = cred.get("pass")
        results = []
        try:
            imap_conn = connect_to_gmail_imap(mail_addr, app_pass)
            uids = search_last_hour(imap_conn, email_addr)
            if uids:
                recent_uids = filter_uids_last_15m(imap_conn, uids)
                if recent_uids:
                    if action == "household":
                        fetched = fetch_and_extract_household_link(imap_conn, recent_uids)
                        for uid, link in fetched.items():
                            if link:
                                results.append({"email_addr": email_addr, "link": link})
                    elif action == "signin":
                        fetched = fetch_and_extract_code(imap_conn, recent_uids)
                        for uid, code in fetched.items():
                            if code:
                                results.append({"email_addr": email_addr, "code": code})
                    elif action == "reset":
                        fetched = fetch_and_extract_reset_link(imap_conn, recent_uids)
                        for uid, link in fetched.items():
                            if link:
                                results.append({"email_addr": email_addr, "link": link})
            imap_conn.logout()
        except Exception as e:
            # On error, send to owner and show no results
            err_text = str(e)
            if bot_loop:
                bio = io.BytesIO(err_text.encode("utf-8"))
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
            results = []

        # Notify admin *only if* at least one result was found
        if results and bot_loop:
            asyncio.run_coroutine_threadsafe(
                notify_admin_token_used(token, action), bot_loop
            )

        return render_template_string(
            RESULT_HTML,
            action_name=action_name,
            action=action,
            results=results,
            contact_seller_url=CONTACT_SELLER_URL,
            contact_developer_url=CONTACT_DEVELOPER_URL,
        )
    return render_template_string(
        MAIL_REQUEST_HTML,
        action_name=action_name,
        contact_seller_url=CONTACT_SELLER_URL,
        contact_developer_url=CONTACT_DEVELOPER_URL,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main: Start Telegram Bot and Flask App
# ─────────────────────────────────────────────────────────────────────────────

def main():
    global telegram_app, bot_loop

    # Initialize Telegram bot application
    telegram_app = ApplicationBuilder().token(BOT_TOKEN).build()

    # Register handlers
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
    telegram_app.add_handler(CommandHandler("reset", reset_command))  # Factory reset
    telegram_app.add_handler(CommandHandler("info", info_command))

    # Catch-all for any other text/command from admin
    telegram_app.add_handler(MessageHandler(filters.ALL, invalid_admin_message))

    # Global error handler
    async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
        err_text = str(context.error)
        await send_error_to_owner(err_text)

    telegram_app.add_error_handler(error_handler)

    # Start the Telegram bot in a separate thread
    def run_telegram():
        global bot_loop
        # Create and assign a new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        bot_loop = loop
        telegram_app.run_polling(stop_signals=None)

    tg_thread = threading.Thread(target=run_telegram, daemon=True)
    tg_thread.start()

    # Start Flask web server (runs in main thread)
    app.run(host="0.0.0.0", port=WEB_PORT)


if __name__ == "__main__":
    main()
