import html
import logging
import os
import random
import sqlite3
import string
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from telegram import ChatPermissions, InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ChatMemberStatus, ParseMode
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    ChatMemberHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    MessageReactionHandler,
    filters,
)

load_dotenv()

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("verification_bot")

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
PROTECTED_CHAT_ID = int(os.getenv("PROTECTED_CHAT_ID", "0") or 0)
OWNER_ID = int(os.getenv("OWNER_ID", "0") or 0)
DB_PATH = os.getenv("DB_PATH", "bot.db")

DEFAULT_ID_THRESHOLD = int(os.getenv("DEFAULT_ID_THRESHOLD", "0") or 0)
DEFAULT_RULES_CHAT_ID = int(os.getenv("DEFAULT_RULES_CHAT_ID", "0") or 0)
DEFAULT_RULES_MESSAGE_ID = int(os.getenv("DEFAULT_RULES_MESSAGE_ID", "0") or 0)
DEFAULT_RULES_EMOJI = os.getenv("DEFAULT_RULES_EMOJI", "👍")

CAPTCHA_TIMEOUT_SECONDS = 60
TEMP_BAN_HOURS = 24

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is not set")

if not PROTECTED_CHAT_ID:
    raise RuntimeError("PROTECTED_CHAT_ID is not set")

RESTRICTED_PERMISSIONS = ChatPermissions(
    can_send_messages=False,
    can_send_audios=False,
    can_send_documents=False,
    can_send_photos=False,
    can_send_videos=False,
    can_send_video_notes=False,
    can_send_voice_notes=False,
    can_send_polls=False,
    can_send_other_messages=False,
    can_add_web_page_previews=False,
    can_change_info=False,
    can_invite_users=False,
    can_pin_messages=False,
    can_manage_topics=False,
)

OPEN_PERMISSIONS = ChatPermissions(
    can_send_messages=True,
    can_send_audios=True,
    can_send_documents=True,
    can_send_photos=True,
    can_send_videos=True,
    can_send_video_notes=True,
    can_send_voice_notes=True,
    can_send_polls=True,
    can_send_other_messages=True,
    can_add_web_page_previews=True,
    can_change_info=False,
    can_invite_users=True,
    can_pin_messages=False,
    can_manage_topics=False,
)


@dataclass
class Settings:
    id_threshold: int
    antispam_enabled: bool
    rules_chat_id: int
    rules_message_id: int
    rules_emoji: str


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.fromisoformat(value)


def html_user_ref(user_id: int, full_name: str) -> str:
    return f'<a href="tg://user?id={user_id}">{html.escape(full_name or str(user_id))}</a>'


def generate_challenge_id(length: int = 12) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def build_captcha() -> tuple[str, str, list[str], str]:
    kind = random.choice(["text", "emoji", "math", "color", "category"])

    if kind == "text":
        choices = ["человек", "бот", "спам", "реклама"]
        correct = "человек"
        prompt = "Нажмите кнопку: человек"

    elif kind == "emoji":
        choices = ["🐱", "🍓", "🚗", "🌙"]
        correct = "🐱"
        prompt = "Нажмите на 🐱"

    elif kind == "math":
        a = random.randint(1, 5)
        b = random.randint(1, 5)
        correct = str(a + b)
        wrong = list({str(a + b + 1), str(max(0, a + b - 1)), str(a + b + 2)})
        choices = [correct] + wrong[:3]
        prompt = f"Сколько будет {a} + {b}?"

    elif kind == "color":
        choices = ["красный", "зелёный", "синий", "жёлтый"]
        correct = "синий"
        prompt = "Нажмите слово: синий"

    else:
        choices = ["кот", "стол", "лампа", "окно"]
        correct = "кот"
        prompt = "Что из этого животное?"

    random.shuffle(choices)
    return kind, prompt, choices, correct


def build_keyboard(chat_id: int, user_id: int, challenge_id: str, choices: list[str]) -> InlineKeyboardMarkup:
    rows = []
    for choice in choices:
        rows.append(
            [
                InlineKeyboardButton(
                    text=choice,
                    callback_data=f"cap|{chat_id}|{user_id}|{challenge_id}|{choice}",
                )
            ]
        )
    return InlineKeyboardMarkup(rows)


class DB:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self):
        with closing(self.connect()) as conn, conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    chat_id INTEGER NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (chat_id, key)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    chat_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    join_attempts INTEGER NOT NULL DEFAULT 0,
                    last_join_at TEXT,
                    ban_until TEXT,
                    verification_stage TEXT,
                    full_name TEXT,
                    username TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (chat_id, user_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS captcha_sessions (
                    chat_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    challenge_id TEXT NOT NULL,
                    captcha_type TEXT NOT NULL,
                    correct_answer TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    message_id INTEGER,
                    PRIMARY KEY (chat_id, user_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    chat_id INTEGER,
                    user_id INTEGER,
                    event_type TEXT NOT NULL,
                    details TEXT,
                    moderator_id INTEGER
                )
                """
            )

        self.bootstrap_defaults(PROTECTED_CHAT_ID)

    def bootstrap_defaults(self, chat_id: int):
        defaults = {
            "id_threshold": str(DEFAULT_ID_THRESHOLD),
            "antispam_enabled": "0",
            "rules_chat_id": str(DEFAULT_RULES_CHAT_ID),
            "rules_message_id": str(DEFAULT_RULES_MESSAGE_ID),
            "rules_emoji": DEFAULT_RULES_EMOJI,
        }

        with closing(self.connect()) as conn, conn:
            for key, value in defaults.items():
                row = conn.execute(
                    "SELECT value FROM settings WHERE chat_id=? AND key=?",
                    (chat_id, key),
                ).fetchone()
                if row is None:
                    conn.execute(
                        "INSERT INTO settings (chat_id, key, value, updated_at) VALUES (?, ?, ?, ?)",
                        (chat_id, key, value, utcnow()),
                    )

    def get_setting(self, chat_id: int, key: str, default: str = "") -> str:
        with closing(self.connect()) as conn:
            row = conn.execute(
                "SELECT value FROM settings WHERE chat_id=? AND key=?",
                (chat_id, key),
            ).fetchone()
            return row["value"] if row else default

    def set_setting(self, chat_id: int, key: str, value: str):
        with closing(self.connect()) as conn, conn:
            conn.execute(
                """
                INSERT INTO settings (chat_id, key, value, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(chat_id, key)
                DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                """,
                (chat_id, key, value, utcnow()),
            )

    def get_settings(self, chat_id: int) -> Settings:
        return Settings(
            id_threshold=int(self.get_setting(chat_id, "id_threshold", str(DEFAULT_ID_THRESHOLD or 0))),
            antispam_enabled=self.get_setting(chat_id, "antispam_enabled", "0") == "1",
            rules_chat_id=int(self.get_setting(chat_id, "rules_chat_id", str(DEFAULT_RULES_CHAT_ID or 0))),
            rules_message_id=int(self.get_setting(chat_id, "rules_message_id", str(DEFAULT_RULES_MESSAGE_ID or 0))),
            rules_emoji=self.get_setting(chat_id, "rules_emoji", DEFAULT_RULES_EMOJI),
        )

    def log(
        self,
        event_type: str,
        chat_id: Optional[int] = None,
        user_id: Optional[int] = None,
        details: str = "",
        moderator_id: Optional[int] = None,
    ):
        with closing(self.connect()) as conn, conn:
            conn.execute(
                """
                INSERT INTO logs (timestamp, chat_id, user_id, event_type, details, moderator_id)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (utcnow(), chat_id, user_id, event_type, details, moderator_id),
            )

    def get_logs(self, limit: int = 20, user_id: Optional[int] = None):
        query = "SELECT * FROM logs"
        params = []
        if user_id is not None:
            query += " WHERE user_id=?"
            params.append(user_id)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with closing(self.connect()) as conn:
            return conn.execute(query, params).fetchall()

    def get_user(self, chat_id: int, user_id: int):
        with closing(self.connect()) as conn:
            return conn.execute(
                "SELECT * FROM users WHERE chat_id=? AND user_id=?",
                (chat_id, user_id),
            ).fetchone()

    def upsert_user(self, chat_id: int, user_id: int, **fields):
        current = self.get_user(chat_id, user_id)

        base = {
            "join_attempts": 0,
            "last_join_at": None,
            "ban_until": None,
            "verification_stage": None,
            "full_name": None,
            "username": None,
            "updated_at": utcnow(),
        }

        if current:
            for key in base:
                base[key] = current[key]

        base.update(fields)
        base["updated_at"] = utcnow()

        with closing(self.connect()) as conn, conn:
            conn.execute(
                """
                INSERT INTO users (
                    chat_id, user_id, join_attempts, last_join_at, ban_until,
                    verification_stage, full_name, username, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chat_id, user_id)
                DO UPDATE SET
                    join_attempts=excluded.join_attempts,
                    last_join_at=excluded.last_join_at,
                    ban_until=excluded.ban_until,
                    verification_stage=excluded.verification_stage,
                    full_name=excluded.full_name,
                    username=excluded.username,
                    updated_at=excluded.updated_at
                """,
                (
                    chat_id,
                    user_id,
                    base["join_attempts"],
                    base["last_join_at"],
                    base["ban_until"],
                    base["verification_stage"],
                    base["full_name"],
                    base["username"],
                    base["updated_at"],
                ),
            )

    def reset_user_attempts(self, chat_id: int, user_id: int):
        self.upsert_user(chat_id, user_id, join_attempts=0, ban_until=None)

    def save_captcha(
        self,
        chat_id: int,
        user_id: int,
        challenge_id: str,
        captcha_type: str,
        correct_answer: str,
        expires_at: str,
        message_id: Optional[int],
    ):
        with closing(self.connect()) as conn, conn:
            conn.execute(
                "UPDATE captcha_sessions SET is_active=0 WHERE chat_id=? AND user_id=?",
                (chat_id, user_id),
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO captcha_sessions
                (
                    chat_id, user_id, challenge_id, captcha_type, correct_answer,
                    created_at, expires_at, is_active, message_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    chat_id,
                    user_id,
                    challenge_id,
                    captcha_type,
                    correct_answer,
                    utcnow(),
                    expires_at,
                    message_id,
                ),
            )

    def get_captcha(self, chat_id: int, user_id: int):
        with closing(self.connect()) as conn:
            return conn.execute(
                """
                SELECT * FROM captcha_sessions
                WHERE chat_id=? AND user_id=? AND is_active=1
                """,
                (chat_id, user_id),
            ).fetchone()

    def deactivate_captcha(self, chat_id: int, user_id: int):
        with closing(self.connect()) as conn, conn:
            conn.execute(
                "UPDATE captcha_sessions SET is_active=0 WHERE chat_id=? AND user_id=?",
                (chat_id, user_id),
            )


async def is_moderator(context: ContextTypes.DEFAULT_TYPE, user_id: int) -> bool:
    if OWNER_ID and user_id == OWNER_ID:
        return True

    try:
        member = await context.bot.get_chat_member(PROTECTED_CHAT_ID, user_id)
        return member.status in {
            ChatMemberStatus.ADMINISTRATOR,
            ChatMemberStatus.OWNER,
        }
    except Exception:
        return False


async def admin_guard(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    user = update.effective_user
    if not user:
        return False

    ok = await is_moderator(context, user.id)
    if not ok and update.effective_message:
        await update.effective_message.reply_text("Доступ только для модераторов и владельца.")
    return ok


async def restrict_new_member(context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int):
    await context.bot.restrict_chat_member(
        chat_id=chat_id,
        user_id=user_id,
        permissions=RESTRICTED_PERMISSIONS,
    )


async def open_member(context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int):
    await context.bot.restrict_chat_member(
        chat_id=chat_id,
        user_id=user_id,
        permissions=OPEN_PERMISSIONS,
    )


async def kick_member(context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int):
    await context.bot.ban_chat_member(chat_id=chat_id, user_id=user_id, until_date=0)
    await context.bot.unban_chat_member(chat_id=chat_id, user_id=user_id, only_if_banned=True)


async def temp_ban_member(context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int, hours: int = 24):
    until_date = datetime.now(timezone.utc) + timedelta(hours=hours)
    await context.bot.ban_chat_member(chat_id=chat_id, user_id=user_id, until_date=until_date)


async def send_rules_instruction(context: ContextTypes.DEFAULT_TYPE, user_id: int, settings: Settings):
    text = (
        "Капча пройдена. Остался последний шаг.\n\n"
        f"Поставьте эмодзи {settings.rules_emoji} под публикацией с правилами.\n"
        "После этого ограничения будут сняты."
    )

    try:
        await context.bot.send_message(chat_id=user_id, text=text)
    except Exception:
        return

    if settings.rules_chat_id and settings.rules_message_id:
        try:
            await context.bot.forward_message(
                chat_id=user_id,
                from_chat_id=settings.rules_chat_id,
                message_id=settings.rules_message_id,
            )
        except Exception:
            pass


async def start_captcha(context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int, full_name: str):
    db: DB = context.application.bot_data["db"]

    kind, prompt, choices, correct = build_captcha()
    challenge_id = generate_challenge_id()
    keyboard = build_keyboard(chat_id, user_id, challenge_id, choices)

    message = await context.bot.send_message(
        chat_id=chat_id,
        text=(
            f"{html_user_ref(user_id, full_name)}, пройдите проверку.\n\n"
            f"{html.escape(prompt)}\n"
            f"У вас {CAPTCHA_TIMEOUT_SECONDS} секунд."
        ),
        reply_markup=keyboard,
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
    )

    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=CAPTCHA_TIMEOUT_SECONDS)).isoformat()

    db.save_captcha(
        chat_id=chat_id,
        user_id=user_id,
        challenge_id=challenge_id,
        captcha_type=kind,
        correct_answer=correct,
        expires_at=expires_at,
        message_id=message.message_id,
    )
    db.upsert_user(chat_id, user_id, verification_stage="captcha_pending")
    db.log("captcha_started", chat_id=chat_id, user_id=user_id, details=f"kind={kind}")

    job_name = f"captcha_timeout:{chat_id}:{user_id}:{challenge_id}"
    for job in context.job_queue.get_jobs_by_name(job_name):
        job.schedule_removal()

    context.job_queue.run_once(
        captcha_timeout_job,
        when=CAPTCHA_TIMEOUT_SECONDS,
        data={"chat_id": chat_id, "user_id": user_id, "challenge_id": challenge_id},
        name=job_name,
    )


async def captcha_timeout_job(context: ContextTypes.DEFAULT_TYPE):
    db: DB = context.application.bot_data["db"]
    data = context.job.data or {}

    chat_id = data.get("chat_id")
    user_id = data.get("user_id")
    challenge_id = data.get("challenge_id")

    session = db.get_captcha(chat_id, user_id)
    if not session:
        return

    if session["challenge_id"] != challenge_id:
        return

    user_row = db.get_user(chat_id, user_id)
    full_name = user_row["full_name"] if user_row and user_row["full_name"] else str(user_id)

    try:
        if session["message_id"]:
            await context.bot.delete_message(chat_id=chat_id, message_id=session["message_id"])
    except Exception:
        pass

    db.deactivate_captcha(chat_id, user_id)
    db.upsert_user(chat_id, user_id, verification_stage="kicked")
    db.log("captcha_timeout", chat_id=chat_id, user_id=user_id, details="timeout")

    try:
        await kick_member(context, chat_id, user_id)
        mention = html_user_ref(user_id, full_name)
        await context.bot.send_message(
            chat_id=chat_id,
            text=f"{mention} — Вы не прошли проверку!",
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )
    except Exception as exc:
        logger.warning("Timeout kick failed: %s", exc)


async def finalize_verification(context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int):
    db: DB = context.application.bot_data["db"]

    message_id = None

    with closing(db.connect()) as conn:
        row = conn.execute(
            "SELECT message_id FROM captcha_sessions WHERE chat_id=? AND user_id=? ORDER BY created_at DESC LIMIT 1",
            (chat_id, user_id),
        ).fetchone()
        if row:
            message_id = row["message_id"]

    try:
        if message_id:
            await context.bot.delete_message(chat_id=chat_id, message_id=message_id)
    except Exception:
        pass

    await open_member(context, chat_id, user_id)
    db.upsert_user(chat_id, user_id, verification_stage="verified")
    db.deactivate_captcha(chat_id, user_id)
    db.reset_user_attempts(chat_id, user_id)
    db.log("verified", chat_id=chat_id, user_id=user_id, details="emoji_confirmed")

    try:
        await context.bot.send_message(chat_id=user_id, text="Проверка завершена. Доступ открыт.")
    except Exception:
        pass


async def handle_new_member(update: Update, context: ContextTypes.DEFAULT_TYPE):
    db: DB = context.application.bot_data["db"]
    cmu = update.chat_member

    if not cmu or cmu.chat.id != PROTECTED_CHAT_ID:
        return

    old_status = cmu.old_chat_member.status
    new_status = cmu.new_chat_member.status

    is_join = (
        old_status in {ChatMemberStatus.LEFT, ChatMemberStatus.BANNED}
        and new_status in {ChatMemberStatus.MEMBER, ChatMemberStatus.RESTRICTED}
    )

    if not is_join:
        return

    user = cmu.new_chat_member.user
    chat_id = cmu.chat.id
    settings = db.get_settings(chat_id)

    db.log("join", chat_id=chat_id, user_id=user.id, details=f"username={user.username or '-'}")

    row = db.get_user(chat_id, user.id)

    if row and row["verification_stage"] in {"captcha_pending", "emoji_pending"}:
        db.log(
            "join_skipped_existing_session",
            chat_id=chat_id,
            user_id=user.id,
            details=f"stage={row['verification_stage']}",
        )
        return

    join_attempts = int(row["join_attempts"] or 0) + 1 if row else 1
    ban_until = parse_dt(row["ban_until"]) if row else None

    db.upsert_user(
        chat_id,
        user.id,
        full_name=user.full_name,
        username=user.username,
        join_attempts=join_attempts,
        last_join_at=utcnow(),
        verification_stage="new_joined",
    )

    try:
        await restrict_new_member(context, chat_id, user.id)
    except Exception as exc:
        logger.warning("Failed to restrict user %s: %s", user.id, exc)

    if ban_until and ban_until > datetime.now(timezone.utc):
        db.log(
            "join_blocked_tempban",
            chat_id=chat_id,
            user_id=user.id,
            details=f"until={ban_until.isoformat()}",
        )
        await temp_ban_member(context, chat_id, user.id, hours=TEMP_BAN_HOURS)
        return

    threshold = settings.id_threshold

    if threshold and user.id >= threshold:
        if settings.antispam_enabled:
            if join_attempts >= 13:
                until = (datetime.now(timezone.utc) + timedelta(hours=TEMP_BAN_HOURS)).isoformat()
                db.upsert_user(chat_id, user.id, verification_stage="temp_banned", ban_until=until)
                db.log("temp_ban", chat_id=chat_id, user_id=user.id, details="antispam_13th_attempt")
                await temp_ban_member(context, chat_id, user.id, hours=TEMP_BAN_HOURS)
                return

            db.upsert_user(chat_id, user.id, verification_stage="kicked")
            db.log("idgate_kick", chat_id=chat_id, user_id=user.id, details=f"attempt={join_attempts};antispam=1")
            await kick_member(context, chat_id, user.id)
            mention = html_user_ref(user.id, user.full_name)
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"{mention} — Вы не прошли проверку!",
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )
            return

        if join_attempts in (1, 2):
            db.upsert_user(chat_id, user.id, verification_stage="kicked")
            db.log("idgate_kick", chat_id=chat_id, user_id=user.id, details=f"attempt={join_attempts}")
            await kick_member(context, chat_id, user.id)
            mention = html_user_ref(user.id, user.full_name)
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"{mention} — Вы не прошли проверку!",
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )
            return

        if join_attempts >= 13:
            until = (datetime.now(timezone.utc) + timedelta(hours=TEMP_BAN_HOURS)).isoformat()
            db.upsert_user(chat_id, user.id, verification_stage="temp_banned", ban_until=until)
            db.log("temp_ban", chat_id=chat_id, user_id=user.id, details="13th_attempt")
            await temp_ban_member(context, chat_id, user.id, hours=TEMP_BAN_HOURS)
            return

    await start_captcha(context, chat_id, user.id, user.full_name)


async def captcha_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    db: DB = context.application.bot_data["db"]
    query = update.callback_query

    if not query or not query.data or not query.data.startswith("cap|"):
        return

    parts = query.data.split("|", 4)
    if len(parts) != 5:
        await query.answer()
        return

    _, chat_id_str, target_user_id_str, challenge_id, answer = parts
    chat_id = int(chat_id_str)
    target_user_id = int(target_user_id_str)

    if not update.effective_user or update.effective_user.id != target_user_id:
        await query.answer("Это не ваша капча.", show_alert=True)
        return

    session = db.get_captcha(chat_id, target_user_id)
    if not session:
        await query.answer("Сессия недействительна.", show_alert=True)
        return

    if session["challenge_id"] != challenge_id:
        await query.answer("Сессия устарела.", show_alert=True)
        return

    expires_at = parse_dt(session["expires_at"])
    if not expires_at or expires_at <= datetime.now(timezone.utc):
        user_row = db.get_user(chat_id, target_user_id)
        full_name = user_row["full_name"] if user_row and user_row["full_name"] else str(target_user_id)

        try:
            if session["message_id"]:
                await context.bot.delete_message(chat_id=chat_id, message_id=session["message_id"])
        except Exception:
            pass

        db.deactivate_captcha(chat_id, target_user_id)
        db.upsert_user(chat_id, target_user_id, verification_stage="kicked")
        db.log("captcha_timeout_click", chat_id=chat_id, user_id=target_user_id, details="expired_before_click")

        await query.answer("Капча просрочена.", show_alert=True)
        await kick_member(context, chat_id, target_user_id)

        try:
            mention = html_user_ref(target_user_id, full_name)
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"{mention} — Вы не прошли проверку!",
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )
        except Exception:
            pass
        return

    if answer != session["correct_answer"]:
        user_row = db.get_user(chat_id, target_user_id)
        full_name = user_row["full_name"] if user_row and user_row["full_name"] else str(target_user_id)

        db.deactivate_captcha(chat_id, target_user_id)
        db.upsert_user(chat_id, target_user_id, verification_stage="kicked")
        db.log("captcha_failed", chat_id=chat_id, user_id=target_user_id, details=f"answer={answer}")

        try:
            if session["message_id"]:
                await context.bot.delete_message(chat_id=chat_id, message_id=session["message_id"])
        except Exception:
            pass

        await query.answer("Неверный ответ.", show_alert=True)
        await kick_member(context, chat_id, target_user_id)

        try:
            mention = html_user_ref(target_user_id, full_name)
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"{mention} — Вы не прошли проверку!",
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )
        except Exception:
            pass
        return

    db.deactivate_captcha(chat_id, target_user_id)
    db.upsert_user(chat_id, target_user_id, verification_stage="emoji_pending")
    db.log("captcha_passed", chat_id=chat_id, user_id=target_user_id)

    settings = db.get_settings(chat_id)
    mention = html_user_ref(target_user_id, update.effective_user.full_name)
    text = (
        f"{mention}, капча пройдена.\n\n"
        f"Теперь поставьте {settings.rules_emoji} под публикацией с правилами. "
        "После этого доступ будет открыт."
    )

    try:
        await query.edit_message_text(
            text,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )
    except Exception:
        pass

    await query.answer("Капча пройдена.")
    await send_rules_instruction(context, target_user_id, settings)


async def reaction_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    db: DB = context.application.bot_data["db"]
    reaction_update = update.message_reaction

    if not reaction_update:
        return

    settings = db.get_settings(PROTECTED_CHAT_ID)
    if not settings.rules_chat_id or not settings.rules_message_id:
        return

    if reaction_update.chat.id != settings.rules_chat_id:
        return

    if reaction_update.message_id != settings.rules_message_id:
        return

    actor = reaction_update.user
    if not actor:
        return

    has_required = False
    for item in reaction_update.new_reaction:
        emoji = getattr(item, "emoji", None)
        if emoji == settings.rules_emoji:
            has_required = True
            break

    if not has_required:
        return

    row = db.get_user(PROTECTED_CHAT_ID, actor.id)
    if not row or row["verification_stage"] != "emoji_pending":
        return

    await finalize_verification(context, PROTECTED_CHAT_ID, actor.id)


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return

    text = (
        "Команды:\n"
        "/status\n"
        "/help\n"
        "/idgate_status\n"
        "/idgate_set <число>\n"
        "/idgate_up <число>\n"
        "/idgate_down <число>\n"
        "/rules_status\n"
        "/rules_setchat <chat_id>\n"
        "/rules_setmsg <message_id>\n"
        "/rules_setemoji <эмодзи>\n"
        "/antispam_on\n"
        "/antispam_off\n"
        "/logs [число]\n"
        "/logs_user <user_id> [число]\n"
        "/reset_attempts <user_id>\n"
        "/unban <user_id>"
    )
    await update.effective_message.reply_text(text)


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return

    db: DB = context.application.bot_data["db"]
    s = db.get_settings(PROTECTED_CHAT_ID)

    text = (
        f"protected_chat_id: {PROTECTED_CHAT_ID}\n"
        f"id_threshold: {s.id_threshold}\n"
        f"antispam: {'on' if s.antispam_enabled else 'off'}\n"
        f"rules_chat_id: {s.rules_chat_id}\n"
        f"rules_message_id: {s.rules_message_id}\n"
        f"rules_emoji: {s.rules_emoji}\n"
        f"captcha_timeout: {CAPTCHA_TIMEOUT_SECONDS} sec"
    )
    await update.effective_message.reply_text(text)


async def cmd_idgate_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return

    db: DB = context.application.bot_data["db"]
    value = db.get_setting(PROTECTED_CHAT_ID, "id_threshold", "0")
    await update.effective_message.reply_text(f"ID threshold: {value}")


async def cmd_idgate_set(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return

    if not context.args:
        await update.effective_message.reply_text("Пример: /idgate_set 7000000000")
        return

    value = int(context.args[0])
    db: DB = context.application.bot_data["db"]
    db.set_setting(PROTECTED_CHAT_ID, "id_threshold", str(value))
    db.log(
        "setting_changed",
        chat_id=PROTECTED_CHAT_ID,
        details=f"id_threshold={value}",
        moderator_id=update.effective_user.id,
    )
    await update.effective_message.reply_text(f"Новый ID threshold: {value}")


async def cmd_idgate_up(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return

    if not context.args:
        await update.effective_message.reply_text("Пример: /idgate_up 1000000")
        return

    step = int(context.args[0])
    db: DB = context.application.bot_data["db"]
    current = int(db.get_setting(PROTECTED_CHAT_ID, "id_threshold", "0"))
    new_value = current + step
    db.set_setting(PROTECTED_CHAT_ID, "id_threshold", str(new_value))
    db.log(
        "setting_changed",
        chat_id=PROTECTED_CHAT_ID,
        details=f"id_threshold={new_value}",
        moderator_id=update.effective_user.id,
    )
    await update.effective_message.reply_text(f"ID threshold: {new_value}")


async def cmd_idgate_down(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return

    if not context.args:
        await update.effective_message.reply_text("Пример: /idgate_down 1000000")
        return

    step = int(context.args[0])
    db: DB = context.application.bot_data["db"]
    current = int(db.get_setting(PROTECTED_CHAT_ID, "id_threshold", "0"))
    new_value = max(0, current - step)
    db.set_setting(PROTECTED_CHAT_ID, "id_threshold", str(new_value))
    db.log(
        "setting_changed",
        chat_id=PROTECTED_CHAT_ID,
        details=f"id_threshold={new_value}",
        moderator_id=update.effective_user.id,
    )
    await update.effective_message.reply_text(f"ID threshold: {new_value}")


async def cmd_rules_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return

    db: DB = context.application.bot_data["db"]
    s = db.get_settings(PROTECTED_CHAT_ID)
    await update.effective_message.reply_text(
        f"rules_chat_id: {s.rules_chat_id}\n"
        f"rules_message_id: {s.rules_message_id}\n"
        f"rules_emoji: {s.rules_emoji}"
    )


async def cmd_rules_setchat(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return

    if not context.args:
        await update.effective_message.reply_text("Пример: /rules_setchat -1001916510076")
        return

    value = int(context.args[0])
    db: DB = context.application.bot_data["db"]
    db.set_setting(PROTECTED_CHAT_ID, "rules_chat_id", str(value))
    db.log(
        "setting_changed",
        chat_id=PROTECTED_CHAT_ID,
        details=f"rules_chat_id={value}",
        moderator_id=update.effective_user.id,
    )
    await update.effective_message.reply_text(f"rules_chat_id: {value}")


async def cmd_rules_setmsg(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return

    if not context.args:
        await update.effective_message.reply_text("Пример: /rules_setmsg 2151")
        return

    value = int(context.args[0])
    db: DB = context.application.bot_data["db"]
    db.set_setting(PROTECTED_CHAT_ID, "rules_message_id", str(value))
    db.log(
        "setting_changed",
        chat_id=PROTECTED_CHAT_ID,
        details=f"rules_message_id={value}",
        moderator_id=update.effective_user.id,
    )
    await update.effective_message.reply_text(f"rules_message_id: {value}")


async def cmd_rules_setemoji(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return

    if not context.args:
        await update.effective_message.reply_text("Пример: /rules_setemoji 👍")
        return

    value = context.args[0].strip()
    db: DB = context.application.bot_data["db"]
    db.set_setting(PROTECTED_CHAT_ID, "rules_emoji", value)
    db.log(
        "setting_changed",
        chat_id=PROTECTED_CHAT_ID,
        details=f"rules_emoji={value}",
        moderator_id=update.effective_user.id,
    )
    await update.effective_message.reply_text(f"rules_emoji: {value}")


async def cmd_antispam_on(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return

    db: DB = context.application.bot_data["db"]
    db.set_setting(PROTECTED_CHAT_ID, "antispam_enabled", "1")
    db.log(
        "setting_changed",
        chat_id=PROTECTED_CHAT_ID,
        details="antispam=1",
        moderator_id=update.effective_user.id,
    )
    await update.effective_message.reply_text("Anti-spam включён.")


async def cmd_antispam_off(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return

    db: DB = context.application.bot_data["db"]
    db.set_setting(PROTECTED_CHAT_ID, "antispam_enabled", "0")
    db.log(
        "setting_changed",
        chat_id=PROTECTED_CHAT_ID,
        details="antispam=0",
        moderator_id=update.effective_user.id,
    )
    await update.effective_message.reply_text("Anti-spam выключен.")


async def cmd_logs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return

    db: DB = context.application.bot_data["db"]
    limit = 20
    if context.args:
        limit = max(1, min(100, int(context.args[0])))

    rows = db.get_logs(limit=limit)
    if not rows:
        await update.effective_message.reply_text("Логи пусты.")
        return

    lines = []
    for row in rows:
        lines.append(
            f"[{row['timestamp']}] {row['event_type']} | user={row['user_id']} | {row['details'] or ''}"
        )

    await update.effective_message.reply_text("\n".join(lines[:50]))


async def cmd_logs_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return

    if not context.args:
        await update.effective_message.reply_text("Пример: /logs_user 123456789 20")
        return

    db: DB = context.application.bot_data["db"]
    target_user_id = int(context.args[0])
    limit = 20
    if len(context.args) > 1:
        limit = max(1, min(100, int(context.args[1])))

    rows = db.get_logs(limit=limit, user_id=target_user_id)
    if not rows:
        await update.effective_message.reply_text("По этому user_id логов нет.")
        return

    lines = []
    for row in rows:
        lines.append(f"[{row['timestamp']}] {row['event_type']} | {row['details'] or ''}")

    await update.effective_message.reply_text("\n".join(lines[:50]))


async def cmd_reset_attempts(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return

    if not context.args:
        await update.effective_message.reply_text("Пример: /reset_attempts 123456789")
        return

    target_user_id = int(context.args[0])
    db: DB = context.application.bot_data["db"]
    db.reset_user_attempts(PROTECTED_CHAT_ID, target_user_id)
    db.log(
        "attempts_reset",
        chat_id=PROTECTED_CHAT_ID,
        user_id=target_user_id,
        moderator_id=update.effective_user.id,
    )
    await update.effective_message.reply_text("Счётчик попыток сброшен.")


async def cmd_unban(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return

    if not context.args:
        await update.effective_message.reply_text("Пример: /unban 123456789")
        return

    target_user_id = int(context.args[0])
    await context.bot.unban_chat_member(
        chat_id=PROTECTED_CHAT_ID,
        user_id=target_user_id,
        only_if_banned=True,
    )

    db: DB = context.application.bot_data["db"]
    db.upsert_user(PROTECTED_CHAT_ID, target_user_id, ban_until=None, verification_stage=None)
    db.log(
        "manual_unban",
        chat_id=PROTECTED_CHAT_ID,
        user_id=target_user_id,
        moderator_id=update.effective_user.id,
    )
    await update.effective_message.reply_text("Пользователь разбанен.")


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    logger.exception("Unhandled exception", exc_info=context.error)


async def handle_new_members_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.new_chat_members:
        return

    if update.effective_chat.id != PROTECTED_CHAT_ID:
        return

    db: DB = context.application.bot_data["db"]

    for user in update.message.new_chat_members:
        db.log(
            "join_message_fallback",
            chat_id=update.effective_chat.id,
            user_id=user.id,
            details=f"username={user.username or '-'}",
        )

        class _Member:
            def __init__(self, status: str, user_obj):
                self.status = status
                self.user = user_obj

        class _CMU:
            def __init__(self, chat, user_obj):
                self.chat = chat
                self.old_chat_member = _Member(ChatMemberStatus.LEFT, user_obj)
                self.new_chat_member = _Member(ChatMemberStatus.MEMBER, user_obj)

        fake_update = Update(
            update.update_id,
            chat_member=_CMU(update.effective_chat, user),
        )

        await handle_new_member(fake_update, context)


def build_app() -> Application:
    db = DB(DB_PATH)

    app = Application.builder().token(BOT_TOKEN).build()
    app.bot_data["db"] = db

    app.add_handler(CommandHandler(["start", "help"], cmd_start))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("idgate_status", cmd_idgate_status))
    app.add_handler(CommandHandler("idgate_set", cmd_idgate_set))
    app.add_handler(CommandHandler("idgate_up", cmd_idgate_up))
    app.add_handler(CommandHandler("idgate_down", cmd_idgate_down))
    app.add_handler(CommandHandler("rules_status", cmd_rules_status))
    app.add_handler(CommandHandler("rules_setchat", cmd_rules_setchat))
    app.add_handler(CommandHandler("rules_setmsg", cmd_rules_setmsg))
    app.add_handler(CommandHandler("rules_setemoji", cmd_rules_setemoji))
    app.add_handler(CommandHandler("antispam_on", cmd_antispam_on))
    app.add_handler(CommandHandler("antispam_off", cmd_antispam_off))
    app.add_handler(CommandHandler("logs", cmd_logs))
    app.add_handler(CommandHandler("logs_user", cmd_logs_user))
    app.add_handler(CommandHandler("reset_attempts", cmd_reset_attempts))
    app.add_handler(CommandHandler("unban", cmd_unban))

    app.add_handler(ChatMemberHandler(handle_new_member, ChatMemberHandler.CHAT_MEMBER))
    app.add_handler(
        MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, handle_new_members_message)
    )
    app.add_handler(CallbackQueryHandler(captcha_callback, pattern=r"^cap\|"))
    app.add_handler(MessageReactionHandler(reaction_handler))

    app.add_error_handler(error_handler)
    return app


def main():
    app = build_app()
    app.run_polling(
        allowed_updates=[
            "message",
            "callback_query",
            "chat_member",
            "message_reaction",
        ],
        drop_pending_updates=True,
    )


if __name__ == "__main__":
    main()