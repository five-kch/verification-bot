# -*- coding: utf-8 -*-
"""
Auto-moderation bot (alerts only to ALERT_CHAT/ALERT_TOPIC with fallback)
- Мьют 3 дня за бан-слова и посты от имени канала.
- Ссылки разрешены.
- Уведомление отправляется в ALERT_CHAT/ALERT_TOPIC; при ошибке — в личку OWNER.
- Команды владельца: /ping, /listwords, /addword, /delword, /testalert, /where
"""

import logging, os, re
from datetime import datetime, timedelta, timezone

# Optional: nest_asyncio
try:
    import nest_asyncio
    nest_asyncio.apply()
except Exception:
    pass

# Load .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from telegram import Update, ChatPermissions
from telegram.constants import ParseMode
from telegram.error import BadRequest, Forbidden, TelegramError
from telegram.ext import ApplicationBuilder, MessageHandler, filters, CommandHandler, ContextTypes

BOT_TOKEN = os.environ.get("BOT_TOKEN")
if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN не задан в .env")

OWNER_ID = int(os.environ.get("OWNER_ID", "143014284"))
BANNED_WORDS_FILE = os.environ.get("BANNED_WORDS_FILE", "banned_words.txt")
MUTE_DAYS = int(os.environ.get("MUTE_DAYS", "3"))
DEBUG = os.environ.get("DEBUG", "1").lower() in ("1","true","yes","y")

ALERT_CHAT = int(os.environ.get("ALERT_CHAT", "0"))  # -100...
try:
    ALERT_TOPIC = int(os.environ.get("ALERT_TOPIC", "0"))  # 0 = без топика
except Exception:
    ALERT_TOPIC = 0

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
log = logging.getLogger("auto-mod")

# === helpers ===
_norm_tbl = str.maketrans({"ё":"е"})
_punct_re = re.compile(r"[^\w\s@#:/.-]", flags=re.UNICODE)

def norm_text(s: str) -> str:
    s = (s or "").lower().translate(_norm_tbl)
    s = _punct_re.sub(" ", s)
    return " ".join(s.split())

def load_banned_words():
    items = []
    if os.path.exists(BANNED_WORDS_FILE):
        with open(BANNED_WORDS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                w = norm_text(line.strip())
                if w:
                    items.append(w)
    return items

BANNED = load_banned_words()

def is_owner(update: Update) -> bool:
    return update.effective_user and update.effective_user.id == OWNER_ID

def alert_kwargs():
    kw = {"chat_id": ALERT_CHAT, "parse_mode": ParseMode.HTML}
    if ALERT_TOPIC:
        kw["message_thread_id"] = ALERT_TOPIC
    return kw

async def send_alert(context: ContextTypes.DEFAULT_TYPE, html_text: str):
    """Пытаемся отправить оповещение в ALERT_CHAT/ALERT_TOPIC, при неудаче — владельцу в ЛС."""
    try:
        if ALERT_CHAT != 0:
            await context.bot.send_message(**alert_kwargs(), text=html_text)
            return True
    except TelegramError as e:
        log.warning("send_alert to ALERT_CHAT failed: %s", e)
        try:
            await context.bot.send_message(chat_id=OWNER_ID, text=f"⚠️ Не удалось отправить в ALERT_CHAT: {e}\n\n{html_text}", parse_mode=ParseMode.HTML)
        except Exception as e2:
            log.warning("fallback DM to owner failed: %s", e2)
        return False

    # Если ALERT_CHAT=0 — сразу в ЛС владельцу
    try:
        await context.bot.send_message(chat_id=OWNER_ID, text=html_text, parse_mode=ParseMode.HTML)
        return True
    except Exception as e2:
        log.warning("fallback DM to owner failed: %s", e2)
        return False

async def can_restrict(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> bool:
    try:
        me = await context.bot.get_chat_member(chat_id, (await context.bot.get_me()).id)
        return getattr(me, "can_restrict_members", False) or me.status in ("creator", "administrator")
    except Exception as e:
        log.warning("get_chat_member(self) failed: %s", e)
        return False

def mention_html(user):
    name = (user.full_name or user.first_name or "пользователь")
    return "<a href='tg://user?id={id}'>{name}</a>".format(id=user.id, name=name)

async def enforce_mute(context, chat_id, user, reason, src_chat_title: str, days=MUTE_DAYS):
    if not await can_restrict(context, chat_id):
        if DEBUG: log.info("Skip mute: no restrict permission in chat %s", chat_id)
        await send_alert(context, "⚠️ Нет прав на ограничение участников в этом чате.\nЧат: {chat} (id: {cid})".format(chat=src_chat_title or "—", cid=chat_id))
        return False
    try:
        member = await context.bot.get_chat_member(chat_id, user.id)
        if member.status in ("administrator", "creator"):
            if DEBUG: log.info("Skip mute: user %s is admin/creator", user.id)
            await send_alert(context, "ℹ️ {who} — админ/владелец, мьют не применён ({reason}).\nЧат: {chat}".format(
                who=mention_html(user), reason=reason, chat=src_chat_title or chat_id
            ))
            return False
    except Exception as e:
        log.warning("get_chat_member(target) failed: %s", e)

    until = datetime.now(timezone.utc) + timedelta(days=days)
    try:
        await context.bot.restrict_chat_member(
            chat_id=chat_id,
            user_id=user.id,
            permissions=ChatPermissions(can_send_messages=False),
            until_date=until
        )
        await send_alert(context,
            "🚫 {who} - нарушитель ата-та. Пиши админам.\n""Мут на {d} дн. до {when}.".format(
                who=mention_html(user),
                d=days,
                when=until.astimezone().strftime('%Y-%m-%d %H:%M'),
                chat=src_chat_title or "—",
                cid=chat_id,
            )
        )
        if DEBUG: log.info("Muted user id=%s reason=%s until=%s", user.id, reason, until)
        return True
    except (BadRequest, Forbidden) as e:
        log.warning("restrict_chat_member failed: %s", e)
        await send_alert(context, "⚠️ Не удалось ограничить {who}: {err}\nЧат: {chat}".format(
            who=mention_html(user), err=e, chat=src_chat_title or chat_id
        ))
        return False
    except Exception as e:
        log.exception("restrict_chat_member unexpected:")
        await send_alert(context, "⚠️ Ошибка при ограничении {who}: {err}\nЧат: {chat}".format(
            who=mention_html(user), err=e, chat=src_chat_title or chat_id
        ))
        return False

# === Owner commands (ANY chat) ===
async def cmd_ping(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update): return
    await update.message.reply_text("✅ Я на месте.")

async def cmd_listwords(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update): return
    await update.message.reply_text("📃 Запрещённые слова:\n" + ("\n".join(BANNED) if BANNED else "— список пуст —"))

async def cmd_addword(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update): return
    if not context.args:
        await update.message.reply_text("❗ Укажи слово: /addword <слово>"); return
    w = norm_text(context.args[0])
    if w in BANNED:
        await update.message.reply_text("⚠️ Уже в списке.")
    else:
        BANNED.append(w)
        with open(BANNED_WORDS_FILE, "w", encoding="utf-8") as f:
            for x in sorted(set(BANNED)): f.write(x + "\n")
        await update.message.reply_text("✅ Добавлено: {w}".format(w=w))

async def cmd_delword(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update): return
    if not context.args:
        await update.message.reply_text("❗ Укажи слово: /delword <слово>"); return
    w = norm_text(context.args[0])
    if w not in BANNED:
        await update.message.reply_text("⚠️ Нет в списке.")
    else:
        BANNED.remove(w)
        with open(BANNED_WORDS_FILE, "w", encoding="utf-8") as f:
            for x in sorted(set(BANNED)): f.write(x + "\n")
        await update.message.reply_text("🗑️ Удалено: {w}".format(w=w))

async def cmd_testalert(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update): return
    ok = await send_alert(context, "🔔 Тестовое уведомление. Если ты это видишь в нужной теме — маршрут настроен.")
    await update.message.reply_text("Отправка в ALERT: " + ("успешна" if ok else "не удалось"))

async def cmd_where(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update): return
    msg = update.effective_message
    tid = getattr(msg, "message_thread_id", None)
    await update.message.reply_text(f"chat.id={update.effective_chat.id}, thread_id={tid}")

# === Moderation (ANY chat) ===
async def on_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    m = update.effective_message
    u = update.effective_user
    c = update.effective_chat
    if not m or not u or not c:
        return
    if u.id == OWNER_ID:
        return

    # Пост от имени канала → удаляем и мутим
    if m.sender_chat:
        try:
            await m.delete()
        except Exception as e:
            log.warning("delete sender_chat failed: %s", e)
        await enforce_mute(context, c.id, u, reason="пост от имени канала", src_chat_title=c.title or "")
        return

    # Бан-слова
    text = norm_text(m.text or m.caption or "")
    for w in BANNED:
        if w and w in text:
            if DEBUG: log.info('BANWORD match: "%s" by user %s in chat %s; text="%s"', w, u.id, c.id, text)
            try:
                await m.delete()
            except Exception as e:
                log.warning("delete banned msg failed: %s", e)
            await enforce_mute(context, c.id, u, reason="запрещённые слова", src_chat_title=c.title or "")
            return

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("ping", cmd_ping))
    app.add_handler(CommandHandler("listwords", cmd_listwords))
    app.add_handler(CommandHandler("addword", cmd_addword))
    app.add_handler(CommandHandler("delword", cmd_delword))
    app.add_handler(CommandHandler("testalert", cmd_testalert))
    app.add_handler(CommandHandler("where", cmd_where))
    app.add_handler(MessageHandler((filters.TEXT | filters.Caption(True)) & ~filters.COMMAND, on_message))
    log.info("Auto-moderation bot started — alerts to ALERT_CHAT/ALERT_TOPIC with owner fallback")
    app.run_polling(allowed_updates=["message", "edited_message"])

if __name__ == "__main__":
    main()
