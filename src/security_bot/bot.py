from __future__ import annotations

import argparse
import asyncio
import logging
import os
from pathlib import Path
import secrets
import time

from telegram import Chat, ChatPermissions, MessageEntity, Update, User
from telegram.constants import ChatMemberStatus, ParseMode
from telegram.error import BadRequest, TelegramError
from telegram.ext import (
    Application,
    ApplicationHandlerStop,
    CallbackQueryHandler,
    ChatMemberHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from .moderation import (
    contains_evm_address,
    display_name,
    escape_html,
    name_matches_keywords,
    normalize_domain,
    message_contains_blocked_url,
)
from .storage import PendingCaptcha, Recipient, SavedFilter, SettingsStore
from .diagnostics import configure_logging
from .workflows import process_member_action, present, retry_delay, remember_cleanup, message_absent
from .workflows import CAPTCHA_MAX_EVENT_AGE_SECONDS
from .background import (
    deliver_pending_alerts, flush_on_shutdown, maintenance, queue_alerts,
    scan_deleted_batch, scan_names,
)


LOGGER = logging.getLogger(__name__)
CAPTCHA_RECOVERY_INTERVAL_SECONDS = 15
CAPTCHA_MAX_CONCURRENT_RECOVERIES = 3
ADMIN_STATUSES = {ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER}
ADMIN_COMMANDS_TEXT = """Admin Commands:
/url ON|OFF - enable or disable URL restriction. Default: OFF.
/addurl example.com - allow a domain and its subdomains.
/listurl - list allowed URL domains.
/delurl example.com - remove an allowed domain.
/alert ON|OFF - enable or disable keyword alerts. Default: OFF.
/addreceiver @username - add an alert receiver.
/listreceiver - list alert receivers.
/delreceiver @username - remove an alert receiver.
/addkeyword Meta - add a watched keyword.
/listkeyword - list watched keywords.
/delkeyword Meta - remove a watched keyword.
/scandelacc - scan known members and report suspected deleted accounts.
/confirmdelacc user_id - remove a reported account after admin review.
/delca ON|OFF - remove users who join with an EVM-like address in their displayed name. Default: OFF.
/sendca ON|OFF - delete messages containing EVM-like addresses. Default: OFF.
/clearevents ON|OFF - delete join and leave service messages. Default: OFF.
/captcha ON|OFF - require new members to verify with a button. Default: OFF.
/captchatime seconds - set CAPTCHA verification time. Default: 60 seconds.
/captchamode button - set CAPTCHA mode. Button is currently the only mode.
/warningmsg ON|OFF - enable or disable scheduled warning messages. Default: OFF.
/warningtxt message - set the warning message text.
/warningfreq seconds - set the warning interval in seconds. Default: 600.
/warnmedia - reply to an image, GIF, or video to attach it to warning messages.
/setfilter keyword - reply to a message to save an exact-match auto-response.
/listfilter - list saved auto-response filters.
/delfilter keyword - delete a saved auto-response filter."""


def _username_key(value: str) -> str:
    normalized = value.strip().lstrip("@").lower()
    if not normalized:
        raise ValueError("username cannot be empty")
    return normalized


def _bool_arg(raw: str | None) -> bool | None:
    if raw is None:
        return None
    value = raw.casefold()
    if value in {"on", "true", "1", "yes", "enable", "enabled"}:
        return True
    if value in {"off", "false", "0", "no", "disable", "disabled"}:
        return False
    return None


def _alert_user_label(user: User) -> str:
    name = display_name(user.first_name, user.last_name, user.username)
    escaped_name = escape_html(name)
    if not user.username:
        return escaped_name
    username = f"@{user.username}"
    if name == username:
        return escaped_name
    return f"{escaped_name} ({escape_html(username)})"


def _alert_with_group(message_html: str, group_title: str | None) -> str:
    title = escape_html(group_title or "Unnamed group")
    return f"{message_html}\n\nGroup: <b>{title}</b>"


def _looks_like_deleted_account(user: User) -> bool:
    return user.first_name == "Deleted Account" and not user.last_name and not user.username


def _warning_job_name(chat_id: int) -> str:
    return f"warning:{chat_id}"


def _captcha_job_name(chat_id: int, user_id: int) -> str:
    return f"captcha:{chat_id}:{user_id}"


def _captcha_key(user_id: int) -> str:
    return str(user_id)


def _captcha_callback_data(chat_id: int, user_id: int, token: str) -> str:
    return f"captcha|{chat_id}|{user_id}|{token}"


def _captcha_permissions() -> ChatPermissions:
    return ChatPermissions(can_send_messages=False)


def _captcha_welcome_text(user: User, timeout_seconds: int) -> str:
    first_name = escape_html(user.first_name or "there")
    user_label = first_name
    if user.username:
        user_label = f"{first_name} ({escape_html('@' + user.username)})"
    return (
        f"Hello {user_label}! Welcome to the community! Please click the button below within "
        f"{timeout_seconds} seconds to join, otherwise you will be kicked!"
    )


def _utf16_len(value: str) -> int:
    return len(value.encode("utf-16-le")) // 2


def _extract_command_payload(text: str) -> tuple[str, int]:
    command_end = next((index for index, char in enumerate(text) if char.isspace()), len(text))
    payload_start = command_end
    while payload_start < len(text) and text[payload_start].isspace():
        payload_start += 1
    return text[payload_start:], _utf16_len(text[:payload_start])


def _shift_message_entities(message, payload_start_offset: int) -> list[dict[str, object]]:
    shifted: list[dict[str, object]] = []
    for entity in message.entities or []:
        entity_data = entity.to_dict()
        entity_start = int(entity_data["offset"])
        entity_end = entity_start + int(entity_data["length"])
        if entity_end <= payload_start_offset:
            continue
        entity_data["offset"] = max(entity_start - payload_start_offset, 0)
        entity_data["length"] = entity_end - max(entity_start, payload_start_offset)
        if entity_data["length"] > 0:
            shifted.append(entity_data)
    return shifted


def _warning_entities(context: ContextTypes.DEFAULT_TYPE, settings) -> list[MessageEntity] | None:
    if not settings.warning_entities:
        return None
    return [MessageEntity.de_json(entity, context.bot) for entity in settings.warning_entities]


def _saved_entities(context: ContextTypes.DEFAULT_TYPE, entities: list[dict[str, object]]) -> list[MessageEntity] | None:
    if not entities:
        return None
    return [MessageEntity.de_json(entity, context.bot) for entity in entities]


async def _is_group_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    chat = update.effective_chat
    user = update.effective_user
    if chat is None or user is None:
        return False
    if chat.type == Chat.PRIVATE:
        return False
    message = update.effective_message
    if message and message.sender_chat and message.sender_chat.id == chat.id:
        return True
    try:
        member = await context.bot.get_chat_member(chat.id, user.id)
    except TelegramError:
        LOGGER.exception("Unable to check admin status for user %s in chat %s", user.id, chat.id)
        return False
    return member.status in ADMIN_STATUSES


async def _is_chat_admin(context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int) -> bool:
    try:
        member = await context.bot.get_chat_member(chat_id, user_id)
    except TelegramError:
        LOGGER.exception("Unable to check admin status for user %s in chat %s", user_id, chat_id)
        return False
    return member.status in ADMIN_STATUSES


async def _require_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if await _is_group_admin(update, context):
        return True
    if update.effective_message:
        await update.effective_message.reply_text("Only group admins can use this command.")
    return False


def _store(context: ContextTypes.DEFAULT_TYPE) -> SettingsStore:
    store = context.application.bot_data.get("store")
    if not isinstance(store, SettingsStore):
        raise RuntimeError("Settings store is not configured")
    return store


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if user and user.username:
        context.application.bot_data.setdefault("private_users", {})[_username_key(user.username)] = user.id
        if update.effective_chat and update.effective_chat.type == Chat.PRIVATE:
            store = _store(context)
            for settings in store.chats().values():
                recipient = settings.recipients.get(_username_key(user.username))
                if recipient and recipient.user_id in {None, user.id}:
                    recipient.user_id = user.id
                    for alert in settings.pending_alerts.values():
                        if alert.receiver == recipient.username:
                            alert.user_id = user.id
                            alert.next_attempt = 0
                    store.mark_dirty()
            store.flush()
    if update.effective_message:
        await update.effective_message.reply_text(
            "Security bot is running. Add me to a group as admin, then configure me there.\n\n"
            f"{ADMIN_COMMANDS_TEXT}"
        )


async def toggle_command(update: Update, context: ContextTypes.DEFAULT_TYPE, key: str, label: str) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return
    desired = _bool_arg(context.args[0] if context.args else None)
    if desired is None:
        await message.reply_text(f"Usage: /{label} ON or /{label} OFF")
        return
    settings = _store(context).chat(chat.id)
    setattr(settings, key, desired)
    _store(context).save()
    await message.reply_text(f"/{label} is {'ON' if desired else 'OFF'}.")


async def url_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await toggle_command(update, context, "url_enabled", "url")


async def alert_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await toggle_command(update, context, "alert_enabled", "alert")
    if update.effective_chat:
        settings = _store(context).chat(update.effective_chat.id)
        if not settings.alert_enabled and settings.pending_alerts:
            settings.pending_alerts.clear()
            _store(context).save()


async def delca_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await toggle_command(update, context, "delca_enabled", "delca")


async def sendca_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await toggle_command(update, context, "sendca_enabled", "sendca")


async def clearevents_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await toggle_command(update, context, "clear_events_enabled", "clearevents")


async def captcha_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await toggle_command(update, context, "captcha_enabled", "captcha")
    chat = update.effective_chat
    if chat is None:
        return
    settings = _store(context).chat(chat.id)
    if settings.captcha_enabled:
        return
    for pending in settings.pending_captchas.values():
        if pending.reason == "captcha" and pending.phase in {"provisioning", "waiting", "verifying", "kick"}:
            pending.phase = "release"
            pending.expires_at = int(time.time())
            _store(context).save()
            _schedule_captcha_timeout(context, chat.id, pending.user_id, pending.token, pending.expires_at)


async def captchatime(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return
    if not context.args:
        await message.reply_text("Usage: /captchatime seconds")
        return
    try:
        seconds = int(context.args[0])
    except ValueError:
        await message.reply_text("CAPTCHA time must be a whole number of seconds.")
        return
    if seconds < 10:
        await message.reply_text("CAPTCHA time must be at least 10 seconds.")
        return
    settings = _store(context).chat(chat.id)
    settings.captcha_timeout_seconds = seconds
    _store(context).save()
    await message.reply_text(f"CAPTCHA verification time set to {seconds} seconds.")


async def captchamode(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    message = update.effective_message
    if message is None:
        return
    mode = context.args[0].casefold() if context.args else ""
    if mode != "button":
        await message.reply_text("Usage: /captchamode button")
        return
    chat = update.effective_chat
    if chat is None:
        return
    settings = _store(context).chat(chat.id)
    settings.captcha_mode = "button"
    _store(context).save()
    await message.reply_text("CAPTCHA mode set to button.")


async def warningmsg_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return
    desired = _bool_arg(context.args[0] if context.args else None)
    if desired is None:
        await message.reply_text("Usage: /warningmsg ON or /warningmsg OFF")
        return
    settings = _store(context).chat(chat.id)
    if desired and not settings.warning_text and not settings.warning_media_file_id:
        await message.reply_text("Set warning text with /warningtxt or media with /warnmedia before turning this ON.")
        return
    settings.warning_enabled = desired
    _store(context).save()
    _schedule_warning_job(context, chat.id)
    await message.reply_text(f"/warningmsg is {'ON' if desired else 'OFF'}.")


async def addurl(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return
    if not context.args:
        await message.reply_text("Usage: /addurl example.com")
        return
    try:
        domain = normalize_domain(context.args[0])
    except ValueError as exc:
        await message.reply_text(str(exc))
        return
    settings = _store(context).chat(chat.id)
    if domain not in settings.allowed_urls:
        settings.allowed_urls.append(domain)
        settings.allowed_urls.sort()
        _store(context).save()
    await message.reply_text(f"Allowed URL domain added: {domain}")


async def listurl(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return
    domains = _store(context).chat(chat.id).allowed_urls
    await message.reply_text("Allowed URL domains:\n" + "\n".join(domains) if domains else "No URL domains are allowed.")


async def delurl(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return
    if not context.args:
        await message.reply_text("Usage: /delurl example.com")
        return
    try:
        domain = normalize_domain(context.args[0])
    except ValueError as exc:
        await message.reply_text(str(exc))
        return
    settings = _store(context).chat(chat.id)
    if domain in settings.allowed_urls:
        settings.allowed_urls.remove(domain)
        _store(context).save()
        await message.reply_text(f"Allowed URL domain removed: {domain}")
    else:
        await message.reply_text(f"{domain} is not in the allowed URL list.")


async def addkeyword(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return
    keyword = " ".join(context.args).strip()
    if not keyword:
        await message.reply_text("Usage: /addkeyword keyword")
        return
    settings = _store(context).chat(chat.id)
    if keyword.casefold() not in {item.casefold() for item in settings.keywords}:
        settings.keywords.append(keyword)
        settings.keywords.sort(key=str.casefold)
        _store(context).save()
    await message.reply_text(f"Keyword added: {keyword}")


async def delkeyword(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return
    keyword = " ".join(context.args).strip()
    if not keyword:
        await message.reply_text("Usage: /delkeyword keyword")
        return
    settings = _store(context).chat(chat.id)
    match = next((item for item in settings.keywords if item.casefold() == keyword.casefold()), None)
    if match is None:
        await message.reply_text(f"Keyword not found: {keyword}")
        return
    settings.keywords.remove(match)
    _store(context).save()
    await message.reply_text(f"Keyword removed: {match}")


async def listkeyword(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return
    keywords = _store(context).chat(chat.id).keywords
    if not keywords:
        await message.reply_text("No keywords are configured.")
        return
    await message.reply_text("Keywords:\n" + "\n".join(keywords))


async def addrecipient(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return
    if not context.args:
        await message.reply_text("Usage: /addreceiver @username")
        return
    try:
        username = _username_key(context.args[0])
    except ValueError as exc:
        await message.reply_text(str(exc))
        return
    private_users = context.application.bot_data.setdefault("private_users", {})
    user_id = private_users.get(username)
    settings = _store(context).chat(chat.id)
    if username in settings.recipients:
        user_id = settings.recipients[username].user_id or user_id
    settings.recipients[username] = Recipient(username=username, user_id=user_id)
    _store(context).save()
    suffix = "" if user_id else " Ask this user to /start the bot once so private alerts can be delivered."
    await message.reply_text(f"Alert recipient added: @{username}.{suffix}")


async def delrecipient(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return
    if not context.args:
        await message.reply_text("Usage: /delreceiver @username")
        return
    try:
        username = _username_key(context.args[0])
    except ValueError as exc:
        await message.reply_text(str(exc))
        return
    settings = _store(context).chat(chat.id)
    if username in settings.recipients:
        del settings.recipients[username]
        settings.pending_alerts = {key: alert for key, alert in settings.pending_alerts.items() if alert.receiver != username}
        _store(context).save()
        await message.reply_text(f"Alert recipient removed: @{username}")
    else:
        await message.reply_text(f"@{username} is not in the alert recipient list.")


async def listrecipient(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return
    recipients = sorted(_store(context).chat(chat.id).recipients)
    if not recipients:
        await message.reply_text("No alert recipients are configured.")
        return
    await message.reply_text("Alert recipients:\n" + "\n".join(f"@{username}" for username in recipients))


async def warningtxt(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return
    raw_text = message.text or ""
    text, payload_start_offset = _extract_command_payload(raw_text)
    if not text:
        await message.reply_text("Usage: /warningtxt message")
        return
    settings = _store(context).chat(chat.id)
    if settings.warning_media_file_id and _utf16_len(text) > 1024:
        await message.reply_text("Warning text with media must fit within 1024 characters. Shorten the text first.")
        return
    settings.warning_text = text
    settings.warning_entities = _shift_message_entities(message, payload_start_offset)
    _store(context).save()
    await message.reply_text("Warning text has been updated.")


async def warningfreq(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return
    if not context.args:
        await message.reply_text("Usage: /warningfreq seconds")
        return
    try:
        seconds = int(context.args[0])
    except ValueError:
        await message.reply_text("Frequency must be a whole number of seconds.")
        return
    if seconds < 10:
        await message.reply_text("Frequency must be at least 10 seconds.")
        return
    settings = _store(context).chat(chat.id)
    settings.warning_freq_seconds = seconds
    _store(context).save()
    _schedule_warning_job(context, chat.id)
    await message.reply_text(f"Warning frequency set to {seconds} seconds.")


def _extract_warning_media(reply_message) -> tuple[str, str] | None:
    if reply_message.photo:
        return "photo", reply_message.photo[-1].file_id
    if reply_message.animation:
        return "animation", reply_message.animation.file_id
    if reply_message.video:
        return "video", reply_message.video.file_id
    if reply_message.document:
        mime_type = reply_message.document.mime_type or ""
        if mime_type.startswith("image/") or mime_type.startswith("video/"):
            return "document", reply_message.document.file_id
    return None


async def warnmedia(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return
    reply = message.reply_to_message
    if reply is None:
        await message.reply_text("Reply to an image, GIF, or video with /warnmedia.")
        return
    media = _extract_warning_media(reply)
    if media is None:
        await message.reply_text("No supported media found. Reply to an image, GIF, or video with /warnmedia.")
        return
    media_type, file_id = media
    settings = _store(context).chat(chat.id)
    if _utf16_len(settings.warning_text) > 1024:
        await message.reply_text("Shorten the warning text to 1024 characters before attaching media.")
        return
    settings.warning_media_type = media_type
    settings.warning_media_file_id = file_id
    _store(context).save()
    await message.reply_text("Media has been added.")


def _filter_key(value: str) -> str:
    normalized = value.strip()
    if normalized.startswith("/") and len(normalized.split()) == 1:
        normalized = normalized[1:]
        normalized = normalized.split("@", 1)[0]
    return normalized.casefold()


def _message_entities_to_dict(entities) -> list[dict[str, object]]:
    return [entity.to_dict() for entity in entities or []]


def _saved_filter_from_message(keyword: str, message) -> SavedFilter | None:
    media = _extract_warning_media(message)
    if message.text:
        return SavedFilter(
            keyword=keyword,
            text=message.text,
            entities=_message_entities_to_dict(message.entities),
        )
    if media is not None:
        media_type, file_id = media
        return SavedFilter(
            keyword=keyword,
            text=message.caption or "",
            entities=_message_entities_to_dict(message.caption_entities),
            media_type=media_type,
            media_file_id=file_id,
        )
    if message.caption:
        return SavedFilter(
            keyword=keyword,
            text=message.caption,
            entities=_message_entities_to_dict(message.caption_entities),
        )
    return None


async def setfilter(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return
    keyword = " ".join(context.args).strip()
    if not keyword:
        await message.reply_text("Usage: /setfilter keyword")
        return
    if message.reply_to_message is None:
        await message.reply_text("Reply to the message you want the bot to save, then send /setfilter keyword.")
        return
    saved_filter = _saved_filter_from_message(keyword, message.reply_to_message)
    if saved_filter is None:
        await message.reply_text("That replied message has no supported text or media to save.")
        return
    settings = _store(context).chat(chat.id)
    settings.filters[_filter_key(keyword)] = saved_filter
    _store(context).save()
    await message.reply_text(f"Filter saved: {keyword}")


async def delfilter(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return
    keyword = " ".join(context.args).strip()
    if not keyword:
        await message.reply_text("Usage: /delfilter keyword")
        return
    settings = _store(context).chat(chat.id)
    removed = settings.filters.pop(_filter_key(keyword), None)
    if removed is None:
        await message.reply_text(f"Filter not found: {keyword}")
        return
    _store(context).save()
    await message.reply_text(f"Filter deleted: {removed.keyword}")


async def listfilter(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return
    saved_filters = sorted(
        _store(context).chat(chat.id).filters.values(),
        key=lambda saved_filter: saved_filter.keyword.casefold(),
    )
    if not saved_filters:
        await message.reply_text("No filters are configured.")
        return
    await message.reply_text("Filters:\n" + "\n".join(saved_filter.keyword for saved_filter in saved_filters))


async def _send_filter_response(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    trigger_message_id: int,
    saved_filter: SavedFilter,
) -> None:
    text = saved_filter.text or None
    entities = _saved_entities(context, saved_filter.entities) if text else None
    if not saved_filter.media_file_id:
        await context.bot.send_message(
            chat_id=chat_id,
            text=text or "",
            entities=entities,
            reply_to_message_id=trigger_message_id,
            allow_sending_without_reply=True,
        )
        return
    if saved_filter.media_type == "photo":
        await context.bot.send_photo(
            chat_id=chat_id,
            photo=saved_filter.media_file_id,
            caption=text,
            caption_entities=entities,
            reply_to_message_id=trigger_message_id,
            allow_sending_without_reply=True,
        )
    elif saved_filter.media_type == "animation":
        await context.bot.send_animation(
            chat_id=chat_id,
            animation=saved_filter.media_file_id,
            caption=text,
            caption_entities=entities,
            reply_to_message_id=trigger_message_id,
            allow_sending_without_reply=True,
        )
    elif saved_filter.media_type == "video":
        await context.bot.send_video(
            chat_id=chat_id,
            video=saved_filter.media_file_id,
            caption=text,
            caption_entities=entities,
            reply_to_message_id=trigger_message_id,
            allow_sending_without_reply=True,
        )
    elif saved_filter.media_type == "document":
        await context.bot.send_document(
            chat_id=chat_id,
            document=saved_filter.media_file_id,
            caption=text,
            caption_entities=entities,
            reply_to_message_id=trigger_message_id,
            allow_sending_without_reply=True,
        )
    else:
        await context.bot.send_message(
            chat_id=chat_id,
            text=text or "",
            entities=entities,
            reply_to_message_id=trigger_message_id,
            allow_sending_without_reply=True,
        )


async def _maybe_send_filter_response(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return False
    text = (message.text or "").strip()
    if not text:
        return False
    if text.startswith("/"):
        command = text.split(maxsplit=1)[0]
        if "@" in command and command.split("@", 1)[1].casefold() != context.bot.username.casefold():
            return False
    saved_filter = _store(context).chat(chat.id).filters.get(_filter_key(text))
    if saved_filter is None:
        return False
    try:
        await _send_filter_response(context, chat.id, message.message_id, saved_filter)
    except TelegramError:
        LOGGER.exception("Unable to send filter response for %s in chat %s", saved_filter.keyword, chat.id)
    return True


async def handle_filter_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat = update.effective_chat
    message = update.effective_message
    user = update.effective_user
    if chat is None or message is None or user is None or chat.type == Chat.PRIVATE:
        return
    await _maybe_send_filter_response(update, context)


async def send_warning_message(context) -> None:
    if context.job is None or context.job.data is None:
        return
    chat_id = int(context.job.data["chat_id"])
    data = context.application.bot_data
    active = data.setdefault("warning_active", set())
    if chat_id in active or data.setdefault("warning_backoff", {}).get(chat_id, 0) > time.time():
        return
    settings = _store(context).chat(chat_id)
    if not settings.warning_enabled or not (settings.warning_text or settings.warning_media_file_id):
        return
    if settings.warning_media_file_id and _utf16_len(settings.warning_text) > 1024:
        LOGGER.error("Warning in chat %s has a caption over 1024 characters; edit /warningtxt before sending", chat_id)
        return
    active.add(chat_id)
    try:
        if not await _delete_previous_warning_messages(context, chat_id):
            return
        if not settings.warning_enabled:
            return
        sent_message = await _send_configured_warning(context, chat_id)
        settings.warning_message_ids = [sent_message.message_id]
        _store(context).save()
    except TelegramError as exc:
        data["warning_backoff"][chat_id] = int(time.time()) + retry_delay(exc, 1)
        LOGGER.warning("Unable to send warning in chat %s: %s", chat_id, exc)
    finally:
        active.discard(chat_id)


async def _delete_previous_warning_messages(context, chat_id: int) -> bool:
    store = _store(context)
    settings = store.chat(chat_id)
    for message_id in list(settings.warning_message_ids):
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=message_id)
        except BadRequest as exc:
            if not message_absent(exc):
                raise
        settings.warning_message_ids.remove(message_id)
        store.save()
    return not settings.warning_message_ids


async def _send_configured_warning(context: ContextTypes.DEFAULT_TYPE, chat_id: int):
    settings = _store(context).chat(chat_id)
    text = settings.warning_text or None
    entities = _warning_entities(context, settings) if text else None
    media_type = settings.warning_media_type
    file_id = settings.warning_media_file_id
    if not file_id:
        return await context.bot.send_message(chat_id=chat_id, text=text or "", entities=entities)
    if media_type == "photo":
        return await context.bot.send_photo(chat_id=chat_id, photo=file_id, caption=text, caption_entities=entities)
    elif media_type == "animation":
        return await context.bot.send_animation(chat_id=chat_id, animation=file_id, caption=text, caption_entities=entities)
    elif media_type == "video":
        return await context.bot.send_video(chat_id=chat_id, video=file_id, caption=text, caption_entities=entities)
    elif media_type == "document":
        return await context.bot.send_document(chat_id=chat_id, document=file_id, caption=text, caption_entities=entities)
    else:
        return await context.bot.send_message(chat_id=chat_id, text=text or "", entities=entities)


def _schedule_warning_job(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> None:
    job_queue = context.application.job_queue
    if job_queue is None:
        LOGGER.warning("Job queue is unavailable; warning messages are disabled.")
        return
    name = _warning_job_name(chat_id)
    for job in job_queue.get_jobs_by_name(name):
        job.schedule_removal()
    settings = _store(context).chat(chat_id)
    if not settings.warning_enabled:
        return
    interval = max(settings.warning_freq_seconds, 10)
    job_queue.run_repeating(
        send_warning_message,
        interval=interval,
        first=interval,
        name=name,
        data={"chat_id": chat_id},
    )


def _schedule_all_warning_jobs(app: Application) -> None:
    job_queue = app.job_queue
    if job_queue is None:
        LOGGER.warning("Job queue is unavailable; warning messages are disabled.")
        return
    store = app.bot_data.get("store")
    if not isinstance(store, SettingsStore):
        return
    for chat_id, settings in store.chats().items():
        if not settings.warning_enabled:
            continue
        interval = max(settings.warning_freq_seconds, 10)
        job_queue.run_repeating(
            send_warning_message,
            interval=interval,
            first=interval,
            name=_warning_job_name(chat_id),
            data={"chat_id": chat_id},
        )


def _schedule_captcha_timeout(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    user_id: int,
    token: str,
    expires_at: int,
) -> None:
    _enqueue_captcha_timeout(context.application, chat_id, user_id, token, expires_at)


def _enqueue_captcha_timeout(
    app: Application, chat_id: int, user_id: int, token: str, expires_at: int,
) -> None:
    job_queue = app.job_queue
    if job_queue is None:
        LOGGER.warning("Job queue is unavailable; CAPTCHA timeout cannot be scheduled.")
        return
    name = _captcha_job_name(chat_id, user_id)
    for job in job_queue.get_jobs_by_name(name):
        job.schedule_removal()
    seconds_remaining = max(expires_at - int(time.time()), 0)
    job_queue.run_once(
        captcha_timeout,
        when=seconds_remaining,
        name=name,
        data={"chat_id": chat_id, "user_id": user_id, "token": token},
        job_kwargs={"misfire_grace_time": None},
    )


async def captcha_timeout(context: ContextTypes.DEFAULT_TYPE) -> None:
    job = context.job
    if job is None or job.data is None:
        return
    chat_id = int(job.data["chat_id"])
    user_id = int(job.data["user_id"])
    token = str(job.data["token"])
    # Reserve the member before waiting for capacity so the watchdog cannot duplicate work.
    active = context.application.bot_data.setdefault("captcha_active", set())
    key = (chat_id, user_id)
    if key in active:
        return
    active.add(key)
    limit = context.application.bot_data.get("captcha_recovery_limit")
    if limit is None:
        limit = asyncio.Semaphore(CAPTCHA_MAX_CONCURRENT_RECOVERIES)
        context.application.bot_data["captcha_recovery_limit"] = limit
    try:
        async with limit:
            await _process_captcha_timeout(context, chat_id, user_id, token)
    finally:
        active.discard(key)
        pending = _store(context).chat(chat_id).pending_captchas.get(str(user_id))
        if pending is not None and pending.token != token:
            # A rapid rejoin may have consumed its new job while the old action held this member.
            _enqueue_captcha_timeout(context.application, chat_id, user_id, pending.token, pending.expires_at)


async def _process_captcha_timeout(context, chat_id: int, user_id: int, token: str) -> None:
    await process_member_action(
        context, chat_id, user_id, token, _schedule_captcha_timeout, _captcha_welcome_text,
    )


def _schedule_all_captcha_timeouts(app: Application) -> None:
    job_queue = app.job_queue
    store = app.bot_data.get("store")
    if job_queue is None or not isinstance(store, SettingsStore):
        return
    changed = False
    for chat_id, settings in store.chats().items():
        for pending in settings.pending_captchas.values():
            if pending.phase == "verifying":
                pending.phase = "release"
                pending.expires_at = int(time.time())
                changed = True
            _enqueue_captcha_timeout(
                app, chat_id, pending.user_id, pending.token, pending.expires_at,
            )
    if changed:
        store.save()


async def recover_missing_captcha_jobs(context: ContextTypes.DEFAULT_TYPE) -> None:
    app = context.application
    queue = app.job_queue
    if queue is None:
        return
    active = app.bot_data.get("captcha_active", set())
    restored = 0
    for chat_id, settings in _store(context).chats().items():
        for pending in list(settings.pending_captchas.values()):
            if (chat_id, pending.user_id) in active:
                continue
            jobs = queue.get_jobs_by_name(_captcha_job_name(chat_id, pending.user_id))
            if any(not job.removed and job.data and job.data.get("token") == pending.token for job in jobs):
                continue
            _enqueue_captcha_timeout(app, chat_id, pending.user_id, pending.token, pending.expires_at)
            restored += 1
    if restored:
        LOGGER.warning("Restored %s missing CAPTCHA timeout/recovery jobs", restored)


async def _start_captcha(update: Update, context: ContextTypes.DEFAULT_TYPE, user: User) -> None:
    chat = update.effective_chat
    if chat is None:
        return
    now = int(time.time())
    change = getattr(update, "chat_member", None)
    joined_at = int(change.date.timestamp()) if change is not None else now
    session_started = context.application.bot_data.get("captcha_session_started_at", 0)
    if (change is not None and joined_at <= session_started) or now - joined_at > CAPTCHA_MAX_EVENT_AGE_SECONDS:
        LOGGER.info("Skipping CAPTCHA for old join: chat %s user %s joined_at=%s session_started=%s", chat.id, user.id, joined_at, session_started)
        return
    settings = _store(context).chat(chat.id)
    old = settings.pending_captchas.get(str(user.id))
    if old:
        remember_cleanup(settings, old.message_id)
    pending = PendingCaptcha(
        user_id=user.id, token=secrets.token_urlsafe(12), message_id=0, expires_at=int(time.time()),
        phase="provisioning", first_name=user.first_name, username=user.username, joined_at=joined_at,
    )
    settings.pending_captchas[str(user.id)] = pending
    _store(context).save()
    _schedule_captcha_timeout(context, chat.id, user.id, pending.token, pending.expires_at)


async def handle_captcha_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if query is None or not isinstance(query.data, str):
        return
    parts = query.data.split("|")
    if len(parts) != 4:
        return
    try:
        chat_id, user_id = int(parts[1]), int(parts[2])
    except ValueError:
        await query.answer("Invalid CAPTCHA.", show_alert=True)
        return
    if query.from_user.id != user_id:
        await query.answer("This CAPTCHA is for another user.", show_alert=True)
        return
    settings = _store(context).chat(chat_id)
    pending = settings.pending_captchas.get(str(user_id))
    if (
        query.message is None or query.message.chat_id != chat_id
        or pending is None or pending.token != parts[3]
        or query.message.message_id != pending.message_id
        or pending.reason != "captcha"
    ):
        await query.answer("This CAPTCHA has expired.", show_alert=True)
        return
    if pending.phase == "release":
        await query.answer("Verification accepted. Restoring your permissions.")
        return
    if pending.phase != "waiting" or (pending.deadline or pending.expires_at) <= int(time.time()):
        await query.answer("This CAPTCHA has expired.", show_alert=True)
        return
    # Accept the click durably before making the Telegram request.
    pending.phase = "release"
    pending.expires_at = int(time.time())
    _store(context).save()
    _schedule_captcha_timeout(context, chat_id, user_id, pending.token, pending.expires_at)
    await query.answer("Verification accepted. Restoring your permissions.")


def _has_pending_captcha(context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int) -> bool:
    pending = _store(context).chat(chat_id).pending_captchas.get(str(user_id))
    return pending is not None and pending.reason == "captcha" and pending.phase != "unban"


async def scandeletedaccounts(update, context) -> None:
    if not await _require_admin(update, context):
        return
    chat, message = update.effective_chat, update.effective_message
    if chat is None or message is None:
        return
    queue = context.application.job_queue
    if queue is None:
        await message.reply_text("Background jobs are unavailable.")
        return
    name = f"deleted-scan:{chat.id}"
    if any(not job.removed for job in queue.get_jobs_by_name(name)):
        await message.reply_text("A scan is already running.")
        return
    context.application.bot_data.setdefault("deleted_candidates", {})[chat.id] = set()
    await message.reply_text("Scanning known members in the background. Suspected deleted accounts will be listed for admin confirmation; no one is removed automatically.")
    queue.run_repeating(
        scan_deleted_batch, interval=5, first=1, name=name,
        data={"chat_id": chat.id, "users": list(_store(context).chat(chat.id).known_names),
              "index": 0, "found": [], "failed": 0},
        job_kwargs={"misfire_grace_time": None, "coalesce": True, "max_instances": 1},
    )


async def confirm_deleted_account(update, context) -> None:
    if not await _require_admin(update, context):
        return
    chat, message = update.effective_chat, update.effective_message
    if chat is None or message is None:
        return
    if len(context.args) != 1 or not context.args[0].isdigit():
        await message.reply_text("Usage: /confirmdelacc user_id")
        return
    uid = int(context.args[0])
    candidates = context.application.bot_data.get("deleted_candidates", {}).get(chat.id, set())
    if uid not in candidates:
        await message.reply_text("This user is not a current scan candidate. Run /scandelacc first.")
        return
    member = await context.bot.get_chat_member(chat_id=chat.id, user_id=uid)
    if not present(member) or member.status in ADMIN_STATUSES or not _looks_like_deleted_account(member.user):
        candidates.discard(uid)
        await message.reply_text("This account no longer matches a removable scan candidate.")
        return
    await _ban_joined_user(update, context, member.user, "confirmed-deleted")
    candidates.discard(uid)
    await message.reply_text("Confirmed removal queued. This is a kick with unban recovery, not a permanent ban.")


async def _delete_message(update: Update, reason: str) -> None:
    message = update.effective_message
    if not message:
        return
    try:
        await message.delete()
    except TelegramError:
        LOGGER.exception("Unable to delete message for reason: %s", reason)


async def _ban_joined_user(update: Update, context, user: User, reason: str) -> None:
    chat = update.effective_chat
    if chat is None:
        return
    settings = _store(context).chat(chat.id)
    old = settings.pending_captchas.get(str(user.id))
    if old:
        remember_cleanup(settings, old.message_id)
    pending = PendingCaptcha(user.id, secrets.token_urlsafe(12), 0, int(time.time()), phase="kick", reason=reason)
    settings.pending_captchas[str(user.id)] = pending
    _store(context).save()
    _schedule_captcha_timeout(context, chat.id, user.id, pending.token, pending.expires_at)


async def _notify_recipients(update, context, message_html: str) -> None:
    chat = update.effective_chat
    if chat is not None:
        _store(context).chat(chat.id).title = chat.title or ""
        queue_alerts(context, chat.id, message_html)


async def _handle_name_seen(update, context, user: User, is_join: bool) -> None:
    chat = update.effective_chat
    if chat is None:
        return
    store = _store(context)
    settings = store.chat(chat.id)
    if settings.title != (chat.title or ""):
        settings.title = chat.title or ""
        store.mark_dirty()
    name = display_name(user.first_name, user.last_name, user.username)
    key = str(user.id)
    previous = settings.known_names.get(key)
    if previous != name:
        settings.known_names[key] = name
        store.mark_dirty()
    interval = context.application.bot_data.get("name_scan_interval", 60)
    context.application.bot_data.setdefault("scan_backoff", {})[(chat.id, key)] = (int(time.time()) + interval, 0)
    if not settings.alert_enabled or not name_matches_keywords(name, settings.keywords):
        return
    label = _alert_user_label(user)
    if is_join:
        queue_alerts(context, chat.id, f"Be aware {label} joined the group")
    elif previous is not None and previous != name:
        queue_alerts(context, chat.id, f"Be aware, user changed its name to {label}")


async def scan_known_member_names(context) -> None:
    await scan_names(context)


async def _notify_recipients_by_chat_id(context, chat_id: int, message_html: str) -> None:
    queue_alerts(context, chat_id, message_html)


async def _handle_joined_user(update: Update, context: ContextTypes.DEFAULT_TYPE, user: User) -> None:
    chat = update.effective_chat
    if chat is None:
        return
    settings = _store(context).chat(chat.id)
    name = display_name(user.first_name, user.last_name, user.username)
    if user.username:
        context.application.bot_data.setdefault("private_users", {})[_username_key(user.username)] = user.id
    if settings.delca_enabled and contains_evm_address(name):
        await _ban_joined_user(update, context, user, "delca")
        return
    await _handle_name_seen(update, context, user, is_join=True)
    if (
        settings.captcha_enabled
        and not user.is_bot
        and not _has_pending_captcha(context, chat.id, user.id)
        and not await _is_chat_admin(context, chat.id, user.id)
    ):
        await _start_captcha(update, context, user)


async def handle_chat_member_join(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    change = update.chat_member
    if change is None:
        return
    chat = update.effective_chat
    member = change.new_chat_member
    settings = _store(context).chat(chat.id)
    pending = settings.pending_captchas.get(str(member.user.id))
    external_action = change.from_user.id != context.bot.id
    override = external_action and (
        member.status == ChatMemberStatus.BANNED
        or (present(change.old_chat_member) and member.status in {ChatMemberStatus.RESTRICTED, *ADMIN_STATUSES})
        or (change.old_chat_member.status == ChatMemberStatus.RESTRICTED and member.status == ChatMemberStatus.MEMBER)
    )
    departure = not present(member) and member.status != ChatMemberStatus.BANNED
    if pending and (override or (departure and pending.phase != "unban")):
        remember_cleanup(settings, pending.message_id)
        del settings.pending_captchas[str(member.user.id)]
        _store(context).save()
        if context.application.job_queue:
            for job in context.application.job_queue.get_jobs_by_name(_captcha_job_name(chat.id, member.user.id)):
                job.schedule_removal()
        LOGGER.info("Member action cancelled for chat %s user %s after external action/departure", chat.id, member.user.id)
    if not present(member):
        settings.known_names.pop(str(member.user.id), None)
        _store(context).mark_dirty()
    if present(change.old_chat_member) or not present(member):
        return
    await _handle_joined_user(update, context, member.user)


async def clear_event_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return
    if not _store(context).chat(chat.id).clear_events_enabled:
        return
    try:
        await message.delete()
    except TelegramError:
        remember_cleanup(_store(context).chat(chat.id), message.message_id)
        _store(context).save()
        LOGGER.exception("Unable to delete membership service message in chat %s", chat.id)


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _maybe_send_filter_response(update, context)


async def moderation_gate(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat, message, user = update.effective_chat, update.effective_message, update.effective_user
    if chat is None or message is None:
        return
    if user and user.username:
        context.application.bot_data.setdefault("private_users", {})[_username_key(user.username)] = user.id
    settings = _store(context).chat(chat.id)
    text = message.text or message.caption or ""
    pending = user is not None and _has_pending_captcha(context, chat.id, user.id)
    blocked = (
        (settings.sendca_enabled and contains_evm_address(text))
        or (settings.url_enabled and message_contains_blocked_url(message, settings.allowed_urls))
    )
    if pending or blocked:
        anonymous_admin = message.sender_chat is not None and message.sender_chat.id == chat.id
        try:
            admin = anonymous_admin or (
                message.sender_chat is None and user is not None
                and (await context.bot.get_chat_member(chat.id, user.id)).status in ADMIN_STATUSES
            )
        except TelegramError:
            LOGGER.warning("Unable to verify moderator exemption in chat %s; message left for admin review", chat.id)
            raise ApplicationHandlerStop
        if not admin:
            try:
                await message.delete()
            except TelegramError:
                remember_cleanup(settings, message.message_id)
                _store(context).save()
            raise ApplicationHandlerStop
    if user and message.sender_chat is None:
        await _handle_name_seen(update, context, user, is_join=False)


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    LOGGER.error("Unhandled bot error. update_id=%s", getattr(update, "update_id", None), exc_info=context.error)


async def initialize_captcha_session(app: Application) -> None:
    # run_polling calls post_init before starting update processing or scheduled jobs.
    now = int(time.time())
    app.bot_data["captcha_session_started_at"] = now
    store = app.bot_data["store"]
    changed = False
    for settings in store.chats().values():
        for uid, pending in list(settings.pending_captchas.items()):
            if pending.reason != "captcha":
                continue
            expired = pending.phase == "waiting" and (pending.deadline or pending.expires_at) <= now
            if pending.phase == "provisioning" and pending.restore_permissions is None:
                remember_cleanup(settings, pending.message_id)
                del settings.pending_captchas[uid]
                changed = True
            elif expired or pending.phase in {"provisioning", "kick", "verifying"}:
                pending.phase = "release"
                pending.expires_at = now
                changed = True
    if changed:
        store.save()
        LOGGER.info("Reconciled interrupted/expired CAPTCHA challenges for startup; unban recovery preserved")
    _schedule_all_captcha_timeouts(app)


def build_application(token: str, data_file: Path) -> Application:
    app = Application.builder().token(token).post_init(initialize_captcha_session).post_shutdown(flush_on_shutdown).build()
    app.bot_data["store"] = SettingsStore(data_file)
    app.bot_data["captcha_session_started_at"] = int(time.time())
    app.bot_data["private_users"] = {}
    try:
        app.bot_data["name_scan_interval"] = max(10, int(os.getenv("SECURITY_BOT_NAME_SCAN_SECONDS", "60")))
    except ValueError:
        app.bot_data["name_scan_interval"] = 60
        LOGGER.warning("Invalid SECURITY_BOT_NAME_SCAN_SECONDS; using 60 seconds")
    app.add_handler(MessageHandler(filters.ChatType.GROUPS & ~filters.StatusUpdate.ALL, moderation_gate), group=-1)

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("url", url_command))
    app.add_handler(CommandHandler("alert", alert_command))
    app.add_handler(CommandHandler("delca", delca_command))
    app.add_handler(CommandHandler("sendca", sendca_command))
    app.add_handler(CommandHandler("clearevents", clearevents_command))
    app.add_handler(CommandHandler("captcha", captcha_command))
    app.add_handler(CommandHandler("captchatime", captchatime))
    app.add_handler(CommandHandler("captchamode", captchamode))
    app.add_handler(CommandHandler("warningmsg", warningmsg_command))
    app.add_handler(CommandHandler("warningtxt", warningtxt))
    app.add_handler(CommandHandler("warningfreq", warningfreq))
    app.add_handler(CommandHandler("warnmedia", warnmedia))
    app.add_handler(CommandHandler("setfilter", setfilter))
    app.add_handler(CommandHandler("delfilter", delfilter))
    app.add_handler(CommandHandler("listfilter", listfilter))
    app.add_handler(CommandHandler("addurl", addurl))
    app.add_handler(CommandHandler("listurl", listurl))
    app.add_handler(CommandHandler("delurl", delurl))
    app.add_handler(CommandHandler("addkeyword", addkeyword))
    app.add_handler(CommandHandler("delkeyword", delkeyword))
    app.add_handler(CommandHandler("listkeyword", listkeyword))
    app.add_handler(CommandHandler("addreceiver", addrecipient))
    app.add_handler(CommandHandler("delreceiver", delrecipient))
    app.add_handler(CommandHandler("listreceiver", listrecipient))
    app.add_handler(CommandHandler("scandelacc", scandeletedaccounts))
    app.add_handler(CommandHandler("confirmdelacc", confirm_deleted_account))
    app.add_handler(CallbackQueryHandler(handle_captcha_callback, pattern=r"^captcha\|"))
    app.add_handler(ChatMemberHandler(handle_chat_member_join, ChatMemberHandler.CHAT_MEMBER))
    app.add_handler(
        MessageHandler(
            filters.StatusUpdate.NEW_CHAT_MEMBERS | filters.StatusUpdate.LEFT_CHAT_MEMBER,
            clear_event_message,
        )
    )
    app.add_handler(MessageHandler(filters.ChatType.GROUPS & filters.COMMAND, handle_filter_command))
    app.add_handler(MessageHandler(filters.ChatType.GROUPS & ~filters.COMMAND, handle_message))
    app.add_error_handler(error_handler)
    if app.job_queue is not None:
        app.job_queue.run_repeating(scan_known_member_names, interval=5, first=5)
        app.job_queue.run_repeating(deliver_pending_alerts, interval=5, first=5)
        app.job_queue.run_repeating(maintenance, interval=5, first=5)
        _schedule_all_warning_jobs(app)
        app.job_queue.run_repeating(
            recover_missing_captcha_jobs,
            interval=CAPTCHA_RECOVERY_INTERVAL_SECONDS,
            first=CAPTCHA_RECOVERY_INTERVAL_SECONDS,
            name="captcha_recovery_watchdog",
            job_kwargs={"misfire_grace_time": None, "coalesce": True, "max_instances": 1},
        )
    else:
        LOGGER.warning("Job queue is unavailable; periodic display-name scans are disabled.")
    return app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Telegram group security bot")
    parser.add_argument("--token", default=os.getenv("TELEGRAM_BOT_TOKEN"), help="Telegram bot token")
    parser.add_argument(
        "--data-file",
        default=os.getenv("SECURITY_BOT_DATA", "data/security-bot.json"),
        type=Path,
        help="JSON file used for persistent settings",
    )
    return parser.parse_args()


def main() -> None:
    configure_logging(os.getenv("LOG_LEVEL", "INFO"))
    args = parse_args()
    if not args.token:
        raise SystemExit("Missing bot token. Set TELEGRAM_BOT_TOKEN or pass --token.")
    print("Telegram security bot is running. Press Ctrl+C to stop.", flush=True)
    build_application(args.token, args.data_file).run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
