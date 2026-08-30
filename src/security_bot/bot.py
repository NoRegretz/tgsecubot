from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

from telegram import Chat, MessageEntity, Update, User
from telegram.constants import ChatMemberStatus, ParseMode
from telegram.error import BadRequest, Forbidden, TelegramError
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from .moderation import (
    contains_blocked_url,
    contains_evm_address,
    display_name,
    escape_html,
    name_matches_keywords,
    normalize_domain,
)
from .storage import Recipient, SavedFilter, SettingsStore


LOGGER = logging.getLogger(__name__)
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
/scandelacc - scan known members and remove deleted Telegram accounts.
/delca ON|OFF - remove users who join with an EVM-like address in their displayed name. Default: OFF.
/sendca ON|OFF - delete messages containing EVM-like addresses. Default: OFF.
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


def _looks_like_deleted_account(user: User) -> bool:
    return user.first_name == "Deleted Account" and not user.last_name and not user.username


def _warning_job_name(chat_id: int) -> str:
    return f"warning:{chat_id}"


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
    try:
        member = await context.bot.get_chat_member(chat.id, user.id)
    except TelegramError:
        LOGGER.exception("Unable to check admin status for user %s in chat %s", user.id, chat.id)
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


async def delca_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await toggle_command(update, context, "delca_enabled", "delca")


async def sendca_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await toggle_command(update, context, "sendca_enabled", "sendca")


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
    settings.warning_media_type = media_type
    settings.warning_media_file_id = file_id
    _store(context).save()
    await message.reply_text("Media has been added.")


def _filter_key(value: str) -> str:
    normalized = value.strip()
    if normalized.startswith("/"):
        normalized = normalized[1:]
        normalized = normalized.split(maxsplit=1)[0]
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
    if user.username:
        context.application.bot_data.setdefault("private_users", {})[_username_key(user.username)] = user.id
    await _handle_name_seen(update, context, user, is_join=False)
    await _maybe_send_filter_response(update, context)


async def send_warning_message(context: ContextTypes.DEFAULT_TYPE) -> None:
    job = context.job
    if job is None or job.data is None:
        return
    chat_id = int(job.data["chat_id"])
    settings = _store(context).chat(chat_id)
    if not settings.warning_enabled:
        return
    if not settings.warning_text and not settings.warning_media_file_id:
        return
    try:
        await _delete_previous_warning_messages(context, chat_id)
        sent_message = await _send_configured_warning(context, chat_id)
        settings.warning_message_ids = [sent_message.message_id]
        _store(context).save()
    except TelegramError:
        LOGGER.exception("Unable to send warning message to chat %s", chat_id)


async def _delete_previous_warning_messages(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> None:
    store = _store(context)
    settings = store.chat(chat_id)
    if not settings.warning_message_ids:
        return
    for message_id in settings.warning_message_ids:
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=message_id)
        except BadRequest:
            LOGGER.info("Previous warning message %s in chat %s could not be deleted.", message_id, chat_id)
        except TelegramError:
            LOGGER.exception("Unable to delete previous warning message %s in chat %s", message_id, chat_id)
    settings.warning_message_ids = []
    store.save()


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


async def scandeletedaccounts(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None:
        return
    settings = _store(context).chat(chat.id)
    known_user_ids = list(settings.known_names)
    scanned = 0
    removed = 0
    stale = 0
    skipped = 0

    for user_id_raw in known_user_ids:
        try:
            user_id = int(user_id_raw)
        except ValueError:
            del settings.known_names[user_id_raw]
            stale += 1
            continue
        try:
            member = await context.bot.get_chat_member(chat_id=chat.id, user_id=user_id)
        except TelegramError:
            stale += 1
            continue
        scanned += 1
        if member.status in {ChatMemberStatus.LEFT, ChatMemberStatus.BANNED}:
            del settings.known_names[user_id_raw]
            stale += 1
            continue
        if not _looks_like_deleted_account(member.user):
            continue
        if member.status not in {ChatMemberStatus.MEMBER, ChatMemberStatus.RESTRICTED}:
            skipped += 1
            continue
        try:
            await chat.ban_member(user_id)
            await chat.unban_member(user_id, only_if_banned=True)
        except TelegramError:
            LOGGER.exception("Unable to remove deleted-looking account %s from chat %s", user_id, chat.id)
            skipped += 1
            continue
        del settings.known_names[user_id_raw]
        removed += 1

    _store(context).save()
    await message.reply_text(
        "Deleted account scan complete.\n"
        f"Known users scanned: {scanned}\n"
        f"Deleted accounts removed: {removed}\n"
        f"Stale records cleaned: {stale}\n"
        f"Skipped: {skipped}"
    )


async def _delete_message(update: Update, reason: str) -> None:
    message = update.effective_message
    if not message:
        return
    try:
        await message.delete()
    except TelegramError:
        LOGGER.exception("Unable to delete message for reason: %s", reason)


async def _ban_joined_user(update: Update, user: User, reason: str) -> None:
    chat = update.effective_chat
    if chat is None:
        return
    try:
        await chat.ban_member(user.id)
        await chat.unban_member(user.id, only_if_banned=True)
    except TelegramError:
        LOGGER.exception("Unable to remove user %s for reason: %s", user.id, reason)


async def _notify_recipients(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    message_html: str,
) -> None:
    chat = update.effective_chat
    if chat is None:
        return
    settings = _store(context).chat(chat.id)
    private_users = context.application.bot_data.setdefault("private_users", {})
    changed = False
    for username, recipient in settings.recipients.items():
        user_id = recipient.user_id or private_users.get(username)
        if user_id is None:
            continue
        if recipient.user_id is None:
            recipient.user_id = user_id
            changed = True
        try:
            await context.bot.send_message(chat_id=user_id, text=message_html, parse_mode=ParseMode.HTML)
        except (Forbidden, BadRequest):
            LOGGER.warning("Unable to alert @%s. They may need to start the bot.", username)
        except TelegramError:
            LOGGER.exception("Unable to send alert to @%s", username)
    if changed:
        _store(context).save()


async def _handle_name_seen(update: Update, context: ContextTypes.DEFAULT_TYPE, user: User, is_join: bool) -> None:
    chat = update.effective_chat
    if chat is None:
        return
    settings = _store(context).chat(chat.id)
    name = display_name(user.first_name, user.last_name, user.username)
    key = str(user.id)
    previous = settings.known_names.get(key)
    settings.known_names[key] = name
    _store(context).save()

    if not settings.alert_enabled or not name_matches_keywords(name, settings.keywords):
        return
    user_label = _alert_user_label(user)
    if is_join:
        await _notify_recipients(update, context, f"Be aware {user_label} joined the group")
    elif previous is not None and previous != name:
        await _notify_recipients(update, context, f"Be aware, user changed its name to {user_label}")


async def scan_known_member_names(context: ContextTypes.DEFAULT_TYPE) -> None:
    store = _store(context)
    for chat_id, settings in store.chats().items():
        if not settings.alert_enabled or not settings.keywords:
            continue
        for user_id_raw, previous in list(settings.known_names.items()):
            try:
                member = await context.bot.get_chat_member(chat_id=chat_id, user_id=int(user_id_raw))
            except TelegramError:
                LOGGER.debug("Unable to scan member %s in chat %s", user_id_raw, chat_id, exc_info=True)
                continue
            user = member.user
            name = display_name(user.first_name, user.last_name, user.username)
            if name == previous:
                continue
            settings.known_names[user_id_raw] = name
            store.save()
            if name_matches_keywords(name, settings.keywords):
                user_label = _alert_user_label(user)
                await _notify_recipients_by_chat_id(
                    context,
                    chat_id,
                    f"Be aware, user changed its name to {user_label}",
                )


async def _notify_recipients_by_chat_id(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    message_html: str,
) -> None:
    settings = _store(context).chat(chat_id)
    private_users = context.application.bot_data.setdefault("private_users", {})
    changed = False
    for username, recipient in settings.recipients.items():
        user_id = recipient.user_id or private_users.get(username)
        if user_id is None:
            continue
        if recipient.user_id is None:
            recipient.user_id = user_id
            changed = True
        try:
            await context.bot.send_message(chat_id=user_id, text=message_html, parse_mode=ParseMode.HTML)
        except (Forbidden, BadRequest):
            LOGGER.warning("Unable to alert @%s. They may need to start the bot.", username)
        except TelegramError:
            LOGGER.exception("Unable to send alert to @%s", username)
    if changed:
        _store(context).save()


async def handle_new_members(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat = update.effective_chat
    message = update.effective_message
    if chat is None or message is None or not message.new_chat_members:
        return
    settings = _store(context).chat(chat.id)
    for user in message.new_chat_members:
        name = display_name(user.first_name, user.last_name, user.username)
        if user.username:
            context.application.bot_data.setdefault("private_users", {})[_username_key(user.username)] = user.id
        if settings.delca_enabled and contains_evm_address(name):
            await _ban_joined_user(update, user, "EVM-like display name")
            continue
        await _handle_name_seen(update, context, user, is_join=True)


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat = update.effective_chat
    message = update.effective_message
    user = update.effective_user
    if chat is None or message is None or user is None or chat.type == Chat.PRIVATE:
        return
    if user.username:
        context.application.bot_data.setdefault("private_users", {})[_username_key(user.username)] = user.id
    await _handle_name_seen(update, context, user, is_join=False)
    if await _maybe_send_filter_response(update, context):
        return

    settings = _store(context).chat(chat.id)
    if await _is_group_admin(update, context):
        return
    text = message.text or message.caption or ""
    if settings.sendca_enabled and contains_evm_address(text):
        await _delete_message(update, "EVM address in message")
        return
    if settings.url_enabled and contains_blocked_url(text, settings.allowed_urls):
        await _delete_message(update, "blocked URL")


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    LOGGER.exception("Unhandled bot error. update=%r", update, exc_info=context.error)


def build_application(token: str, data_file: Path) -> Application:
    app = Application.builder().token(token).build()
    app.bot_data["store"] = SettingsStore(data_file)
    app.bot_data["private_users"] = {}

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("url", url_command))
    app.add_handler(CommandHandler("alert", alert_command))
    app.add_handler(CommandHandler("delca", delca_command))
    app.add_handler(CommandHandler("sendca", sendca_command))
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
    app.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, handle_new_members))
    app.add_handler(MessageHandler(filters.ChatType.GROUPS & filters.COMMAND, handle_filter_command))
    app.add_handler(MessageHandler(filters.ChatType.GROUPS & ~filters.COMMAND, handle_message))
    app.add_error_handler(error_handler)
    if app.job_queue is not None:
        interval = int(os.getenv("SECURITY_BOT_NAME_SCAN_SECONDS", "60"))
        app.job_queue.run_repeating(scan_known_member_names, interval=interval, first=interval)
        _schedule_all_warning_jobs(app)
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
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    args = parse_args()
    if not args.token:
        raise SystemExit("Missing bot token. Set TELEGRAM_BOT_TOKEN or pass --token.")
    print("Telegram security bot is running. Press Ctrl+C to stop.", flush=True)
    build_application(args.token, args.data_file).run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
