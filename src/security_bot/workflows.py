"""Durable member actions. Only records owned by this bot are processed."""

import asyncio
import logging
import time
from datetime import datetime, timedelta

from telegram import ChatPermissions, User
from telegram.constants import ChatMemberStatus, ParseMode
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram.error import BadRequest, Forbidden, RetryAfter, TelegramError


LOGGER = logging.getLogger(__name__)
ADMINS = {ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER}
CAPTCHA_BAN_SAFETY_SECONDS = 120
CAPTCHA_MAX_EVENT_AGE_SECONDS = 120
CAPTCHA_CLEANUP_TIMEOUT_SECONDS = 2


def present(member) -> bool:
    if member.status == ChatMemberStatus.RESTRICTED:
        return member.is_member
    return member.status in {ChatMemberStatus.MEMBER, *ADMINS}


def retry_delay(exc: Exception, attempts: int) -> int:
    delay = min(10 * 2 ** min(max(attempts - 1, 0), 5), 300)
    if isinstance(exc, RetryAfter):
        value = exc.retry_after
        seconds = value.total_seconds() if isinstance(value, timedelta) else value
        delay = max(delay, int(seconds) + 1)
    return delay


def remember_cleanup(settings, message_id: int) -> None:
    if message_id and message_id not in settings.cleanup_message_ids:
        settings.cleanup_message_ids.append(message_id)


def message_absent(exc: BadRequest) -> bool:
    return "message to delete not found" in str(exc).lower()


async def try_cleanup_message(context, chat_id: int, message_id: int) -> bool:
    data = context.application.bot_data
    store = data["store"]
    settings = store.chat(chat_id)
    if not message_id or message_id not in settings.cleanup_message_ids:
        return True
    key = (chat_id, message_id)
    active = data.setdefault("cleanup_active", set())
    backoff = data.setdefault("cleanup_backoff", {})
    now = int(time.time())
    if key in active or backoff.get(key, 0) > now or data.get("cleanup_pause_until", 0) > now:
        return False
    active.add(key)
    try:
        try:
            # Cleanup must not hold up member recovery when Telegram is slow.
            async with asyncio.timeout(CAPTCHA_CLEANUP_TIMEOUT_SECONDS):
                await context.bot.delete_message(chat_id=chat_id, message_id=message_id)
        except (TelegramError, TimeoutError) as exc:
            if not isinstance(exc, BadRequest) or not message_absent(exc):
                backoff[key] = int(time.time()) + (300 if isinstance(exc, (BadRequest, Forbidden)) else retry_delay(exc, 1))
                if isinstance(exc, RetryAfter):
                    data["cleanup_pause_until"] = backoff[key]
                LOGGER.warning("Cleanup of message %s in chat %s failed: %s", message_id, chat_id, exc)
                return False
        if message_id in settings.cleanup_message_ids:
            settings.cleanup_message_ids.remove(message_id)
            store.save()
        backoff.pop(key, None)
        return True
    finally:
        active.discard(key)


def stale_captcha(pending, now: int) -> bool:
    if pending.reason != "captcha":
        return False
    if pending.phase == "provisioning":
        return bool(pending.joined_at and now - pending.joined_at > CAPTCHA_MAX_EVENT_AGE_SECONDS)
    if pending.phase == "waiting":
        deadline = pending.deadline or pending.expires_at
        return bool(deadline and now - deadline > CAPTCHA_MAX_EVENT_AGE_SECONDS)
    return False


async def process_member_action(context, chat_id, user_id, token, schedule, welcome):
    store = context.application.bot_data["store"]
    settings = store.chat(chat_id)
    pending = settings.pending_captchas.get(str(user_id))
    if pending is None or pending.token != token:
        return

    def current():
        return settings.pending_captchas.get(str(user_id)) is pending

    async def finish():
        if current():
            message_id = pending.message_id
            remember_cleanup(settings, pending.message_id)
            del settings.pending_captchas[str(user_id)]
            store.save()
            await try_cleanup_message(context, chat_id, message_id)

    now = int(time.time())
    if pending.expires_at > now:
        schedule(context, chat_id, user_id, token, pending.expires_at)
        return
    try:
        if pending.phase == "waiting" and not pending.deadline and pending.expires_at:
            pending.deadline = pending.expires_at
            store.save()
        if pending.phase == "verifying":
            pending.phase = "release"
            store.save()
        if pending.reason == "captcha" and not settings.captcha_enabled and pending.phase in {"provisioning", "waiting", "kick"}:
            pending.phase = "release"
            store.save()

        if pending.phase in {"provisioning", "release", "waiting", "kick"}:
            member = await context.bot.get_chat_member(chat_id=chat_id, user_id=user_id)
            if not current():
                return
            if not present(member) or member.status in ADMINS:
                await finish()
                return

        if stale_captcha(pending, int(time.time())):
            LOGGER.info("Releasing stale CAPTCHA instead of challenging/removing chat %s user %s", chat_id, user_id)
            if pending.phase == "provisioning" and pending.restore_permissions is None:
                await finish()
                return
            pending.phase = "release"
            store.save()

        if pending.phase != "provisioning" and pending.message_id:
            message_id = pending.message_id
            remember_cleanup(settings, message_id)
            pending.message_id = 0
            store.save()
            await try_cleanup_message(context, chat_id, message_id)
            if not current():
                return

        if pending.phase == "provisioning":
            if pending.restore_permissions is None:
                pending.restore_permissions = ChatPermissions.all_permissions().to_dict()
                if member.status == ChatMemberStatus.RESTRICTED:
                    pending.restore_permissions = {key: value for key, value in member.to_dict().items() if key.startswith("can_")}
                    until = member.until_date
                    pending.restore_until = int(until.timestamp()) if isinstance(until, datetime) else int(until or 0)
                store.save()
            await context.bot.restrict_chat_member(
                chat_id=chat_id, user_id=user_id, permissions=ChatPermissions(can_send_messages=False), until_date=0,
            )
            if not current():
                return
            if pending.phase != "provisioning":
                schedule(context, chat_id, user_id, token, pending.expires_at)
                return
            if stale_captcha(pending, int(time.time())):
                pending.phase = "release"
                pending.expires_at = int(time.time())
                store.save()
                schedule(context, chat_id, user_id, token, pending.expires_at)
                return
            user = User(user_id, pending.first_name, False, username=pending.username)
            sent = await context.bot.send_message(
                chat_id=chat_id, text=welcome(user, settings.captcha_timeout_seconds), parse_mode=ParseMode.HTML,
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(
                    "Tap to join!", callback_data=f"captcha|{chat_id}|{user_id}|{token}",
                )]]),
            )
            if not current():
                remember_cleanup(settings, sent.message_id)
                store.save()
                return
            pending.message_id = sent.message_id
            if stale_captcha(pending, int(time.time())):
                pending.phase = "release"
                pending.expires_at = int(time.time())
            if pending.phase != "provisioning":
                store.save()
                schedule(context, chat_id, user_id, token, pending.expires_at)
                return
            pending.deadline = int(time.time()) + settings.captcha_timeout_seconds
            pending.expires_at = pending.deadline
            pending.phase = "waiting"
            store.save()
            schedule(context, chat_id, user_id, token, pending.expires_at)
            return

        if pending.phase == "release":
            permissions = pending.restore_permissions
            until = pending.restore_until
            if permissions is None or (until and until <= now):
                permissions = ChatPermissions.all_permissions().to_dict()
                until = 0
            await context.bot.restrict_chat_member(
                chat_id=chat_id, user_id=user_id,
                permissions=ChatPermissions.de_json(permissions, context.bot), until_date=until,
                use_independent_chat_permissions=True,
            )
            if not current():
                return
            restored = await context.bot.get_chat_member(chat_id=chat_id, user_id=user_id)
            if not current():
                return
            if restored.status == ChatMemberStatus.RESTRICTED and restored.is_member:
                if permissions.get("can_send_messages") and not restored.can_send_messages:
                    raise TelegramError("Member still muted after permission restoration; recovery retained")
            if until and 0 < until - now < 30:
                # Telegram treats a short restriction as permanent; lift it at the original expiry.
                pending.expires_at = until
                store.save()
                schedule(context, chat_id, user_id, token, until)
                return
            await finish()
            return

        if pending.phase in {"waiting", "kick"}:
            pending.phase = "unban"
            store.save()
            try:
                ban_options = {}
                if pending.reason == "captcha":
                    # Compute after queue/disk waits; Telegram treats bans under 30 seconds as permanent.
                    ban_options["until_date"] = int(time.time()) + CAPTCHA_BAN_SAFETY_SECONDS
                await context.bot.ban_chat_member(chat_id=chat_id, user_id=user_id, **ban_options)
            except (RetryAfter, Forbidden, BadRequest):
                # Definite API rejection: the ban was not applied, so retry the removal stage.
                if current():
                    pending.phase = "kick"
                raise
            except TelegramError:
                LOGGER.warning("Removal result uncertain for chat %s user %s; recovering unban", chat_id, user_id)
            if not current():
                return

        if pending.phase == "unban":
            await context.bot.unban_chat_member(chat_id=chat_id, user_id=user_id, only_if_banned=True)
            if not current():
                return
            member = await context.bot.get_chat_member(chat_id=chat_id, user_id=user_id)
            if not current():
                return
            LOGGER.info("Post-unban status for %s removal: chat %s user %s: %s", pending.reason, chat_id, user_id, member.status)
            if member.status == ChatMemberStatus.BANNED:
                raise TelegramError("Member remains banned; recovery retained")
            if pending.reason == "captcha" and member.status == ChatMemberStatus.RESTRICTED and member.is_member:
                # An ambiguous failed kick must not strand our own indefinitely muted member.
                pending.phase = "release"
                pending.expires_at = int(time.time())
                store.save()
                schedule(context, chat_id, user_id, token, pending.expires_at)
                return
            await finish()
    except TelegramError as exc:
        if not current():
            return
        pending.retry_count += 1
        pending.expires_at = int(time.time()) + retry_delay(exc, pending.retry_count)
        store.save()
        schedule(context, chat_id, user_id, token, pending.expires_at)
        LOGGER.warning("%s action %s for chat %s user %s failed: %s; retry at %s", pending.reason, pending.phase, chat_id, user_id, exc, pending.expires_at)
