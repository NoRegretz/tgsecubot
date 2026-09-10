"""Bounded background delivery, cleanup and scans."""

import logging
import secrets
import time

from telegram.constants import ParseMode
from telegram.error import BadRequest, Forbidden, RetryAfter, TelegramError

from .moderation import display_name, name_matches_keywords
from .storage import PendingAlert
from .workflows import ADMINS, present, retry_delay, try_cleanup_message

LOGGER = logging.getLogger(__name__)


def queue_alerts(context, chat_id, message_html):
    from .bot import _alert_with_group

    store = context.application.bot_data["store"]
    settings = store.chat(chat_id)
    if not settings.alert_enabled:
        return
    text = _alert_with_group(message_html, settings.title or str(chat_id))
    private_users = context.application.bot_data.get("private_users", {})
    for username, recipient in settings.recipients.items():
        uid = recipient.user_id or private_users.get(username)
        recipient.user_id = uid
        settings.pending_alerts[secrets.token_urlsafe(12)] = PendingAlert(username, text, uid)
    # Persist the observed name and its deliveries together.
    store.save()


async def deliver_pending_alerts(context):
    data = context.application.bot_data
    store = data["store"]
    now = int(time.time())
    if data.get("alerts_pause_until", 0) > now:
        return
    targets = [(cid, key, item) for cid, settings in store.chats().items()
               for key, item in settings.pending_alerts.items()]
    if not targets:
        return
    start = data.get("alerts_cursor", 0) % len(targets)
    attempted = 0
    for offset in range(len(targets)):
        if attempted >= 5:
            break
        index = (start + offset) % len(targets)
        data["alerts_cursor"] = index + 1
        cid, key, item = targets[index]
        settings = store.chat(cid)
        if not settings.alert_enabled or item.receiver not in settings.recipients:
            settings.pending_alerts.pop(key, None)
            store.mark_dirty()
            continue
        if item.next_attempt > now:
            continue
        item.user_id = item.user_id or settings.recipients[item.receiver].user_id or data.get("private_users", {}).get(item.receiver)
        if item.user_id is None:
            continue
        settings.recipients[item.receiver].user_id = item.user_id
        attempted += 1
        try:
            await context.bot.send_message(chat_id=item.user_id, text=item.text, parse_mode=ParseMode.HTML)
        except TelegramError as exc:
            item.attempts += 1
            item.next_attempt = now + (86400 if isinstance(exc, (Forbidden, BadRequest)) else retry_delay(exc, item.attempts))
            if isinstance(exc, RetryAfter):
                data["alerts_pause_until"] = item.next_attempt
            LOGGER.warning("Alert delivery to user %s failed: %s", item.user_id, exc)
        else:
            settings.pending_alerts.pop(key, None)
        store.save()
        if data.get("alerts_pause_until", 0) > now:
            break
    store.flush()


async def scan_names(context):
    from .bot import _alert_user_label

    data = context.application.bot_data
    store = data["store"]
    now = int(time.time())
    if data.get("scanner_pause_until", 0) > now:
        return
    targets = [(cid, uid) for cid, settings in store.chats().items()
               if settings.alert_enabled and settings.keywords for uid in settings.known_names]
    if not targets:
        return
    backoff = data.setdefault("scan_backoff", {})
    start = data.get("scan_cursor", 0) % len(targets)
    attempted = 0
    for offset in range(len(targets)):
        if attempted >= 5:
            break
        index = (start + offset) % len(targets)
        data["scan_cursor"] = index + 1
        cid, uid = targets[index]
        due, failures = backoff.get((cid, uid), (0, 0))
        if due > now:
            continue
        settings = store.chat(cid)
        previous = settings.known_names.get(uid)
        attempted += 1
        try:
            member = await context.bot.get_chat_member(chat_id=cid, user_id=int(uid))
        except RetryAfter as exc:
            data["scanner_pause_until"] = now + retry_delay(exc, 1)
            break
        except (TelegramError, ValueError) as exc:
            failures += 1
            backoff[(cid, uid)] = (now + min(60 * 2 ** min(failures - 1, 6), 3600), failures)
            LOGGER.warning("Name scan skipped chat %s user %s: %s", cid, uid, exc)
            continue
        backoff[(cid, uid)] = (now + data.get("name_scan_interval", 60), 0)
        if settings.known_names.get(uid) != previous:
            continue
        if not present(member):
            settings.known_names.pop(uid, None)
            backoff.pop((cid, uid), None)
            store.mark_dirty()
            continue
        user = member.user
        name = display_name(user.first_name, user.last_name, user.username)
        if name != previous:
            settings.known_names[uid] = name
            store.mark_dirty()
            if settings.alert_enabled and name_matches_keywords(name, settings.keywords):
                queue_alerts(context, cid, f"Be aware, user changed its name to {_alert_user_label(user)}")
    store.flush()


async def scan_deleted_batch(context):
    from .bot import _looks_like_deleted_account

    data = context.application.bot_data
    work = context.job.data
    now = int(time.time())
    if data.get("scanner_pause_until", 0) > now or work.get("pause_until", 0) > now:
        return
    cid = work["chat_id"]
    candidates = data.setdefault("deleted_candidates", {}).setdefault(cid, set())
    for _ in range(5):
        if work["index"] >= len(work["users"]):
            lines = ["Scan complete. These names are only suspects, not proof of deletion."]
            lines += [f"Suspected account {uid}: /confirmdelacc {uid}" for uid in work["found"]]
            lines += [f"Known users checked: {work['index']}. Failed lookups: {work['failed']}. No accounts removed automatically."]
            work.setdefault("reports", ["\n".join(lines[i:i + 30]) for i in range(0, len(lines), 30)])
            try:
                await context.bot.send_message(chat_id=cid, text=work["reports"][0])
            except TelegramError as exc:
                work["pause_until"] = now + retry_delay(exc, 1)
                return
            work["reports"].pop(0)
            if not work["reports"]:
                context.job.schedule_removal()
            return
        uid = work["users"][work["index"]]
        try:
            member = await context.bot.get_chat_member(chat_id=cid, user_id=int(uid))
        except RetryAfter as exc:
            data["scanner_pause_until"] = now + retry_delay(exc, 1)
            return
        except (TelegramError, ValueError):
            work["failed"] += 1
        else:
            if present(member) and member.status not in ADMINS and _looks_like_deleted_account(member.user):
                candidates.add(int(uid))
                work["found"].append(int(uid))
        work["index"] += 1


async def maintenance(context):
    data = context.application.bot_data
    store = data["store"]
    now = int(time.time())
    backoff = data.setdefault("cleanup_backoff", {})
    attempted = 0
    for cid, settings in store.chats().items():
        for mid in list(settings.cleanup_message_ids):
            if attempted >= 5 or data.get("cleanup_pause_until", 0) > now:
                store.flush()
                return
            if backoff.get((cid, mid), 0) > now:
                continue
            attempted += 1
            await try_cleanup_message(context, cid, mid)
    store.flush()


async def flush_on_shutdown(application):
    application.bot_data["store"].flush()
