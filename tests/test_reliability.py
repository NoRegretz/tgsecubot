import asyncio
from dataclasses import asdict
from datetime import datetime, timezone
import json
import logging
import time
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, Mock, patch

import pytest
from telegram import Chat, ChatMemberMember, Message, MessageEntity, Update, User
from telegram.error import BadRequest, Forbidden, RetryAfter, TimedOut
from telegram.ext import ApplicationHandlerStop, ExtBot

from security_bot import bot
from security_bot.background import deliver_pending_alerts, maintenance, scan_deleted_batch, scan_names
from security_bot.diagnostics import RedactingFormatter
from security_bot.storage import PendingCaptcha, Recipient, SavedFilter, SettingsStore


def environment(tmp_path):
    store = SettingsStore(tmp_path / "settings.json")
    queue = Mock()
    queue.get_jobs_by_name.return_value = []
    user = User(42, "Lev", False, username="noregretz")
    api = NS(id=999, username="SecurityBot", get_chat_member=AsyncMock(return_value=ChatMemberMember(user)),
             restrict_chat_member=AsyncMock(), ban_chat_member=AsyncMock(), unban_chat_member=AsyncMock(),
             send_message=AsyncMock(return_value=NS(message_id=99)), delete_message=AsyncMock(),
             send_photo=AsyncMock(return_value=NS(message_id=100)), send_animation=AsyncMock(),
             send_video=AsyncMock(), send_document=AsyncMock())
    context = NS(application=NS(bot_data={"store": store}, job_queue=queue), bot=api,
                 job=NS(data={"chat_id": -123, "user_id": 42, "token": "test"}), args=[])
    message = NS(message_id=15, text="hello", caption=None, entities=[], caption_entities=[],
                 sender_chat=None, reply_text=AsyncMock(), delete=AsyncMock(), reply_to_message=None)
    update = NS(effective_chat=Chat(-123, "supergroup", title="Test <Group>"), effective_user=user,
                effective_message=message)
    return store, context, update


def run(action):
    return asyncio.run(action)


def test_provisioning_is_saved_before_api_and_retried_from_persisted_state(tmp_path):
    store, ctx, update = environment(tmp_path)
    settings = store.chat(-123)
    settings.captcha_enabled = True
    run(bot._start_captcha(update, ctx, update.effective_user))
    pending = settings.pending_captchas["42"]
    assert SettingsStore(store.path).chat(-123).pending_captchas["42"].phase == "provisioning"
    ctx.job.data["token"] = pending.token
    ctx.bot.send_message.side_effect = TimedOut()
    run(bot.captcha_timeout(ctx))
    assert ctx.bot.restrict_chat_member.call_args.kwargs["until_date"] == 0
    reloaded = SettingsStore(store.path)
    ctx.application.bot_data["store"] = reloaded
    pending = reloaded.chat(-123).pending_captchas["42"]
    assert pending.phase == "provisioning"
    pending.expires_at = 0
    ctx.bot.send_message.side_effect = None
    run(bot.captcha_timeout(ctx))
    assert pending.phase == "waiting"
    assert pending.deadline >= int(time.time()) + 59
    assert "Lev (@noregretz)" in ctx.bot.send_message.call_args.kwargs["text"]
    assert ctx.bot.send_message.call_args.kwargs["reply_markup"].inline_keyboard[0][0].text == "Tap to join!"


def test_owner_click_is_durable_and_release_failure_never_becomes_kick(tmp_path):
    store, ctx, update = environment(tmp_path)
    settings = store.chat(-123)
    settings.captcha_enabled = True
    settings.pending_captchas["42"] = PendingCaptcha(42, "test", 99, int(time.time()) + 60)
    query = NS(data="captcha|-123|42|test", from_user=User(43, "Other", False),
               message=NS(chat_id=-123, message_id=99), answer=AsyncMock())
    update.callback_query = query
    run(bot.handle_captcha_callback(update, ctx))
    assert settings.pending_captchas["42"].phase == "waiting"
    query.from_user = update.effective_user
    run(bot.handle_captcha_callback(update, ctx))
    assert SettingsStore(store.path).chat(-123).pending_captchas["42"].phase == "release"
    ctx.bot.restrict_chat_member.side_effect = TimedOut()
    run(bot.captcha_timeout(ctx))
    reloaded = SettingsStore(store.path)
    assert reloaded.chat(-123).pending_captchas["42"].phase == "release"
    reloaded.chat(-123).pending_captchas["42"].expires_at = 0
    ctx.application.bot_data["store"] = reloaded
    ctx.bot.restrict_chat_member.side_effect = None
    run(bot.captcha_timeout(ctx))
    assert not reloaded.chat(-123).pending_captchas
    assert reloaded.chat(-123).cleanup_message_ids == []
    ctx.bot.ban_chat_member.assert_not_awaited()
    run(maintenance(ctx))
    ctx.bot.delete_message.assert_awaited_once_with(chat_id=-123, message_id=99)


@pytest.mark.parametrize("kind", ["wrong-token", "wrong-message", "expired"])
def test_invalid_captcha_never_releases(tmp_path, kind):
    store, ctx, update = environment(tmp_path)
    settings = store.chat(-123)
    settings.pending_captchas["42"] = PendingCaptcha(42, "test", 99, int(time.time()) + 60)
    update.callback_query = NS(data="captcha|-123|42|test", from_user=update.effective_user,
                               message=NS(chat_id=-123, message_id=99), answer=AsyncMock())
    if kind == "wrong-token":
        update.callback_query.data += "stale"
    elif kind == "wrong-message":
        update.callback_query.message.message_id = 100
    else:
        settings.pending_captchas["42"].expires_at = 0
    run(bot.handle_captcha_callback(update, ctx))
    assert settings.pending_captchas["42"].phase == "waiting"
    ctx.bot.restrict_chat_member.assert_not_awaited()


def test_external_moderator_ban_cancels_owned_recovery(tmp_path):
    store, ctx, update = environment(tmp_path)
    store.chat(-123).pending_captchas["42"] = PendingCaptcha(42, "test", 99, 0, phase="unban")
    update.chat_member = NS(from_user=User(88, "Admin", False),
        old_chat_member=ChatMemberMember(update.effective_user),
        new_chat_member=NS(user=update.effective_user, status="kicked"))
    run(bot.handle_chat_member_join(update, ctx))
    run(bot.captcha_timeout(ctx))
    assert not SettingsStore(store.path).chat(-123).pending_captchas
    ctx.bot.unban_chat_member.assert_not_awaited()


def test_captcha_off_releases_without_changing_other_kicks(tmp_path):
    store, ctx, update = environment(tmp_path)
    settings = store.chat(-123)
    settings.captcha_enabled = True
    settings.pending_captchas = {
        "42": PendingCaptcha(42, "test", 99, int(time.time()) + 60),
        "43": PendingCaptcha(43, "delca", 0, 0, phase="unban", reason="delca"),
    }
    ctx.args = ["OFF"]
    with patch("security_bot.bot._require_admin", new_callable=AsyncMock, return_value=True):
        run(bot.captcha_command(update, ctx))
    assert settings.pending_captchas["42"].phase == "release"
    assert settings.pending_captchas["43"].phase == "unban"
    run(bot.captcha_timeout(ctx))
    ctx.bot.ban_chat_member.assert_not_awaited()


def test_disable_during_provisioning_does_not_reactivate_captcha(tmp_path):
    store, ctx, update = environment(tmp_path)
    settings = store.chat(-123)
    settings.captcha_enabled = True
    pending = PendingCaptcha(42, "test", 0, 0, phase="provisioning", first_name="Lev")
    settings.pending_captchas["42"] = pending

    async def disable(**kwargs):
        settings.captcha_enabled = False
        pending.phase = "release"
        return NS(message_id=99)

    ctx.bot.send_message.side_effect = disable
    run(bot.captcha_timeout(ctx))
    assert pending.phase == "release"
    assert pending.message_id == 99
    run(bot.captcha_timeout(ctx))
    assert not settings.pending_captchas


@pytest.mark.parametrize("text,hidden,caption", [
    ("/start https://blocked.example", None, False),
    ("/CA", "https://blocked.example", False),
    ("click here", "https://blocked.example", True),
    ("/CA 0x" + "a" * 40, None, False),
])
def test_moderation_blocks_commands_and_hidden_links(tmp_path, text, hidden, caption):
    store, ctx, update = environment(tmp_path)
    settings = store.chat(-123)
    settings.url_enabled = settings.sendca_enabled = True
    message = update.effective_message
    message.text, message.caption = (None, text) if caption else (text, None)
    if hidden:
        setattr(message, "caption_entities" if caption else "entities",
                [MessageEntity("text_link", 0, len(text), url=hidden)])
    with pytest.raises(ApplicationHandlerStop):
        run(bot.moderation_gate(update, ctx))
    message.delete.assert_awaited_once()


def test_safe_messages_skip_admin_requests_and_unchanged_metadata_writes(tmp_path):
    store, ctx, update = environment(tmp_path)
    store.chat(-123).url_enabled = True
    update.effective_message.text = "1.5% and 22.3K"
    run(bot.moderation_gate(update, ctx))
    store.flush()
    with patch.object(store, "save", wraps=store.save) as save:
        run(bot.moderation_gate(update, ctx))
        store.flush()
        save.assert_not_called()
    ctx.bot.get_chat_member.assert_not_awaited()
    update.effective_message.delete.assert_not_awaited()


def test_admin_and_anonymous_admin_url_exemption(tmp_path):
    store, ctx, update = environment(tmp_path)
    store.chat(-123).url_enabled = True
    update.effective_message.text = "https://blocked.example"
    ctx.bot.get_chat_member.return_value = NS(status="administrator")
    run(bot.moderation_gate(update, ctx))
    update.effective_message.sender_chat = update.effective_chat
    ctx.bot.get_chat_member.reset_mock()
    run(bot.moderation_gate(update, ctx))
    ctx.bot.get_chat_member.assert_not_awaited()
    update.effective_message.delete.assert_not_awaited()


def test_real_dispatcher_moderates_before_registered_command(tmp_path):
    async def scenario():
        app = bot.build_application("123456:TEST_TOKEN_NOT_REAL", tmp_path / "dispatch.json")
        app._initialized = True
        app.bot._bot_user = User(999, "Security", True, username="SecurityBot")
        app.bot_data["store"].chat(-123).url_enabled = True
        message = Message(15, datetime.now(timezone.utc), Chat(-123, "supergroup"),
                          from_user=User(42, "User", False), text="/start https://blocked.example",
                          entities=[MessageEntity("bot_command", 0, 6)])
        message.set_bot(app.bot)
        with patch.object(ExtBot, "get_chat_member", new_callable=AsyncMock, return_value=NS(status="member")), \
             patch.object(ExtBot, "delete_message", new_callable=AsyncMock) as delete, \
             patch.object(ExtBot, "send_message", new_callable=AsyncMock) as send:
            await app.process_update(Update(1, message=message))
            delete.assert_awaited_once()
            send.assert_not_awaited()
    run(scenario())


@pytest.mark.parametrize("failure", [TimedOut(), RetryAfter(120), BadRequest("Message can't be deleted")])
def test_warning_does_not_replace_until_old_message_deleted(tmp_path, failure):
    store, ctx, update = environment(tmp_path)
    settings = store.chat(-123)
    settings.warning_enabled = True
    settings.warning_text = "Warning"
    settings.warning_message_ids = [77]
    store.save()
    ctx.bot.delete_message.side_effect = failure
    run(bot.send_warning_message(ctx))
    assert SettingsStore(store.path).chat(-123).warning_message_ids == [77]
    ctx.bot.send_message.assert_not_awaited()
    ctx.bot.delete_message.side_effect = None
    ctx.application.bot_data["warning_backoff"][-123] = 0
    run(bot.send_warning_message(ctx))
    assert SettingsStore(store.path).chat(-123).warning_message_ids == [99]
    ctx.bot.send_message.assert_awaited_once()


def test_missing_old_warning_allows_replacement(tmp_path):
    store, ctx, update = environment(tmp_path)
    settings = store.chat(-123)
    settings.warning_enabled = True
    settings.warning_text = "Notice"
    settings.warning_message_ids = [77]
    ctx.bot.delete_message.side_effect = BadRequest("Message to delete not found")
    run(bot.send_warning_message(ctx))
    assert settings.warning_message_ids == [99]


def test_warning_formatting_and_caption_validation(tmp_path):
    store, ctx, update = environment(tmp_path)
    settings = store.chat(-123)
    message = update.effective_message
    message.text = "/warningtxt First\nBold"
    message.entities = [MessageEntity("bot_command", 0, 11), MessageEntity("bold", 18, 4)]
    with patch("security_bot.bot._require_admin", new_callable=AsyncMock, return_value=True):
        run(bot.warningtxt(update, ctx))
        assert settings.warning_text == "First\nBold"
        assert settings.warning_entities == [{"type": "bold", "offset": 6, "length": 4}]
        settings.warning_media_file_id = "photo"
        message.text = "/warningtxt " + "x" * 1025
        run(bot.warningtxt(update, ctx))
        assert settings.warning_text == "First\nBold"


def test_alert_queue_retries_after_restart_with_group_and_username(tmp_path):
    store, ctx, update = environment(tmp_path)
    settings = store.chat(-123)
    settings.alert_enabled = True
    settings.keywords = ["lev"]
    settings.recipients = {"receiver": Recipient("receiver", 80)}
    settings.known_names["42"] = "Old name"
    run(bot._handle_name_seen(update, ctx, update.effective_user, False))
    assert len(settings.pending_alerts) == 1
    item = next(iter(settings.pending_alerts.values()))
    assert "Lev (@noregretz)" in item.text
    assert "Test &lt;Group&gt;" in item.text
    ctx.bot.send_message.side_effect = TimedOut()
    run(deliver_pending_alerts(ctx))
    reloaded = SettingsStore(store.path)
    ctx.application.bot_data["store"] = reloaded
    item = next(iter(reloaded.chat(-123).pending_alerts.values()))
    assert item.attempts == 1
    item.next_attempt = 0
    ctx.bot.send_message.side_effect = None
    run(deliver_pending_alerts(ctx))
    assert not SettingsStore(store.path).chat(-123).pending_alerts
    run(bot._handle_name_seen(update, ctx, update.effective_user, False))
    assert not reloaded.chat(-123).pending_alerts


def test_alert_unresolved_recipient_can_start_after_event(tmp_path):
    store, ctx, update = environment(tmp_path)
    settings = store.chat(-123)
    settings.alert_enabled = True
    settings.keywords = ["lev"]
    settings.recipients = {"noregretz": Recipient("noregretz")}
    run(bot._handle_name_seen(update, ctx, update.effective_user, True))
    run(deliver_pending_alerts(ctx))
    ctx.bot.send_message.assert_not_awaited()
    update.effective_chat = Chat(42, "private")
    run(bot.start(update, ctx))
    run(deliver_pending_alerts(ctx))
    ctx.bot.send_message.assert_awaited_once()
    assert not settings.pending_alerts


def test_scanner_budget_backoff_and_departed_cleanup(tmp_path):
    store, ctx, update = environment(tmp_path)
    for cid in (-123, -456):
        settings = store.chat(cid)
        settings.alert_enabled = True
        settings.keywords = ["meta"]
        settings.known_names = {str(uid): "Previous" for uid in range(15)}
    ctx.bot.get_chat_member.return_value = NS(status="left")
    run(scan_names(ctx))
    assert ctx.bot.get_chat_member.await_count == 5
    assert sum(len(x.known_names) for x in store.chats().values()) == 25
    ctx.bot.get_chat_member.reset_mock()
    ctx.bot.get_chat_member.side_effect = RetryAfter(90)
    run(scan_names(ctx))
    run(scan_names(ctx))
    assert ctx.bot.get_chat_member.await_count == 1
    assert ctx.application.bot_data["scanner_pause_until"] >= time.time() + 89


def test_disabled_scanner_makes_no_requests(tmp_path):
    store, ctx, update = environment(tmp_path)
    store.chat(-123).known_names = {"42": "Lev"}
    run(scan_names(ctx))
    ctx.bot.get_chat_member.assert_not_awaited()


def test_deleted_scan_requires_confirmation_and_is_batched(tmp_path):
    store, ctx, update = environment(tmp_path)
    store.chat(-123).known_names = {str(uid): "Deleted Account" for uid in range(12)}
    with patch("security_bot.bot._require_admin", new_callable=AsyncMock, return_value=True):
        run(bot.scandeletedaccounts(update, ctx))
        ctx.bot.get_chat_member.assert_not_awaited()
        work = ctx.application.job_queue.run_repeating.call_args.kwargs["data"]
        ctx.job = NS(data=work, schedule_removal=Mock())
        ctx.bot.get_chat_member.return_value = ChatMemberMember(User(42, "Deleted Account", False))
        run(scan_deleted_batch(ctx))
        assert ctx.bot.get_chat_member.await_count == 5
        ctx.bot.ban_chat_member.assert_not_awaited()
        ctx.args = ["42"]
        run(bot.confirm_deleted_account(update, ctx))
        assert not store.chat(-123).pending_captchas
        # A reported ID is required, and its current name is checked again.
        ctx.application.bot_data["deleted_candidates"][-123].add(42)
        run(bot.confirm_deleted_account(update, ctx))
        assert store.chat(-123).pending_captchas["42"].reason == "confirmed-deleted"


@pytest.mark.parametrize("command", [
    "url_command", "alert_command", "captcha_command", "captchatime", "captchamode", "clearevents_command",
    "delca_command", "sendca_command", "warningmsg_command", "warningtxt", "warningfreq", "warnmedia",
    "addurl", "delurl", "listurl", "addkeyword", "delkeyword", "listkeyword", "addrecipient",
    "delrecipient", "listrecipient", "setfilter", "delfilter", "listfilter", "scandeletedaccounts", "confirm_deleted_account",
])
def test_all_admin_commands_reject_ordinary_members(tmp_path, command):
    store, ctx, update = environment(tmp_path)
    settings = store.chat(-123)
    before = asdict(settings)
    ctx.args = ["ON"]
    run(getattr(bot, command)(update, ctx))
    assert asdict(settings) == before
    update.effective_message.reply_text.assert_awaited_once()
    ctx.bot.ban_chat_member.assert_not_awaited()


def test_legacy_settings_preserved_with_untouched_first_backup(tmp_path):
    path = tmp_path / "legacy.json"
    legacy = {"-123": {
        "url_enabled": True, "captcha_enabled": True, "alert_enabled": True,
        "warning_enabled": True, "warning_freq_seconds": 120, "warning_text": "A\nB",
        "warning_entities": [{"type": "bold", "offset": 0, "length": 1}],
        "allowed_urls": ["x.com"], "keywords": ["Meta"],
        "recipients": {"lev": {"username": "lev", "user_id": 42}},
        "filters": {"ca": {"keyword": "CA", "text": "0x" + "a" * 40}},
        "pending_captchas": {"42": {"user_id": 42, "token": "old", "message_id": 1, "expires_at": 0, "phase": "unban"}},
    }}
    original = json.dumps(legacy).encode()
    path.write_bytes(original)
    store = SettingsStore(path)
    store.save()
    new = json.loads(path.read_text())
    for key, value in legacy["-123"].items():
        if key not in {"filters", "pending_captchas"}:
            assert new["-123"][key] == value
    assert store.chat(-123).filters["ca"].text == legacy["-123"]["filters"]["ca"]["text"]
    assert store.chat(-123).pending_captchas["42"].phase == "unban"
    assert path.with_name(path.name + ".pre-reliability.bak").read_bytes() == original
    store.chat(-123).keywords.append("Other")
    SettingsStore(path).save()
    assert path.with_name(path.name + ".pre-reliability.bak").read_bytes() == original
    fresh = store.chat(-456)
    assert not any(getattr(fresh, key) for key in vars(fresh) if key.endswith("_enabled"))
    assert fresh.warning_freq_seconds == 600 and fresh.captcha_timeout_seconds == 60


def test_token_redaction_in_messages_and_tracebacks():
    token = "123456789:" + "x" * 35
    formatter = RedactingFormatter("%(message)s")
    record = logging.LogRecord("test", logging.ERROR, __file__, 1, "POST https://api.telegram.org/bot%s/getMe", (token,), None)
    assert token not in formatter.format(record)
    try:
        raise RuntimeError(token)
    except RuntimeError:
        import sys
        record.exc_info = sys.exc_info()
    assert token not in formatter.format(record)


def test_filter_exact_match_including_slash_and_addressed_bot(tmp_path):
    store, ctx, update = environment(tmp_path)
    store.chat(-123).filters["ca"] = SavedFilter("CA", "contract address")
    for text in ("CA", "ca", "/CA", "/CA@SecurityBot"):
        update.effective_message.text = text
        assert run(bot._maybe_send_filter_response(update, ctx))
    for text in ("CA extra", "/CA extra", "/CA@OtherBot"):
        update.effective_message.text = text
        assert not run(bot._maybe_send_filter_response(update, ctx))


def test_permission_restore_success_response_but_still_muted_retries(tmp_path):
    store, ctx, update = environment(tmp_path)
    settings = store.chat(-123)
    settings.pending_captchas["42"] = PendingCaptcha(42, "test", 99, 0, phase="release")
    ctx.bot.get_chat_member.return_value = NS(status="restricted", is_member=True, can_send_messages=False)
    run(bot.captcha_timeout(ctx))
    assert settings.pending_captchas["42"].phase == "release"
    assert settings.pending_captchas["42"].retry_count == 1
    ctx.bot.ban_chat_member.assert_not_awaited()


def test_original_short_restriction_gets_expiry_recovery(tmp_path):
    store, ctx, update = environment(tmp_path)
    pending = PendingCaptcha(42, "test", 99, 0, phase="release",
                             restore_permissions={"can_send_messages": False},
                             restore_until=int(time.time()) + 15)
    store.chat(-123).pending_captchas["42"] = pending
    ctx.bot.get_chat_member.return_value = NS(status="restricted", is_member=True, can_send_messages=False)
    run(bot.captcha_timeout(ctx))
    assert pending.expires_at == pending.restore_until
    assert pending.phase == "release"
    ctx.bot.ban_chat_member.assert_not_awaited()


def test_delca_kick_has_its_own_reason_and_recovery_when_captcha_off(tmp_path):
    store, ctx, update = environment(tmp_path)
    store.chat(-123).delca_enabled = True
    user = User(42, "Name before 0x" + "a" * 40, False)
    run(bot._handle_joined_user(update, ctx, user))
    pending = store.chat(-123).pending_captchas["42"]
    assert pending.reason == "delca" and pending.phase == "kick"
    assert not store.chat(-123).captcha_enabled
    ctx.job.data["token"] = pending.token
    ctx.bot.unban_chat_member.side_effect = TimedOut()
    run(bot.captcha_timeout(ctx))
    assert SettingsStore(store.path).chat(-123).pending_captchas["42"].phase == "unban"
    ctx.bot.ban_chat_member.assert_awaited_once()


def test_other_channel_is_not_exempt_from_url_moderation(tmp_path):
    store, ctx, update = environment(tmp_path)
    store.chat(-123).url_enabled = True
    update.effective_user = None
    update.effective_message.sender_chat = Chat(-456, "channel")
    update.effective_message.text = "https://blocked.example"
    with pytest.raises(ApplicationHandlerStop):
        run(bot.moderation_gate(update, ctx))
    update.effective_message.delete.assert_awaited_once()
    ctx.bot.get_chat_member.assert_not_awaited()


def test_noncaptcha_recovery_does_not_lift_individual_restrictions(tmp_path):
    store, ctx, update = environment(tmp_path)
    store.chat(-123).pending_captchas["42"] = PendingCaptcha(42, "test", 0, 0, phase="unban", reason="delca")
    ctx.bot.get_chat_member.return_value = NS(status="restricted", is_member=True, can_send_messages=False)
    run(bot.captcha_timeout(ctx))
    ctx.bot.restrict_chat_member.assert_not_awaited()
    assert not store.chat(-123).pending_captchas


def test_reassigned_username_cannot_take_over_resolved_recipient(tmp_path):
    store, ctx, update = environment(tmp_path)
    store.chat(-123).recipients["noregretz"] = Recipient("noregretz", 80)
    update.effective_chat = Chat(42, "private")
    run(bot.start(update, ctx))
    assert store.chat(-123).recipients["noregretz"].user_id == 80


def test_cleanup_failure_is_persisted_and_does_not_block_other_message(tmp_path):
    store, ctx, update = environment(tmp_path)
    store.chat(-123).cleanup_message_ids = [1, 2]
    store.save()
    ctx.bot.delete_message.side_effect = [Forbidden("Not allowed"), True]
    run(maintenance(ctx))
    assert SettingsStore(store.path).chat(-123).cleanup_message_ids == [1]
    ctx.bot.delete_message.reset_mock()
    run(maintenance(ctx))
    ctx.bot.delete_message.assert_not_awaited()


@pytest.mark.parametrize("prefix", ["Ox", "ox"])
@pytest.mark.parametrize("caption", [False, True])
def test_sendca_blocks_letter_o_lookalikes_in_text_commands_and_captions(tmp_path, prefix, caption):
    store, ctx, update = environment(tmp_path)
    store.chat(-123).sendca_enabled = True
    text = "/CA " + prefix + "ffDA10b7fd9Cf172e0502A6Bc0e5E355516c5232"
    update.effective_message.text = None if caption else text
    update.effective_message.caption = text if caption else None
    with pytest.raises(ApplicationHandlerStop):
        run(bot.moderation_gate(update, ctx))
    update.effective_message.delete.assert_awaited_once()


@pytest.mark.parametrize("admin,enabled", [(True, True), (False, False)])
def test_sendca_lookalikes_preserve_admin_exemption_and_off_switch(tmp_path, admin, enabled):
    store, ctx, update = environment(tmp_path)
    store.chat(-123).sendca_enabled = enabled
    update.effective_message.text = "OxffDA10b7fd9Cf172e0502A6Bc0e5E355516c5232"
    if admin:
        ctx.bot.get_chat_member.return_value = NS(status="administrator")
    run(bot.moderation_gate(update, ctx))
    update.effective_message.delete.assert_not_awaited()


@pytest.mark.parametrize("enabled", [True, False])
def test_delca_checks_letter_o_lookalikes_inside_display_names(tmp_path, enabled):
    store, ctx, update = environment(tmp_path)
    store.chat(-123).delca_enabled = enabled
    user = User(42, "Support OxffDA10b7fd9Cf172e0502A6Bc0e5E355516c5232 Team", False)
    run(bot._handle_joined_user(update, ctx, user))
    pending = store.chat(-123).pending_captchas.get("42")
    if enabled:
        assert pending.reason == "delca" and pending.phase == "kick"
    else:
        assert pending is None
