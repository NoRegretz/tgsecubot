import asyncio
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, Mock

import pytest
from telegram import Chat, User
from telegram.error import RetryAfter, TimedOut

from security_bot.background import maintenance
from security_bot.bot import _start_captcha, captcha_timeout, handle_captcha_callback
from security_bot.storage import PendingCaptcha, SettingsStore


@pytest.fixture
def setup(tmp_path, monkeypatch):
    clock = [1_800_000_000]
    monkeypatch.setattr("security_bot.workflows.time.time", lambda: clock[0])
    store = SettingsStore(tmp_path / "state.json")
    settings = store.chat(-123)
    settings.captcha_enabled = True
    settings.pending_captchas["42"] = PendingCaptcha(42, "old", 99, clock[0], deadline=clock[0])
    queue = Mock()
    queue.get_jobs_by_name.return_value = []
    api = NS(get_chat_member=AsyncMock(return_value=NS(status="member")),
        restrict_chat_member=AsyncMock(), ban_chat_member=AsyncMock(), unban_chat_member=AsyncMock(),
        delete_message=AsyncMock(), send_message=AsyncMock(return_value=NS(message_id=100)))
    ctx = NS(application=NS(bot_data={"store": store}, job_queue=queue), bot=api,
             job=NS(data={"chat_id": -123, "user_id": 42, "token": "old"}))
    return store, ctx, clock


def test_timeout_deletes_old_challenge_before_kick_and_unban(setup):
    store, ctx, clock = setup
    calls = []

    async def delete(**kwargs):
        saved = SettingsStore(store.path).chat(-123)
        assert saved.cleanup_message_ids == [99]
        assert saved.pending_captchas["42"].message_id == 0
        calls.append("delete")

    async def ban(**kwargs):
        calls.append("ban")

    async def unban(**kwargs):
        calls.append("unban")
        raise TimedOut()

    ctx.bot.delete_message.side_effect = delete
    ctx.bot.ban_chat_member.side_effect = ban
    ctx.bot.unban_chat_member.side_effect = unban
    asyncio.run(captcha_timeout(ctx))
    assert calls == ["delete", "ban", "unban"]
    assert not store.chat(-123).cleanup_message_ids
    assert store.chat(-123).pending_captchas["42"].phase == "unban"
    clock[0] = store.chat(-123).pending_captchas["42"].expires_at
    asyncio.run(captcha_timeout(ctx))
    ctx.bot.delete_message.assert_awaited_once()


@pytest.mark.parametrize("error", [TimedOut(), RetryAfter(60)])
def test_failed_cleanup_survives_restart_without_stopping_unban(setup, error):
    store, ctx, clock = setup
    ctx.bot.delete_message.side_effect = error
    asyncio.run(captcha_timeout(ctx))
    ctx.bot.ban_chat_member.assert_awaited_once()
    ctx.bot.unban_chat_member.assert_awaited_once()
    assert not store.chat(-123).pending_captchas
    assert SettingsStore(store.path).chat(-123).cleanup_message_ids == [99]
    asyncio.run(maintenance(ctx))
    ctx.bot.delete_message.assert_awaited_once()
    clock[0] += 61
    ctx.application.bot_data = {"store": SettingsStore(store.path)}
    ctx.bot.delete_message.side_effect = None
    asyncio.run(maintenance(ctx))
    assert not SettingsStore(store.path).chat(-123).cleanup_message_ids


def test_slow_cleanup_has_a_short_budget_and_cannot_strand_member(setup, monkeypatch):
    store, ctx, clock = setup
    monkeypatch.setattr("security_bot.workflows.CAPTCHA_CLEANUP_TIMEOUT_SECONDS", 0.01)

    async def hanging_delete(**kwargs):
        await asyncio.Future()

    ctx.bot.delete_message.side_effect = hanging_delete
    asyncio.run(asyncio.wait_for(captcha_timeout(ctx), timeout=1))
    ctx.bot.unban_chat_member.assert_awaited_once()
    assert store.chat(-123).cleanup_message_ids == [99]
    assert not ctx.application.bot_data["cleanup_active"]


def test_maintenance_and_immediate_cleanup_do_not_delete_same_message_twice(setup):
    store, ctx, clock = setup

    async def scenario():
        store.chat(-123).cleanup_message_ids = [99]
        started, release = asyncio.Event(), asyncio.Event()

        async def deleting(**kwargs):
            started.set()
            await release.wait()

        ctx.bot.delete_message.side_effect = deleting
        task = asyncio.create_task(maintenance(ctx))
        try:
            await asyncio.wait_for(started.wait(), timeout=1)
            await captcha_timeout(ctx)
            assert store.chat(-123).cleanup_message_ids == [99]
        finally:
            release.set()
            await task
        ctx.bot.delete_message.assert_awaited_once()
        assert not SettingsStore(store.path).chat(-123).cleanup_message_ids
        assert not store.chat(-123).pending_captchas

    asyncio.run(scenario())


def test_quick_rejoin_hands_off_immediately_and_old_button_cannot_verify_new_challenge(setup):
    store, ctx, clock = setup

    async def scenario():
        started, release = asyncio.Event(), asyncio.Event()

        async def unban(**kwargs):
            ctx.bot.delete_message.assert_awaited_once_with(chat_id=-123, message_id=99)
            started.set()
            await release.wait()

        ctx.bot.unban_chat_member.side_effect = unban
        old_task = asyncio.create_task(captcha_timeout(ctx))
        update = NS(effective_chat=Chat(-123, "supergroup"), effective_user=User(42, "Member", False))
        try:
            await asyncio.wait_for(started.wait(), timeout=1)
            # Telegram has applied the unban, but its response has not returned yet.
            await _start_captcha(update, ctx, update.effective_user)
            fresh = store.chat(-123).pending_captchas["42"]
            fresh_context = NS(application=ctx.application, bot=ctx.bot,
                job=NS(data={"chat_id": -123, "user_id": 42, "token": fresh.token}))
            await captcha_timeout(fresh_context)
            ctx.bot.send_message.assert_not_awaited()
            ctx.application.job_queue.run_once.reset_mock()
        finally:
            release.set()
            await old_task
        queued = ctx.application.job_queue.run_once.call_args.kwargs
        assert queued["data"]["token"] == fresh.token
        assert queued["when"] == 0
        await captcha_timeout(fresh_context)
        assert fresh.phase == "waiting" and fresh.message_id == 100
        assert fresh.deadline == clock[0] + 60
        assert not store.chat(-123).cleanup_message_ids
        update.callback_query = NS(data="captcha|-123|42|old", from_user=update.effective_user,
            message=NS(chat_id=-123, message_id=99), answer=AsyncMock())
        await handle_captcha_callback(update, ctx)
        assert fresh.phase == "waiting"
        assert "expired" in update.callback_query.answer.call_args.args[0]
        # A late old timeout does not delete or replace the fresh message.
        await captcha_timeout(ctx)
        assert store.chat(-123).pending_captchas["42"] is fresh
        ctx.bot.delete_message.assert_awaited_once_with(chat_id=-123, message_id=99)

    asyncio.run(scenario())
