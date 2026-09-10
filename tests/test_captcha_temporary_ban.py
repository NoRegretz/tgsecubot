import asyncio
from collections import Counter
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, Mock

import pytest
from telegram import Chat, ChatMemberMember, User
from telegram.error import RetryAfter, TimedOut

from security_bot.bot import (
    CAPTCHA_MAX_CONCURRENT_RECOVERIES,
    _start_captcha,
    captcha_timeout,
    handle_captcha_callback,
    recover_missing_captcha_jobs,
)
from security_bot.storage import PendingCaptcha, SettingsStore
from security_bot.workflows import CAPTCHA_BAN_SAFETY_SECONDS


@pytest.fixture
def setup(tmp_path, monkeypatch):
    clock = [1_800_000_000]
    monkeypatch.setattr("security_bot.workflows.time.time", lambda: clock[0])
    store = SettingsStore(tmp_path / "state.json")
    store.chat(-123).captcha_enabled = True
    queue = Mock()
    queue.get_jobs_by_name.return_value = []
    api = NS(
        get_chat_member=AsyncMock(return_value=NS(status="member")),
        ban_chat_member=AsyncMock(), unban_chat_member=AsyncMock(),
        delete_message=AsyncMock(),
    )
    ctx = NS(application=NS(bot_data={"store": store}, job_queue=queue), bot=api,
             job=NS(data={"chat_id": -123, "user_id": 42, "token": "test"}))
    return store, ctx, clock


def test_expiry_is_computed_after_storage_delay_not_from_challenge_deadline(setup, monkeypatch):
    store, ctx, clock = setup
    store.chat(-123).pending_captchas["42"] = PendingCaptcha(42, "test", 99, clock[0] - 60, deadline=clock[0] - 60)
    save = store.save

    def slow_save():
        save()
        clock[0] += 180

    monkeypatch.setattr(store, "save", slow_save)

    async def ban(**kwargs):
        assert kwargs["until_date"] == clock[0] + 120
        assert SettingsStore(store.path).chat(-123).pending_captchas["42"].phase == "unban"

    ctx.bot.ban_chat_member.side_effect = ban
    asyncio.run(captcha_timeout(ctx))
    ctx.bot.ban_chat_member.assert_awaited_once()
    ctx.bot.unban_chat_member.assert_awaited_once_with(chat_id=-123, user_id=42, only_if_banned=True)


def test_rejected_ban_gets_fresh_expiry_but_unban_retries_never_extend_it(setup):
    store, ctx, clock = setup
    pending = PendingCaptcha(42, "test", 99, 0)
    store.chat(-123).pending_captchas["42"] = pending
    ctx.bot.ban_chat_member.side_effect = [RetryAfter(240), True]
    asyncio.run(captcha_timeout(ctx))
    first_until = ctx.bot.ban_chat_member.call_args.kwargs["until_date"]
    assert pending.phase == "kick"
    assert pending.expires_at >= clock[0] + 240
    ctx.bot.unban_chat_member.assert_not_awaited()
    clock[0] = pending.expires_at
    ctx.bot.unban_chat_member.side_effect = TimedOut()
    asyncio.run(captcha_timeout(ctx))
    assert ctx.bot.ban_chat_member.call_args.kwargs["until_date"] == clock[0] + 120
    assert ctx.bot.ban_chat_member.call_args.kwargs["until_date"] > first_until
    assert pending.phase == "unban"
    for _ in range(3):
        clock[0] = pending.expires_at
        asyncio.run(captcha_timeout(ctx))
    assert ctx.bot.ban_chat_member.await_count == 2


@pytest.mark.parametrize("reason", ["delca", "confirmed-deleted"])
def test_other_removal_reasons_do_not_get_captcha_expiry(setup, reason):
    store, ctx, clock = setup
    store.chat(-123).pending_captchas["42"] = PendingCaptcha(42, "test", 0, 0, phase="kick", reason=reason)
    asyncio.run(captcha_timeout(ctx))
    ctx.bot.ban_chat_member.assert_awaited_once_with(chat_id=-123, user_id=42)


def test_restart_after_timed_ban_expiry_does_not_ban_again(setup):
    store, ctx, clock = setup
    store.chat(-123).pending_captchas["42"] = PendingCaptcha(42, "test", 99, 0)
    ctx.bot.unban_chat_member.side_effect = TimedOut()
    asyncio.run(captcha_timeout(ctx))
    until = ctx.bot.ban_chat_member.call_args.kwargs["until_date"]
    assert store.chat(-123).pending_captchas["42"].phase == "unban"
    clock[0] = until + 60
    ctx.application.bot_data["store"] = SettingsStore(store.path)
    ctx.bot.ban_chat_member.reset_mock()
    ctx.bot.unban_chat_member.side_effect = None
    ctx.bot.get_chat_member.return_value = NS(status="left")
    asyncio.run(captcha_timeout(ctx))
    ctx.bot.ban_chat_member.assert_not_awaited()
    assert not SettingsStore(store.path).chat(-123).pending_captchas


def test_frequent_joins_clicks_timeouts_and_rejoins_remain_independent(setup):
    store, ctx, clock = setup

    async def scenario():
        targets = [(chat, uid) for chat in (-123, -456) for uid in range(1, 51)]
        members = {key: "member" for key in targets}
        ban_attempts = Counter()
        unban_attempts = Counter()
        expiries = {}
        live, peak, message_id = 0, 0, 100
        started = asyncio.Event()
        release = asyncio.Event()

        def member_context(key, token=None):
            cid, uid = key
            pending = ctx.application.bot_data["store"].chat(cid).pending_captchas.get(str(uid))
            return NS(application=ctx.application, bot=ctx.bot,
                      job=NS(data={"chat_id": cid, "user_id": uid, "token": token or pending.token}))

        def update_for(key):
            cid, uid = key
            return NS(effective_chat=Chat(cid, "supergroup", title="Test"),
                      effective_user=User(uid, f"User{uid}", False))

        async def lookup(chat_id, user_id):
            await asyncio.sleep(0)
            status = members[(chat_id, user_id)]
            user = User(user_id, f"User{user_id}", False)
            if status == "member":
                return ChatMemberMember(user)
            return NS(status=status, user=user, is_member=status == "restricted", can_send_messages=False)

        async def restrict(chat_id, user_id, permissions, **kwargs):
            await asyncio.sleep(0)
            members[(chat_id, user_id)] = "member" if permissions.can_send_messages else "restricted"

        async def send(**kwargs):
            nonlocal message_id
            await asyncio.sleep(0)
            message_id += 1
            return NS(message_id=message_id)

        async def ban(chat_id, user_id, until_date):
            nonlocal live, peak
            key = (chat_id, user_id)
            assert until_date == clock[0] + CAPTCHA_BAN_SAFETY_SECONDS
            assert ctx.application.bot_data["store"].chat(chat_id).pending_captchas[str(user_id)].phase == "unban"
            ban_attempts[key] += 1
            live += 1
            peak = max(peak, live)
            if live == CAPTCHA_MAX_CONCURRENT_RECOVERIES:
                started.set()
            try:
                await release.wait()
                if user_id % 11 == 0 and ban_attempts[key] == 1:
                    raise RetryAfter(180)
                members[key] = "kicked"
                expiries[key] = until_date
            finally:
                live -= 1

        async def unban(chat_id, user_id, only_if_banned):
            key = (chat_id, user_id)
            assert only_if_banned is True
            unban_attempts[key] += 1
            await asyncio.sleep(0)
            if user_id % 5 == 0 and unban_attempts[key] == 1:
                raise TimedOut()
            if members[key] == "kicked":
                members[key] = "left"

        ctx.bot.get_chat_member.side_effect = lookup
        ctx.bot.restrict_chat_member = AsyncMock(side_effect=restrict)
        ctx.bot.send_message = AsyncMock(side_effect=send)
        ctx.bot.ban_chat_member.side_effect = ban
        ctx.bot.unban_chat_member.side_effect = unban
        for key in targets:
            store.chat(key[0]).captcha_enabled = True
            update = update_for(key)
            await _start_captcha(update, ctx, update.effective_user)
        await asyncio.gather(*(captcha_timeout(member_context(key)) for key in targets))
        old_tokens = {key: store.chat(key[0]).pending_captchas[str(key[1])].token for key in targets}
        assert len(set(old_tokens.values())) == len(targets)
        assert all(members[key] == "restricted" for key in targets)

        verified = {key for key in targets if key[1] % 3 == 0}
        for key in verified:
            cid, uid = key
            update = update_for(key)
            pending = store.chat(cid).pending_captchas[str(uid)]
            update.callback_query = NS(data=f"captcha|{cid}|{uid}|{pending.token}", from_user=update.effective_user,
                                       message=NS(chat_id=cid, message_id=pending.message_id), answer=AsyncMock())
            await handle_captcha_callback(update, ctx)

        clock[0] += 61
        tasks = [asyncio.create_task(captcha_timeout(member_context(key))) for key in targets]
        try:
            await asyncio.wait_for(started.wait(), timeout=10)
            # Duplicate events cannot start a second action, including while capacity is exhausted.
            active_keys = set(ctx.application.bot_data["captcha_active"])
            await asyncio.gather(*(captcha_timeout(member_context(key, old_tokens[key])) for key in active_keys))
            await recover_missing_captcha_jobs(ctx)
        finally:
            release.set()
            await asyncio.gather(*tasks)
        assert peak == CAPTCHA_MAX_CONCURRENT_RECOVERIES
        assert all(ban_attempts[key] == 0 and members[key] == "member" for key in verified)
        assert all(ban_attempts[key] == 1 for key in set(targets) - verified)

        # Rejoin while old unban recovery still exists; stale retries must not touch the new challenge.
        rejoins = {key for key in targets if members[key] == "left" or (key[1] % 5 == 0 and key not in verified)}
        for key in rejoins:
            members[key] = "member"
            update = update_for(key)
            await _start_captcha(update, ctx, update.effective_user)
        ban_counts = ban_attempts.copy()
        await asyncio.gather(*(captcha_timeout(member_context(key, old_tokens[key])) for key in rejoins))
        assert ban_counts == ban_attempts
        await asyncio.gather(*(captcha_timeout(member_context(key)) for key in rejoins))
        for key in rejoins:
            pending = store.chat(key[0]).pending_captchas[str(key[1])]
            assert pending.phase == "waiting" and pending.token != old_tokens[key]
            assert pending.deadline == clock[0] + 60
            assert members[key] == "restricted"

        # Resume the remaining removal retries after a simulated process restart.
        ctx.application.bot_data = {"store": SettingsStore(store.path)}
        clock[0] += 240
        rejected = set(targets) - verified - rejoins
        assert rejected
        await asyncio.gather(*(captcha_timeout(member_context(key)) for key in rejected))
        assert all(members[key] == "left" for key in rejected)
        assert all(expiries[key] == clock[0] + 120 for key in rejected)
        assert all(not ctx.application.bot_data["store"].chat(key[0]).pending_captchas.get(str(key[1])) for key in rejected)
        assert not ctx.application.bot_data["captcha_active"]

    asyncio.run(scenario())
