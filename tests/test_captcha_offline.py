import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, Mock

import pytest
from telegram import Chat, ChatMemberMember, User
from telegram.error import TimedOut

from security_bot.bot import (
    _start_captcha, build_application, captcha_timeout, handle_chat_member_join,
    initialize_captcha_session,
)
from security_bot.storage import PendingCaptcha, SettingsStore


@pytest.fixture
def setup(tmp_path, monkeypatch):
    clock = [1_800_000_000]
    monkeypatch.setattr("security_bot.bot.time.time", lambda: clock[0])
    store = SettingsStore(tmp_path / "state.json")
    store.chat(-123).captcha_enabled = True
    queue = Mock()
    queue.get_jobs_by_name.return_value = []
    user = User(42, "Member", False)
    bot = NS(id=999, get_chat_member=AsyncMock(return_value=ChatMemberMember(user)),
             restrict_chat_member=AsyncMock(), ban_chat_member=AsyncMock(), unban_chat_member=AsyncMock(),
             delete_message=AsyncMock(),
             send_message=AsyncMock(return_value=NS(message_id=99)))
    ctx = NS(application=NS(bot_data={"store": store}, job_queue=queue), bot=bot,
             job=NS(data={"chat_id": -123, "user_id": 42, "token": "test"}))
    return store, ctx, clock


def join_update(cid, uid, joined_at):
    user = User(uid, f"Member{uid}", False)
    return NS(effective_chat=Chat(cid, "supergroup", title="Test"), effective_user=user,
              chat_member=NS(date=datetime.fromtimestamp(joined_at, timezone.utc), from_user=user,
                  old_chat_member=NS(status="left"), new_chat_member=ChatMemberMember(user)))


@pytest.mark.parametrize("age", [0, 1, 60, 3600, 86400])
def test_pre_start_and_start_boundary_joins_do_not_get_captcha(setup, age):
    store, ctx, clock = setup
    asyncio.run(initialize_captcha_session(ctx.application))
    update = join_update(-123, 42, clock[0] - age)
    asyncio.run(handle_chat_member_join(update, ctx))
    assert not store.chat(-123).pending_captchas
    assert store.chat(-123).known_names["42"] == "Member42"
    ctx.bot.restrict_chat_member.assert_not_awaited()
    ctx.bot.send_message.assert_not_awaited()
    ctx.bot.ban_chat_member.assert_not_awaited()


def test_old_join_after_network_outage_without_restart_is_skipped(setup):
    store, ctx, clock = setup
    asyncio.run(initialize_captcha_session(ctx.application))
    joined_at = clock[0] + 10
    clock[0] += 86400
    asyncio.run(handle_chat_member_join(join_update(-123, 42, joined_at), ctx))
    assert not store.chat(-123).pending_captchas


def test_bulk_replayed_joins_then_fresh_joins_in_two_groups(setup):
    store, ctx, clock = setup

    async def scenario():
        await initialize_captcha_session(ctx.application)
        startup = clock[0]
        clock[0] += 5
        for cid in (-123, -456):
            store.chat(cid).captcha_enabled = True
            for uid in range(50):
                await handle_chat_member_join(join_update(cid, uid, startup - 3600), ctx)
            assert not store.chat(cid).pending_captchas
        for cid in (-123, -456):
            for uid in range(50, 75):
                await handle_chat_member_join(join_update(cid, uid, clock[0]), ctx)
            assert len(store.chat(cid).pending_captchas) == 25
        pending_jobs = ctx.application.job_queue.run_once.call_args_list
        assert len(pending_jobs) == 50
        assert len({call.kwargs["name"] for call in pending_jobs}) == 50
        for cid in (-123, -456):
            for uid in range(50, 75):
                pending = store.chat(cid).pending_captchas[str(uid)]
                member_ctx = NS(application=ctx.application, bot=ctx.bot,
                    job=NS(data={"chat_id": cid, "user_id": uid, "token": pending.token}))
                await captcha_timeout(member_ctx)
                assert pending.phase == "waiting"
                assert pending.deadline == clock[0] + 60
        assert ctx.bot.send_message.await_count == 50
        ctx.bot.ban_chat_member.assert_not_awaited()

    asyncio.run(scenario())


def test_startup_releases_expired_challenges_but_preserves_recoveries_and_settings(setup):
    store, ctx, clock = setup
    settings = store.chat(-123)
    settings.allowed_urls = ["x.com"]
    settings.warning_text = "Keep me"
    now = clock[0]
    cases = {
        "1": PendingCaptcha(1, "expired", 101, now - 3600, deadline=now - 3600),
        "2": PendingCaptcha(2, "future", 102, now + 30, deadline=now + 30),
        "3": PendingCaptcha(3, "setup", 0, now - 3600, phase="provisioning"),
        "4": PendingCaptcha(4, "muted-setup", 0, now + 100, phase="provisioning", restore_permissions={"can_send_messages": True}),
        "5": PendingCaptcha(5, "unban", 105, now + 300, phase="unban", retry_count=3),
        "6": PendingCaptcha(6, "release", 106, now + 100, phase="release"),
        "7": PendingCaptcha(7, "delca", 0, now + 200, phase="kick", reason="delca"),
        "8": PendingCaptcha(8, "confirmed", 0, now + 200, phase="unban", reason="confirmed-deleted"),
        "9": PendingCaptcha(9, "rejected-kick", 109, now + 200, phase="kick"),
        "10": PendingCaptcha(10, "legacy", 110, now - 100),
    }
    settings.pending_captchas = cases
    store.save()
    ctx.application.bot_data["store"] = store = SettingsStore(store.path)
    asyncio.run(initialize_captcha_session(ctx.application))
    restored = SettingsStore(store.path).chat(-123)
    assert restored.allowed_urls == ["x.com"] and restored.warning_text == "Keep me"
    assert "3" not in restored.pending_captchas
    for uid in ("1", "4", "9", "10"):
        assert restored.pending_captchas[uid].phase == "release"
        assert restored.pending_captchas[uid].expires_at == now
    for uid in ("2", "5", "6", "7", "8"):
        assert restored.pending_captchas[uid] == cases[uid]
    assert ctx.application.job_queue.run_once.call_count == 9
    ctx.bot.ban_chat_member.assert_not_awaited()
    ctx.bot.unban_chat_member.assert_not_awaited()


def test_expired_challenge_release_retries_instead_of_kicking(setup):
    store, ctx, clock = setup
    store.chat(-123).pending_captchas["42"] = PendingCaptcha(42, "test", 99, clock[0] - 86400)
    asyncio.run(initialize_captcha_session(ctx.application))
    ctx.bot.restrict_chat_member.side_effect = TimedOut()
    asyncio.run(captcha_timeout(ctx))
    reloaded = SettingsStore(store.path)
    pending = reloaded.chat(-123).pending_captchas["42"]
    assert pending.phase == "release"
    clock[0] = pending.expires_at
    ctx.application.bot_data["store"] = reloaded
    ctx.bot.restrict_chat_member.side_effect = None
    asyncio.run(captcha_timeout(ctx))
    assert not reloaded.chat(-123).pending_captchas
    assert reloaded.chat(-123).cleanup_message_ids == []
    ctx.bot.delete_message.assert_awaited_once_with(chat_id=-123, message_id=99)
    ctx.bot.ban_chat_member.assert_not_awaited()


@pytest.mark.parametrize("phase,muted", [("provisioning", False), ("provisioning", True), ("waiting", True)])
def test_delayed_work_after_outage_does_not_start_or_enforce_stale_challenge(setup, phase, muted):
    store, ctx, clock = setup
    pending = PendingCaptcha(42, "test", 99 if phase == "waiting" else 0,
        clock[0] - 300, phase=phase, joined_at=clock[0] - 3600,
        deadline=clock[0] - 300 if phase == "waiting" else 0,
        restore_permissions={"can_send_messages": True} if muted else None)
    store.chat(-123).pending_captchas["42"] = pending
    asyncio.run(captcha_timeout(ctx))
    assert not store.chat(-123).pending_captchas
    ctx.bot.send_message.assert_not_awaited()
    ctx.bot.ban_chat_member.assert_not_awaited()
    assert ctx.bot.restrict_chat_member.await_count == (1 if muted else 0)


def test_fresh_join_gets_normal_captcha_and_temporary_timeout_ban(setup):
    store, ctx, clock = setup
    asyncio.run(initialize_captcha_session(ctx.application))
    clock[0] += 1
    asyncio.run(handle_chat_member_join(join_update(-123, 42, clock[0]), ctx))
    pending = store.chat(-123).pending_captchas["42"]
    ctx.job.data["token"] = pending.token
    asyncio.run(captcha_timeout(ctx))
    assert pending.phase == "waiting" and pending.deadline == clock[0] + 60
    clock[0] += 60
    asyncio.run(captcha_timeout(ctx))
    ctx.bot.ban_chat_member.assert_awaited_once_with(chat_id=-123, user_id=42, until_date=clock[0] + 120)
    ctx.bot.unban_chat_member.assert_awaited_once()


def test_real_application_initializes_startup_policy_before_scheduling_recovery(tmp_path):
    store = SettingsStore(tmp_path / "state.json")
    store.chat(-123).pending_captchas["42"] = PendingCaptcha(42, "expired", 99, 1)
    store.save()
    app = build_application("123456:TEST_TOKEN_NOT_REAL", store.path)
    assert app.post_init is initialize_captcha_session
    assert not app.job_queue.get_jobs_by_name("captcha:-123:42")
    asyncio.run(app.post_init(app))
    assert app.bot_data["store"].chat(-123).pending_captchas["42"].phase == "release"
    assert len(app.job_queue.get_jobs_by_name("captcha:-123:42")) == 1
