import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from unittest.mock import patch
import time
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from telegram.error import RetryAfter, TimedOut

from security_bot.bot import captcha_timeout, _schedule_all_captcha_timeouts
from security_bot.bot import _has_pending_captcha, handle_chat_member_join
from security_bot.bot import (
    CAPTCHA_MAX_CONCURRENT_RECOVERIES,
    _schedule_captcha_timeout,
    recover_missing_captcha_jobs,
)
from security_bot.storage import PendingCaptcha, SettingsStore


def context_for(store):
    for settings in store.chats().values():
        settings.captcha_enabled = True
    queue = Mock()
    queue.get_jobs_by_name.return_value = []
    return SimpleNamespace(
        application=SimpleNamespace(bot_data={"store": store}, job_queue=queue),
        bot=SimpleNamespace(
            id=999,
            ban_chat_member=AsyncMock(), unban_chat_member=AsyncMock(), delete_message=AsyncMock(),
            restrict_chat_member=AsyncMock(),
            get_chat_member=AsyncMock(return_value=SimpleNamespace(status="member")),
        ),
        job=SimpleNamespace(data={"chat_id": -123, "user_id": 42, "token": "test"}),
    )


def test_failed_unban_survives_restart_without_rebanning(tmp_path):
    store = SettingsStore(tmp_path / "state.json")
    store.chat(-123).pending_captchas["42"] = PendingCaptcha(42, "test", 99, 0)
    context = context_for(store)
    context.bot.unban_chat_member.side_effect = TimedOut()
    asyncio.run(captcha_timeout(context))
    reloaded = SettingsStore(store.path)
    pending = reloaded.chat(-123).pending_captchas["42"]
    assert pending.phase == "unban"
    assert pending.retry_count == 1
    restarted = context_for(reloaded)
    _schedule_all_captcha_timeouts(restarted.application)
    restarted.application.job_queue.run_once.assert_called_once()
    pending.expires_at = 0
    asyncio.run(captcha_timeout(restarted))
    restarted.bot.ban_chat_member.assert_not_awaited()
    restarted.bot.unban_chat_member.assert_awaited_once_with(chat_id=-123, user_id=42, only_if_banned=True)
    assert not SettingsStore(store.path).chat(-123).pending_captchas


def test_record_exists_before_ban_and_ambiguous_ban_is_unbanned(tmp_path):
    store = SettingsStore(tmp_path / "state.json")
    store.chat(-123).pending_captchas["42"] = PendingCaptcha(42, "test", 99, 0)
    context = context_for(store)

    async def uncertain_ban(**kwargs):
        assert SettingsStore(store.path).chat(-123).pending_captchas["42"].phase == "unban"
        raise TimedOut()

    context.bot.ban_chat_member.side_effect = uncertain_ban
    asyncio.run(captcha_timeout(context))
    context.bot.unban_chat_member.assert_awaited_once()
    assert not store.chat(-123).pending_captchas


def test_rate_limit_delay_is_respected(tmp_path):
    store = SettingsStore(tmp_path / "state.json")
    store.chat(-123).pending_captchas["42"] = PendingCaptcha(42, "test", 99, 0, phase="unban")
    context = context_for(store)
    context.bot.unban_chat_member.side_effect = RetryAfter(600)
    asyncio.run(captcha_timeout(context))
    assert context.application.job_queue.run_once.call_args.kwargs["when"] >= 600


def test_timeout_does_not_kick_while_verification_is_running(tmp_path):
    store = SettingsStore(tmp_path / "state.json")
    store.chat(-123).pending_captchas["42"] = PendingCaptcha(42, "test", 99, 0, phase="verifying")
    context = context_for(store)
    asyncio.run(captcha_timeout(context))
    context.bot.ban_chat_member.assert_not_awaited()


def test_successful_unban_response_but_still_banned_keeps_recovery(tmp_path):
    store = SettingsStore(tmp_path / "state.json")
    pending = PendingCaptcha(42, "test", 99, 0, phase="unban")
    store.chat(-123).pending_captchas["42"] = pending
    context = context_for(store)
    context.bot.get_chat_member.return_value.status = "kicked"
    asyncio.run(captcha_timeout(context))
    assert SettingsStore(store.path).chat(-123).pending_captchas["42"].retry_count == 1
    context.bot.ban_chat_member.assert_not_awaited()
    pending.expires_at = 0
    context.bot.get_chat_member.return_value.status = "left"
    asyncio.run(captcha_timeout(context))
    assert not SettingsStore(store.path).chat(-123).pending_captchas


def test_status_check_failure_keeps_recovery(tmp_path):
    store = SettingsStore(tmp_path / "state.json")
    store.chat(-123).pending_captchas["42"] = PendingCaptcha(42, "test", 99, 0, phase="unban")
    context = context_for(store)
    context.bot.get_chat_member.side_effect = TimedOut()
    asyncio.run(captcha_timeout(context))
    assert SettingsStore(store.path).chat(-123).pending_captchas["42"].phase == "unban"


def test_recovery_does_not_count_as_active_challenge(tmp_path):
    store = SettingsStore(tmp_path / "state.json")
    store.chat(-123).pending_captchas["42"] = PendingCaptcha(42, "test", 99, int(time.time()) + 300, phase="unban")
    assert not _has_pending_captcha(context_for(store), -123, 42)


def test_old_retry_does_not_delete_new_challenge(tmp_path):
    store = SettingsStore(tmp_path / "state.json")
    store.chat(-123).pending_captchas["42"] = PendingCaptcha(42, "old", 99, 0, phase="unban")
    context = context_for(store)
    context.job.data["token"] = "old"
    fresh = PendingCaptcha(42, "new", 100, int(time.time()) + 60)

    async def rejoin_during_request(**kwargs):
        store.chat(-123).pending_captchas["42"] = fresh
        store.save()
        return SimpleNamespace(status="member")

    context.bot.get_chat_member.side_effect = rejoin_during_request
    asyncio.run(captcha_timeout(context))
    assert SettingsStore(store.path).chat(-123).pending_captchas["42"].token == "new"


def test_restricted_nonmember_rejoin_triggers_join_handler(tmp_path):
    update = SimpleNamespace(effective_chat=SimpleNamespace(id=-123), chat_member=SimpleNamespace(
        from_user=SimpleNamespace(id=42),
        old_chat_member=SimpleNamespace(status="restricted", is_member=False),
        new_chat_member=SimpleNamespace(status="restricted", is_member=True, user=SimpleNamespace(id=42)),
    ))
    with patch("security_bot.bot._handle_joined_user", new_callable=AsyncMock) as handler:
        asyncio.run(handle_chat_member_join(update, context_for(SettingsStore(tmp_path / "state.json"))))
        handler.assert_awaited_once()


def test_watchdog_restores_missing_jobs_without_shortening_backoff(tmp_path):
    store = SettingsStore(tmp_path / "state.json")
    now = int(time.time())
    store.chat(-123).pending_captchas.update({
        "1": PendingCaptcha(1, "missing", 91, 0, phase="unban"),
        "2": PendingCaptcha(2, "future", 92, now + 600, phase="unban"),
        "3": PendingCaptcha(3, "scheduled", 93, 0),
        "4": PendingCaptcha(4, "active", 94, 0),
    })
    context = context_for(store)
    context.application.bot_data["captcha_active"] = {(-123, 4)}
    queue = context.application.job_queue
    scheduled = SimpleNamespace(removed=False, data={"token": "scheduled"})
    queue.get_jobs_by_name.side_effect = lambda name: [scheduled] if name.endswith(":3") else []
    asyncio.run(recover_missing_captcha_jobs(context))
    calls = queue.run_once.call_args_list
    assert [call.kwargs["data"]["user_id"] for call in calls] == [1, 2]
    assert calls[0].kwargs["when"] == 0
    assert calls[1].kwargs["when"] >= 599


def test_overdue_job_runs_with_captcha_scheduler_policy(tmp_path):
    async def scenario():
        context = context_for(SettingsStore(tmp_path / "state.json"))
        _schedule_captcha_timeout(context, -123, 42, "test", 0)
        options = context.application.job_queue.run_once.call_args.kwargs["job_kwargs"]
        scheduler = AsyncIOScheduler()
        finished = asyncio.Event()

        async def callback():
            finished.set()

        scheduler.add_job(callback, "date", run_date=datetime.now(timezone.utc) - timedelta(seconds=30), **options)
        scheduler.start()
        try:
            await asyncio.wait_for(finished.wait(), timeout=2)
        finally:
            scheduler.shutdown()

    asyncio.run(scenario())


def test_burst_retries_are_independent_bounded_and_survive_restart(tmp_path):
    async def scenario():
        store = SettingsStore(tmp_path / "state.json")
        targets = [(chat, user) for chat in (-123, -456) for user in range(15)]
        for chat, user in targets:
            store.chat(chat).pending_captchas[str(user)] = PendingCaptcha(user, f"token-{user}", 100 + user, 0)
        context = context_for(store)
        live = 0
        peak = 0
        started = asyncio.Event()
        release = asyncio.Event()

        async def failed_unban(**kwargs):
            nonlocal live, peak
            live += 1
            peak = max(peak, live)
            if live == CAPTCHA_MAX_CONCURRENT_RECOVERIES:
                started.set()
            await release.wait()
            await asyncio.sleep(0)
            live -= 1
            raise TimedOut()

        context.bot.unban_chat_member.side_effect = failed_unban

        def for_member(base, chat, user):
            return SimpleNamespace(
                application=base.application, bot=base.bot,
                job=SimpleNamespace(data={"chat_id": chat, "user_id": user, "token": f"token-{user}"}),
            )

        tasks = [asyncio.create_task(captcha_timeout(for_member(context, chat, user))) for chat, user in targets]
        try:
            await asyncio.wait_for(started.wait(), timeout=2)
            # Even concurrent duplicate callbacks and watchdog scans cannot run a second removal.
            await asyncio.gather(*(captcha_timeout(for_member(context, chat, user)) for chat, user in targets))
            await recover_missing_captcha_jobs(context)
            context.application.job_queue.run_once.assert_not_called()
        finally:
            release.set()
            await asyncio.gather(*tasks)
        assert peak == CAPTCHA_MAX_CONCURRENT_RECOVERIES
        assert context.bot.ban_chat_member.await_count == len(targets)
        assert context.bot.unban_chat_member.await_count == len(targets)
        calls = context.application.job_queue.run_once.call_args_list
        assert len({call.kwargs["name"] for call in calls}) == len(targets)
        assert not context.application.bot_data["captcha_active"]

        restarted_store = SettingsStore(store.path)
        for settings in restarted_store.chats().values():
            assert len(settings.pending_captchas) == 15
            for pending in settings.pending_captchas.values():
                assert pending.phase == "unban"
                pending.expires_at = 0
        restarted = context_for(restarted_store)
        _schedule_all_captcha_timeouts(restarted.application)
        assert restarted.application.job_queue.run_once.call_count == len(targets)
        await asyncio.gather(*(captcha_timeout(for_member(restarted, chat, user)) for chat, user in targets))
        restarted.bot.ban_chat_member.assert_not_awaited()
        assert restarted.bot.unban_chat_member.await_count == len(targets)
        assert all(not settings.pending_captchas for settings in SettingsStore(store.path).chats().values())

    asyncio.run(scenario())
