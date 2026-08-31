from telegram import User

from security_bot.bot import _captcha_welcome_text
from security_bot.storage import PendingCaptcha, SettingsStore


def test_captcha_defaults_are_disabled(tmp_path):
    store = SettingsStore(tmp_path / "settings.json")

    settings = store.chat(-100123)

    assert not settings.clear_events_enabled
    assert not settings.captcha_enabled
    assert settings.captcha_timeout_seconds == 60
    assert settings.captcha_mode == "button"
    assert settings.pending_captchas == {}


def test_pending_captcha_survives_store_reload(tmp_path):
    path = tmp_path / "settings.json"
    store = SettingsStore(path)
    settings = store.chat(-100123)
    settings.pending_captchas["42"] = PendingCaptcha(
        user_id=42,
        token="verification-token",
        message_id=99,
        expires_at=1_800_000_000,
    )
    store.save()

    reloaded = SettingsStore(path).chat(-100123)

    assert reloaded.pending_captchas["42"].user_id == 42
    assert reloaded.pending_captchas["42"].token == "verification-token"
    assert reloaded.pending_captchas["42"].message_id == 99


def test_captcha_welcome_text_uses_first_name_and_configured_timeout():
    user = User(id=42, first_name="Alex", is_bot=False)

    assert _captcha_welcome_text(user, 60) == (
        "Hello Alex! Welcome to the community! Please click the button below within "
        "60 seconds to join, otherwise you will be kicked!"
    )
