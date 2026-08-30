from security_bot.bot import _filter_key


def test_filter_key_accepts_plain_text_and_slash_commands():
    assert _filter_key("CA") == "ca"
    assert _filter_key("ca") == "ca"
    assert _filter_key("/CA") == "ca"
    assert _filter_key("/CA@SecurityBot") == "ca"
