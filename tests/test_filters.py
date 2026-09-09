from security_bot.bot import _alert_with_group, _filter_key


def test_filter_key_accepts_plain_text_and_slash_commands():
    assert _filter_key("CA") == "ca"
    assert _filter_key("ca") == "ca"
    assert _filter_key("/CA") == "ca"
    assert _filter_key("/CA@SecurityBot") == "ca"


def test_alert_includes_escaped_group_title():
    assert _alert_with_group("Be aware User joined the group", "Meta <Official>") == (
        "Be aware User joined the group\n\nGroup: <b>Meta &lt;Official&gt;</b>"
    )
