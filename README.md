# Telegram Security Bot

Telegram group moderation bot with admin-controlled URL blocking, keyword alerts, and EVM address detection.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
$env:TELEGRAM_BOT_TOKEN = "123456:bot-token"
telegram-security-bot
```

The bot stores group settings in `data/security-bot.json` by default. Override it with `SECURITY_BOT_DATA` or `--data-file`.

## Telegram Permissions

Add the bot to your group as an admin. It needs permission to delete messages and ban users.

For private alerts, each recipient must open the bot in Telegram and send `/start` once. Telegram does not let bots initiate private chats with users who have never started them.

## Admin Commands

- `/url ON|OFF` enables or disables URL restriction. Default: OFF.
- `/addurl example.com` allows a domain and its subdomains.
- `/listurl` lists allowed URL domains.
- `/delurl example.com` removes an allowed domain.
- `/alert ON|OFF` enables or disables keyword alerts. Default: OFF.
- `/addreceiver @username` adds an alert recipient.
- `/listreceiver` lists alert recipients.
- `/delreceiver @username` removes an alert recipient.
- `/addkeyword Meta` adds a watched keyword.
- `/listkeyword` lists watched keywords.
- `/delkeyword Meta` removes a watched keyword.
- `/scandelacc` scans known group members and removes deleted Telegram accounts.
- `/delca ON|OFF` removes users when they join with an EVM-like address in their displayed name. Default: OFF.
- `/sendca ON|OFF` deletes messages containing EVM-like addresses. Default: OFF.
- `/warningmsg ON|OFF` enables or disables scheduled warning messages. Default: OFF.
- `/warningtxt message` sets the warning message text.
- `/warningfreq seconds` sets how often the warning is sent. Default: 600 seconds.
- `/warnmedia` adds media to warning messages by replying to an image, GIF, or video.
- `/setfilter keyword` saves an exact-match auto-response by replying to a message.
- `/listfilter` lists saved auto-response filters.
- `/delfilter keyword` deletes a saved auto-response filter.

Group admins are always allowed to send URLs. Only group admins can change bot settings.

Keyword alerts trigger on joins, on messages from a user whose display name changed, and on a periodic scan of users the bot has already seen in the group. The scan interval defaults to 60 seconds and can be changed with `SECURITY_BOT_NAME_SCAN_SECONDS`.

`/scandelacc` can only scan users the bot already knows from joins or messages. Telegram Bot API does not provide bots with a full group member list.

For `/warnmedia`, first send the image, GIF, or video in the group, then reply to that media message with `/warnmedia`. Telegram file IDs are stored, not downloaded media files.

Before each scheduled warning is posted, the bot deletes the previous warning message it sent in that group.

`/warningtxt` preserves new lines and Telegram text formatting such as bold, italic, links, and code. For multi-line warnings, send the command like this:

```text
/warningtxt First line
Second line
Third line
```

Filters work like simple Rose-style saved answers. Send the answer message first, then reply to it with:

```text
/setfilter CA
```

After that, when someone sends exactly `CA`, `ca`, `Ca`, or `/CA`, the bot replies with the saved answer. Filter setup is admin-only. Saved filter answers preserve text formatting and supported media.
