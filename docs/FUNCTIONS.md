# Telegram Security Bot: Functions and Reliability Update

This guide describes the local reliability update. It has not been pushed to GitHub. Automated checks use mocked Telegram responses; they do not verify permissions or Telegram behavior in your live group.

## Settings and Compatibility

- Settings are separate for each group, keyed by its numeric chat ID. Adding the same bot to another group does not copy the first group's settings.
- All switches default to **OFF for a new group**. Existing ON/OFF values, keywords, receivers, domains, filters, warning formatting/media, and timing values are preserved.
- Defaults remain CAPTCHA **60 seconds**, warning frequency **600 seconds**, and CAPTCHA button **Tap to join!**.
- Use the same settings file when updating an existing installation. The default is `data/security-bot.json`, relative to the working directory; `SECURITY_BOT_DATA` or `--data-file` overrides it. A different path appears to be a fresh installation.
- On the first save with this version, an existing settings file is backed up alongside itself as `security-bot.json.pre-reliability.bak` (or the equivalent for a custom filename). An existing backup is never overwritten. Make an additional backup before deploying on a VPS.
- Added fields load with compatible defaults. Critical actions and settings changes are saved immediately using atomic replacement. Changed name/title metadata is flushed periodically and at graceful shutdown; an abrupt crash can lose the last few seconds of that noncritical metadata.
- Run one process per bot token, and use a separate data file for each distinct bot. Multiple processes must not write the same file. Media file IDs belong to the bot that obtained them; they are not portable between tokens.
- No automatic mass-unban is performed. Old bans without an owned recovery record still need administrator review.

## Permissions and Setup

Create a bot through BotFather `/newbot`, retain its token privately, and enable group use. Add it as an administrator with **Delete messages** and **Ban/restrict users**, plus the ability to send text and the media you configure. CAPTCHA muting requires a supergroup; use a test supergroup first.

BotFather privacy mode can be disabled with `/setprivacy` then **Disable**. The program explicitly requests membership updates and callback queries. A button failure is not fixed by enabling inline mode. All configuration, list, and scan/confirmation commands below are administrator-only in the relevant group; ordinary members can use saved-response triggers and their own CAPTCHA button. Anonymous group-admin commands are accepted when Telegram identifies the sender as that group.

In private chat, `/start` keeps the original running message and adds the admin-command list. Alert receivers should send `/start` after being configured, or again if delivery is unavailable.

## URL Restriction

| Command | Effect |
| --- | --- |
| `/url ON` / `/url OFF` | Enable/disable URL moderation. Default OFF. |
| `/addurl x.com` | Allow that domain and its subdomains. |
| `/listurl` | Show allowed domains. |
| `/delurl x.com` | Remove that allowance. |

The bot deletes blocked links in messages and captions, including links hidden behind formatted text. Checks also run on edited messages and before command/filter handlers, so putting a link after a command no longer bypasses moderation. `x.com.evil.example` is not allowed by an `x.com` entry. Decimal text such as `1.5%` and `22.3K` is not treated as a website.

Group administrators remain exempt. Posting as another channel is not an admin exemption. If Telegram cannot confirm an ordinary sender's admin status, the bot leaves that message in place and suppresses command/filter handling rather than risk deleting an admin's message. This condition is logged. URL detection is not a phishing classifier: images, QR codes, deliberately obfuscated links, and every unusual URL syntax are not covered.

## Keyword Alerts

| Command | Effect |
| --- | --- |
| `/alert ON` / `/alert OFF` | Enable/disable alerts. Default OFF. OFF also cancels queued deliveries for that group. |
| `/addreceiver @username` | Register an alert recipient. |
| `/listreceiver` | List recipients. |
| `/delreceiver @username` | Remove the recipient and their queued deliveries. |
| `/addkeyword Meta` | Add a case-insensitive display-name substring. |
| `/listkeyword` | List keywords. |
| `/delkeyword Meta` | Stop watching that keyword. |

Names are checked on joins, on observed messages, and by scanning known members. Alerts include the displayed name, `(@username)` when available, and the originating group title (numeric group ID if the title is not yet known).

Examples:

```text
Be aware Meta (@exampleuser) joined the group

Group: My Community
```

```text
Be aware, user changed its name to Meta (@exampleuser)

Group: My Community
```

Delivery is queued per receiver and survives restart. Transient failures retry with backoff; Telegram rate-limit delays are respected. A blocked/unavailable private chat is retried much less often, and a matching `/start` makes it eligible again. Unresolved recipients remain queued until their user ID is known. Once resolved, delivery stays bound to the numeric account ID; transferring a username does not transfer an existing recipient binding. To deliberately replace that account, remove and re-add the receiver.

The name scanner attempts at most five member lookups per five-second tick across alert-enabled groups. A successful lookup normally waits at least 60 seconds before another check of that member; `SECURITY_BOT_NAME_SCAN_SECONDS` changes that per-member target, with a minimum of 10 seconds. Failed lookups back off up to an hour, rate limits pause scans, and departed members are removed from the known-name cache. Large groups take longer to cycle through. Unchanged observed names no longer rewrite the entire settings file on every message.

This is not instantaneous whole-group surveillance. Telegram does not deliver a dedicated display-name-change event to this bot, and the scanner only knows users it has observed. A first-ever observed message establishes a name baseline; it is not treated as proof of a name change. A queued alert is a historical event: removing a keyword does not retract an already queued alert. Removing a receiver or turning alerts OFF cancels pending deliveries, except a request already in flight. Ambiguous network timeouts can cause a duplicate alert because Telegram has no send-message idempotency key for this workflow.

## EVM Address Restrictions

| Command | Effect |
| --- | --- |
| `/delca ON` / `/delca OFF` | Remove a newcomer whose displayed name contains an EVM-style address, including words before or after it. Default OFF. |
| `/sendca ON` / `/sendca OFF` | Delete non-admin messages/captions containing an EVM-style address. Default OFF. |

The detector recognizes `0x` followed by 40 hexadecimal characters, case-insensitively, anywhere in the text. It also blocks the confusing lookalike prefixes `Ox` and `ox` (letter O instead of zero), including uppercase X variants. These lookalikes are not valid EVM addresses; they are treated as address-like content for moderation. Both `/sendca` and `/delca` use this detection. Ordinary text such as `O instead of 0` is unaffected. The detector does not validate ownership, checksum, or whether an address is a wallet or contract. Shortened, spaced-out, or other Unicode-lookalike addresses are not covered by this change.

`/delca` takes precedence over CAPTCHA for a matching newcomer. Removal remains a **kick**, implemented as ban then unban, not a permanent blacklist. It now has durable unban recovery labeled `delca`, separate from CAPTCHA-owned actions. Turning CAPTCHA OFF does not cancel a delca recovery. A queued removal is an action already accepted by the bot; switching delca OFF does not retroactively revoke it. Admin accounts are not removed.

## CAPTCHA

| Command | Effect |
| --- | --- |
| `/captcha ON` / `/captcha OFF` | Enable/disable newcomer verification. Default OFF. |
| `/captchatime 60` | Set the verification window in seconds; minimum 10. |
| `/captchamode button` | Select the supported button mode. |

Default greeting:

```text
Hello Lev (@noregretz)! Welcome to the community! Please click the button below within 60 seconds to join, otherwise you will be kicked!
```

The greeting uses the user's first name, plus username in brackets when available. The number follows `/captchatime`. The button remains **Tap to join!**. Existing members are not retroactively challenged when CAPTCHA is enabled. New administrators and bots are exempt.

### Join and Verification

1. Save a pending setup record before making Telegram requests.
2. Record existing individual permissions, then mute the newcomer. The mute does not expire automatically at the CAPTCHA deadline, so a delayed timeout job does not create a free-chat window.
3. Send the challenge. The full verification countdown starts after Telegram confirms sending it; setup retries do not consume the newcomer's time.
4. Only that user can validate that challenge token and message. Another user's click has no effect. Old or expired buttons cannot validate a new join.
5. Save an accepted click before requesting permission restoration. If restoration fails, retry that restoration, including after restart. An accepted click is not subsequently converted into a timeout kick.
6. Restore pre-existing individual restrictions when recorded; otherwise request removal of the CAPTCHA restrictions. Group-wide permissions still apply. Verification does not promote the user to administrator. When timeout or release processing begins, retire the CAPTCHA message and immediately attempt its deletion; failed deletion stays queued for background retry.

### Timeout and Recovery

Without a valid click, the bot first records the old CAPTCHA for cleanup and attempts to delete it, then records removal recovery before requesting a **120-second temporary ban** and immediately unbans with `only_if_banned=True`. The default CAPTCHA verification window is still **60 seconds**: 120 seconds is a separate fallback ban duration, not extra time to verify or a mandatory wait before rejoining. If immediate unban succeeds, the user can rejoin without waiting for expiry.

The immediate deletion attempt has a two-second time budget and respects cleanup rate-limit/backoff state. A failed deletion does not stop removal/unban recovery; the old message ID remains saved for periodic retry, independent of the member's recovery record. Immediate cleanup and the background worker cannot issue simultaneous deletes for the same chat/message. Old buttons are invalidated even when Telegram cannot remove their messages yet. This removes the normal five-second maintenance wait, but cannot guarantee instant deletion during Telegram errors or missing permissions.

When a user rejoins while an old workflow is still finishing, the new challenge has its own token and is queued immediately after the old workflow releases that member. It no longer has to wait for the 15-second watchdog if its first job encountered that active workflow. Old cleanup operates only on the old message ID; stale timeout jobs cannot delete the new challenge. Under normal API operation, timeout cleanup completes before the kick, so a rapid rejoin does not leave the previous CAPTCHA alongside the new one.

If Telegram accepted the timed ban, it has a server-side expiry even if the bot subsequently stops or cannot unban. The expiry is calculated immediately before each removal request, after waiting for processing capacity and saving state. A definite ban rejection retries the removal stage with a fresh expiry. Telegram treats bans shorter than 30 seconds as permanent, so the 120-second duration provides a safety margin; keep the VPS clock synchronized. See [Telegram's timed-ban rules](https://core.telegram.org/bots/api#banchatmember).

The bot still checks membership after unbanning and retains recovery if Telegram reports the member banned. An ambiguous ban timeout proceeds to unban recovery so it does not deliberately repeat an uncertain removal. **Unban retries and restarts never reissue the ban or extend its expiry.** Re-entry starts a new challenge with a new token; an old recovery token cannot operate on that new challenge.

This fallback applies only to CAPTCHA timeout removals in supergroups. Delca and confirmed deleted-account removal behavior is unchanged by this addition. Existing permanent bans are not retroactively converted, and a separate later moderator ban can still prevent re-entry. A timed ban that Telegram never accepted cannot provide an expiry guarantee.

Retries begin around 10 seconds, back off up to five minutes, and honor longer Telegram rate-limit delays. Saved recovery jobs resume after restart, subject to the startup safety policy below. A watchdog checks every 15 seconds for missing jobs. At most three member workflows run concurrently; each member has separate recovery state. A busy period can delay actions beyond their scheduled time without replacing another member's recovery.

Turning CAPTCHA OFF releases outstanding setup/waiting challenges and stops starting new ones. A ban already sent still completes its unban recovery. Observed external moderator bans or permission changes cancel the bot's pending action for that member so recovery does not knowingly undo a later moderator decision. Leaving during an active challenge cancels it. Actions from another moderator during an API request, or updates lost while offline, cannot be attributed perfectly; avoid overlapping moderation bots controlling the same users.

Because muting now lasts until a release/removal action, a prolonged outage or permanently missing permissions can leave an unsolved newcomer muted until service is restored or an admin intervenes. This trades the old automatic-unmute loophole for explicit recovery. Watch the logs and do not leave a broken bot unattended.

### Offline and Startup Safety

Telegram can deliver join events queued while the bot was offline; updates can be retained for up to 24 hours. The bot checks the event's original timestamp rather than assuming its arrival means a new join. [Telegram update delivery](https://core.telegram.org/bots/api#getting-updates)

- A join dated before startup does not start a CAPTCHA. Joins in the exact startup second are also skipped conservatively because timestamps have one-second precision.
- A join event more than 120 seconds old when handled is skipped for CAPTCHA even without a process restart, covering extended disconnections and update backlogs.
- Fresh joins after startup still get the normal challenge and full configured verification window. The 120-second event-age limit is not the CAPTCHA deadline and does not change `/captchatime`.
- On startup, an expired saved waiting challenge is changed to permission restoration and cleanup, not a kick. Interrupted setup is cancelled before any new challenge is sent; if its permission snapshot was saved, restoration is queued. A saved CAPTCHA kick retry that has not reached unban recovery is also released rather than retried as a kick.
- A still-valid waiting challenge resumes with its original message and deadline. Accepted clicks and existing unban recovery remain intact, including the temporary-ban fallback. Non-CAPTCHA removal records are not changed by this policy.
- During a running session, newly recorded setup delayed more than 120 seconds from its join is cancelled/released. First-time timeout enforcement delayed more than 120 seconds beyond its challenge deadline is also released, rather than kicking someone long after the expected check. A removal already in progress retains its recovery behavior.
- The bot does not drop all pending Telegram updates. Other configured features, including keyword alerts and delca, can still process queued events. Skipping an old CAPTCHA does not exempt a member from other group rules.

This intentionally favors avoiding retroactive CAPTCHA kicks over catching every newcomer during outages or severe overload. Members who joined while the bot was stopped are not automatically verified later. Release requests can themselves need retries if Telegram is unavailable or permissions are missing. Keep the host clock synchronized. Existing permanent bans without a recovery record still require administrator review.

## Suspected Deleted Accounts

| Command | Effect |
| --- | --- |
| `/scandelacc` | Start a background scan of known members. Report suspects without automatically removing them. |
| `/confirmdelacc 123456789` | Confirm removal of a numeric user ID reported by the current scan. |

**Intentional behavior change:** a display name of `Deleted Account` is not proof that the account was deleted. The bot reports matching names with no last name or username; an administrator reviews and confirms each one. Confirmation rechecks membership and the suspect name, then queues a kick with durable recovery labeled `confirmed-deleted`. Administrators are excluded.

The scan works in batches of five every five seconds, leaving normal update processing available. One scan runs per group. Scan progress and confirmation candidates are in memory; after a restart, run the scan again. Confirmed removal actions themselves are saved and recovered. This bot cannot enumerate the complete group member list or reliably identify every deleted account through the Bot API.

## Scheduled Warnings

| Command | Effect |
| --- | --- |
| `/warningmsg ON` / `/warningmsg OFF` | Enable/disable scheduled warnings. Default OFF. |
| `/warningtxt message` | Set text, preserving newlines and supported Telegram formatting entities. |
| `/warningfreq 600` | Set interval in seconds; minimum 10, default 600. |
| `/warnmedia` | Reply to a photo, GIF/animation, video, or supported image/video document to attach it. |

The first warning follows the configured interval after enabling/restarting. At each due send, delete the previous warning first, then post the replacement. Failed deletion retains its message ID and blocks replacement; it is not silently forgotten. A confirmed "message not found" is treated as already deleted. Failures and rate limits delay retries; overlapping sends for the same group are suppressed.

Formatting uses Telegram entities, not literal Markdown parsing: format the text in the Telegram composer. With media attached, warning text must fit the 1024-unit caption guard (UTF-16; some emoji count twice). Oversized edits/media attachments are rejected without changing the previous configuration. An existing oversized caption is preserved but will not send until shortened. Text-only warnings retain Telegram's normal message-size limit.

OFF stops future sends but leaves the last posted warning in place. Telegram deletion restrictions, removed permissions, or messages that have become too old can block replacement; delete the previous warning manually and restore permissions as needed. A crash or ambiguous send timeout after Telegram accepts a message but before its ID is saved can still leave an untracked duplicate.

## Saved Responses

| Command | Effect |
| --- | --- |
| `/setfilter CA` | Reply to an answer message to save it under that trigger. |
| `/listfilter` | Show saved triggers. |
| `/delfilter CA` | Remove a saved answer. |

Exact case-insensitive `CA` and `/CA` trigger the same answer; `/CA@ThisBotsUsername` also works. `/CA extra` is not an exact match, and commands addressed to a different bot are ignored. Built-in admin commands take precedence over filters of the same name. Text, supported formatting, and photo/GIF/video/image-video-document media are retained. The response is sent by the bot; URL/EVM restrictions apply to the member's trigger message, not the admin-configured answer.

There is no filter ON/OFF switch. Delete a filter to stop it. Members with pending CAPTCHA verification cannot use a trigger to bypass moderation. Failed response sends are logged but are not durably replayed later, to avoid unsolicited stale replies.

## Join/Leave Service Messages

`/clearevents ON` removes join/leave/removal notices delivered by Telegram; `/clearevents OFF` stops doing so. Default OFF. CAPTCHA membership handling uses separate membership updates, so removing a service notice does not disable verification. Failed deletions are queued for retry. This does not clear old group history or every type of Telegram system message.

## Operational Limits and Logging

HTTP request chatter is suppressed, and bot-token-shaped credentials are redacted from formatted logs, including exceptions. Keep the token private anyway; redaction does not revoke previously exposed tokens. Errors include chat/user/message IDs where useful without dumping entire incoming updates.

This update improves recoverability and reduces unnecessary work; it cannot promise flawless behavior in every case. Telegram outages, API limits, disk failures, revoked permissions, multiple running instances, dropped updates, and another moderator's concurrent actions remain external failure conditions. Delivery and cleanup queues persist, but the bot cannot guarantee exactly-once effects after ambiguous network failures. Queues and the JSON data file can grow if failures remain unresolved; monitor disk space and recurring warnings.

The Telegram platform constraints above follow its [Bot API documentation](https://core.telegram.org/bots/api): [restriction restoration](https://core.telegram.org/bots/api#restrictchatmember), [unban semantics](https://core.telegram.org/bots/api#unbanchatmember), [user fields](https://core.telegram.org/bots/api#user), and [message deletion limits](https://core.telegram.org/bots/api#deletemessage).

## Local Start and Test Checklist

Use a separate test bot token while the production token runs on the VPS. Do not run a second polling instance with that production token.

```powershell
cd C:\Dev\projects\ai-app
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
$env:TELEGRAM_BOT_TOKEN = "YOUR_TEST_BOT_TOKEN"
telegram-security-bot --data-file "C:\Dev\projects\ai-app\data\security-bot.json"
```

The example explicitly uses the usual existing local data file. For a distinct test bot/environment, use a different filename; it intentionally starts with fresh settings. Do not paste PowerShell prompt text such as `PS C:\...>` or `(.venv)` as commands. Stop with Ctrl+C before editing/updating an installation.

Run offline automated tests in a second terminal:

```powershell
cd C:\Dev\projects\ai-app
.\.venv\Scripts\python.exe -m pytest -q
```

| Local Telegram test | Expected result |
| --- | --- |
| Check existing group settings after restart | Existing switches/lists/text/media/timers remain; a new group has all switches OFF. |
| Try each configuration command as a regular member | No setting change; admin-only response. |
| Enable URL blocking; send blocked link, hidden text link, and link after `/start` | Each member message deleted; admin links allowed; `1.5%` and `22.3K` retained. |
| Set a CA response; send `CA`, `/CA`, then `/CA extra` | First two reply; third does not. |
| Enable alerts in two test groups; join/rename to a keyword | Correct name, username, and source group in each private alert. |
| Set formatted multiline warning plus GIF and short test interval | Formatting retained; only the latest tracked warning remains after each cycle. |
| Remove Delete messages permission while a warning exists | No accumulating replacement warnings; restore permission and verify recovery. |
| Join, click someone else's CAPTCHA, then click your own | Other click rejected; correct click accepted; permissions restored and CAPTCHA cleaned up. |
| Ignore CAPTCHA, rejoin repeatedly, and test several accounts joining together | Kick/unban recovery completes independently; every rejoin gets a fresh challenge. |
| In a controlled test, interrupt unban recovery after Telegram accepts a CAPTCHA timed ban | The server-side ban expiry should permit re-entry after about 120 seconds from the ban request, even while the bot is stopped. Restart the bot before testing the next challenge. |
| Stop the bot, join with another account, then start it | The offline join does not produce a CAPTCHA or CAPTCHA removal; fresh joins after startup still do. |
| Restart after an unsolved challenge's deadline passed | Old challenge is cleaned up and CAPTCHA restrictions are released, not timeout-kicked. |
| Restart before an unsolved challenge's deadline / immediately after accepted click | Still-valid challenge retains its deadline; accepted release resumes without resetting acceptance. |
| Turn CAPTCHA OFF while a user is waiting | They are released, not timeout-kicked. |
| Explicitly ban a waiting user as an admin | Observed moderator ban remains; bot recovery is cancelled. |
| Join with words plus a full EVM address while delca ON | Kick/recovery occurs even if CAPTCHA is OFF. |
| Run `/scandelacc` on a test account named Deleted Account | It is reported, not removed, until an admin confirms its reported ID. |
| Enable clearevents and repeat join/leave tests | Delivered membership notices are removed without affecting CAPTCHA. |

The temporary-ban regression tests also simulate 100 newcomers across two groups, mixed valid clicks and timeouts, duplicate callbacks, rate-limit rejection, failed unban, rejoining with old recovery still recorded, and process restart. These are offline simulations, not a measured Telegram throughput guarantee. During sustained overload, actions can be delayed; monitor the VPS and Telegram errors.

Startup regression tests additionally cover 100 replayed offline joins followed by 50 fresh joins across two groups, startup-second boundaries, disconnection without restart, expired challenge release failures, and preservation of settings and unrelated recoveries.

Cleanup regression tests verify deletion before timeout removal, recovery despite slow/failed deletion, cleanup persistence across restart, simultaneous maintenance, and a rejoin while the old unban response is still in flight. The old button and late timeout cannot operate on the replacement challenge.

Do not use actual funds, sensitive documents, or production-only accounts in tests. Review logs for repeated recovery failures before deploying. The code, docs, and tests remain local until you explicitly request a push.
