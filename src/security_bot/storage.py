from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
import tempfile
from threading import RLock
from typing import Any


@dataclass
class Recipient:
    username: str
    user_id: int | None = None


@dataclass
class SavedFilter:
    keyword: str
    text: str = ""
    entities: list[dict[str, object]] = field(default_factory=list)
    media_type: str | None = None
    media_file_id: str | None = None


@dataclass
class ChatSettings:
    url_enabled: bool = False
    alert_enabled: bool = False
    delca_enabled: bool = False
    sendca_enabled: bool = False
    warning_enabled: bool = False
    warning_text: str = ""
    warning_entities: list[dict[str, object]] = field(default_factory=list)
    warning_freq_seconds: int = 600
    warning_media_type: str | None = None
    warning_media_file_id: str | None = None
    warning_message_ids: list[int] = field(default_factory=list)
    allowed_urls: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    recipients: dict[str, Recipient] = field(default_factory=dict)
    filters: dict[str, SavedFilter] = field(default_factory=dict)
    known_names: dict[str, str] = field(default_factory=dict)


class SettingsStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = RLock()
        self._data: dict[str, ChatSettings] = {}
        self._load()

    def chat(self, chat_id: int) -> ChatSettings:
        key = str(chat_id)
        with self._lock:
            if key not in self._data:
                self._data[key] = ChatSettings()
                self.save()
            return self._data[key]

    def chats(self) -> dict[int, ChatSettings]:
        with self._lock:
            return {int(chat_id): settings for chat_id, settings in self._data.items()}

    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = {chat_id: asdict(settings) for chat_id, settings in self._data.items()}
            with tempfile.NamedTemporaryFile("w", delete=False, dir=self.path.parent, encoding="utf-8") as tmp:
                json.dump(payload, tmp, indent=2, sort_keys=True)
                tmp.write("\n")
                tmp_path = Path(tmp.name)
            tmp_path.replace(self.path)

    def _load(self) -> None:
        if not self.path.exists():
            return
        raw: dict[str, Any] = json.loads(self.path.read_text(encoding="utf-8"))
        for chat_id, value in raw.items():
            recipients = {
                username: Recipient(**recipient)
                for username, recipient in value.get("recipients", {}).items()
            }
            saved_filters = {
                keyword: SavedFilter(**saved_filter)
                for keyword, saved_filter in value.get("filters", {}).items()
            }
            self._data[chat_id] = ChatSettings(
                url_enabled=bool(value.get("url_enabled", False)),
                alert_enabled=bool(value.get("alert_enabled", False)),
                delca_enabled=bool(value.get("delca_enabled", False)),
                sendca_enabled=bool(value.get("sendca_enabled", False)),
                warning_enabled=bool(value.get("warning_enabled", False)),
                warning_text=str(value.get("warning_text", "")),
                warning_entities=list(value.get("warning_entities", [])),
                warning_freq_seconds=int(value.get("warning_freq_seconds", 600)),
                warning_media_type=value.get("warning_media_type"),
                warning_media_file_id=value.get("warning_media_file_id"),
                warning_message_ids=[int(message_id) for message_id in value.get("warning_message_ids", [])],
                allowed_urls=list(value.get("allowed_urls", [])),
                keywords=list(value.get("keywords", [])),
                recipients=recipients,
                filters=saved_filters,
                known_names=dict(value.get("known_names", {})),
            )
