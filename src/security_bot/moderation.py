from __future__ import annotations

from dataclasses import dataclass
from html import escape
import re
from typing import Iterable
from urllib.parse import urlparse


# Treat letter-O prefixes as address lookalikes, not as valid on-chain addresses.
EVM_ADDRESS_RE = re.compile(r"(?i)[0o]x[a-f0-9]{40}")
URL_RE = re.compile(
    r"(?i)\b((?:https?://|www\.)[^\s<>()]+|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z][a-z0-9-]{1,62}(?:/[^\s<>()]*)?)"
)


@dataclass(frozen=True)
class FoundUrl:
    raw: str
    host: str


def display_name(first_name: str | None, last_name: str | None = None, username: str | None = None) -> str:
    name = " ".join(part for part in (first_name, last_name) if part).strip()
    if name:
        return name
    if username:
        return f"@{username}"
    return "Unknown user"


def escape_html(value: str) -> str:
    return escape(value, quote=False)


def normalize_domain(value: str) -> str:
    candidate = value.strip().lower()
    if not candidate:
        raise ValueError("domain cannot be empty")
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").strip(".").lower()
    if not host or "." not in host:
        raise ValueError("domain must look like example.com")
    if host.startswith("www."):
        host = host[4:]
    return host


def host_allowed(host: str, allowed_domains: Iterable[str]) -> bool:
    normalized_host = normalize_domain(host)
    for allowed in allowed_domains:
        normalized_allowed = normalize_domain(allowed)
        if normalized_host == normalized_allowed or normalized_host.endswith(f".{normalized_allowed}"):
            return True
    return False


def extract_urls(text: str) -> list[FoundUrl]:
    found: list[FoundUrl] = []
    for match in URL_RE.finditer(text):
        raw = match.group(1).rstrip(".,;:!?)]}")
        candidate = raw if "://" in raw else f"https://{raw}"
        try:
            parsed = urlparse(candidate)
            host = (parsed.hostname or "").lower()
        except ValueError:
            continue
        if host and "." in host:
            if host.startswith("www."):
                host = host[4:]
            found.append(FoundUrl(raw=raw, host=host))
    return found


def contains_blocked_url(text: str, allowed_domains: Iterable[str]) -> bool:
    return any(not host_allowed(found.host, allowed_domains) for found in extract_urls(text))


def message_contains_blocked_url(message, allowed_domains: Iterable[str]) -> bool:
    text = message.text or message.caption or ""
    if contains_blocked_url(text, allowed_domains):
        return True
    for entity in tuple(message.entities or ()) + tuple(message.caption_entities or ()):
        if entity.type != "text_link" or not entity.url:
            continue
        try:
            host = urlparse(entity.url).hostname
            if not host or not host_allowed(host, allowed_domains):
                return True
        except ValueError:
            return True
    return False


def contains_evm_address(text: str) -> bool:
    return bool(EVM_ADDRESS_RE.search(text))


def name_matches_keywords(name: str, keywords: Iterable[str]) -> bool:
    lowered = name.casefold()
    return any(keyword.casefold() in lowered for keyword in keywords if keyword)
