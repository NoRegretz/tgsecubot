import logging
import re


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        return re.sub(r"(?<!\d)\d{5,}:[A-Za-z0-9_-]{20,}", "[TOKEN REDACTED]", rendered)


def configure_logging(level: str) -> None:
    logging.basicConfig(level=level)
    for handler in logging.getLogger().handlers:
        handler.setFormatter(RedactingFormatter("%(asctime)s %(levelname)s:%(name)s:%(message)s"))
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
