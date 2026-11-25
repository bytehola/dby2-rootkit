from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable


IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_PATTERN = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
ADB_PUBLIC_KEY_PATTERN = re.compile(r"\bAAAA[A-Za-z0-9+/=]{40,}\b")
HOME_PATTERN = re.compile(r"/(?:home|Users)/[^/\s]+")
WINDOWS_HOME_PATTERN = re.compile(r"[A-Za-z]:\\Users\\[^\\\s]+")


def stable_hash(value: str, length: int = 12) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest[:length]


def redact_text(
    text: str,
    secrets: Iterable[str] = (),
    preserved_values: Iterable[str] = (),
) -> str:
    redacted_text = text
    preserved_replacements: dict[str, str] = {}

    for preserved_index, preserved_value in enumerate(
        sorted(
            {value for value in preserved_values if value},
            key=len,
            reverse=True,
        )
    ):
        if preserved_value not in redacted_text:
            continue
        placeholder = f"__DBY2_PRESERVED_{preserved_index}__"
        redacted_text = redacted_text.replace(preserved_value, placeholder)
        preserved_replacements[placeholder] = preserved_value

    for secret in sorted(set(secrets), key=len, reverse=True):
        if secret:
            redacted_text = redacted_text.replace(secret, "<redacted>")

    redacted_text = IPV4_PATTERN.sub("<ip>", redacted_text)
    redacted_text = MAC_PATTERN.sub("<mac>", redacted_text)
    redacted_text = ADB_PUBLIC_KEY_PATTERN.sub("<adb-public-key>", redacted_text)
    redacted_text = HOME_PATTERN.sub("<home>", redacted_text)
    redacted_text = WINDOWS_HOME_PATTERN.sub("<home>", redacted_text)

    for placeholder, preserved_value in preserved_replacements.items():
        redacted_text = redacted_text.replace(placeholder, preserved_value)

    return redacted_text
