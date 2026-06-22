from __future__ import annotations

import re
from urllib.parse import urlsplit


_GITHUB_REPO_PATH_RE = re.compile(r"^/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?$")
_GITHUB_SSH_RE = re.compile(r"^git@github\.com:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?$")
_MODEL_NAME_RE = re.compile(r"^[A-Za-z0-9._:-]+$")
_BRANCH_SAFE_CHARS_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


def has_control_chars(value: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def is_index_session_ref(value: str) -> bool:
    ref = value.strip().lower()
    return ref in {"last", "latest"} or ref.isdigit()


def looks_like_github_url(value: str) -> bool:
    if has_control_chars(value) or len(value) > 500:
        return False
    if any(char.isspace() for char in value):
        return False
    if _GITHUB_SSH_RE.fullmatch(value):
        return True
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        return False
    if parsed.query or parsed.fragment:
        return False
    return bool(_GITHUB_REPO_PATH_RE.fullmatch(parsed.path))


def is_safe_short_value(value: str, max_len: int) -> bool:
    if not value or len(value) > max_len or has_control_chars(value):
        return False
    return not any(char.isspace() for char in value)


def is_safe_model_name(value: str) -> bool:
    if not is_safe_short_value(value, 120):
        return False
    return bool(_MODEL_NAME_RE.fullmatch(value))


def is_safe_git_branch_name(value: str) -> bool:
    if not is_safe_short_value(value, 120):
        return False
    if not _BRANCH_SAFE_CHARS_RE.fullmatch(value):
        return False
    forbidden_chars = set("~^:?*[\\")
    if any(char in forbidden_chars for char in value):
        return False
    if (
        value.startswith("-")
        or value.startswith("/")
        or value.endswith("/")
        or value.endswith(".")
        or value.endswith(".lock")
        or ".." in value
        or "//" in value
        or "@{" in value
        or value == "@"
    ):
        return False
    for component in value.split("/"):
        if not component or component.startswith(".") or component.endswith(".lock"):
            return False
    return True
