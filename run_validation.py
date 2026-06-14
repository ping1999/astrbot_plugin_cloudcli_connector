from __future__ import annotations


def has_control_chars(value: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def is_index_session_ref(value: str) -> bool:
    ref = value.strip().lower()
    return ref in {"last", "latest"} or ref.isdigit()


def looks_like_github_url(value: str) -> bool:
    if has_control_chars(value) or len(value) > 500:
        return False
    return (
        value.startswith("https://github.com/")
        or value.startswith("git@github.com:")
    )


def is_safe_short_value(value: str, max_len: int) -> bool:
    if not value or len(value) > max_len or has_control_chars(value):
        return False
    return not any(char.isspace() for char in value)


def is_safe_git_branch_name(value: str) -> bool:
    if not is_safe_short_value(value, 120):
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
    return True
