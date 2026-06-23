"""`/cloudcli run` 参数的安全校验。"""

from __future__ import annotations

import re
from urllib.parse import urlsplit


_GITHUB_REPO_PATH_RE = re.compile(r"^/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?$")
_GITHUB_SSH_RE = re.compile(r"^git@github\.com:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?$")
_MODEL_NAME_RE = re.compile(r"^[A-Za-z0-9._:-]+$")
_BRANCH_SAFE_CHARS_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


def has_control_chars(value: str) -> bool:
    """控制字符不应进入路径、URL、模型名或分支名。"""
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def is_index_session_ref(value: str) -> bool:
    """判断用户输入是否是最近 session 序号引用。"""
    ref = value.strip().lower()
    return ref in {"last", "latest"} or ref.isdigit()


def looks_like_github_url(value: str) -> bool:
    """只允许 github.com 标准仓库 URL，拒绝 query/fragment 和空白字符。"""
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
    """通用短值校验：非空、不超长、无控制字符、无空白。"""
    if not value or len(value) > max_len or has_control_chars(value):
        return False
    return not any(char.isspace() for char in value)


def is_safe_model_name(value: str) -> bool:
    """模型名只允许常见模型 ID 字符，避免把任意 shell-like 文本传下去。"""
    if not is_safe_short_value(value, 120):
        return False
    return bool(_MODEL_NAME_RE.fullmatch(value))


def is_safe_git_branch_name(value: str) -> bool:
    """按 Git refname 的常见危险规则校验分支名。"""
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
