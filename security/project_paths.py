"""本地项目路径授权策略。"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    from ..core.config import ConnectorSettings
    from ..persistence.state_models import UserRef
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from core.config import ConnectorSettings
    from persistence.state_models import UserRef


@dataclass(frozen=True)
class ProjectPathDecision:
    """本地项目路径授权结果；path 是解析后的绝对路径。"""

    allowed: bool
    path: str = ""
    message: str = ""


class ProjectPathPolicy:
    """校验 `/cloudcli run --project` 可访问的本地路径范围。"""

    def __init__(self, settings: ConnectorSettings) -> None:
        self.settings = settings

    def authorize(self, user: UserRef, project_path: str) -> ProjectPathDecision:
        """先做配置级早拒绝，再解析路径，避免拒绝路径触发文件系统探测。"""
        if not project_path:
            return ProjectPathDecision(True, "")

        roots = self.settings.allowed_project_roots
        if not roots:
            if not self.settings.allow_unrestricted_project_paths:
                return ProjectPathDecision(
                    False,
                    "",
                    "未配置 allowed_project_roots，不能使用本地 --project。"
                    "请配置允许的项目根目录，或显式开启 allow_unrestricted_project_paths。",
                )
            if _is_windows_special_path(project_path):
                return ProjectPathDecision(
                    False,
                    "",
                    "projectPath 是 UNC 或 Windows 设备路径；请通过 allowed_project_roots 显式允许该根目录。",
                )
            return ProjectPathDecision(True, _resolve_path(project_path))

        if _should_reject_special_path_before_resolve(project_path, roots):
            return ProjectPathDecision(False, "", "projectPath 不在 allowed_project_roots 允许的目录内。")

        resolved_project = _resolve_path(project_path)
        normalized_project = _normalize_resolved_path(resolved_project)
        for root in roots:
            if _is_path_within(normalized_project, _normalize_path(root)):
                return ProjectPathDecision(True, resolved_project)
        return ProjectPathDecision(False, "", "projectPath 不在 allowed_project_roots 允许的目录内。")

    def validate(self, user: UserRef, project_path: str) -> str:
        """兼容旧调用方：返回空字符串表示通过。"""
        return self.authorize(user, project_path).message


def _should_reject_special_path_before_resolve(project_path: str, roots: tuple[str, ...]) -> bool:
    """未显式配置相同特殊路径根时，先拒绝 UNC/device path。"""
    expanded = _expand_path_text(project_path)
    if not _is_windows_special_path(expanded):
        return False
    return not any(_special_root_matches(expanded, _expand_path_text(root)) for root in roots)


def _special_root_matches(path: str, root: str) -> bool:
    """判断配置根是否显式覆盖了同一个 UNC share 或 Windows device 根。"""
    path_root = _windows_special_root(path)
    root_root = _windows_special_root(root)
    if not path_root or not root_root:
        return False
    return os.path.normcase(path_root) == os.path.normcase(root_root)


def _is_windows_special_path(value: str) -> bool:
    """识别容易触发远端访问或设备语义的 Windows 特殊路径。"""
    return bool(_windows_special_root(value))


def _windows_special_root(value: str) -> str:
    """提取 UNC share 或 Windows device 前缀；普通路径返回空字符串。"""
    normalized = value.replace("/", "\\")
    if normalized.startswith("\\\\?\\UNC\\"):
        parts = normalized.split("\\")
        if len(parts) >= 6 and parts[4] and parts[5]:
            return "\\\\?\\UNC\\" + parts[4] + "\\" + parts[5]
        return "\\\\?\\UNC"
    if normalized.startswith("\\\\?\\") or normalized.startswith("\\\\.\\"):
        parts = normalized.split("\\")
        if len(parts) >= 4 and parts[3]:
            return "\\".join(parts[:4])
        return normalized[:4]
    if normalized.startswith("\\\\"):
        parts = normalized.split("\\")
        if len(parts) >= 4 and parts[2] and parts[3]:
            return "\\\\" + parts[2] + "\\" + parts[3]
        return "\\\\"
    return ""


def _expand_path_text(value: str) -> str:
    """只展开文本形式的用户目录和环境变量，不访问文件系统。"""
    return os.path.expandvars(os.path.expanduser(value))


def _resolve_path(value: str) -> str:
    """展开环境变量和用户目录，并尽量解析成绝对路径。"""
    expanded = _expand_path_text(value)
    try:
        resolved = Path(expanded).resolve(strict=False)
    except (OSError, RuntimeError):
        resolved = Path(os.path.abspath(expanded))
    return str(resolved)


def _normalize_path(value: str) -> str:
    """按当前操作系统规则归一化路径大小写和分隔符。"""
    return _normalize_resolved_path(_resolve_path(value))


def _normalize_resolved_path(value: str) -> str:
    return os.path.normcase(value)


def _is_path_within(path: str, root: str) -> bool:
    """判断 path 是否位于 root 内；不同盘符会触发 ValueError。"""
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False
