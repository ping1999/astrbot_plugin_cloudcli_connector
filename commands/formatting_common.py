from __future__ import annotations

import json
from typing import Any

try:
    from ..core.redaction import redact_text
except ImportError:  # pragma: no cover - AstrBot may load plugin modules flat.
    from core.redaction import redact_text


HELP_TEXT = """CloudCLI Connector 指令：
/cloudcli help：列出插件支持的指令
/cloudcli status：检查 CloudCLI 连接、认证、REST、WebSocket 和 agent 配置
/cloudcli session：列出 CloudCLI 正在运行和最近可绑定的 session
/cloudcli bind list：列出当前用户绑定的 session
/cloudcli bind <sessionId|序号|last>：绑定 session
/cloudcli unbind <sessionId>：解绑 session
/cloudcli unbind all：解绑全部 session
/cloudcli chat [sessionId] [limit]：查看 session 最近消息；单绑定时可省略 sessionId
/cloudcli run [选项] <任务>：发起 CloudCLI agent 任务并推送状态
/cloudcli run list [数量]：列出当前用户发起的 CloudCLI 任务
/cloudcli run log <任务编号>：查看任务日志
/cloudcli run cancel <任务编号>：取消任务，并尽量中止关联 session
/cloudcli stop <sessionId|序号|last> [provider]：中止正在执行的 CloudCLI session
/cloudcli pending：列出已绑定 session 的待审批权限
/cloudcli allow [序号]：允许权限；只有一条时可省略序号
/cloudcli deny [序号] <原因>：拒绝权限；只有一条时可省略序号
/cloudcli audit [数量]：查看审批审计记录
/cloudcli whoami：查看当前 AstrBot 用户标识，用于配置审批白名单

run 选项：--project <path>、--github <url>、--session <sessionId>、--provider <claude|cursor|codex|gemini|opencode>、--model <model>、--branch <name>、--pr、--no-cleanup
"""


def clip_text(text: str, limit: int) -> str:
    if limit < 20:
        limit = 20
    text = redact_text(text, limit)
    if len(text) <= limit:
        return text
    return f"{text[: limit - 20]}\n... 已截断 {len(text) - limit + 20} 字符"


def read_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def read_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def render_compact_json(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("url", "html_url"):
            if value.get(key):
                return str(value[key])
        if value.get("number"):
            return f"#{value['number']} {value.get('name') or value.get('title') or ''}".strip()
        if value.get("name"):
            return str(value["name"])
    return clip_text(render_input(value), 300)


def render_input(value: Any) -> str:
    if value is None:
        return "(empty)"
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
    except TypeError:
        return str(value)


def extract_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = [extract_text(item) for item in value]
        return "\n".join(part for part in parts if part)
    if not isinstance(value, dict):
        return ""

    if isinstance(value.get("text"), str):
        return value["text"]
    if isinstance(value.get("content"), str):
        return value["content"]
    if isinstance(value.get("content"), list):
        return extract_text(value["content"])
    message = value.get("message")
    if isinstance(message, dict):
        text = extract_text(message.get("content"))
        if text:
            return text
    data = value.get("data")
    if isinstance(data, dict):
        text = extract_text(data)
        if text:
            return text
    delta = value.get("delta")
    if isinstance(delta, dict):
        text = extract_text(delta)
        if text:
            return text
    return ""
