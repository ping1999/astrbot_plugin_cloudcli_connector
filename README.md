# astrbot_plugin_cloudcli_connector

用于在 AstrBot 聊天平台中查看 CloudCLI 正在运行和最近可绑定的 session，并审批 Claude 权限请求的插件。

[English README](README_en.md)

## 指令

- `/cloudcli help`
- `/cloudcli session`
- `/cloudcli bind list`
- `/cloudcli bind <sessionId>`
- `/cloudcli unbind <sessionId>`
- `/cloudcli unbind all`
- `/cloudcli chat [sessionId] [limit]`
- `/cloudcli run [options] <message>`
- `/cloudcli pending`
- `/cloudcli allow [requestNo]`
- `/cloudcli deny [requestNo] <reason>`

`requestNo` 是 `/cloudcli pending` 展示的简单序号。当前只有一条可见待审批内容时，`allow` 和 `deny` 可以省略序号。

`/cloudcli chat` 用于查看 session 最近消息。当前用户只绑定了一个 session 时，可以省略 `sessionId`。

`/cloudcli run` 用于从 AstrBot 发起 CloudCLI agent 任务，并把状态和完成结果主动推回当前聊天。常用写法：

- `/cloudcli run --session <sessionId> 修复登录失败问题`
- `/cloudcli run --project "D:\work\repo" --provider codex 检查测试失败原因`
- `/cloudcli run --github https://github.com/user/repo --branch fix-bug --pr 修复鉴权 bug`

可用选项：`--project <path>`、`--github <url>`、`--session <sessionId>`、`--provider <claude|cursor|codex|gemini>`、`--model <model>`、`--branch <name>`、`--pr`、`--no-cleanup`。

## 说明

- 权限审批依赖 CloudCLI Claude provider 的 WebSocket 功能。
- CloudCLI 的 active session 只表示“当前正在执行”的会话；已经回复完成但仍在网页中可见的会话，会通过 `/cloudcli session` 的“最近可绑定 session”展示。
- 请配置 `cloudcli_jwt_token`，或配置 `cloudcli_username` 与 `cloudcli_password`。
- `/cloudcli run` 使用 CloudCLI 的外部 agent API，需要在 `cloudcli_api_key` 填写 CloudCLI UI 中 Settings → API & Tokens 生成的 API Key。
- 如果 CloudCLI 启动时设置了全局 `API_KEY`，受保护接口也需要配置 `cloudcli_api_key`。
- 用户只会收到自己已绑定 session 的主动审批推送。

## CloudCLI 配置

对于自托管 CloudCLI，请从 CloudCLI UI 创建或获取凭据：

- `cloudcli_base_url`：通常是 `http://127.0.0.1:3001`
- `cloudcli_jwt_token`：如果已有当前 UI 的 JWT token，可以直接粘贴到这里
- `cloudcli_username` / `cloudcli_password`：用于替代手动填写 JWT token，插件会自动登录获取 token
- `cloudcli_api_key`：用于 `/api/agent`；在 CloudCLI UI 的 Settings → API & Tokens 中生成
- `recent_sessions_limit`：`/cloudcli session` 展示的最近会话数量
- `chat_messages_limit`：`/cloudcli chat` 默认展示的最近消息数量
- `max_run_message_length`：`/cloudcli run` 接受的任务文本长度上限
- `run_status_interval_seconds` / `max_run_status_pushes`：控制长任务状态推送频率

插件会使用 CloudCLI 的 `/ws` 消息、REST 接口和外部 agent API：

- `get-active-sessions`
- `get-pending-permissions`
- `claude-permission-response`
- `GET /api/projects?sessionsLimit=...`
- `GET /api/providers/sessions/:sessionId/messages`
- `POST /api/agent`

由于权限审批会控制真实的本地工具执行，请只在可信聊天中绑定 session。

## 真实 CloudCLI 集成测试

仓库内提供了一个不依赖 AstrBot 主程序的真实环境测试脚本：`integration_tests/real_cloudcli_command_test.py`。它会注入假的 AstrBot 上下文，加载插件类，然后连接真实 CloudCLI 测试命令流。

PowerShell 示例：

```powershell
$env:CLOUDCLI_TEST_BASE_URL = "http://127.0.0.1:13002"
$env:CLOUDCLI_TEST_USERNAME = "你的 CloudCLI 用户名"
$env:CLOUDCLI_TEST_PASSWORD = "你的 CloudCLI 密码"
python integration_tests/real_cloudcli_command_test.py
```

如果已经有 JWT，也可以用：

```powershell
$env:CLOUDCLI_TEST_JWT_TOKEN = "你的 CloudCLI JWT"
```

默认测试会执行：

- `/cloudcli help`
- `/cloudcli session`
- 自动选择最近 session，或使用 `CLOUDCLI_TEST_SESSION_ID`
- `/cloudcli bind <sessionId>`
- `/cloudcli bind list`
- `/cloudcli chat 5`
- `/cloudcli pending`
- `/cloudcli unbind <sessionId>`

`/cloudcli run` 默认跳过，避免误触发真实 agent 任务。需要测试时显式启用：

```powershell
$env:CLOUDCLI_TEST_API_KEY = "CloudCLI UI 生成的 API Key"
$env:CLOUDCLI_TEST_RUN_ENABLED = "1"
$env:CLOUDCLI_TEST_RUN_PROJECT = "F:\work\repo"
$env:CLOUDCLI_TEST_RUN_PROVIDER = "claude"
python integration_tests/real_cloudcli_command_test.py
```
