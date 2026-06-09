# astrbot_plugin_cloudcli_connector

用于在 AstrBot 聊天平台中查看 CloudCLI 正在运行和最近可绑定的 session，并审批 Claude 权限请求的插件。

[English README](README_en.md)

## 指令

- `/cloudcli help`
- `/cloudcli status`
- `/cloudcli session`
- `/cloudcli bind list`
- `/cloudcli bind <sessionId|序号|last>`
- `/cloudcli unbind <sessionId>`
- `/cloudcli unbind all`
- `/cloudcli chat [sessionId] [limit]`
- `/cloudcli run [options] <message>`
- `/cloudcli run list [数量]`
- `/cloudcli run log <任务编号>`
- `/cloudcli run cancel <任务编号>`
- `/cloudcli stop <sessionId|序号|last> [provider]`
- `/cloudcli pending`
- `/cloudcli allow [requestNo]`
- `/cloudcli deny [requestNo] <reason>`
- `/cloudcli audit [数量]`
- `/cloudcli whoami`

`requestNo` 是 `/cloudcli pending` 展示的简单序号。当前只有一条可见待审批内容时，`allow` 和 `deny` 可以省略序号。

`/cloudcli status` 用于检查 CloudCLI 地址、认证、WebSocket、REST 和 agent API Key 配置。

`/cloudcli session` 会刷新当前用户的 session 序号缓存。之后可以用 `/cloudcli bind 1` 或 `/cloudcli bind last` 绑定最近可绑定 session 列表中的会话。

`/cloudcli chat` 用于查看 session 最近消息。当前用户只绑定了一个 session 时，可以省略 `sessionId`。

`/cloudcli run` 用于从 AstrBot 发起 CloudCLI agent 任务，并把状态和完成结果主动推回当前聊天。常用写法：

- `/cloudcli run --session <sessionId> 修复登录失败问题`
- `/cloudcli run --session 1 继续处理这个会话`
- `/cloudcli run --project "D:\work\repo" --provider codex 检查测试失败原因`
- `/cloudcli run --github https://github.com/user/repo --branch fix-bug --pr 修复鉴权 bug`

可用选项：`--project <path>`、`--github <url>`、`--session <sessionId>`、`--provider <claude|cursor|codex|gemini>`、`--model <model>`、`--branch <name>`、`--pr`、`--no-cleanup`。

每个 `/cloudcli run` 会生成任务编号，可用 `/cloudcli run list` 查看，`/cloudcli run log <任务编号>` 查看状态日志，`/cloudcli run cancel <任务编号>` 取消本地任务并尽量中止关联的 CloudCLI session。

`/cloudcli stop <sessionId|序号|last> [provider]` 会向 CloudCLI WebSocket 发送 `abort-session`，用于中止正在执行的 session。

`/cloudcli audit [数量]` 会展示当前用户可见的审批审计记录。`/cloudcli whoami` 用于查看当前用户标识，方便配置审批白名单。

## 说明

- 权限审批依赖 CloudCLI Claude provider 的 WebSocket 功能。
- CloudCLI 的 active session 只表示“当前正在执行”的会话；已经回复完成但仍在网页中可见的会话，会通过 `/cloudcli session` 的“最近可绑定 session”展示。
- 请配置 `cloudcli_jwt_token`，或配置 `cloudcli_username` 与 `cloudcli_password`。
- `/cloudcli run` 使用 CloudCLI 的外部 agent API，需要在 `cloudcli_api_key` 填写 CloudCLI UI 中 Settings → API & Tokens 生成的 API Key。
- 如果 CloudCLI 启动时设置了全局 `API_KEY`，受保护接口也需要配置 `cloudcli_api_key`。
- 用户只会收到自己已绑定 session 的主动审批推送。
- `approval_allowed_user_keys` 为空时，能看到绑定 session 待审批的用户都可以审批；配置后只有白名单用户可以 `/cloudcli allow` 或 `/cloudcli deny`。
- 审批超时默认只提醒，不会自动允许。只有把 `approval_timeout_action` 设置为 `deny` 时才会自动拒绝。

## CloudCLI 配置

对于自托管 CloudCLI，请从 CloudCLI UI 创建或获取凭据：

- `cloudcli_base_url`：通常是 `http://127.0.0.1:3001`
- `cloudcli_jwt_token`：如果已有当前 UI 的 JWT token，可以直接粘贴到这里
- `cloudcli_username` / `cloudcli_password`：用于替代手动填写 JWT token，插件会自动登录获取 token
- `cloudcli_api_key`：用于 `/api/agent`；在 CloudCLI UI 的 Settings → API & Tokens 中生成
- `recent_sessions_limit`：`/cloudcli session` 展示的最近会话数量
- `chat_messages_limit`：`/cloudcli chat` 默认展示的最近消息数量
- `max_run_message_length`：`/cloudcli run` 接受的任务文本长度上限
- `run_list_limit`：`/cloudcli run list` 默认展示的任务数量
- `run_status_interval_seconds` / `max_run_status_pushes`：控制长任务状态推送频率
- `approval_allowed_user_keys`：审批白名单，多个用户标识用英文逗号分隔；用 `/cloudcli whoami` 获取当前用户标识
- `approval_timeout_seconds`：审批超时时间，`0` 表示关闭超时处理
- `approval_timeout_action`：超时动作，支持 `remind` 或 `deny`

插件会使用 CloudCLI 的 `/ws` 消息、REST 接口和外部 agent API：

- `get-active-sessions`
- `abort-session`
- `get-pending-permissions`
- `claude-permission-response`
- `GET /api/projects?sessionsLimit=...`
- `GET /api/providers/sessions/:sessionId/messages`
- `POST /api/agent`

由于权限审批会控制真实的本地工具执行，请只在可信聊天中绑定 session。
