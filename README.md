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

可用选项：`--project <path>`、`--github <url>`、`--session <sessionId>`、`--provider <claude|cursor|codex|gemini|opencode>`、`--model <model>`、`--branch <name>`、`--pr`、`--no-cleanup`。

每个 `/cloudcli run` 会生成任务编号，可用 `/cloudcli run list` 查看，`/cloudcli run log <任务编号>` 查看状态日志，`/cloudcli run cancel <任务编号>` 取消本地任务并尽量中止关联的 CloudCLI session。

`/cloudcli stop <sessionId|序号|last> [provider]` 会向 CloudCLI WebSocket 发送 `abort-session`，用于中止正在执行的 session。它使用独立的 `stop_access_mode` / `stop_allowed_user_keys` 权限，不会因为 `session_access_mode=authenticated` 自动开放。

`/cloudcli audit [数量]` 会展示当前用户可见的审批审计记录。`/cloudcli whoami` 用于查看当前用户标识，方便配置审批白名单。

## 说明

- 权限审批依赖 CloudCLI Claude provider 的 WebSocket 功能。
- CloudCLI 的 active session 只表示“当前正在执行”的会话；已经回复完成但仍在网页中可见的会话，会通过 `/cloudcli session` 的“最近可绑定 session”展示。
- 请配置 `cloudcli_jwt_token`，或配置 `cloudcli_username` 与 `cloudcli_password`。
- `/cloudcli run` 使用 CloudCLI 的外部 agent API，需要在 `cloudcli_api_key` 填写 CloudCLI UI 中 Settings → API & Tokens 生成的 API Key。
- 如果 CloudCLI 启动时设置了全局 `API_KEY`，受保护接口也需要配置 `cloudcli_api_key`。
- 用户只会收到自己已绑定 session 的主动审批推送。
- session 绑定、序号缓存、审批列表、审计记录和任务日志默认按当前聊天会话隔离；同一用户在私聊中的绑定不会自动出现在群聊中。
- WebSocket 断开后插件会自动退避重连，避免 CloudCLI 重启或短暂网络抖动后审批推送长期失效。
- 默认只有 AstrBot 管理员或 `session_allowed_user_keys` 白名单用户可以查看、绑定和读取 CloudCLI session；中止 session 由独立的 `stop_allowed_user_keys` / `stop_access_mode` 控制。
- 默认只有 AstrBot 管理员或 `run_allowed_user_keys` 白名单用户可以使用 `/cloudcli run` 发起 agent 任务。
- 使用 `/cloudcli run --project` 时建议配置 `allowed_project_roots`，否则默认会拒绝访问本地任意目录；只有显式开启 `allow_unrestricted_project_paths` 才会放开。
- 默认 `persist_sensitive_state=false`，审批输入、审计输入摘要和 `/cloudcli run` 原始任务文本不会完整写入本地 `state.json`；当前进程内刚收到或刚刷新的审批详情仍可正常查看。
- 非管理员默认不能直接手填未绑定的 sessionId；请先执行 `/cloudcli session` 后使用序号，或由管理员开启 `allow_direct_session_id`。
- 默认只有 AstrBot 管理员或 `approval_allowed_user_keys` 白名单用户可以查看、接收和处理审批请求。
- `approval_allowed_user_keys` 用户可以处理已绑定 session 的审批。审批白名单用户默认不能直接绑定任意已知 sessionId；只应在可信聊天中显式开启 `approval_allow_direct_session_bind=true`。
- 为避免历史管理员状态失效导致敏感审批内容误推，主动审批详情只会推送到绑定该 session 的聊天会话，并且默认只主动推给 `approval_allowed_user_keys` 中的用户；只有同时显式设置 `approval_access_mode=authenticated` 和 `approval_push_details_to_authenticated=true` 时才会推给所有已验证绑定用户。管理员仍可主动执行 `/cloudcli pending` 查看并处理。
- `/cloudcli pending` 会按 CloudCLI 当前返回结果刷新本地待审批缓存，已不存在的审批会从本地清理。
- `/cloudcli allow` 和 `/cloudcli deny` 在同步待审批列表失败时不会使用旧缓存继续决策。
- 审批超时默认只提醒，不会自动允许。只有把 `approval_timeout_action` 设置为 `deny` 时才会自动拒绝。

## CloudCLI 配置

对于自托管 CloudCLI，请从 CloudCLI UI 创建或获取凭据：

- `cloudcli_base_url`：通常是 `http://127.0.0.1:3001`
- `cloudcli_jwt_token`：如果已有当前 UI 的 JWT token，可以直接粘贴到这里
- `cloudcli_username` / `cloudcli_password`：用于替代手动填写 JWT token，插件会自动登录获取 token
- `cloudcli_api_key`：用于 `/api/agent`；在 CloudCLI UI 的 Settings → API & Tokens 中生成
- `session_allowed_user_keys`：session 命令白名单，多个用户标识用英文逗号分隔
- `session_access_mode`：session 权限模式，可选 `admin_or_allowlist`、`allowlist_only`、`authenticated`
- `session_require_admin`：兼容旧配置。建议改用 `session_access_mode`；不配置 access mode 时，把它设为 `false` 现在表示仅白名单，而不是所有用户。
- `allow_direct_session_id`：是否允许非管理员直接使用未绑定、未出现在当前 session 序号缓存中的 sessionId
- `stop_allowed_user_keys`：`/cloudcli stop` 白名单，多个用户标识用英文逗号分隔
- `stop_access_mode`：`/cloudcli stop` 独立权限模式，可选 `admin_or_allowlist`、`allowlist_only`、`authenticated`
- `stop_require_admin`：兼容旧配置。建议改用 `stop_access_mode`
- `recent_sessions_limit`：`/cloudcli session` 展示的最近会话数量
- `session_index_ttl_seconds`：`/cloudcli session` 序号缓存有效期，默认 3600 秒
- `chat_messages_limit`：`/cloudcli chat` 默认展示的最近消息数量
- `max_run_message_length`：`/cloudcli run` 接受的任务文本长度上限
- `run_allowed_user_keys`：`/cloudcli run` 白名单，多个用户标识用英文逗号分隔
- `run_access_mode`：run 权限模式，可选 `admin_or_allowlist`、`allowlist_only`、`authenticated`
- `run_require_admin`：兼容旧配置。建议改用 `run_access_mode`；不配置 access mode 时，把它设为 `false` 现在表示仅白名单，而不是所有用户。
- `allowed_project_roots`：允许 `/cloudcli run --project` 访问的本地根目录，多个目录用英文逗号分隔
- `allow_unrestricted_project_paths`：是否在未配置 `allowed_project_roots` 时允许访问任意本地路径；如果已经配置了 `allowed_project_roots`，所有用户都必须落在这些根目录内
- `max_active_runs_per_user` / `max_active_runs_global`：限制并发 `/cloudcli run` 任务数量，`0` 表示不限制
- `max_run_history_per_user` / `max_run_history_global`：保留已完成 `/cloudcli run` 历史的上限，`0` 表示不裁剪
- `persist_sensitive_state`：是否把审批输入、审计输入摘要和原始 run 任务文本完整持久化到 `state.json`；默认 `false`
- `agent_idle_timeout_seconds`：`/cloudcli run` 流式响应空闲超时
- `agent_max_duration_seconds`：单个 `/cloudcli run` 最大等待时间，`0` 表示关闭
- `run_list_limit`：`/cloudcli run list` 默认展示的任务数量
- `run_status_interval_seconds` / `max_run_status_pushes`：控制长任务状态推送频率
- `approval_allowed_user_keys`：审批白名单，多个用户标识用英文逗号分隔；用 `/cloudcli whoami` 获取当前用户标识
- `approval_access_mode`：审批权限模式，可选 `admin_or_allowlist`、`allowlist_only`、`authenticated`
- `approval_require_admin`：兼容旧配置。建议改用 `approval_access_mode`；不配置 access mode 时，把它设为 `false` 现在表示仅白名单，而不是所有用户。
- `approval_push_details_to_authenticated`：是否在 `approval_access_mode=authenticated` 时把包含工具输入的主动审批详情推给所有已验证绑定用户；默认 `false`
- `approval_allow_direct_session_bind`：是否允许审批用户在无 session 浏览权限时直接绑定已知 sessionId；默认 `false`
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
