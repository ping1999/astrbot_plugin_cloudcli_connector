# astrbot_plugin_cloudcli_connector

AstrBot plugin for viewing CloudCLI running and recently bindable sessions, and approving Claude permission requests from chat.

## Commands

- `/cloudcli help`
- `/cloudcli status`
- `/cloudcli session`
- `/cloudcli bind list`
- `/cloudcli bind <sessionId|index|last>`
- `/cloudcli unbind <sessionId>`
- `/cloudcli unbind all`
- `/cloudcli chat [sessionId] [limit]`
- `/cloudcli run [options] <message>`
- `/cloudcli run list [count]`
- `/cloudcli run log <taskId>`
- `/cloudcli run cancel <taskId>`
- `/cloudcli stop <sessionId|index|last> [provider]`
- `/cloudcli pending`
- `/cloudcli allow [requestNo]`
- `/cloudcli deny [requestNo] <reason>`
- `/cloudcli audit [count]`
- `/cloudcli whoami`

`requestNo` is the simple number shown by `/cloudcli pending`. If only one visible approval is pending, `allow` and `deny` may omit the number.

`/cloudcli status` checks the CloudCLI base URL, authentication, WebSocket, REST, and agent API key configuration.

`/cloudcli session` refreshes the current user's session index cache. You can then bind sessions with `/cloudcli bind 1` or `/cloudcli bind last`.

`/cloudcli chat` shows recent messages from a session. If the current user has exactly one bound session, `sessionId` may be omitted.

`/cloudcli run` starts a CloudCLI agent task from AstrBot and pushes status/completion updates back to the current chat. Examples:

- `/cloudcli run --session <sessionId> Fix the login failure`
- `/cloudcli run --session 1 Continue this session`
- `/cloudcli run --project "D:\work\repo" --provider codex Inspect the failing tests`
- `/cloudcli run --github https://github.com/user/repo --branch fix-bug --pr Fix the auth bug`

Options: `--project <path>`, `--github <url>`, `--session <sessionId>`, `--provider <claude|cursor|codex|gemini>`, `--model <model>`, `--branch <name>`, `--pr`, `--no-cleanup`.

Each `/cloudcli run` gets a task ID. Use `/cloudcli run list`, `/cloudcli run log <taskId>`, and `/cloudcli run cancel <taskId>` to inspect or cancel tasks.

`/cloudcli stop <sessionId|index|last> [provider]` sends `abort-session` through the CloudCLI WebSocket.

`/cloudcli audit [count]` shows visible approval audit records. `/cloudcli whoami` prints the current AstrBot user key for approval allowlist configuration.

## Notes

- Permission approval is a CloudCLI Claude-provider WebSocket feature.
- CloudCLI active sessions only mean sessions that are currently executing. Sessions that already replied but are still visible in the web UI are shown by `/cloudcli session` under "recently bindable sessions".
- Configure either `cloudcli_jwt_token`, or `cloudcli_username` plus `cloudcli_password`.
- `/cloudcli run` uses CloudCLI's external agent API, so `cloudcli_api_key` must contain an API key generated in CloudCLI Settings → API & Tokens.
- If CloudCLI is started with a global `API_KEY`, protected endpoints also need `cloudcli_api_key`.
- Users only receive push notifications for sessions they have bound.
- When `approval_allowed_user_keys` is empty, any user who can see a bound session approval may approve it. Once configured, only allowlisted users can run `/cloudcli allow` or `/cloudcli deny`.
- Approval timeout defaults to reminders only. Automatic denial happens only when `approval_timeout_action` is set to `deny`.

## CloudCLI setup

For self-hosted CloudCLI, create or obtain credentials from the CloudCLI UI:

- `cloudcli_base_url`: usually `http://127.0.0.1:3001`
- `cloudcli_jwt_token`: paste a current UI JWT token if you already have one
- `cloudcli_username` / `cloudcli_password`: alternative to a pasted JWT token
- `cloudcli_api_key`: used for `/api/agent`; generate it in CloudCLI Settings → API & Tokens
- `recent_sessions_limit`: number of recent sessions shown by `/cloudcli session`
- `chat_messages_limit`: default recent message count shown by `/cloudcli chat`
- `max_run_message_length`: maximum task text length accepted by `/cloudcli run`
- `run_list_limit`: default task count shown by `/cloudcli run list`
- `run_status_interval_seconds` / `max_run_status_pushes`: control background run status push frequency
- `approval_allowed_user_keys`: comma-separated approval allowlist; use `/cloudcli whoami` to get the current user key
- `approval_timeout_seconds`: seconds before timeout handling; `0` disables it
- `approval_timeout_action`: timeout action, `remind` or `deny`

The plugin uses CloudCLI `/ws` messages, REST endpoints, and the external agent API:

- `get-active-sessions`
- `abort-session`
- `get-pending-permissions`
- `claude-permission-response`
- `GET /api/projects?sessionsLimit=...`
- `GET /api/providers/sessions/:sessionId/messages`
- `POST /api/agent`

Because approval controls real local tool execution, only bind sessions in trusted chats.
