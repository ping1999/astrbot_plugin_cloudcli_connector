# astrbot_plugin_cloudcli_connector

AstrBot plugin for viewing CloudCLI running and recently bindable sessions, and approving Claude permission requests from chat.

## Commands

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

`requestNo` is the simple number shown by `/cloudcli pending`. If only one visible approval is pending, `allow` and `deny` may omit the number.

`/cloudcli chat` shows recent messages from a session. If the current user has exactly one bound session, `sessionId` may be omitted.

`/cloudcli run` starts a CloudCLI agent task from AstrBot and pushes status/completion updates back to the current chat. Examples:

- `/cloudcli run --session <sessionId> Fix the login failure`
- `/cloudcli run --project "D:\work\repo" --provider codex Inspect the failing tests`
- `/cloudcli run --github https://github.com/user/repo --branch fix-bug --pr Fix the auth bug`

Options: `--project <path>`, `--github <url>`, `--session <sessionId>`, `--provider <claude|cursor|codex|gemini>`, `--model <model>`, `--branch <name>`, `--pr`, `--no-cleanup`.

## Notes

- Permission approval is a CloudCLI Claude-provider WebSocket feature.
- CloudCLI active sessions only mean sessions that are currently executing. Sessions that already replied but are still visible in the web UI are shown by `/cloudcli session` under "recently bindable sessions".
- Configure either `cloudcli_jwt_token`, or `cloudcli_username` plus `cloudcli_password`.
- `/cloudcli run` uses CloudCLI's external agent API, so `cloudcli_api_key` must contain an API key generated in CloudCLI Settings → API & Tokens.
- If CloudCLI is started with a global `API_KEY`, protected endpoints also need `cloudcli_api_key`.
- Users only receive push notifications for sessions they have bound.

## CloudCLI setup

For self-hosted CloudCLI, create or obtain credentials from the CloudCLI UI:

- `cloudcli_base_url`: usually `http://127.0.0.1:3001`
- `cloudcli_jwt_token`: paste a current UI JWT token if you already have one
- `cloudcli_username` / `cloudcli_password`: alternative to a pasted JWT token
- `cloudcli_api_key`: used for `/api/agent`; generate it in CloudCLI Settings → API & Tokens
- `recent_sessions_limit`: number of recent sessions shown by `/cloudcli session`
- `chat_messages_limit`: default recent message count shown by `/cloudcli chat`
- `max_run_message_length`: maximum task text length accepted by `/cloudcli run`
- `run_status_interval_seconds` / `max_run_status_pushes`: control background run status push frequency

The plugin uses CloudCLI `/ws` messages, REST endpoints, and the external agent API:

- `get-active-sessions`
- `get-pending-permissions`
- `claude-permission-response`
- `GET /api/projects?sessionsLimit=...`
- `GET /api/providers/sessions/:sessionId/messages`
- `POST /api/agent`

Because approval controls real local tool execution, only bind sessions in trusted chats.
