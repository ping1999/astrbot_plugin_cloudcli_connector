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

Options: `--project <path>`, `--github <url>`, `--session <sessionId>`, `--provider <claude|cursor|codex|gemini|opencode>`, `--model <model>`, `--branch <name>`, `--pr`, `--no-cleanup`.

Each `/cloudcli run` gets a task ID. Use `/cloudcli run list`, `/cloudcli run log <taskId>`, and `/cloudcli run cancel <taskId>` to inspect or cancel tasks.

`/cloudcli stop <sessionId|index|last> [provider]` sends `abort-session` through the CloudCLI WebSocket. It uses independent `stop_access_mode` / `stop_allowed_user_keys` permissions, so `session_access_mode=authenticated` does not automatically grant stop access.

`/cloudcli audit [count]` shows visible approval audit records. `/cloudcli whoami` prints the current AstrBot user key for approval allowlist configuration.

## Notes

- Permission approval is a CloudCLI Claude-provider WebSocket feature.
- CloudCLI active sessions only mean sessions that are currently executing. Sessions that already replied but are still visible in the web UI are shown by `/cloudcli session` under "recently bindable sessions".
- Configure either `cloudcli_jwt_token`, or `cloudcli_username` plus `cloudcli_password`.
- `/cloudcli run` uses CloudCLI's external agent API, so `cloudcli_api_key` must contain an API key generated in CloudCLI Settings → API & Tokens.
- If CloudCLI is started with a global `API_KEY`, protected endpoints also need `cloudcli_api_key`.
- Users only receive push notifications for sessions they have bound.
- Session bindings, session indexes, pending approvals, audit entries, and run logs are scoped to the current chat origin by default. A private-chat binding is not automatically visible in a group chat for the same user.
- The WebSocket connection is supervised and reconnects with backoff after CloudCLI restarts or transient network failures.
- By default, only AstrBot admins or users in `session_allowed_user_keys` can list, bind, or read CloudCLI sessions; stopping sessions is controlled by independent `stop_allowed_user_keys` / `stop_access_mode` settings.
- By default, only AstrBot admins or users in `run_allowed_user_keys` can start `/cloudcli run` agent tasks.
- For non-admin `/cloudcli run --project`, configure `allowed_project_roots`; otherwise arbitrary local paths are rejected by default.
- By default, `persist_sensitive_state=false`, so approval input bodies, audit input summaries, and raw `/cloudcli run` task text are not written in full to local `state.json`. Fresh approval details are still available in memory after a push or refresh.
- Non-admin users cannot directly type an unbound raw sessionId by default. They should use an index from `/cloudcli session`, or an admin can enable `allow_direct_session_id`.
- By default, only AstrBot admins or users in `approval_allowed_user_keys` can view, receive, and decide approval requests.
- Users in `approval_allowed_user_keys` can handle approvals for sessions they have bound. Binding arbitrary raw session IDs for approval-only users is disabled by default; set `approval_allow_direct_session_bind=true` only in trusted chats.
- To avoid leaking sensitive approval input through stale stored admin state, proactive approval detail pushes only go to the chat origin that bound that session. Detailed proactive pushes are sent only to `approval_allowed_user_keys`, unless both `approval_access_mode=authenticated` and `approval_push_details_to_authenticated=true` are explicitly configured; admins can still run `/cloudcli pending` to view and handle requests.
- `/cloudcli pending` refreshes the local pending approval cache from CloudCLI and removes approvals that no longer exist upstream.
- `/cloudcli allow` and `/cloudcli deny` stop when the pending approval refresh fails instead of acting on stale cache.
- Approval timeout defaults to reminders only. Automatic denial happens only when `approval_timeout_action` is set to `deny`.

## CloudCLI setup

For self-hosted CloudCLI, create or obtain credentials from the CloudCLI UI:

- `cloudcli_base_url`: usually `http://127.0.0.1:3001`
- `cloudcli_jwt_token`: paste a current UI JWT token if you already have one
- `cloudcli_username` / `cloudcli_password`: alternative to a pasted JWT token
- `cloudcli_api_key`: used for `/api/agent`; generate it in CloudCLI Settings → API & Tokens
- `session_allowed_user_keys`: comma-separated allowlist for session commands
- `session_access_mode`: session access mode: `admin_or_allowlist`, `allowlist_only`, or `authenticated`
- `session_require_admin`: legacy compatibility flag. Prefer `session_access_mode`; setting this to `false` without an access mode now means allowlist-only, not all users.
- `allow_direct_session_id`: allow non-admin users to use raw session IDs that are not bound and not in their current session index
- `stop_allowed_user_keys`: comma-separated allowlist for `/cloudcli stop`
- `stop_access_mode`: independent `/cloudcli stop` access mode: `admin_or_allowlist`, `allowlist_only`, or `authenticated`
- `stop_require_admin`: legacy compatibility flag. Prefer `stop_access_mode`
- `recent_sessions_limit`: number of recent sessions shown by `/cloudcli session`
- `chat_messages_limit`: default recent message count shown by `/cloudcli chat`
- `max_run_message_length`: maximum task text length accepted by `/cloudcli run`
- `run_allowed_user_keys`: comma-separated allowlist for `/cloudcli run`
- `run_access_mode`: run access mode: `admin_or_allowlist`, `allowlist_only`, or `authenticated`
- `run_require_admin`: legacy compatibility flag. Prefer `run_access_mode`; setting this to `false` without an access mode now means allowlist-only, not all users.
- `allowed_project_roots`: comma-separated local roots allowed for `/cloudcli run --project`
- `allow_unrestricted_project_paths`: allow non-admin users to use arbitrary local paths only when `allowed_project_roots` is empty; once roots are configured, non-admin paths must stay inside them
- `max_active_runs_per_user` / `max_active_runs_global`: concurrent `/cloudcli run` limits; `0` disables a limit
- `max_run_history_per_user` / `max_run_history_global`: retain completed `/cloudcli run` history up to these limits; `0` disables pruning
- `persist_sensitive_state`: persist approval inputs, audit input summaries, and raw run task text to `state.json`; default is `false`
- `agent_idle_timeout_seconds`: idle timeout for the `/cloudcli run` streaming response
- `agent_max_duration_seconds`: maximum wait time for one `/cloudcli run`; `0` disables this guard
- `run_list_limit`: default task count shown by `/cloudcli run list`
- `run_status_interval_seconds` / `max_run_status_pushes`: control background run status push frequency
- `approval_allowed_user_keys`: comma-separated approval allowlist; use `/cloudcli whoami` to get the current user key
- `approval_access_mode`: approval access mode: `admin_or_allowlist`, `allowlist_only`, or `authenticated`
- `approval_require_admin`: legacy compatibility flag. Prefer `approval_access_mode`; setting this to `false` without an access mode now means allowlist-only, not all users.
- `approval_push_details_to_authenticated`: when `approval_access_mode=authenticated`, also push detailed approval input to all verified users bound to the session; default `false`
- `approval_allow_direct_session_bind`: allow approval users to bind raw known session IDs without session browsing access; default `false`
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
