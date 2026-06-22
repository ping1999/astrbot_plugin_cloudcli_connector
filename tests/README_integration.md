# CloudCLI Connector Tests

This directory contains local regression tests plus optional real CloudCLI integration tests.

Run from the plugin root:

```powershell
python -m unittest discover -s tests -v
```

`test_real_cloudcli_command.py` reads test settings only from `tests/config.yaml`. It does not read `config.example.yaml`, environment-variable credential overrides, or the legacy `..\integration_tests\config.yaml` path. Do not commit a real `config.yaml`.

Create `tests/config.yaml` from the example and edit the values there:

```yaml
real_enabled: true
base_url: "http://127.0.0.1:13002"
username: "your username"
password: "your password"
# or:
jwt_token: "your JWT"
```

Real `/cloudcli run` and `/cloudcli stop` tests are skipped unless explicitly enabled:

```yaml
run_enabled: true
run_project: "F:\\work\\repo"

stop_enabled: true
stop_session_ref: "1"
```
