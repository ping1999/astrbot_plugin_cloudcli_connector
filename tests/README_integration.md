# CloudCLI Connector Tests

This directory contains local regression tests plus optional real CloudCLI integration tests.

Run from the plugin root:

```powershell
python -m unittest discover -s tests -v
```

`test_real_cloudcli_command.py` can read credentials from environment variables, `tests/config.yaml`, or the legacy `..\integration_tests\config.yaml` path when it exists locally. Do not commit a real `config.yaml`.

Useful environment variables:

```powershell
$env:CLOUDCLI_TEST_BASE_URL = "http://127.0.0.1:13002"
$env:CLOUDCLI_TEST_USERNAME = "your username"
$env:CLOUDCLI_TEST_PASSWORD = "your password"
# or:
$env:CLOUDCLI_TEST_JWT_TOKEN = "your JWT"
```

Real `/cloudcli run` and `/cloudcli stop` tests are skipped unless explicitly enabled:

```powershell
$env:CLOUDCLI_TEST_RUN_ENABLED = "1"
$env:CLOUDCLI_TEST_RUN_PROJECT = "F:\work\repo"

$env:CLOUDCLI_TEST_STOP_ENABLED = "1"
$env:CLOUDCLI_TEST_STOP_SESSION_REF = "1"
```
