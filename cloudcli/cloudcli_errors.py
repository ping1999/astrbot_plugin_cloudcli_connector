from __future__ import annotations


class CloudCLIError(RuntimeError):
    pass


class CloudCLITimeout(CloudCLIError):
    pass
