"""Watchtower exception-capture SDK (stdlib only).

Report exceptions to a watchtower server; the server fingerprints and
groups them into incidents. Configure via env:

    WATCHTOWER_ENDPOINT     required, e.g. http://server:18788
    WATCHTOWER_TOKEN        required, bearer token
    WATCHTOWER_HOST_ID      default: socket hostname
    WATCHTOWER_SERVICE      default: app
    WATCHTOWER_ENVIRONMENT  default: prod
"""

import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request


def _env(name, default=None):
    return os.environ.get(name, default)


class Client:
    def __init__(self, endpoint=None, token=None, host_id=None,
                 service=None, environment=None):
        self.endpoint = (endpoint or _env("WATCHTOWER_ENDPOINT", "")).rstrip("/")
        self.token = token or _env("WATCHTOWER_TOKEN", "")
        self.host_id = host_id or _env("WATCHTOWER_HOST_ID", socket.gethostname())
        self.service = service or _env("WATCHTOWER_SERVICE", "app")
        self.environment = environment or _env("WATCHTOWER_ENVIRONMENT", "prod")

    def capture(self, level, exception_type, message, frames=None):
        """frames: list of (file, line, function). Best-effort, one retry."""
        if not self.endpoint or not self.token:
            return False
        frames = frames or []
        body = json.dumps({
            "host_id": self.host_id,
            "service": self.service,
            "environment": self.environment,
            "exception": {
                "type": exception_type,
                "message": message,
                "level": level,
                "frames": [
                    {"file": f[0], "line": f[1], "function": f[2] if len(f) > 2 else ""}
                    for f in frames
                ],
            },
        }).encode("utf-8")
        url = self.endpoint + "/v1/errors"
        for attempt in (0, 1):
            try:
                req = urllib.request.Request(
                    url, data=body, method="POST",
                    headers={"Content-Type": "application/json",
                             "Authorization": "Bearer " + self.token})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return 200 <= resp.status < 300
            except (urllib.error.URLError, OSError, ValueError):
                if attempt == 0:
                    time.sleep(0.2)
        return False

    def capture_exception(self, level="error"):
        """Capture the currently-handled exception (sys.exc_info)."""
        exc_type, exc_value, exc_tb = sys.exc_info()
        if exc_type is None:
            return False
        frames = []
        tb = exc_tb
        while tb is not None:
            code = tb.tb_frame.f_code
            frames.append((code.co_filename, tb.tb_lineno, code.co_name))
            tb = tb.tb_next
        return self.capture(level, exc_type.__name__, str(exc_value), frames)
