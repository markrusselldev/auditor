"""Test-suite setup.

The SSRF egress guard (auditor.security) is default-DENY: it refuses to fetch loopback/private
hosts in production. The test fixtures serve on 127.0.0.1, so the whole suite runs with the
documented escape hatch enabled. Individual security tests flip it back OFF to assert the
production posture.
"""

import os

os.environ.setdefault("AUDITOR_ALLOW_PRIVATE_HOSTS", "1")
