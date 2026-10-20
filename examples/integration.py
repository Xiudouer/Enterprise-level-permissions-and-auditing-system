"""Run at project root: python -m examples.integration

No sample key/token literals. A temporary state is generated and then removed.
"""
from pathlib import Path
import json
import tempfile

from securitykit import SecurityError
from securitykit.cli import initialize
from securitykit.core import load_kernel
from securitykit.pki import TemporaryWorkspace


with TemporaryWorkspace(prefix="securitykit-integration-") as directory:
    state = Path(directory) / "state"
    initialize(state)
    kernel = load_kernel(state)
    clients = json.loads((state / "clients.json").read_text())
    authorization = "Bearer " + clients["viewer-a"]["token"]

    # Tenant, action and required role are chosen by a trusted server route.
    # A real callback uses the provided transaction for the business tables.
    result = kernel.run(authorization, "tenant-a", "reports.read", "report-1", "viewer",
                        lambda tx, principal: {"allowed": True, "subject": principal.subject})
    print(result)
    print(kernel.verify_audit())
