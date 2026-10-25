"""Authority provisioning tests; run outside the restricted worker account."""

import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

import pytest

from cops.contracts.models import ActionPlan
from cops.execution.control import ApprovalAuthorityServer
from tests.auth_testkit import make_test_approval_authority


@pytest.fixture
def authority_context(tmp_path):
    fixture = Path(__file__).resolve().parents[2] / "cops/contracts/fixtures/valid_action_plan.json"
    plan = ActionPlan.from_dict(json.loads(fixture.read_text(encoding="utf-8")))
    return make_test_approval_authority(tmp_path, plan)


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="the production authority socket boundary is Linux-only",
)
def test_authority_listener_requires_protected_startup_and_leaves_no_socket(authority_context):
    authority, _, _ = authority_context
    control_dir = Path(tempfile.mkdtemp(prefix="cops-control-", dir="/tmp"))
    os.chown(control_dir, -1, authority.worker_gid)
    control_dir.chmod(0o2710)
    try:
        server = ApprovalAuthorityServer(control_dir / "authority.sock", authority)

        with server.listener() as listener:
            socket_stat = os.lstat(server.socket_path)
            assert stat.S_ISSOCK(socket_stat.st_mode)
            assert stat.S_IMODE(socket_stat.st_mode) == 0o660
            assert listener.get_inheritable() is False

        assert not os.path.lexists(server.socket_path)
    finally:
        shutil.rmtree(control_dir)
