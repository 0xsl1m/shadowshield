"""Fail-closed checks for the manual existing-digest signing workflow."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

_WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "shadowshield-sign-existing-v0.10.2.yml"
)
_SHA = "a" * 40
_OTHER_SHA = "b" * 40
_IMAGE = "ghcr.io/0xsl1m/shadowshield@sha256:0d6a7678abc0a95fbccf2bc83b47752c488984e244f322e0c6b57c3f45b772e3"
_RELEASE_SHA = "6967ac893213c56a6fb1ce57c44a6e90757deba5"


def _dispatch_step() -> tuple[dict, dict]:
    workflow = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    # PyYAML's YAML 1.1 parser treats the Actions `on` key as a boolean.
    events = workflow.get("on", workflow.get(True))
    dispatch = events["workflow_dispatch"]
    assert set(workflow["jobs"]) == {"sign-existing-digest"}
    steps = workflow["jobs"]["sign-existing-digest"]["steps"]
    assert len(steps) == 1
    step = steps[0]
    return dispatch, step


def test_dispatch_requires_sha_and_passes_it_only_through_env() -> None:
    dispatch, step = _dispatch_step()
    sha_input = dispatch["inputs"]["expected_main_sha"]
    assert sha_input["type"] == "string"
    assert sha_input["required"] is True
    assert "default" not in sha_input
    assert step["env"]["EXPECTED_MAIN_SHA"] == "${{ inputs.expected_main_sha }}"
    assert "${{ inputs.expected_main_sha }}" not in step["run"]


def test_signing_target_is_fixed_to_verified_release() -> None:
    workflow = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    events = workflow.get("on", workflow.get(True))
    assert set(events) == {"workflow_dispatch"}
    _, step = _dispatch_step()
    script = step["run"]
    assert f"image='{_IMAGE}'" in script
    assert f"source_sha='{_RELEASE_SHA}'" in script
    assert "--source-ref refs/tags/v0.10.2" in script
    assert '--cert-identity "$original_identity"' in script
    assert '"$cosign_bin" sign --yes "$image"' in script
    assert "v0.10.1" not in script


@pytest.mark.parametrize(
    ("expected", "github_sha", "workflow_sha", "expected_exit"),
    [
        (None, _SHA, _SHA, 1),
        ("", _SHA, _SHA, 1),
        ("A" * 40, _SHA, _SHA, 1),
        ("a" * 39, _SHA, _SHA, 1),
        ("g" * 40, _SHA, _SHA, 1),
        (_OTHER_SHA, _SHA, _SHA, 1),
        (_SHA, _OTHER_SHA, _SHA, 1),
        (_SHA, _SHA, _OTHER_SHA, 1),
        (_SHA, _SHA, _SHA, 90),
    ],
)
def test_dispatch_sha_gates_network_and_registry(
    expected: str | None, github_sha: str, workflow_sha: str, expected_exit: int
) -> None:
    _, step = _dispatch_step()
    bash = Path("C:/Program Files/Git/bin/bash.exe") if os.name == "nt" else shutil.which("bash")
    if not bash or not Path(bash).is_file():
        pytest.skip("Bash is unavailable")

    # The workflow body is executed, but these functions make a misplaced
    # download, registry login, or signing command observable without network.
    blocked_commands = """\
curl() { echo REACHED_EXTERNAL_COMMAND >&2; exit 90; }
docker() { echo REACHED_EXTERNAL_COMMAND >&2; exit 90; }
gh() { echo REACHED_EXTERNAL_COMMAND >&2; exit 90; }
cosign() { echo REACHED_EXTERNAL_COMMAND >&2; exit 90; }
mkdir() { :; }
"""
    env = os.environ.copy()
    env.update(
        GITHUB_SHA=github_sha,
        GITHUB_WORKFLOW_SHA=workflow_sha,
        GITHUB_REPOSITORY="0xsl1m/shadowshield",
        GITHUB_REF="refs/heads/main",
        GITHUB_EVENT_NAME="workflow_dispatch",
        GITHUB_RUN_ATTEMPT="1",
        GITHUB_WORKFLOW_REF=(
            "0xsl1m/shadowshield/.github/workflows/"
            "shadowshield-sign-existing-v0.10.2.yml@refs/heads/main"
        ),
    )
    if expected is None:
        env.pop("EXPECTED_MAIN_SHA", None)
    else:
        env["EXPECTED_MAIN_SHA"] = expected
    result = subprocess.run(
        [str(bash), "-c", blocked_commands + step["run"]],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == expected_exit, result.stderr
    assert ("REACHED_EXTERNAL_COMMAND" in result.stderr) is (expected_exit == 90)
