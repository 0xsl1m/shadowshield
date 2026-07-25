"""Repository policy checks for GitHub Actions workflow maintenance."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOW_DIR = _ROOT / ".github" / "workflows"
_FULL_SHA = re.compile(r"[0-9a-f]{40}")
_FULL_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_JOB_TIMEOUT_MINUTES = 60


def _workflow_paths() -> list[Path]:
    return sorted((*_WORKFLOW_DIR.glob("*.yml"), *_WORKFLOW_DIR.glob("*.yaml")))


def _uses_values(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "uses":
                assert isinstance(child, str), f"uses must be a string, got {child!r}"
                yield child
            yield from _uses_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _uses_values(child)


def test_workflow_jobs_have_bounded_timeouts_and_actions_are_pinned() -> None:
    paths = _workflow_paths()
    assert paths, "no GitHub Actions workflows found"

    for path in paths:
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(workflow, dict), f"{path} must contain a workflow mapping"

        jobs = workflow.get("jobs")
        assert isinstance(jobs, dict) and jobs, f"{path} must define jobs"
        for job_name, job in jobs.items():
            assert isinstance(job, dict), f"{path}:{job_name} must be a job mapping"
            timeout = job.get("timeout-minutes")
            assert (
                isinstance(timeout, int)
                and not isinstance(timeout, bool)
                and 0 < timeout <= _MAX_JOB_TIMEOUT_MINUTES
            ), (
                f"{path}:{job_name} must set timeout-minutes between "
                f"1 and {_MAX_JOB_TIMEOUT_MINUTES}"
            )

        for uses in _uses_values(workflow):
            if uses.startswith("./"):
                continue
            if uses.startswith("docker://"):
                _, separator, digest = uses.rpartition("@")
                assert separator and _FULL_DIGEST.fullmatch(digest), (
                    f"{path}: Docker action must be pinned to a full digest: {uses}"
                )
                continue
            action, separator, revision = uses.rpartition("@")
            assert separator and "/" in action and _FULL_SHA.fullmatch(revision), (
                f"{path}: action must be pinned to a full commit SHA: {uses}"
            )


def test_release_builds_install_hash_locked_dependencies() -> None:
    build_lock = (_ROOT / "requirements" / "build.lock").read_text(encoding="utf-8")
    container_lock = (_ROOT / "requirements" / "container.lock").read_text(encoding="utf-8")
    for name, lock in (("build", build_lock), ("container", container_lock)):
        requirements = [
            line for line in lock.splitlines() if line and not line[0].isspace() and line[0] != "#"
        ]
        assert requirements, f"{name} lock must contain packages"
        assert all("==" in requirement for requirement in requirements)
        assert "--hash=sha256:" in lock

    dockerfile = (_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert re.fullmatch(
        r"# syntax=docker/dockerfile:1@sha256:[0-9a-f]{64}",
        dockerfile.splitlines()[0],
    )
    assert dockerfile.count("--require-hashes") == 2
    assert "requirements/build.lock" in dockerfile
    assert "requirements/container.lock" in dockerfile
    assert "--no-deps /tmp/*.whl" in dockerfile

    for workflow_name in ("ci.yml", "publish.yml"):
        workflow = (_WORKFLOW_DIR / workflow_name).read_text(encoding="utf-8")
        assert "--require-hashes -r requirements/build.lock" in workflow
        assert "python -m build --no-isolation --outdir dist-a" in workflow
        assert "python -m build --no-isolation --outdir dist-b" in workflow
        assert 'cmp "$artifact" "dist-b/$(basename "$artifact")"' in workflow

    container_release = (_WORKFLOW_DIR / "container-release.yml").read_text(encoding="utf-8")
    assert "resolve_tag_digest" in container_release
    assert "IMAGE_REUSED" in container_release
    assert "org.opencontainers.image.revision" in container_release
    provenance_check = 'gh attestation verify "oci://$image@$resolved_digest"'
    assert provenance_check in container_release
    assert "--predicate-type https://slsa.dev/provenance/v1" in container_release
    assert '--source-digest "$GITHUB_SHA"' in container_release
    assert container_release.index(provenance_check) < container_release.index(
        "reused=true",
        container_release.index(provenance_check),
    )
    assert 'test "$tags_verified" = true' in container_release
    assert "gh release upload" in container_release
    assert "--clobber" not in container_release
