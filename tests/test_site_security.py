from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"


def _site_config() -> dict[str, object]:
    return json.loads((SITE / "vercel.json").read_text(encoding="utf-8"))


def _headers(config: dict[str, object]) -> dict[str, str]:
    rules = config["headers"]
    assert isinstance(rules, list)
    catch_all = next(rule for rule in rules if rule["source"] == "/(.*)")
    return {item["key"]: item["value"] for item in catch_all["headers"]}


def _csp_hash(body: str) -> str:
    digest = hashlib.sha256(body.encode()).digest()
    return "sha256-" + base64.b64encode(digest).decode()


def test_www_redirects_to_canonical_apex_without_open_redirect() -> None:
    config = _site_config()
    assert config["redirects"] == [
        {
            "source": "/(.*)",
            "has": [{"type": "host", "value": "www.shadowshield.xyz"}],
            "destination": "https://shadowshield.xyz/$1",
            "permanent": True,
        }
    ]


def test_public_site_version_matches_latest_changelog_release() -> None:
    index = (SITE / "app" / "page.tsx").read_text(encoding="utf-8")
    og = (SITE / "og.html").read_text(encoding="utf-8")
    llms = (SITE / "llms-full.txt").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    released = re.search(r"^## \[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}$", changelog, re.MULTILINE)
    assert released is not None
    version = released.group(1)

    assert f"V{version}" in index
    assert json.loads((SITE / "package.json").read_text(encoding="utf-8"))["version"] == version
    assert f"v{version} · Agentic-AI Security" in og
    assert f"Version: {version}" in llms


def test_site_security_headers_are_fail_closed() -> None:
    headers = _headers(_site_config())
    assert headers["Strict-Transport-Security"] == ("max-age=63072000; includeSubDomains; preload")
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert headers["Referrer-Policy"] == "strict-origin-when-cross-origin"

    permissions = headers["Permissions-Policy"]
    for capability in (
        "accelerometer",
        "autoplay",
        "browsing-topics",
        "camera",
        "geolocation",
        "gyroscope",
        "magnetometer",
        "microphone",
        "payment",
        "usb",
    ):
        assert f"{capability}=()" in permissions

    csp = headers["Content-Security-Policy"]
    assert "'unsafe-inline'" not in csp
    assert "'unsafe-eval'" not in csp
    for directive in (
        "script-src-attr 'none'",
        "style-src-attr 'none'",
        "object-src 'none'",
        "frame-src 'none'",
        "worker-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        "form-action 'none'",
        "upgrade-insecure-requests",
    ):
        assert directive in csp


def test_static_export_is_checked_before_deploy() -> None:
    csp = _headers(_site_config())["Content-Security-Policy"]
    package = json.loads((SITE / "package.json").read_text(encoding="utf-8"))
    assert (
        package["scripts"]["build"]
        == "node scripts/prepare-assets.mjs && next build && node scripts/csp.mjs --check"
    )
    assert _site_config()["buildCommand"] == "npm run build"
    assert _site_config()["outputDirectory"] == "out"
    html = (SITE / "og.html").read_text(encoding="utf-8")
    assert re.search(r"\sstyle\s*=", html, re.IGNORECASE) is None
    assert re.search(r"\son[a-z]+\s*=", html, re.IGNORECASE) is None
    for body in re.findall(r"<style[^>]*>(.*?)</style>", html, re.IGNORECASE | re.DOTALL):
        assert f"'{_csp_hash(body)}'" in csp
