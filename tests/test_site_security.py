from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

from shadowshield import __version__

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


def test_public_site_version_matches_the_package() -> None:
    index = (SITE / "index.html").read_text(encoding="utf-8")
    og = (SITE / "og.html").read_text(encoding="utf-8")
    llms = (SITE / "llms-full.txt").read_text(encoding="utf-8")

    assert f'"softwareVersion": "{__version__}"' in index
    assert f"v<b>{__version__}</b>" in index
    assert f"v{__version__} · Agentic-AI Security" in og
    assert f"Version: {__version__}" in llms


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


def test_every_inline_block_is_covered_by_the_csp_and_attributes_are_absent() -> None:
    csp = _headers(_site_config())["Content-Security-Policy"]

    for filename, expected_blocks in (("index.html", 4), ("og.html", 1)):
        html = (SITE / filename).read_text(encoding="utf-8")
        assert re.search(r"\sstyle\s*=", html, re.IGNORECASE) is None
        assert re.search(r"\son[a-z]+\s*=", html, re.IGNORECASE) is None
        for dynamic_sink in (
            ".style.",
            ".cssText",
            ".innerHTML",
            ".insertRule",
            ".setAttribute",
            "eval(",
        ):
            assert dynamic_sink not in html

        blocks = re.findall(
            r"<(script|style)([^>]*)>(.*?)</\1>",
            html,
            flags=re.IGNORECASE | re.DOTALL,
        )
        assert len(blocks) == expected_blocks
        for tag, attributes, body in blocks:
            assert "src=" not in attributes.lower()
            digest = _csp_hash(body)
            assert f"'{digest}'" in csp, f"{filename} {tag} block is missing CSP hash {digest}"
