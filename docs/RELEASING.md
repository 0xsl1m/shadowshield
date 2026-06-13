# Releasing ShadowShield to PyPI

ShadowShield publishes via **PyPI Trusted Publishing** (OpenID Connect from GitHub
Actions). No API token is ever created, stored, or pasted anywhere — PyPI trusts
this specific GitHub workflow directly. The pipeline is
[`.github/workflows/publish.yml`](../.github/workflows/publish.yml).

## One-time setup (PyPI account owner only)

This must be done in the PyPI web UI by the account that will own the project —
it cannot be automated.

1. Create a PyPI account (and enable 2FA): <https://pypi.org/account/register/>.
2. Go to **<https://pypi.org/manage/account/publishing/>** → "Add a new pending
   publisher" and enter **exactly**:
   - **PyPI Project Name:** `shadowshield`
   - **Owner:** `0xsl1m`
   - **Repository name:** `shadowshield`
   - **Workflow name:** `publish.yml`
   - **Environment name:** *(leave blank — the workflow declares no environment)*
3. Save. This registers a *pending publisher*; the PyPI project is created
   automatically on the first successful publish.

> Optional hardening: create a GitHub Environment named `pypi` with required
> reviewers, add `environment: pypi` to the `publish` job, and set the same
> environment name in the PyPI publisher config. Then every publish needs manual
> approval in GitHub.

## Cutting a release

Trusted publishing fires automatically when a **GitHub Release is published**:

```bash
# 1. bump the version in pyproject.toml + src/shadowshield/__init__.py, update CHANGELOG
# 2. commit + push to main
git tag -a vX.Y.Z -m "ShadowShield X.Y.Z"
git push origin vX.Y.Z
gh release create vX.Y.Z --title "ShadowShield X.Y.Z" --notes "..."
# -> the Publish workflow builds, twine-checks, and uploads to PyPI via OIDC
```

To publish the **current** version without a new release (e.g. the first publish
of an already-tagged version), trigger the workflow manually:

```bash
gh workflow run publish.yml --ref main
gh run watch        # follow it
```

## Verify

```bash
pip index versions shadowshield          # should list the new version
pip install shadowshield==X.Y.Z          # clean-env smoke test
python -c "import shadowshield as ss; print(ss.__version__)"
```

## Notes

- **Versions are immutable.** A published version can never be re-uploaded, only
  *yanked*. Always confirm `twine check` is green (CI does this) before releasing.
- The default install stays lightweight; the ML/vector/PII/dataset stacks are
  optional extras (see `pyproject.toml`).
- Want to rehearse first? Configure a second pending publisher on
  <https://test.pypi.org> and add a TestPyPI step — but the production path above
  is already `twine check`-validated.
