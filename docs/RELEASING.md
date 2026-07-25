# Releasing ShadowShield

ShadowShield publishes via **PyPI Trusted Publishing** (OpenID Connect from GitHub
Actions). No API token is ever created, stored, or pasted anywhere — PyPI trusts
this specific GitHub workflow directly. The pipeline is
[`publish.yml`](../.github/workflows/publish.yml).

The same GitHub Release also triggers
[`container-release.yml`](../.github/workflows/container-release.yml). It builds
one image from the release tag, generates a CycloneDX SBOM, rejects fixable
high/critical findings, pushes that exact scanned image to GHCR, verifies an
anonymous pull by digest, and attaches `container-digest.txt` plus the SBOM to
the GitHub Release.

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

## One-time setup (GHCR package owner only)

GitHub may create a first-published container package as private. The release
workflow deliberately fails its anonymous-pull gate if that happens.

1. Let the first `Publish release container` run push the package.
2. If the anonymous-pull step fails, open the `shadowshield` package settings
   under the `0xsl1m` account and change visibility to **Public**.
3. Re-run the failed workflow job. Do not publish the release digest to operators
   until the anonymous pull and evidence-attachment steps are green.

## Cutting a release

Only release an exact commit whose PR and `main` CI checks are green:

```bash
# 1. bump the version in pyproject.toml + src/shadowshield/__init__.py, update CHANGELOG
# 2. merge through a reviewed PR and wait for main CI + site deployment
# 3. create the release/tag at that exact merge commit
merge_sha="$(git rev-parse origin/main)"
gh release create vX.Y.Z --target "$merge_sha" \
  --title "ShadowShield X.Y.Z" --notes "..."
# -> PyPI publishing and exact-image scan/publish run independently
```

Do not create the release while required checks are pending. A partial release
is recoverable by fixing the failed workflow and re-running it, but the PyPI
version itself cannot be replaced.

To publish the **current** Python version without a new release (for example, the
first publish of an already-tagged version), trigger only the PyPI workflow:

```bash
gh workflow run publish.yml --ref main
gh run watch        # follow it
```

## Verify

```bash
pip index versions shadowshield          # should list the new version
pip install shadowshield==X.Y.Z          # clean-env smoke test
python -c "import shadowshield as ss; print(ss.__version__)"

gh release download vX.Y.Z \
  --pattern container-digest.txt --pattern shadowshield-sbom.cdx.json
docker pull "ghcr.io/0xsl1m/shadowshield@$(cat container-digest.txt)"
```

## Notes

- **Versions are immutable.** A published version can never be re-uploaded, only
  *yanked*. Always confirm `twine check` is green (CI does this) before releasing.
- Deploy the container by the exact `image@sha256` value in
  `container-digest.txt`, never by a mutable version tag or a local Compose
  rebuild. The release SBOM describes that exact pre-push-scanned image.
- The default install stays lightweight; the ML/vector/PII/dataset stacks are
  optional extras (see `pyproject.toml`).
- Want to rehearse first? Configure a second pending publisher on
  <https://test.pypi.org> and add a TestPyPI step — but the production path above
  is already `twine check`-validated.
