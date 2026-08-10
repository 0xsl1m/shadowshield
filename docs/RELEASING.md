# Releasing ShadowShield

ShadowShield publishes via **PyPI Trusted Publishing** (OpenID Connect from GitHub
Actions). No API token is ever created, stored, or pasted anywhere — PyPI trusts
this specific GitHub workflow directly. The pipeline is
[`publish.yml`](../.github/workflows/publish.yml).

The same GitHub Release also triggers
[`container-release.yml`](../.github/workflows/container-release.yml). It builds
one image from the release tag, generates a CycloneDX SBOM, rejects fixable
high/critical findings, pushes that exact scanned image to GHCR, signs SLSA
provenance and CycloneDX attestations through GitHub's Sigstore-backed OIDC
service, verifies the signed provenance and an anonymous pull by digest, and
attaches `container-digest.txt` plus the SBOM to the GitHub Release.

Build tooling and the production container dependency graph are version- and
hash-locked in `requirements/build.lock` and `requirements/container.lock`.
Release jobs build the sdist and wheel twice and require byte-identical outputs.

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
3. Re-run the failed workflow job. It will reuse an existing image only when the
   version and exact-commit tags resolve to the same digest and its revision and
   version labels match the release **and** that digest already has trusted source
   provenance from this workflow for the exact commit. It never overwrites a
   conflicting or unattested tag. If an interruption happens after an image push
   but before provenance is attached, delete the incomplete version/commit tags
   from GHCR and re-run; the workflow deliberately refuses to bless them.
   Do not publish the digest to operators until the anonymous-pull and
   evidence-attachment steps are green.

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

Do not create the release while required checks are pending. Once trusted source
provenance exists, a partial container release is recoverable by fixing the
failed workflow and using its restricted recovery dispatch from protected
`main`:

```bash
gh workflow run container-release.yml --ref main -f release_tag=vX.Y.Z
```

The recovery path accepts only an existing stable release whose tag resolves to
an exact green commit contained in `main`. Exact matching registry content is
pulled only after its labels and prior release-source SLSA provenance verify,
then it is rescanned and the missing evidence is attached. The recovered SBOM
attestation records the protected `main` workflow commit that performed the
repair; the independently verified SLSA provenance continues to record the exact
release-source commit. An interruption between the first image push and
provenance attachment intentionally needs the incomplete GHCR tags removed
before retry. Conflicting tags and existing evidence assets are never
overwritten. The PyPI version itself cannot be replaced.

Both publication workflows independently reject non-stable tags, tag/source
version mismatches, commits outside `main`, and commits without a successful
exact-SHA `main` CI run. Manual dispatch cannot publish an unattested image: it
is a recovery-only path for an existing release digest with trusted
release-source provenance.

## Verify

```bash
pip index versions shadowshield          # should list the new version
pip install shadowshield==X.Y.Z          # clean-env smoke test
python -c "import shadowshield as ss; print(ss.__version__)"

gh release download vX.Y.Z \
  --pattern container-digest.txt --pattern shadowshield-sbom.cdx.json
digest="$(cat container-digest.txt)"
image="ghcr.io/0xsl1m/shadowshield@$digest"
release_sha="$(git rev-list -n 1 vX.Y.Z)"
# For a normal release, both attestations use the release SHA. If evidence was
# completed by the recovery dispatch, use that successful run's protected-main
# head SHA for evidence_sha:
evidence_sha="$release_sha"
# evidence_sha="$(gh run view RECOVERY_RUN_ID --json headSha --jq .headSha)"
docker pull "$image"
gh attestation verify "oci://$image" \
  --repo 0xsl1m/shadowshield \
  --bundle-from-oci \
  --predicate-type https://slsa.dev/provenance/v1 \
  --signer-workflow 0xsl1m/shadowshield/.github/workflows/container-release.yml \
  --source-digest "$release_sha" \
  --deny-self-hosted-runners
gh attestation verify "oci://$image" \
  --repo 0xsl1m/shadowshield \
  --bundle-from-oci \
  --predicate-type https://cyclonedx.org/bom \
  --signer-workflow 0xsl1m/shadowshield/.github/workflows/container-release.yml \
  --source-digest "$evidence_sha" \
  --deny-self-hosted-runners
```

## Notes

- **Versions are immutable.** A published version can never be re-uploaded, only
  *yanked*. Always confirm `twine check` is green (CI does this) before releasing.
- Regenerate dependency locks only in a dedicated reviewed PR, using the exact
  commands recorded at the top of each lock file; CI audits both locked graphs.
- Deploy the container by the exact `image@sha256` value in
  `container-digest.txt`, never by a mutable version tag or a local Compose
  rebuild. The release SBOM describes that exact pre-push-scanned image.
- The default install stays lightweight; the ML/vector/PII/dataset stacks are
  optional extras (see `pyproject.toml`).
- Want to rehearse first? Configure a second pending publisher on
  <https://test.pypi.org> and add a TestPyPI step — but the production path above
  is already `twine check`-validated.
