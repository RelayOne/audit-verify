# Build and Release

## Building locally

`audit-verify` is a statically linked Go binary with a single dependency
(`github.com/lib/pq`). CGO is disabled. It runs on any Linux/macOS/Windows host
without installing a Go runtime.

```bash
# Linux/amd64
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags='-s -w' \
  -o audit-verify-linux-amd64 .

# macOS/amd64 (Intel)
CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -ldflags='-s -w' \
  -o audit-verify-darwin-amd64 .

# macOS/arm64 (Apple Silicon)
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags='-s -w' \
  -o audit-verify-darwin-arm64 .

# Windows/amd64
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags='-s -w' \
  -o audit-verify-windows-amd64.exe .
```

SHA-256 checksums:

```bash
sha256sum audit-verify-linux-amd64 \
          audit-verify-darwin-amd64 \
          audit-verify-darwin-arm64 \
          audit-verify-windows-amd64.exe > SHA256SUMS
```

## Reproducible builds

To verify a pre-built binary matches the source:

1. Install Go 1.21 or later.
2. Clone this repo and check out the tagged commit:
   ```bash
   git clone https://github.com/relayone/audit-verify
   git checkout v1.0.0
   ```
3. Build with the same flags as above for your target platform.
4. Compare SHA-256 of your binary with the published `SHA256SUMS` file in the
   release artifacts. The binary should match byte-for-byte when built with the
   same Go toolchain version.

Note: `-ldflags='-s -w'` strips debug symbols and the DWARF table to reduce
binary size. The flags themselves are deterministic; the output hash depends on
the Go toolchain version. The published checksums are built with Go 1.21.

## Cosign signature verification

Release binaries are signed with [cosign](https://github.com/sigstore/cosign)
using a GCP KMS key managed in `relayone-488319`.

To verify:

```bash
# Install cosign
brew install cosign            # macOS
go install github.com/sigstore/cosign/v2/cmd/cosign@latest  # any platform

# Verify a binary (example: linux/amd64)
# The canonical GCP KMS URI form is:
#   gcpkms://projects/<proj>/locations/<loc>/keyRings/<ring>/cryptoKeys/<key>/cryptoKeyVersions/<ver>
# (note: cryptoKeys/<name> then cryptoKeyVersions/<version> — NOT cryptoKeyVersions/<name>)
cosign verify-blob audit-verify-linux-amd64 \
  --key gcpkms://projects/relayone-488319/locations/global/keyRings/release-signing/cryptoKeys/audit-verify-signing/cryptoKeyVersions/1 \
  --signature audit-verify-linux-amd64.sig
```

## CI/CD: Cloud Build (not GitHub Actions)

All CI and release builds run on GCP Cloud Build in project `relayone-488319`.
We do not use GitHub Actions for any build, test, or release automation.

### Cloud Build trigger (release)

The release trigger is configured in GCP Cloud Build and fires when a tag
matching `v[0-9]*` is pushed to this repository.

Trigger configuration (apply via `gcloud builds triggers create`):

```yaml
# cloudbuild-release.yaml (stored in this repo)
# Builds four target platforms, signs binaries with cosign + GCP KMS,
# and creates a GitHub release with the signed artifacts.
steps:
  - name: golang:1.21
    id: build-linux-amd64
    env:
      - CGO_ENABLED=0
      - GOOS=linux
      - GOARCH=amd64
    args: [go, build, -ldflags=-s -w, -o, /workspace/dist/audit-verify-linux-amd64, .]

  - name: golang:1.21
    id: build-darwin-amd64
    env:
      - CGO_ENABLED=0
      - GOOS=darwin
      - GOARCH=amd64
    args: [go, build, -ldflags=-s -w, -o, /workspace/dist/audit-verify-darwin-amd64, .]

  - name: golang:1.21
    id: build-darwin-arm64
    env:
      - CGO_ENABLED=0
      - GOOS=darwin
      - GOARCH=arm64
    args: [go, build, -ldflags=-s -w, -o, /workspace/dist/audit-verify-darwin-arm64, .]

  - name: golang:1.21
    id: build-windows-amd64
    env:
      - CGO_ENABLED=0
      - GOOS=windows
      - GOARCH=amd64
    args: [go, build, -ldflags=-s -w, -o, /workspace/dist/audit-verify-windows-amd64.exe, .]

  - name: gcr.io/google.com/cloudsdktool/cloud-sdk:slim
    id: sha256sums
    script: |
      sha256sum /workspace/dist/audit-verify-* > /workspace/dist/SHA256SUMS

  - name: gcr.io/projectsigstore/cosign:v2
    id: cosign-sign-linux-amd64
    args:
      - sign-blob
      - /workspace/dist/audit-verify-linux-amd64
      - --key
      - gcpkms://projects/relayone-488319/locations/global/keyRings/release-signing/cryptoKeys/audit-verify-signing
      - --output-signature
      - /workspace/dist/audit-verify-linux-amd64.sig

  - name: gcr.io/projectsigstore/cosign:v2
    id: cosign-sign-darwin-amd64
    args:
      - sign-blob
      - /workspace/dist/audit-verify-darwin-amd64
      - --key
      - gcpkms://projects/relayone-488319/locations/global/keyRings/release-signing/cryptoKeys/audit-verify-signing
      - --output-signature
      - /workspace/dist/audit-verify-darwin-amd64.sig

  - name: gcr.io/projectsigstore/cosign:v2
    id: cosign-sign-darwin-arm64
    args:
      - sign-blob
      - /workspace/dist/audit-verify-darwin-arm64
      - --key
      - gcpkms://projects/relayone-488319/locations/global/keyRings/release-signing/cryptoKeys/audit-verify-signing
      - --output-signature
      - /workspace/dist/audit-verify-darwin-arm64.sig

  - name: gcr.io/projectsigstore/cosign:v2
    id: cosign-sign-windows-amd64
    args:
      - sign-blob
      - /workspace/dist/audit-verify-windows-amd64.exe
      - --key
      - gcpkms://projects/relayone-488319/locations/global/keyRings/release-signing/cryptoKeys/audit-verify-signing
      - --output-signature
      - /workspace/dist/audit-verify-windows-amd64.exe.sig

  - name: gcr.io/google.com/cloudsdktool/cloud-sdk:slim
    id: github-release
    secretEnv: [GITHUB_TOKEN]
    script: |
      TAG=$(echo $TAG_NAME)
      gh release create "$TAG" /workspace/dist/* \
        --repo RelayOne/audit-verify \
        --title "audit-verify $TAG" \
        --notes-file RELEASES.md

availableSecrets:
  secretManager:
    - versionName: projects/relayone-488319/secrets/github-release-token/versions/latest
      env: GITHUB_TOKEN

serviceAccount: projects/relayone-488319/serviceAccounts/release-builder@relayone-488319.iam.gserviceaccount.com
```

### To register the Cloud Build trigger

```bash
gcloud builds triggers create github \
  --project=relayone-488319 \
  --repo-name=audit-verify \
  --repo-owner=RelayOne \
  --tag-pattern="v[0-9].*" \
  --build-config=cloudbuild-release.yaml \
  --name=audit-verify-release \
  --description="Build, sign, and release audit-verify on version tags"
```

The trigger requires:
- A Cloud Build service account `release-builder@relayone-488319.iam.gserviceaccount.com` with `roles/cloudkms.signer` on the `audit-verify-signing` key.
- A Secret Manager secret `github-release-token` with a GitHub PAT that has `repo` scope on `RelayOne/audit-verify`.

### Unit tests (PR trigger)

A separate Cloud Build trigger fires on every pull request and runs:

```bash
go test ./...
go vet ./...
```

The stresstest in `stresstest/` is excluded from the PR trigger (it requires a
live Postgres) and runs only in the nightly integration trigger against a
Cloud SQL instance.
