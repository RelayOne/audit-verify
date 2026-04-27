# Releases

## v1.0.0 (2026-04-27)

First public release. Split from the RelayOne monorepo
(`packages/onprem-installer/cmd/audit-verify`) to a standalone public
repository under Apache-2.0 so customers can obtain, audit, rebuild, and
verify the binary entirely independently of any RelayOne-controlled artifact
pipeline.

### What it verifies

1. **Per-event hash chain.** Walks `audit_events` in `(org_id, timestamp, id)`
   order and confirms that each row's `previous_event_hash` equals the prior
   row's `event_hash`. The first divergent row is reported with both expected
   and found hashes. Exit code 2 = TAMPERED, exit code 3 = GAP.

2. **Merkle-root reconstruction.** For each row in `audit_log_seals`, collects
   the events in that batch's `[start_time, end_time]` window, sorts by
   timestamp ascending, and recomputes the bottom-up SHA-256 Merkle tree using
   the same algorithm as
   `apps/control-plane/src/modules/audit/immutable-log.service.ts`. A root
   mismatch exits with code 4 = SEAL_INVALID.

3. **Ed25519 seal signatures.** Verifies each seal's `signature` field against
   the customer-supplied `--pubkey`. The canonical signing payload matches the
   TypeScript seal builder exactly, including JS-style ISO millisecond timestamp
   formatting. Exit code 4 on any signature mismatch.

4. **Gap detection.** A seal that declares `event_count=N` for a window where
   fewer than N rows are present is reported as a GAP. A row whose
   `previous_event_hash` matches an earlier non-immediate chain hash is also
   classified as a GAP (row was deleted from the middle).

### Artifacts

All four platform artifacts are cosign-signed using a GCP KMS key in
`relayone-488319`. Signatures are published alongside the binaries.

| File | Platform |
|---|---|
| `audit-verify-linux-amd64` | Linux / x86-64 |
| `audit-verify-darwin-amd64` | macOS / Intel |
| `audit-verify-darwin-arm64` | macOS / Apple Silicon |
| `audit-verify-windows-amd64.exe` | Windows / x86-64 |
| `SHA256SUMS` | SHA-256 checksums for all binaries |
| `audit-verify-linux-amd64.sig` | cosign signature (linux/amd64) |
| `audit-verify-darwin-amd64.sig` | cosign signature (darwin/amd64) |
| `audit-verify-darwin-arm64.sig` | cosign signature (darwin/arm64) |
| `audit-verify-windows-amd64.exe.sig` | cosign signature (windows/amd64) |

### Verifying the signatures

```bash
cosign verify-blob audit-verify-linux-amd64 \
  --key gcpkms://projects/relayone-488319/locations/global/keyRings/release-signing/cryptoKeys/audit-verify-signing \
  --signature audit-verify-linux-amd64.sig
```

See `BUILD.md` for full cosign verification instructions.

### Database schema compatibility

This release is tested against the schema written by RelayOne v1.0 and later.
Required columns:

`audit_events`: `id`, `org_id`, `timestamp`, `event_type`,
`previous_event_hash`, `event_hash`, `gateway_signature`

`audit_log_seals`: `id`, `org_id`, `batch_number`, `start_time`, `end_time`,
`event_count`, `merkle_root`, `previous_seal_id`, `signature`,
`signing_key_id`, `created_at`

If `audit_log_seals` is absent (fresh install, seal checkpoints not yet
generated), the verifier falls back to hash-chain-only verification and emits
a note. Exit code 0 if the hash chain is intact.

### Changes from the embedded version in the monorepo

- Go module path changed from
  `github.com/relayone/onprem-installer/cmd/audit-verify` to
  `github.com/relayone/audit-verify`.
- Go minimum version lowered from 1.26 to 1.21 to support older toolchains
  in air-gapped customer environments.
- Stresstest run instructions updated to reflect standalone repo layout.
- Build instructions in `BUILD.md` are Cloud Build-native (not GitHub Actions).

### Cross-tenant negative test

See `stresstest/stress_test.go` — `TestCrossTenantIsolation` demonstrates that
tenant A plaintext + tenant B KEK fails to decrypt. This is the cryptographic
proof of per-tenant isolation. Anyone can run:

```bash
cd stresstest
AUDIT_VERIFY_DSN=... go test -run TestCrossTenantIsolation -v .
```

The test generates two tenants with independent HKDF-derived keys, seals a
record under tenant A's key, attempts decryption with tenant B's key, and
asserts failure. Exit 0 = isolation holds. Exit non-zero = isolation broken.
