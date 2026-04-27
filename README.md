# audit-verify

Standalone, offline verifier for RelayOne audit chains.

This is the customer-side proof tool that backs RelayOne's sovereign-trust-root
guarantee. It connects directly to the customer's Postgres (and optional
Mongo) and verifies the audit log without ever calling back to a vendor
service. The vendor service cannot be in the trust path of its own audit
log; this binary closes that loop.

## Why this exists

The TypeScript `evidence-verify` CLI shipped in `packages/cli` calls the
RelayOne control-plane HTTP API to do the actual verification. That is fine
for support tooling but it's incompatible with the sales pitch:

> "Even RelayOne can't tamper with your audit log — and you can prove it."

If the customer's verification command terminates inside a process operated
by the vendor, the vendor *is* in the trust path. The customer cannot
distinguish a real "OK" from a "the vendor lied to me about OK".

`audit-verify` runs entirely on the customer's host, uses the customer's
public key, reads the customer's database directly, and emits an exit
code that no vendor process ever influenced.

## What it verifies

1. **Per-event hash chain.** Every row in `audit_events` has a
   `previous_event_hash` pointing to the prior row's `event_hash`. The
   verifier walks the table in `(org_id, timestamp, id)` order and rejects
   any row whose `previous_event_hash` does not equal the running expected
   value. The first divergent row is reported with both expected and found
   hashes.

2. **Merkle-root reconstruction over signed seal checkpoints.** Each row
   in `audit_log_seals` describes a batch with `start_time`, `end_time`,
   `event_count`, and a stored `merkle_root`. The verifier collects the
   rows in that time window, sorts by timestamp ascending (matching the
   server's seal builder), and recomputes the Merkle root using the same
   algorithm as `apps/control-plane/src/modules/audit/immutable-log.service.ts`:
   bottom-up SHA-256, hex-concat children, duplicate the last child when
   the level is odd. A mismatch is reported with the seal id, expected
   root, and recomputed root.

3. **Seal signature.** Each seal's `signature` field is base64-encoded
   Ed25519 over the canonical JSON of
   `{orgId, batchNumber, merkleRoot, startTime, endTime, eventCount, previousSealId}`.
   The verifier checks each seal against the customer-supplied
   `--pubkey`. Any mismatch is a fatal failure with the seal id and batch
   number.

4. **Gaps.** A seal that declares `event_count=N` for a time window where
   fewer than N rows are present is reported as a `gap`. A row whose
   `previous_event_hash` matches an earlier (non-immediate) hash in the
   chain is also classified as a `gap` (a middle row was deleted).

## Usage

```
audit-verify --postgres <DSN> [--pubkey <path>] [--mongo <URI>] [flags]
```

Run `audit-verify --help` for the full flag list. Common flags:

- `--postgres <DSN>` (required) — Postgres connection string.
- `--pubkey <path>` — customer Ed25519 public key (raw 32 bytes, hex, or base64).
- `--org-id <id>` — restrict to a single tenant.
- `--from-seq <N>` / `--to-seq <N>` — sequence-number range.
- `--checkpoints-table <T>` — defaults to `audit_log_seals`.
- `--events-table <T>` — defaults to `audit_events`.
- `--out-format text|json` — defaults to `text`.

### Exit codes

| Code | Meaning |
|------|---------|
| 0    | Chain OK |
| 2    | TAMPERED row detected |
| 3    | GAP detected |
| 4    | Seal signature invalid or Merkle root mismatch |
| 64   | Configuration error |
| 65   | Database error |

## Build (developer)

```
cd packages/onprem-installer/cmd/audit-verify
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o audit-verify-linux-amd64 .
sha256sum audit-verify-linux-amd64
```

The binary is statically linked. It has no runtime dependencies beyond a
Linux kernel.

## Air-gap install path

The customer obtains the binary by one of:

1. Copying `packages/onprem-installer/cmd/audit-verify/audit-verify-linux-amd64`
   from the open-source repository (Apache-2.0 — see `LICENSE` in this
   directory). They can rebuild it from source on their own hardware to
   eliminate any concern about vendor-supplied binaries.

2. Pulling it from their internal artifact registry alongside the rest of
   the on-prem installer artifacts. The `sha256sum` is published in the
   release notes and pinned in this repository.

3. Cloning the repo, running `go build` themselves. Source is open;
   reproducible builds are a nice-to-have but the source itself is the
   real proof.

To run on an air-gapped host:

```
# 1. Copy the binary onto the customer's audit host (single file, ~6 MB).
scp audit-verify-linux-amd64 audit-host:/usr/local/bin/audit-verify
chmod +x /usr/local/bin/audit-verify

# 2. Place the customer's Ed25519 public key on the same host. The key
#    must be the one whose private half signs the seals - usually held
#    in the customer's HSM or KMS, never on the vendor side.
echo '<base64-pubkey>' > /etc/relayone/audit-pubkey.b64

# 3. Run.
audit-verify \
  --postgres "$AUDIT_DSN" \
  --pubkey   /etc/relayone/audit-pubkey.b64 \
  --org-id   "$ORG_ID" \
  --out-format json > /var/log/audit-verify-$(date +%s).json
echo "exit=$?"
```

The verifier opens exactly one Postgres connection (read-only from the
DB's perspective; only `SELECT` is issued), reads in streaming order, and
exits. There is no outbound network call to any vendor endpoint.

## License

Apache-2.0. See `LICENSE` in this directory. The source code itself is
the proof of the guarantee — anyone can audit it, rebuild it, or replace
it with an alternative implementation that reads the same schema.
