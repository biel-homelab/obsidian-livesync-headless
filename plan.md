# Plan: Fix Slow Startup & False-Positive Encryption Detection

## Context / Diagnosis (verified against live remote 2026-10-10)

Remote: `homelab` DB on `obsidian-sync-...isengard.page` (CouchDB 3.4.2, RTT ~150ms).
Database shape: 881 docs — 854 chunks (`h:` prefix), 27 notes, all plaintext
(`type: plain`, no `e_` flags, no `syncinfo` doc, plaintext paths).

### Root cause 1 — False-positive encryption detection (the crash loop)

`src/livesync/decode-adapter.ts` `looksEncryptedString()` treats any string
starting with `[`, `%`, or `/\:` as encrypted. Real LiveSync V1 ciphertext has a
strict envelope: `["<base64>","<32-hex iv>","<32-hex salt>"]`.

Two chunks in the live DB are plaintext markdown starting with a `[` link:

- `h:1glg4b822a6po` → `[this guide](https://guides.viren070.me/selfhosting/oracle)`
- `h:3bcjzxkxlakhb` → `[Site creation confirmation](https://content.gitbook.com/...)`

Regex test against strict V1 envelope across all 854 chunks: 0 real matches,
2 false positives. Result: `DECRYPT_FAILED` → block actions → auto-arm fails →
daemon exits → Docker restart loop (23 restarts, ~45s cadence).

Upstream commonlib treats the explicit `e_ === true` flag as the authoritative
encrypted signal (`getEncryptionVersion` in `dist/pouchdb/encryption.js`); the
prefix heuristic is only a legacy no-flag fallback.

### Root cause 2 — ~900 sequential HTTP round-trips per sync pass

`inventoryRemoteDocuments` pages `_all_docs` with IDs only, then every chunk is
fetched one-by-one via `fetchChunk` → `assembleChunks`. Measured: 53ms/req →
~45s for 854 chunks. Same 881 docs via `_all_docs?include_docs=true` or
`_bulk_get`: 0.98s in 9 requests.

### Root cause 3 — Startup work done twice + no incremental pulls

- Auto-arm's `executeReadOnlyPullAndMaterialize` does a full inventory+decode+
  materialize, then `ContinuousEngine.executeCatchUpPass` calls
  `SyncCoordinator.sync()` which re-inventories and re-decodes everything.
- Persisted `lastUpdateSeq` checkpoint is saved but never used for pulls — every
  startup and every 300s periodic scan re-reads the whole DB.

### Safety hazard found during diagnosis

`AutoArmCoordinator.runWorkflow` wipes the local vault and state DB
(`cleanupLocalVault`/`cleanupLocalState`) **before** confirming it can read the
remote (e.g., before passphrase feasibility). Currently delete-then-fail on
every restart attempt.

## Phases

### Phase 0 — Fix false-positive encryption detection (unblocks daemon)

1. `decode-adapter.ts`: `e_ === true` is the authoritative encrypted signal.
   Legacy no-flag heuristic must require strict formats:
   - `[` → full V1 envelope `^["[A-Za-z0-9+/=]+","[0-9a-f]{32}","[0-9a-f]{32}"]$`
   - `%` → `%=`/`%~` HKDF prefixes, or `%` + 64-hex IV + 32-hex salt + base64 (V2)
   - `/\:` → unchanged (encrypted meta)
   Otherwise treat as plaintext.
2. `syncinfo.ts`: same strict check on the `[` case.
3. Keep fail-closed behavior for genuinely `e_`-flagged docs missing a passphrase.
4. Tests: plaintext chunk starting with `[` (exact failure case), real V1
   envelope, `%=` HKDF, `e_`-flagged-without-passphrase, obfuscated paths.

### Phase 1 — Batched inventory (~45s → ~1s)

1. `include_docs=true&conflicts=true` on existing `_all_docs` pages.
2. Build in-memory `Map<chunkId, doc>` chunk cache; serve `fetchChunk` from it;
   keep per-doc GET fallback for misses. `assembleChunks` interface unchanged.
3. Pagination via `startkey_docid` instead of `skip=1`.

### Phase 2 — Stop doing startup work twice

Deduplicate daemon startup: when auto-arm just completed a pull, hand its
checkpoint/inventory result to the catch-up pass (or skip the second full pass
when the checkpoint is already current).

### Phase 3 — Incremental pulls

Use persisted `lastUpdateSeq` + `_changes?since=...&style=all_docs` for
steady-state pulls; full inventory only on first contact or checkpoint
invalidation. Periodic scans stop re-reading the whole DB.

### Phase 4 — Safety & operability

1. Auto-arm must validate decryption/passphrase feasibility BEFORE
   `cleanupLocalVault`/`cleanupLocalState`; never clean up when the pull plan
   contains block actions.
2. Per-stage timing logs (probe / inventory / decode / scan / apply).

## Validation

- Unit tests per phase (see tasks.md).
- Integration (testcontainers CouchDB): request counts (≤ ~15 for this DB
  shape), pull correctness for plain/binary/encrypted/conflicted docs.
- Re-run mixed-client interop tests — protocol compatibility must be untouched.

## Expected outcome

Daemon startup for a ~30-note vault drops from ~5 minutes (crash loop + ~45s
sequential fetch) to a few seconds; periodic scans stop being full re-syncs.
