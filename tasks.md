# Tasks: Fix Slow Startup & False-Positive Encryption Detection

## Phase 0 — Fix false-positive encryption detection (P0, unblocks daemon)

- [x] P0.1 Add strict ciphertext-format validators in `src/livesync/decode-adapter.ts`:
      `looksLikeV1Envelope` (strict `["b64","32hex","32hex"]`), `looksLikeV2Ciphertext`
      (`%` + 64-hex IV + 32-hex salt + base64 body), keep `/\:` meta check as-is.
- [x] P0.2 Rewrite `looksEncryptedString` to use: `e_ === true` handled by caller
      context; heuristic only when no `e_` flag — require strict V1/V2 formats
      instead of bare prefix `startsWith`.
- [x] P0.3 Apply same strict check in `src/livesync/syncinfo.ts` `[` case.
- [x] P0.4 Keep fail-closed for `e_`-flagged docs without passphrase (no behavior change).
- [x] P0.5 Unit tests: plaintext chunk starting with `[` (exact live failure case),
      real V1 envelope, `%=` HKDF, `e_`-flagged-without-passphrase, obfuscated
      paths, `syncinfo` `[` false positive. Update existing tests that relied on
      loose prefix matching.
- [x] P0.6 Run full unit test suite + characterization tests green.

## Phase 1 — Batched inventory (~45s → ~1s)

- [x] P1.1 `inventoryRemoteDocuments`: add `include_docs=true&conflicts=true` to
      `_all_docs` paging; emit chunk docs with bodies.
- [x] P1.2 Build in-memory `Map<chunkId, doc>` chunk cache; wire a cache-first
      `fetchChunk` in `SyncCoordinator` and `AutoArmCoordinator`; per-doc GET
      fallback on miss. `assembleChunks` interface unchanged.
- [x] P1.3 Fix pagination to `startkey_docid` instead of `skip=1`.
- [x] P1.4 Unit tests: cache hit/miss, fallback path, paging correctness.
- [x] P1.5 Integration: request-count assertion (≤ ~15 requests for 881-doc shape)
      using testcontainers CouchDB.

## Phase 2 — Stop doing startup work twice

- [x] P2.1 Daemon: skip/short-circuit second full sync pass when auto-arm just
      completed a pull (reuse checkpoint freshness).
- [x] P2.2 Unit tests: daemon startup does one inventory pass after auto-arm.

## Phase 3 — Incremental pulls

- [x] P3.1 `SyncCoordinator`: use persisted `lastUpdateSeq` +
      `_changes?since=...&style=all_docs` for steady-state pulls; full inventory
      only on first contact or checkpoint invalidation.
- [x] P3.2 Periodic scans use incremental path; full scan only after errors or
      identity change.
- [x] P3.3 Unit tests: since-token use, invalidation fallback, checkpoint advance
      only after commit.
- [x] P3.4 Integration: incremental pull applies only new changes; no history purge.

## Phase 4 — Safety & operability

- [x] P4.1 Auto-arm: validate remote readability + passphrase feasibility BEFORE
      `cleanupLocalVault`/`cleanupLocalState`; abort before any cleanup when pull
      plan contains block actions.
- [x] P4.2 Unit tests: cleanup never runs when passphrase missing; cleanup never
      runs when block actions present.
- [x] P4.3 Add per-stage timing logs (probe / inventory / decode / scan / apply).
- [x] P4.4 Full test suite + mixed-client interop tests green.

## Validation (cross-phase)

- [ ] V.1 Full unit suite green.
- [ ] V.2 Integration suite (testcontainers) green.
- [ ] V.3 Mixed-client interop tests green (protocol compatibility untouched).
- [ ] V.4 Live smoke: deploy image to `boromir` stack, confirm daemon reaches
      steady state without restart loop; log timings visible.
