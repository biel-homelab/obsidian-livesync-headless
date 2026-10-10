import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { CouchDbTestHarness } from './couchdb-harness.js';
import { SyncCoordinator } from '../../src/domain/sync-coordinator.js';
import { openDatabase } from '../../src/storage/sqlite.js';
import { ProvenanceRepository } from '../../src/storage/provenance-repo.js';

/**
 * Phase 1 regression guard: startup pull must use the batched inventory
 * (include_docs=true) plus the in-memory chunk cache so that a database with
 * tens of chunk documents is pulled in a handful of HTTP requests instead of
 * one request per document/chunk.
 */
describe('Batched inventory request-count integration (Real CouchDB)', () => {
  const harness = new CouchDbTestHarness();
  let tempDir: string;
  let vaultDir: string;
  let stateDir: string;

  beforeAll(async () => {
    await harness.start();
  }, 120000);

  afterAll(async () => {
    await harness.stop();
  }, 60000);

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'inventory-batch-test-'));
    vaultDir = path.join(tempDir, 'vault');
    stateDir = path.join(tempDir, 'state');
    fs.mkdirSync(vaultDir, { recursive: true });
    fs.mkdirSync(stateDir, { recursive: true });
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  function countingFetch() {
    const requests: { url: string; method: string }[] = [];
    const counted: typeof globalThis.fetch = async (input, init) => {
      requests.push({
        url: input.toString(),
        method: init?.method ?? 'GET',
      });
      return fetch(input, init);
    };
    return { counted, requests };
  }

  it('pulls ~40 chunk docs + 10 notes in a small number of HTTP requests with correct contents', async () => {
    const dbName = 'inventory-batch-request-count';
    await harness.createDatabase(dbName);
    await harness.seedLiveSyncData(dbName, { version: 12, locked: false });

    // 10 chunked notes (2 chunks each = 20 chunk docs)
    const noteContents: string[] = [];
    for (let i = 1; i <= 10; i++) {
      const content = `# Batched Note ${i}\n\n${'x'.repeat(100)}\n`;
      noteContents.push(content);
      await harness.seedChunkedPlainNote(dbName, `Batched${String(i).padStart(2, '0')}.md`, content);
    }

    // 20 additional standalone chunk docs (total 40 chunk docs)
    for (let i = 1; i <= 20; i++) {
      await harness.putDocument(dbName, `h:orphan-chunk-${i}`, {
        _id: `h:orphan-chunk-${i}`,
        type: 'leaf',
        data: `orphan-${i}`,
      });
    }

    const { counted, requests } = countingFetch();
    const statePath = path.join(stateDir, 'state.sqlite');

    const coordinator = new SyncCoordinator({
      baseUrl: harness.getBaseUrl(),
      databaseName: dbName,
      vaultRoot: vaultDir,
      statePath,
      dryRun: false,
      pullOnly: true,
      credentials: harness.getCredentials(),
      // Harness seeds note ids with path2id_base(..., caseInsensitive=true),
      // so decode must run in case-insensitive mode to match.
      remoteFingerprint: 'fp-batched-inventory',
      fetch: counted,
    });

    const result = await coordinator.sync();

    expect(result.ok).toBe(true);
    expect(result.errors).toEqual([]);

    // Request budget: with include_docs=true inventory (1 page for ≤100 docs)
    // plus the chunk cache serving assembly from memory, the pull must stay a
    // small constant — not one request per chunk (the pre-fix behavior would
    // issue ~45+ requests for this shape).
    expect(requests.length).toBeLessThanOrEqual(15);

    const allDocsRequests = requests.filter((r) => r.url.includes('/_all_docs'));
    expect(allDocsRequests.length).toBe(1);
    const allDocsUrl = new URL(allDocsRequests[0].url);
    expect(allDocsUrl.searchParams.get('include_docs')).toBe('true');
    expect(allDocsUrl.searchParams.get('conflicts')).toBe('true');

    // No per-chunk document GETs at all: every chunk is served from cache.
    const chunkGetRequests = requests.filter((r) => /\/h%3[Aa]|\/h:/.test(r.url));
    expect(chunkGetRequests.length).toBe(0);

    // Pull correctness: all 10 files materialized with exact contents.
    for (let i = 1; i <= 10; i++) {
      const fileName = `Batched${String(i).padStart(2, '0')}.md`;
      const onDisk = fs.readFileSync(path.join(vaultDir, fileName), 'utf8');
      expect(onDisk).toBe(noteContents[i - 1]);
    }

    // Provenance recorded for every pulled note.
    const db = openDatabase(statePath);
    try {
      const provRepo = new ProvenanceRepository(db);
      const provenance = provRepo.getAllAsMap();
      expect(provenance.size).toBe(10);
      for (let i = 1; i <= 10; i++) {
        expect(provenance.has(`Batched${String(i).padStart(2, '0')}.md`)).toBe(true);
      }
    } finally {
      db.close();
    }
  }, 60000);
});
