import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { CouchDbTestHarness } from './couchdb-harness.js';
import { SyncCoordinator } from '../../src/domain/sync-coordinator.js';
import { openDatabase } from '../../src/storage/sqlite.js';
import { ProvenanceRepository } from '../../src/storage/provenance-repo.js';
import { CheckpointRepository } from '../../src/storage/checkpoint-repo.js';

/**
 * Phase 3 integration guard: a pull-only pass with a persisted checkpoint must
 * fetch ONLY the documents changed since the checkpoint (via
 * `_changes?since=...`) instead of re-inventorying the entire database, apply
 * the delta correctly, and never purge remote history (revisions preserved).
 */
describe('Incremental pull integration (Real CouchDB)', () => {
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
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'incremental-pull-test-'));
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

  function pullOnlyCoordinator(
    dbName: string,
    statePath: string,
    fetchFn: typeof globalThis.fetch,
    updateSeq?: string
  ) {
    return new SyncCoordinator({
      baseUrl: harness.getBaseUrl(),
      databaseName: dbName,
      vaultRoot: vaultDir,
      statePath,
      dryRun: false,
      pullOnly: true,
      credentials: harness.getCredentials(),
      // Harness seeds note ids with path2id_base(..., caseInsensitive=true),
      // so decode must run in case-insensitive mode to match.
      remoteFingerprint: 'fp-incremental-pull',
      updateSeq,
      fetch: fetchFn,
    });
  }

  async function fetchUpdateSeq(dbName: string): Promise<string> {
    const creds = harness.getCredentials();
    const res = await fetch(new URL(`/${encodeURIComponent(dbName)}`, harness.getBaseUrl()).toString(), {
      headers: {
        Authorization: 'Basic ' + Buffer.from(`${creds.username}:${creds.password}`).toString('base64'),
      },
    });
    const json = (await res.json()) as { update_seq?: string | number };
    return String(json.update_seq ?? '0');
  }

  it('second pull after remote writes fetches only the delta and preserves history', async () => {
    const dbName = 'incremental-pull-delta';
    await harness.createDatabase(dbName);
    await harness.seedLiveSyncData(dbName, { version: 12, locked: false });
    const statePath = path.join(stateDir, 'state.sqlite');

    // ---- Pass 1: full-inventory first contact with 2 notes ----
    await harness.writeUpstreamPlainNote(dbName, 'Alpha.md', '# Alpha\nfirst contact\n');
    await harness.writeUpstreamPlainNote(dbName, 'Beta.md', '# Beta\nfirst contact\n');

    const first = countingFetch();
    // First contact mirrors the daemon/sync command: pass the probe-time
    // update_seq so Stage 6 persists the initial pull checkpoint.
    const firstUpdateSeq = await fetchUpdateSeq(dbName);
    const firstCoordinator = pullOnlyCoordinator(dbName, statePath, first.counted, firstUpdateSeq);
    const firstResult = await firstCoordinator.sync();

    expect(firstResult.ok).toBe(true);
    expect(firstResult.errors).toEqual([]);
    expect(firstResult.plan.summary.pullCreates).toBe(2);
    expect(firstResult.incrementalLastSeq).toBeUndefined();
    expect(fs.readFileSync(path.join(vaultDir, 'Alpha.md'), 'utf8')).toBe('# Alpha\nfirst contact\n');
    expect(fs.readFileSync(path.join(vaultDir, 'Beta.md'), 'utf8')).toBe('# Beta\nfirst contact\n');

    // Checkpoint saved at the probe/update sequence.
    const firstDb = openDatabase(statePath);
    let firstCheckpointSeq: string | undefined;
    try {
      const cRepo = new CheckpointRepository(firstDb);
      firstCheckpointSeq = cRepo.getCheckpoint('fp-incremental-pull')?.lastUpdateSeq;
    } finally {
      firstDb.close();
    }
    expect(firstCheckpointSeq).toBeDefined();
    expect(firstCheckpointSeq!.length).toBeGreaterThan(0);
    expect(first.requests.some((r) => r.url.includes('/_all_docs'))).toBe(true);

    // Record pre-existing revisions for the history-preservation assertion.
    const { path2id_base } = await import('@vrtmrz/livesync-commonlib/compat/string_and_binary/path');
    const alphaDocId = String(await path2id_base('Alpha.md', false, true));
    const revBefore = (await harness.getDocument(dbName, alphaDocId))?._rev as string;

    // ---- Remote-only writes while the client is away ----
    await harness.writeUpstreamPlainNote(dbName, 'Gamma.md', '# Gamma\nadded while away\n');
    await harness.writeUpstreamPlainNote(dbName, 'Alpha.md', '# Alpha\nupdated while away\n');
    await harness.writeUpstreamLogicalDeletion(dbName, 'Beta.md');

    // ---- Pass 2: incremental pull must fetch ONLY the delta ----
    const second = countingFetch();
    const secondCoordinator = pullOnlyCoordinator(dbName, statePath, second.counted);
    const secondResult = await secondCoordinator.sync();

    expect(secondResult.ok).toBe(true);
    expect(secondResult.errors).toEqual([]);

    // The second pass used _changes with the persisted since token and never
    // re-inventoried the whole database.
    expect(second.requests.some((r) => r.url.includes('/_all_docs'))).toBe(false);
    const changesRequests = second.requests.filter((r) => r.url.includes('/_changes'));
    expect(changesRequests.length).toBeGreaterThanOrEqual(1);
    const sinceParam = new URL(changesRequests[0].url).searchParams.get('since');
    expect(sinceParam).toBeTruthy();
    expect(sinceParam).toBe(firstCheckpointSeq);

    // Exactly the delta materialized: Gamma created, Alpha updated, Beta deleted.
    expect(secondResult.plan.summary.pullCreates).toBe(1);
    expect(secondResult.plan.summary.pullUpdates).toBe(1);
    expect(secondResult.plan.summary.pullDeletes).toBe(1);

    expect(fs.readFileSync(path.join(vaultDir, 'Gamma.md'), 'utf8')).toBe('# Gamma\nadded while away\n');
    expect(fs.readFileSync(path.join(vaultDir, 'Alpha.md'), 'utf8')).toBe('# Alpha\nupdated while away\n');
    expect(fs.existsSync(path.join(vaultDir, 'Beta.md'))).toBe(false);

    // Provenance tracks the delta paths only (2 pulled + 1 deleted).
    const db = openDatabase(statePath);
    try {
      const provRepo = new ProvenanceRepository(db);
      const provenance = provRepo.getAllAsMap();
      expect(provenance.has('Alpha.md')).toBe(true);
      expect(provenance.has('Gamma.md')).toBe(true);
      expect(provenance.has('Beta.md')).toBe(false);

      // Checkpoint advanced to the _changes last_seq, not reset or dropped.
      const cp = new CheckpointRepository(db).getCheckpoint('fp-incremental-pull');
      expect(cp?.lastUpdateSeq).toBeDefined();
      expect(cp?.lastUpdateSeq).not.toBe(firstCheckpointSeq);
    } finally {
      db.close();
    }

    // ---- No history purge: the remote doc keeps its full revision chain ----
    const docAfter = await harness.getDocument(dbName, alphaDocId);
    expect(docAfter).not.toBeNull();
    expect(docAfter?._rev).not.toBe(revBefore); // a new revision was created by upstream writes
    const revsUrl = new URL(
      `/${encodeURIComponent(dbName)}/${encodeURIComponent(alphaDocId)}?revs=true`,
      harness.getBaseUrl()
    );
    const revsRes = await fetch(revsUrl.toString(), {
      headers: { Authorization: 'Basic ' + Buffer.from(`${harness.getCredentials().username}:${harness.getCredentials().password}`).toString('base64') },
    });
    expect(revsRes.ok).toBe(true);
    const revsJson = (await revsRes.json()) as { _revisions?: { ids: string[] } };
    // The pre-pull revision ancestry is still reachable from the winning rev.
    const ancestry = revsJson._revisions?.ids ?? [];
    expect(ancestry.length).toBeGreaterThanOrEqual(2);
    const revBeforeSuffix = revBefore.split('-')[1];
    expect(ancestry).toContain(revBeforeSuffix);
  }, 120000);

  it('no-op incremental pass issues a single _changes request and advances nothing but the seq', async () => {
    const dbName = 'incremental-pull-noop';
    await harness.createDatabase(dbName);
    await harness.seedLiveSyncData(dbName, { version: 12, locked: false });
    const statePath = path.join(stateDir, 'state.sqlite');

    await harness.writeUpstreamPlainNote(dbName, 'Solo.md', '# Solo\nonly note\n');

    const firstUpdateSeq = await fetchUpdateSeq(dbName);
    const firstCoordinator = pullOnlyCoordinator(dbName, statePath, countingFetch().counted, firstUpdateSeq);
    const firstResult = await firstCoordinator.sync();
    expect(firstResult.ok).toBe(true);

    // No remote writes at all: second pass sees an empty delta.
    const second = countingFetch();
    const secondCoordinator = pullOnlyCoordinator(dbName, statePath, second.counted);
    const secondResult = await secondCoordinator.sync();

    expect(secondResult.ok).toBe(true);
    expect(secondResult.plan.summary.totalActions).toBe(0);
    expect(secondResult.appliedActions).toBe(0);
    expect(second.requests.some((r) => r.url.includes('/_all_docs'))).toBe(false);
    expect(second.requests.filter((r) => r.url.includes('/_changes')).length).toBe(1);
    // File and provenance untouched.
    expect(fs.readFileSync(path.join(vaultDir, 'Solo.md'), 'utf8')).toBe('# Solo\nonly note\n');
  }, 120000);
});
