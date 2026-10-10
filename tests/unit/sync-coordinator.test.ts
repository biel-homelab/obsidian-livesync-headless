import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { SyncCoordinator } from '../../src/domain/sync-coordinator.js';
import { createWriteCapability } from '../../src/security/capabilities.js';
import { openDatabase } from '../../src/storage/sqlite.js';
import { ProvenanceRepository } from '../../src/storage/provenance-repo.js';
import { QuarantineRepository } from '../../src/storage/quarantine-repo.js';
import { CheckpointRepository } from '../../src/storage/checkpoint-repo.js';

describe('SyncCoordinator (Unit)', () => {
  let tempDir: string;
  let vaultRoot: string;
  let statePath: string;
  const baseUrl = new URL('http://127.0.0.1:5984');
  const databaseName = 'testdb';
  const remoteFingerprint = 'fp-test-1234';

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'sync-coord-unit-'));
    vaultRoot = path.join(tempDir, 'vault');
    statePath = path.join(tempDir, 'state.sqlite');
    await fs.mkdir(vaultRoot, { recursive: true });
  });

  afterEach(async () => {
    try {
      await fs.rm(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('throws when not in dry-run mode and no WriteCapability is provided', async () => {
    const coordinator = new SyncCoordinator({
      baseUrl,
      databaseName,
      vaultRoot,
      statePath,
      dryRun: false,
      remoteFingerprint,
    });

    await expect(coordinator.sync(undefined)).rejects.toThrow(
      /SyncCoordinator requires WriteCapability/
    );
  });

  it('handles dry-run mode: computes plan and performs zero writes', async () => {
    // Mock fetch for CouchDB inventory
    const mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      const urlStr = input.toString();
      if (urlStr.includes('/_all_docs')) {
        return new Response(
          JSON.stringify({
            total_rows: 1,
            offset: 0,
            rows: [
              {
                id: 'remote.md',
                key: 'remote.md',
                value: { rev: '1-abc' },
              },
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      if (urlStr.includes('remote.md')) {
        return new Response(
          JSON.stringify({
            _id: 'remote.md',
            _rev: '1-abc',
            type: 'notes',
            path: 'remote.md',
            data: 'Remote content',
            mtime: Date.now(),
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });

    const coordinator = new SyncCoordinator({
      baseUrl,
      databaseName,
      vaultRoot,
      statePath,
      dryRun: true,
      remoteFingerprint,
      handleFilenameCaseSensitive: true,
      fetch: mockFetch as any,
    });

    const result = await coordinator.sync();

    expect(result.ok).toBe(true);
    expect(result.appliedActions).toBe(0);
    expect(result.plan.summary.pullCreates).toBe(1);

    // Verify no files written to disk
    const filesOnDisk = await fs.readdir(vaultRoot);
    expect(filesOnDisk.length).toBe(0);

    // Verify SQLite has zero provenance records
    const db = openDatabase(statePath);
    const pRepo = new ProvenanceRepository(db);
    expect(pRepo.getAllAsMap().size).toBe(0);
    db.close();
  });

  it('executes apply mode for bidirectional sync (pulls remote, pushes local, updates provenance & checkpoint)', async () => {
    // 1. Create a local file to push
    const localContent = 'Hello from local file';
    await fs.writeFile(path.join(vaultRoot, 'local.md'), localContent);

    const uploadedDocs: any[] = [];

    // Mock fetch for inventory and push
    const mockFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const urlStr = input.toString();
      const method = init?.method ?? 'GET';

      if (urlStr.includes('/_all_docs')) {
        return new Response(
          JSON.stringify({
            total_rows: 1,
            offset: 0,
            rows: [
              {
                id: 'remote.md',
                key: 'remote.md',
                value: { rev: '1-rem' },
              },
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      if (urlStr.includes('remote.md') && method === 'GET') {
        return new Response(
          JSON.stringify({
            _id: 'remote.md',
            _rev: '1-rem',
            type: 'notes',
            path: 'remote.md',
            data: 'Remote pulled content',
            mtime: Date.now(),
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      if (method === 'PUT') {
        const body = JSON.parse(init?.body as string);
        uploadedDocs.push(body);
        return new Response(JSON.stringify({ ok: true, id: body._id, rev: '1-pushed' }), {
          status: 201,
          headers: { 'content-type': 'application/json' },
        });
      }

      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });

    const coordinator = new SyncCoordinator({
      baseUrl,
      databaseName,
      vaultRoot,
      statePath,
      dryRun: false,
      remoteFingerprint,
      handleFilenameCaseSensitive: true,
      updateSeq: '42-seq',
      fetch: mockFetch as any,
    });

    const capability = createWriteCapability(baseUrl, databaseName, 'grant-1', remoteFingerprint, vaultRoot);
    const result = await coordinator.sync(capability);

    expect(result.errors).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.appliedActions).toBe(2); // 1 pull-create, 1 push-create
    expect(result.plan.summary.pullCreates).toBe(1);
    expect(result.plan.summary.pushCreates).toBe(1);

    // Check remote pulled file is installed on disk
    const pulledData = await fs.readFile(path.join(vaultRoot, 'remote.md'), 'utf8');
    expect(pulledData).toBe('Remote pulled content');

    // Check local file was pushed
    expect(uploadedDocs.length).toBe(1);
    expect(uploadedDocs[0]._id).toBe('local.md');

    // Check provenance in SQLite
    const db = openDatabase(statePath);
    const pRepo = new ProvenanceRepository(db);
    const pulledProv = pRepo.getByPath('remote.md');
    const pushedProv = pRepo.getByPath('local.md');
    expect(pulledProv?.remoteRevision).toBe('1-rem');
    expect(pushedProv?.remoteRevision).toBe('1-pushed');

    // Check checkpoint updated
    const cRepo = new CheckpointRepository(db);
    const cp = cRepo.getCheckpoint(remoteFingerprint);
    expect(cp?.lastUpdateSeq).toBe('42-seq');
    db.close();
  });

  it('safely surfaces conflicts and halts fail-closed without overwriting either side (SYNC-06, SYNC-07)', async () => {
    // Local and remote have divergent content and different base
    await fs.writeFile(path.join(vaultRoot, 'conflict.md'), 'Local divergent edit');

    const db = openDatabase(statePath);
    const pRepo = new ProvenanceRepository(db);
    pRepo.saveProvenance({
      path: 'conflict.md',
      remoteRevision: '1-old',
      contentSha256: 'oldhash',
      observedMtime: 1000,
      remoteFingerprint,
      reflectedAt: new Date().toISOString(),
    });
    db.close();

    const mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      const urlStr = input.toString();
      if (urlStr.includes('/_all_docs')) {
        return new Response(
          JSON.stringify({
            total_rows: 1,
            offset: 0,
            rows: [
              {
                id: 'conflict.md',
                key: 'conflict.md',
                value: { rev: '2-remote' },
              },
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      if (urlStr.includes('conflict.md')) {
        return new Response(
          JSON.stringify({
            _id: 'conflict.md',
            _rev: '2-remote',
            type: 'notes',
            path: 'conflict.md',
            data: 'Remote divergent edit',
            mtime: 2000,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });

    const coordinator = new SyncCoordinator({
      baseUrl,
      databaseName,
      vaultRoot,
      statePath,
      dryRun: false,
      remoteFingerprint,
      handleFilenameCaseSensitive: true,
      fetch: mockFetch as any,
    });

    const capability = createWriteCapability(baseUrl, databaseName, 'grant-1', remoteFingerprint, vaultRoot);
    const result = await coordinator.sync(capability);

    expect(result.ok).toBe(false);
    expect(result.conflicts.length).toBe(1);
    expect(result.conflicts[0]).toContain("Conflict at 'conflict.md'");
    expect(result.appliedActions).toBe(0);

    // Ensure local file was not overwritten
    const localAfter = await fs.readFile(path.join(vaultRoot, 'conflict.md'), 'utf8');
    expect(localAfter).toBe('Local divergent edit');
  });
});

describe('SyncCoordinator incremental pull (Unit, Phase 3)', () => {
  let tempDir: string;
  let vaultRoot: string;
  let statePath: string;
  const baseUrl = new URL('http://127.0.0.1:5984');
  const databaseName = 'testdb';
  const remoteFingerprint = 'fp-incremental';

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'sync-coord-incr-'));
    vaultRoot = path.join(tempDir, 'vault');
    statePath = path.join(tempDir, 'state.sqlite');
    await fs.mkdir(vaultRoot, { recursive: true });
  });

  afterEach(async () => {
    try {
      await fs.rm(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  function saveCheckpoint(lastUpdateSeq: string): void {
    const db = openDatabase(statePath);
    try {
      const cRepo = new CheckpointRepository(db);
      cRepo.saveCheckpoint({ remoteFingerprint, lastUpdateSeq, completedAt: new Date().toISOString() });
    } finally {
      db.close();
    }
  }

  function changesResponse(
    results: Record<string, unknown>[],
    lastSeq: string | number
  ): Response {
    return new Response(
      JSON.stringify({ results, last_seq: lastSeq }),
      { status: 200, headers: { 'content-type': 'application/json' } }
    );
  }

  function noteDoc(id: string, data: string): Record<string, unknown> {
    return {
      _id: id,
      _rev: '1-rem',
      type: 'notes',
      path: id,
      data,
      size: new TextEncoder().encode(data).byteLength,
      deleted: false,
      mtime: Date.now(),
    };
  }

  function pullOnlyCoordinator(fetch: typeof globalThis.fetch, opts?: { useIncrementalPull?: boolean }) {
    return new SyncCoordinator({
      baseUrl,
      databaseName,
      vaultRoot,
      statePath,
      dryRun: false,
      pullOnly: true,
      remoteFingerprint,
      handleFilenameCaseSensitive: true,
      useIncrementalPull: opts?.useIncrementalPull,
      fetch,
    });
  }

  it('uses the persisted since token and applies only changed documents', async () => {
    saveCheckpoint('seq-41');

    const requests: string[] = [];
    const mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      const urlStr = input.toString();
      requests.push(urlStr);
      if (urlStr.includes('/_changes')) {
        return changesResponse(
          [
            {
              seq: 43,
              id: 'delta.md',
              changes: [{ rev: '1-rem' }],
              doc: noteDoc('delta.md', 'Delta content'),
            },
          ],
          43
        );
      }
      throw new Error(`Unexpected request: ${urlStr}`);
    });

    const coordinator = pullOnlyCoordinator(mockFetch as any);
    const result = await coordinator.sync();

    expect(result.ok).toBe(true);
    expect(result.incrementalLastSeq).toBe('43');

    // The _changes query used the persisted checkpoint verbatim.
    const changesCalls = requests.filter((u) => u.includes('/_changes'));
    expect(changesCalls.length).toBe(1);
    expect(new URL(changesCalls[0]).searchParams.get('since')).toBe('seq-41');
    // No _all_docs inventory was issued at all.
    expect(requests.some((u) => u.includes('/_all_docs'))).toBe(false);

    // Only the changed document was planned and applied.
    expect(result.appliedActions).toBe(1);
    expect(result.plan.summary.pullCreates).toBe(1);
    const onDisk = await fs.readFile(path.join(vaultRoot, 'delta.md'), 'utf8');
    expect(onDisk).toBe('Delta content');

    // Checkpoint advanced to the _changes last_seq after the successful apply.
    const db = openDatabase(statePath);
    try {
      const cRepo = new CheckpointRepository(db);
      expect(cRepo.getCheckpoint(remoteFingerprint)?.lastUpdateSeq).toBe('43');
    } finally {
      db.close();
    }
  });

  it('falls back to full inventory when no checkpoint exists (first contact)', async () => {
    const requests: string[] = [];
    const mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      const urlStr = input.toString();
      requests.push(urlStr);
      if (urlStr.includes('/_all_docs')) {
        return new Response(
          JSON.stringify({
            total_rows: 1,
            offset: 0,
            rows: [
              {
                id: 'first.md',
                key: 'first.md',
                value: { rev: '1-rem' },
              },
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }
      if (urlStr.includes('first.md')) {
        return new Response(
          JSON.stringify(noteDoc('first.md', 'First contact content')),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }
      throw new Error(`Unexpected request: ${urlStr}`);
    });

    const coordinator = pullOnlyCoordinator(mockFetch as any);
    const result = await coordinator.sync();

    expect(result.ok).toBe(true);
    expect(result.incrementalLastSeq).toBeUndefined();
    expect(requests.some((u) => u.includes('/_all_docs'))).toBe(true);
    expect(requests.some((u) => u.includes('/_changes'))).toBe(false);
    expect(result.plan.summary.pullCreates).toBe(1);
  });

  it('falls back to full inventory when CouchDB rejects the since token with 400', async () => {
    saveCheckpoint('stale-seq');

    const requests: string[] = [];
    const mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      const urlStr = input.toString();
      requests.push(urlStr);
      if (urlStr.includes('/_changes')) {
        return new Response(
          JSON.stringify({ error: 'bad_request', reason: 'Invalid since' }),
          { status: 400, headers: { 'content-type': 'application/json' } }
        );
      }
      if (urlStr.includes('/_all_docs')) {
        return new Response(
          JSON.stringify({
            total_rows: 1,
            offset: 0,
            rows: [
              { id: 'fallback.md', key: 'fallback.md', value: { rev: '1-rem' } },
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }
      if (urlStr.includes('fallback.md')) {
        return new Response(
          JSON.stringify(noteDoc('fallback.md', 'Fallback content')),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }
      throw new Error(`Unexpected request: ${urlStr}`);
    });

    const coordinator = pullOnlyCoordinator(mockFetch as any);
    const result = await coordinator.sync();

    // The pass did not fail; it degraded to a full inventory.
    expect(result.ok).toBe(true);
    expect(result.incrementalLastSeq).toBeUndefined();
    expect(requests.filter((u) => u.includes('/_changes')).length).toBe(1);
    expect(requests.some((u) => u.includes('/_all_docs'))).toBe(true);
    expect(result.plan.summary.pullCreates).toBe(1);
  });

  it('falls back to full inventory when useIncrementalPull is false', async () => {
    saveCheckpoint('seq-41');

    const requests: string[] = [];
    const mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      const urlStr = input.toString();
      requests.push(urlStr);
      if (urlStr.includes('/_all_docs')) {
        return new Response(
          JSON.stringify({
            total_rows: 1,
            offset: 0,
            rows: [
              { id: 'full.md', key: 'full.md', value: { rev: '1-rem' } },
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }
      if (urlStr.includes('full.md')) {
        return new Response(
          JSON.stringify(noteDoc('full.md', 'Full inventory content')),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }
      throw new Error(`Unexpected request: ${urlStr}`);
    });

    const coordinator = pullOnlyCoordinator(mockFetch as any, { useIncrementalPull: false });
    const result = await coordinator.sync();

    expect(result.ok).toBe(true);
    expect(requests.some((u) => u.includes('/_changes'))).toBe(false);
    expect(requests.some((u) => u.includes('/_all_docs'))).toBe(true);
    expect(result.plan.summary.pullCreates).toBe(1);
  });

  it('runs full inventory for bidirectional (non pull-only) passes even with a checkpoint', async () => {
    saveCheckpoint('seq-41');
    await fs.writeFile(path.join(vaultRoot, 'local.md'), 'Local content');

    const requests: string[] = [];
    const mockFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const urlStr = input.toString();
      const method = init?.method ?? 'GET';
      requests.push(`${method} ${urlStr}`);
      if (urlStr.includes('/_all_docs')) {
        return new Response(
          JSON.stringify({ total_rows: 1, offset: 0, rows: [] }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }
      if (method === 'HEAD') {
        return new Response(null, { status: 404 });
      }
      if (method === 'PUT') {
        return new Response(JSON.stringify({ ok: true, rev: '1-pushed' }), {
          status: 201,
          headers: { 'content-type': 'application/json' },
        });
      }
      throw new Error(`Unexpected request: ${urlStr}`);
    });

    const capability = createWriteCapability(baseUrl, databaseName, 'grant-1', remoteFingerprint, vaultRoot);
    const coordinator = new SyncCoordinator({
      baseUrl,
      databaseName,
      vaultRoot,
      statePath,
      dryRun: false,
      remoteFingerprint,
      handleFilenameCaseSensitive: true,
      fetch: mockFetch as any,
    });
    const result = await coordinator.sync(capability);

    expect(result.ok).toBe(true);
    expect(result.incrementalLastSeq).toBeUndefined();
    expect(requests.some((u) => u.includes('/_changes'))).toBe(false);
    expect(requests.some((u) => u.includes('/_all_docs'))).toBe(true);
    // Local-only file is planned as a push because the full remote state was seen.
    expect(result.plan.summary.pushCreates).toBe(1);
  });

  it('does not advance the checkpoint when the pass contains block observations', async () => {
    saveCheckpoint('seq-41');

    // The changed doc fails decode with PATH_ID_MISMATCH (path2id mismatch),
    // producing a `block` observation. The planner cannot express blocks as
    // actions, so the incremental safety valve must refuse to advance the
    // checkpoint past them — otherwise the next pass would never re-examine
    // this document. The next pass re-runs _changes from the old checkpoint.
    const unsafeDoc = {
      _id: 'unsafe',
      _rev: '1-rem',
      type: 'notes',
      path: '../escape.md',
      data: 'x',
      size: 1,
      deleted: false,
      mtime: Date.now(),
    };
    const mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      const urlStr = input.toString();
      if (urlStr.includes('/_changes')) {
        return changesResponse(
          [{ seq: 44, id: 'unsafe', changes: [{ rev: '1-rem' }], doc: unsafeDoc }],
          44
        );
      }
      throw new Error(`Unexpected request: ${urlStr}`);
    });

    const coordinator = pullOnlyCoordinator(mockFetch as any);
    const result = await coordinator.sync();

    expect(result.incrementalLastSeq).toBeUndefined();

    const db = openDatabase(statePath);
    try {
      const cRepo = new CheckpointRepository(db);
      expect(cRepo.getCheckpoint(remoteFingerprint)?.lastUpdateSeq).toBe('seq-41');
    } finally {
      db.close();
    }
  });

  it('dry-run incremental pass reports the last seq but leaves the checkpoint untouched', async () => {
    saveCheckpoint('seq-41');

    const mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      const urlStr = input.toString();
      if (urlStr.includes('/_changes')) {
        return changesResponse(
          [
            {
              seq: 45,
              id: 'delta.md',
              changes: [{ rev: '1-rem' }],
              doc: noteDoc('delta.md', 'Delta content'),
            },
          ],
          45
        );
      }
      throw new Error(`Unexpected request: ${urlStr}`);
    });

    const coordinator = new SyncCoordinator({
      baseUrl,
      databaseName,
      vaultRoot,
      statePath,
      dryRun: true,
      pullOnly: true,
      remoteFingerprint,
      handleFilenameCaseSensitive: true,
      fetch: mockFetch as any,
    });
    const result = await coordinator.sync();

    expect(result.ok).toBe(true);
    expect(result.plan.summary.pullCreates).toBe(1);
    expect(result.incrementalLastSeq).toBe('45');

    // Dry-run must never mutate state: checkpoint stays at the prior value.
    const db = openDatabase(statePath);
    try {
      const cRepo = new CheckpointRepository(db);
      expect(cRepo.getCheckpoint(remoteFingerprint)?.lastUpdateSeq).toBe('seq-41');
    } finally {
      db.close();
    }
  });

  it('serves chunks referenced by changed docs from chunk rows delivered in the same _changes feed', async () => {
    saveCheckpoint('seq-50');

    const chunkData = 'chunked payload';
    const chunkDoc = {
      _id: 'h:incr-chunk-1',
      _rev: '1-chunkrev',
      type: 'leaf',
      data: chunkData,
    };
    const bytes = new TextEncoder().encode(chunkData);
    const noteDocChunked = {
      _id: 'chunked.md',
      _rev: '1-rem',
      type: 'plain',
      path: 'chunked.md',
      children: ['h:incr-chunk-1'],
      size: bytes.byteLength,
      deleted: false,
      mtime: Date.now(),
    };
    const requests: string[] = [];
    const mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      const urlStr = input.toString();
      requests.push(urlStr);
      if (urlStr.includes('/_changes')) {
        return changesResponse(
          [
            { seq: 51, id: 'h:incr-chunk-1', changes: [{ rev: '1-chunkrev' }], doc: chunkDoc },
            { seq: 52, id: 'chunked.md', changes: [{ rev: '1-rem' }], doc: noteDocChunked },
          ],
          52
        );
      }
      throw new Error(`Unexpected per-chunk GET: ${urlStr}`);
    });

    const coordinator = pullOnlyCoordinator(mockFetch as any);
    const result = await coordinator.sync();

    expect(result.ok).toBe(true);
    expect(result.appliedActions).toBe(1);
    const onDisk = await fs.readFile(path.join(vaultRoot, 'chunked.md'), 'utf8');
    expect(onDisk).toBe(chunkData);
    // The chunk was served from the _changes row: no per-chunk document GETs.
    expect(requests.length).toBe(1);
  });
});
