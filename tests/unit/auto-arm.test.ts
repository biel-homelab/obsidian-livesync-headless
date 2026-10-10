import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { AutoArmCoordinator } from '../../src/domain/auto-arm.js';
import { openDatabase } from '../../src/storage/sqlite.js';
import { ProvenanceRepository } from '../../src/storage/provenance-repo.js';
import { WriteGrantRepo } from '../../src/storage/write-grant-repo.js';
import { AdmissionRepository } from '../../src/storage/admission-repo.js';
import { loadConfig } from '../../src/config/loader.js';
import { parseCliArgs } from '../../src/cli/index.js';
import { path2id_base, type CouchDbDocument } from '../../src/livesync/decode-adapter.js';
import type { LoadedConfig } from '../../src/config/schema.js';
import type { RemoteProbeResult } from '../../src/livesync/inspector.js';

describe('AutoArmCoordinator & LIVESYNC_WRITE=auto-arm', () => {
  let tmpDir: string;
  let vaultRoot: string;
  let statePath: string;
  const remoteFingerprint = 'test-fingerprint-123';

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'auto-arm-test-'));
    vaultRoot = path.join(tmpDir, 'vault');
    statePath = path.join(tmpDir, 'state.db');
    await fs.mkdir(vaultRoot, { recursive: true });
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  describe('Trigger detection', () => {
    it('triggers EMPTY_VAULT when vault is empty', async () => {
      const coordinator = new AutoArmCoordinator();
      const res = await coordinator.checkTrigger({
        vaultRoot,
        statePath,
        remoteFingerprint,
      });

      expect(res.shouldAutoArm).toBe(true);
      expect(res.code).toBe('EMPTY_VAULT');
      expect(res.reason).toContain('empty');
    });

    it('triggers EMPTY_STATE when state database does not exist', async () => {
      // Create a file in vault so vault is not empty
      await fs.writeFile(path.join(vaultRoot, 'note.md'), 'hello world');

      const coordinator = new AutoArmCoordinator();
      const res = await coordinator.checkTrigger({
        vaultRoot,
        statePath,
        remoteFingerprint,
      });

      expect(res.shouldAutoArm).toBe(true);
      expect(res.code).toBe('EMPTY_STATE');
      expect(res.reason).toContain('does not exist');
    });

    it('triggers EMPTY_STATE when state database has no provenance records', async () => {
      await fs.writeFile(path.join(vaultRoot, 'note.md'), 'hello world');
      const db = openDatabase(statePath);
      db.close();

      const coordinator = new AutoArmCoordinator();
      const res = await coordinator.checkTrigger({
        vaultRoot,
        statePath,
        remoteFingerprint,
      });

      expect(res.shouldAutoArm).toBe(true);
      expect(res.code).toBe('EMPTY_STATE');
      expect(res.reason).toContain('no recorded file provenance');
    });

    it('triggers EXCESSIVE_LOCAL_CHANGES when >= 10 new local files exist', async () => {
      const db = openDatabase(statePath);
      const provRepo = new ProvenanceRepository(db);
      // Save 1 existing provenance record
      provRepo.saveProvenance({
        path: 'existing.md',
        remoteRevision: '1-abc',
        contentSha256: crypto.createHash('sha256').update('old').digest('hex'),
        observedMtime: Date.now(),
        remoteFingerprint,
        reflectedAt: new Date().toISOString(),
      });
      const grantRepo = new WriteGrantRepo(db);
      grantRepo.issueGrant({
        remoteFingerprint,
        vaultRoot,
        settingsHash: 'hash',
        commonlibVersion: '0.1.21',
        bootstrapGeneration: '1',
      });
      db.close();

      // Create existing.md + 10 new files in vault
      await fs.writeFile(path.join(vaultRoot, 'existing.md'), 'old');
      for (let i = 1; i <= 10; i++) {
        await fs.writeFile(path.join(vaultRoot, `new-note-${i}.md`), `content ${i}`);
      }

      const coordinator = new AutoArmCoordinator();
      const res = await coordinator.checkTrigger({
        vaultRoot,
        statePath,
        remoteFingerprint,
        threshold: 10,
      });

      expect(res.shouldAutoArm).toBe(true);
      expect(res.code).toBe('EXCESSIVE_LOCAL_CHANGES');
      expect(res.localNewCount).toBe(10);
      expect(res.reason).toContain('exceed threshold');
    });

    it('triggers EXCESSIVE_LOCAL_CHANGES when >= 10 deleted local files exist', async () => {
      const db = openDatabase(statePath);
      const provRepo = new ProvenanceRepository(db);
      for (let i = 1; i <= 10; i++) {
        provRepo.saveProvenance({
          path: `note-${i}.md`,
          remoteRevision: `1-rev-${i}`,
          contentSha256: crypto.createHash('sha256').update(`content ${i}`).digest('hex'),
          observedMtime: Date.now(),
          remoteFingerprint,
          reflectedAt: new Date().toISOString(),
        });
      }
      const grantRepo = new WriteGrantRepo(db);
      grantRepo.issueGrant({
        remoteFingerprint,
        vaultRoot,
        settingsHash: 'hash',
        commonlibVersion: '0.1.21',
        bootstrapGeneration: '1',
      });
      db.close();

      // Vault only has 1 file, 10 recorded in provenance are deleted
      await fs.writeFile(path.join(vaultRoot, 'extra.md'), 'extra');

      const coordinator = new AutoArmCoordinator();
      const res = await coordinator.checkTrigger({
        vaultRoot,
        statePath,
        remoteFingerprint,
        threshold: 10,
      });

      expect(res.shouldAutoArm).toBe(true);
      expect(res.code).toBe('EXCESSIVE_LOCAL_CHANGES');
      expect(res.localDeletedCount).toBe(10);
    });

    it('triggers MISSING_WRITE_GRANT when vault and state are valid but write grant is missing', async () => {
      const content = 'clean file';
      const sha = crypto.createHash('sha256').update(content).digest('hex');
      await fs.writeFile(path.join(vaultRoot, 'note.md'), content);

      const db = openDatabase(statePath);
      const provRepo = new ProvenanceRepository(db);
      provRepo.saveProvenance({
        path: 'note.md',
        remoteRevision: '1-abc',
        contentSha256: sha,
        observedMtime: Date.now(),
        remoteFingerprint,
        reflectedAt: new Date().toISOString(),
      });
      db.close();

      const coordinator = new AutoArmCoordinator();
      const res = await coordinator.checkTrigger({
        vaultRoot,
        statePath,
        remoteFingerprint,
      });

      expect(res.shouldAutoArm).toBe(true);
      expect(res.code).toBe('MISSING_WRITE_GRANT');
    });

    it('does not trigger when vault, state, and write grant are all valid with < 10 changes', async () => {
      const content = 'clean file';
      const sha = crypto.createHash('sha256').update(content).digest('hex');
      await fs.writeFile(path.join(vaultRoot, 'note.md'), content);
      await fs.writeFile(path.join(vaultRoot, 'new1.md'), 'new1'); // 1 new file (< 10)

      const db = openDatabase(statePath);
      const provRepo = new ProvenanceRepository(db);
      provRepo.saveProvenance({
        path: 'note.md',
        remoteRevision: '1-abc',
        contentSha256: sha,
        observedMtime: Date.now(),
        remoteFingerprint,
        reflectedAt: new Date().toISOString(),
      });
      const grantRepo = new WriteGrantRepo(db);
      grantRepo.issueGrant({
        remoteFingerprint,
        vaultRoot,
        settingsHash: 'hash',
        commonlibVersion: '0.1.21',
        bootstrapGeneration: '1',
      });
      db.close();

      const coordinator = new AutoArmCoordinator();
      const res = await coordinator.checkTrigger({
        vaultRoot,
        statePath,
        remoteFingerprint,
        threshold: 10,
      });

      expect(res.shouldAutoArm).toBe(false);
      expect(res.code).toBe('NONE');
    });
  });

  describe('Cleanup & Validation', () => {
    it('cleanupLocalVault removes user files and subfolders while leaving directory intact', async () => {
      const coordinator = new AutoArmCoordinator();
      await fs.mkdir(path.join(vaultRoot, 'subfolder'), { recursive: true });
      await fs.writeFile(path.join(vaultRoot, 'subfolder', 'test.md'), 'data');
      await fs.writeFile(path.join(vaultRoot, 'root.md'), 'data');

      await coordinator.cleanupLocalVault(vaultRoot);

      const entries = await fs.readdir(vaultRoot);
      expect(entries.length).toBe(0);
    });

    it('cleanupLocalState removes state database and WAL files', async () => {
      const coordinator = new AutoArmCoordinator();
      await fs.writeFile(statePath, 'mock db');
      await fs.writeFile(`${statePath}-wal`, 'mock wal');
      await fs.writeFile(`${statePath}-shm`, 'mock shm');

      await coordinator.cleanupLocalState(statePath);

      let exists = true;
      try {
        await fs.stat(statePath);
      } catch {
        exists = false;
      }
      expect(exists).toBe(false);
    });

    it('validateSynchronization succeeds when disk matches provenance exactly', async () => {
      const coordinator = new AutoArmCoordinator();
      const content = 'synchronized content';
      const sha = crypto.createHash('sha256').update(content).digest('hex');
      await fs.writeFile(path.join(vaultRoot, 'synced.md'), content);

      const db = openDatabase(statePath);
      const provRepo = new ProvenanceRepository(db);
      provRepo.saveProvenance({
        path: 'synced.md',
        remoteRevision: '1-xyz',
        contentSha256: sha,
        observedMtime: Date.now(),
        remoteFingerprint,
        reflectedAt: new Date().toISOString(),
      });
      db.close();

      const validation = await coordinator.validateSynchronization(
        vaultRoot,
        statePath,
        remoteFingerprint
      );

      expect(validation.valid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    it('validateSynchronization fails when disk file is missing or hash mismatches', async () => {
      const coordinator = new AutoArmCoordinator();
      const db = openDatabase(statePath);
      const provRepo = new ProvenanceRepository(db);
      provRepo.saveProvenance({
        path: 'missing.md',
        remoteRevision: '1-xyz',
        contentSha256: 'expected-hash',
        observedMtime: Date.now(),
        remoteFingerprint,
        reflectedAt: new Date().toISOString(),
      });
      db.close();

      const validation = await coordinator.validateSynchronization(
        vaultRoot,
        statePath,
        remoteFingerprint
      );

      expect(validation.valid).toBe(false);
      expect(validation.errors[0]).toContain('missing from local vault');
    });
  });

  describe('Configuration and CLI Parsing for auto-arm', () => {
    it('parses LIVESYNC_MODE=auto-arm from environment variables', async () => {
      const config = await loadConfig(undefined, {
        LIVESYNC_COUCHDB_URL: 'http://127.0.0.1:5984',
        LIVESYNC_COUCHDB_DATABASE: 'testdb',
        LIVESYNC_VAULT_PATH: vaultRoot,
        LIVESYNC_STATE_PATH: statePath,
        LIVESYNC_MODE: 'auto-arm',
      });

      expect(config.cli?.write).toBe('auto-arm');
      expect(config.cli?.autoArm).toBe(true);
    });

    it('parses LIVESYNC_MODE=write and LIVESYNC_MODE=read-only', async () => {
      const writeConfig = await loadConfig(undefined, {
        LIVESYNC_COUCHDB_URL: 'http://127.0.0.1:5984',
        LIVESYNC_COUCHDB_DATABASE: 'testdb',
        LIVESYNC_VAULT_PATH: vaultRoot,
        LIVESYNC_STATE_PATH: statePath,
        LIVESYNC_MODE: 'write',
      });
      expect(writeConfig.cli?.write).toBe(true);
      expect(writeConfig.cli?.autoArm).toBe(false);

      const roConfig = await loadConfig(undefined, {
        LIVESYNC_COUCHDB_URL: 'http://127.0.0.1:5984',
        LIVESYNC_COUCHDB_DATABASE: 'testdb',
        LIVESYNC_VAULT_PATH: vaultRoot,
        LIVESYNC_STATE_PATH: statePath,
        LIVESYNC_MODE: 'read-only',
      });
      expect(roConfig.cli?.write).toBe(false);
      expect(roConfig.cli?.autoArm).toBe(false);
    });

    it('supports backward compatible LIVESYNC_WRITE=auto-arm', async () => {
      const config = await loadConfig(undefined, {
        LIVESYNC_COUCHDB_URL: 'http://127.0.0.1:5984',
        LIVESYNC_COUCHDB_DATABASE: 'testdb',
        LIVESYNC_VAULT_PATH: vaultRoot,
        LIVESYNC_STATE_PATH: statePath,
        LIVESYNC_WRITE: 'auto-arm',
      });

      expect(config.cli?.write).toBe('auto-arm');
    });

    it('parses --auto-arm from CLI arguments', () => {
      const parsed = parseCliArgs(['daemon', '--auto-arm']);
      expect(parsed.command).toBe('daemon');
      expect(parsed.options.autoArm).toBe(true);
    });
  });
});

/**
 * Phase 4.1/4.2 — fail-closed ordering: the destructive cleanup
 * (cleanupLocalVault / cleanupLocalState) must never run unless the read-only
 * pull plan is proven feasible (inventory + decode succeed with no block
 * actions and encryption is resolvable).
 */
describe('AutoArmCoordinator fail-closed cleanup ordering (Phase 4)', () => {
  let tmpDir: string;
  let vaultRoot: string;
  let statePath: string;
  const baseUrl = new URL('http://127.0.0.1:5984');
  const databaseName = 'testdb';
  const remoteFingerprint = 'phase4-fingerprint';

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'auto-arm-phase4-'));
    vaultRoot = path.join(tmpDir, 'vault');
    statePath = path.join(tmpDir, 'state.db');
    await fs.mkdir(vaultRoot, { recursive: true });
    // Local content that MUST survive every failed workflow below.
    await fs.writeFile(path.join(vaultRoot, 'precious.md'), 'do not lose me');
    await fs.writeFile(statePath, 'mock existing state db');
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  function makeConfig(overrides?: { encryptionPassphrase?: string }): LoadedConfig {
    return {
      remote: { url: baseUrl.href, database: databaseName },
      vault: { path: vaultRoot, dedicated: true },
      state: { path: statePath },
      resolvedVaultPath: vaultRoot,
      resolvedStatePath: statePath,
      resolvedSecrets: {
        encryptionPassphrase: overrides?.encryptionPassphrase,
      },
    } as LoadedConfig;
  }

  function makeProbeResult(): RemoteProbeResult {
    return {
      databaseInfo: { docCount: 3, updateSeq: '42', couchdbVersion: '3.5.2' },
      versionDoc: { _id: 'obsydian_livesync_version', _rev: '1-v', version: 12 },
      milestoneDoc: {
        _id: '_local/obsydian_livesync_milestone',
        _rev: '1-m',
        locked: false,
        tweak_values: { PREFERRED: {} },
      },
      syncParamsDoc: null,
      syncinfoDoc: null,
      sampleDocs: [],
    };
  }

  /**
   * Minimal LiveSync-compatible note doc: `_id` must be `path2id_base(path)`
   * so `verifyPathIdentity` passes for non-obfuscated, case-sensitive paths.
   */
  async function noteDoc(relPath: string, data: string): Promise<CouchDbDocument> {
    return {
      _id: String(await path2id_base(relPath as never, false, false)),
      _rev: '1-n',
      type: 'plain',
      path: relPath,
      children: [],
      size: 0,
      data,
    };
  }

  function okJson(body: unknown): Response {
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }

  it('planReadOnlyPull aborts with MISSING_PASSPHRASE and never cleans up when the remote is encrypted and no passphrase is configured', async () => {
    const encryptedChunk: CouchDbDocument = {
      _id: 'h:encrypted',
      _rev: '1-c',
      type: 'leaf',
      e_: true,
      data: '%=hkdf-ciphertext-body',
    };
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/_all_docs')) {
        return okJson({
          total_rows: 2,
          offset: 0,
          rows: [
            {
              id: 'h:encrypted',
              key: 'h:encrypted',
              value: { rev: '1-c' },
              doc: encryptedChunk,
            },
            {
              id: 'noteplain',
              key: 'noteplain',
              value: { rev: '1-n' },
              doc: await noteDoc('plain.md', 'hello'),
            },
          ],
        });
      }
      return okJson({});
    });

    const coordinator = new AutoArmCoordinator();
    const plan = await coordinator.planReadOnlyPull(
      makeConfig(), // no passphrase
      fetchMock as unknown as typeof globalThis.fetch,
      makeProbeResult(),
      {
        admitted: true,
        remoteFingerprint,
        negotiatedSettingsHash: 'hash',
        negotiatedSettings: {},
        adoptedTweaks: {},
        blockers: [],
        admittedCapabilities: [],
        unsupportedCapabilities: [],
      } as never
    );

    expect(plan.success).toBe(false);
    expect(plan.error).toContain('no encryption passphrase is configured');
    expect(plan.error).toContain('BEFORE local cleanup');
    const blocks = plan.actions.filter((a) => a.kind === 'block');
    expect(blocks.length).toBe(1);
    expect((blocks[0] as { code: string }).code).toBe('MISSING_PASSPHRASE');

    // Vault and state untouched.
    expect(await fs.readFile(path.join(vaultRoot, 'precious.md'), 'utf8')).toBe('do not lose me');
    expect(await fs.readFile(statePath, 'utf8')).toBe('mock existing state db');
  });

  it('planReadOnlyPull does not false-positive on plaintext markdown links (live incident regression)', async () => {
    const body = '[this guide](https://guides.viren070.me/selfhosting/oracle)';
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/_all_docs')) {
        return okJson({
          total_rows: 2,
          offset: 0,
          rows: [
            {
              id: 'h:1glg4b822a6po',
              key: 'h:1glg4b822a6po',
              value: { rev: '1-c' },
              doc: { _id: 'h:1glg4b822a6po', _rev: '1-c', type: 'leaf', data: body },
            },
            {
              id: 'linksdoc',
              key: 'linksdoc',
              value: { rev: '1-n' },
              doc: {
                ...(await noteDoc('Links.md', '')),
                children: ['h:1glg4b822a6po'],
                size: new TextEncoder().encode(body).byteLength,
                data: undefined,
              },
            },
          ],
        });
      }
      return okJson({});
    });

    const coordinator = new AutoArmCoordinator();
    const plan = await coordinator.planReadOnlyPull(
      makeConfig(),
      fetchMock as unknown as typeof globalThis.fetch,
      makeProbeResult(),
      {
        admitted: true,
        remoteFingerprint,
        negotiatedSettingsHash: 'hash',
        negotiatedSettings: { handleFilenameCaseSensitive: true },
        adoptedTweaks: {},
        blockers: [],
        admittedCapabilities: [],
        unsupportedCapabilities: [],
      } as never
    );

    expect(plan.success).toBe(true);
    const creates = plan.actions.filter((a) => a.kind === 'create');
    expect(creates.length).toBe(1);
  });

  it('runWorkflow aborts BEFORE cleanup when the remote is encrypted and the passphrase is missing', async () => {
    const encryptedChunk: CouchDbDocument = {
      _id: 'h:encrypted',
      _rev: '1-c',
      type: 'leaf',
      e_: true,
      data: '%=hkdf-ciphertext-body',
    };
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith('/')) {
        return okJson({ version: '3.5.2' });
      }
      if (url.endsWith(`/${databaseName}`) || url.endsWith(`/${databaseName}/`)) {
        return okJson({ db_name: databaseName, doc_count: 2, update_seq: '42' });
      }
      if (url.includes('obsydian_livesync_version')) {
        return okJson({ _id: 'obsydian_livesync_version', _rev: '1-v', version: 12 });
      }
      if (url.includes('obsydian_livesync_milestone')) {
        return okJson({
          _id: '_local/obsydian_livesync_milestone',
          _rev: '1-m',
          locked: false,
          tweak_values: { PREFERRED: {} },
        });
      }
      if (url.includes('_all_docs')) {
        return okJson({
          total_rows: 2,
          offset: 0,
          rows: [
            {
              id: 'h:encrypted',
              key: 'h:encrypted',
              value: { rev: '1-c' },
              doc: encryptedChunk,
            },
            {
              id: 'noteplain',
              key: 'noteplain',
              value: { rev: '1-n' },
              doc: await noteDoc('plain.md', 'hello'),
            },
          ],
        });
      }
      return new Response(JSON.stringify({ error: 'not_found' }), { status: 404 });
    });

    const coordinator = new AutoArmCoordinator();
    const cleanupVaultSpy = vi
      .spyOn(coordinator, 'cleanupLocalVault')
      .mockResolvedValue(undefined);
    const cleanupStateSpy = vi
      .spyOn(coordinator, 'cleanupLocalState')
      .mockResolvedValue(undefined);

    const result = await coordinator.runWorkflow({
      config: makeConfig(), // no passphrase
      guardedFetch: fetchMock as unknown as typeof globalThis.fetch,
    });

    expect(result.success).toBe(false);
    expect(result.triggered).toBe(true);
    expect(result.error).toContain('BEFORE local cleanup');
    expect(result.error).toContain('no encryption passphrase is configured');
    // THE core Phase 4 assertion: cleanup never ran.
    expect(cleanupVaultSpy).not.toHaveBeenCalled();
    expect(cleanupStateSpy).not.toHaveBeenCalled();

    // Real files also untouched (spies were mocked out, so check disk too).
    expect(await fs.readFile(path.join(vaultRoot, 'precious.md'), 'utf8')).toBe('do not lose me');
    expect(await fs.readFile(statePath, 'utf8')).toBe('mock existing state db');
  });

  it('runWorkflow aborts BEFORE cleanup when decode produces block actions', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith('/')) {
        return okJson({ version: '3.5.2' });
      }
      if (url.endsWith(`/${databaseName}`) || url.endsWith(`/${databaseName}/`)) {
        return okJson({ db_name: databaseName, doc_count: 1, update_seq: '42' });
      }
      if (url.includes('obsydian_livesync_version')) {
        return okJson({ _id: 'obsydian_livesync_version', _rev: '1-v', version: 12 });
      }
      if (url.includes('obsydian_livesync_milestone')) {
        return okJson({
          _id: '_local/obsydian_livesync_milestone',
          _rev: '1-m',
          locked: false,
          tweak_values: { PREFERRED: {} },
        });
      }
      if (url.includes('_all_docs')) {
        return okJson({
          total_rows: 1,
          offset: 0,
          rows: [
            {
              id: 'brokennote',
              key: 'brokennote',
              value: { rev: '1-n' },
              doc: {
                _id: 'brokennote',
                _rev: '1-n',
                type: 'plain',
                path: 'broken.md',
                // Non-zero size with no children -> MISSING_CHUNK block.
                children: [],
                size: 512,
              },
            },
          ],
        });
      }
      return new Response(JSON.stringify({ error: 'not_found' }), { status: 404 });
    });

    const coordinator = new AutoArmCoordinator();
    const cleanupVaultSpy = vi
      .spyOn(coordinator, 'cleanupLocalVault')
      .mockResolvedValue(undefined);
    const cleanupStateSpy = vi
      .spyOn(coordinator, 'cleanupLocalState')
      .mockResolvedValue(undefined);

    const result = await coordinator.runWorkflow({
      config: makeConfig(),
      guardedFetch: fetchMock as unknown as typeof globalThis.fetch,
    });

    expect(result.success).toBe(false);
    expect(result.triggered).toBe(true);
    expect(result.error).toContain('BEFORE local cleanup');
    expect(result.error).toContain('block actions');
    expect(cleanupVaultSpy).not.toHaveBeenCalled();
    expect(cleanupStateSpy).not.toHaveBeenCalled();
  });

  it('runWorkflow cleans up only AFTER the plan succeeds, then applies, validates, and grants (happy path)', async () => {
    const body = 'happy path note body';
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith('/')) {
        return okJson({ version: '3.5.2' });
      }
      if (url.endsWith(`/${databaseName}`) || url.endsWith(`/${databaseName}/`)) {
        return okJson({ db_name: databaseName, doc_count: 1, update_seq: '42' });
      }
      if (url.includes('obsydian_livesync_version')) {
        return okJson({ _id: 'obsydian_livesync_version', _rev: '1-v', version: 12 });
      }
      if (url.includes('obsydian_livesync_milestone')) {
        return okJson({
          _id: '_local/obsydian_livesync_milestone',
          _rev: '1-m',
          locked: false,
          tweak_values: { PREFERRED: {} },
        });
      }
      if (url.includes('_all_docs')) {
        return okJson({
          total_rows: 1,
          offset: 0,
          rows: [
            {
              id: 'notedoc',
              key: 'notedoc',
              value: { rev: '1-n' },
              doc: await noteDoc('pulled.md', body),
            },
          ],
        });
      }
      return new Response(JSON.stringify({ error: 'not_found' }), { status: 404 });
    });

    const coordinator = new AutoArmCoordinator();
    const calls: string[] = [];
    // Spy with call-through: record ordering, but let the real cleanup and
    // apply run so the subsequent validation and grant issuance operate on
    // genuine state.
    const origCleanupVault = coordinator.cleanupLocalVault.bind(coordinator);
    const cleanupVaultSpy = vi
      .spyOn(coordinator, 'cleanupLocalVault')
      .mockImplementation(async (root: string) => {
        calls.push('cleanup-vault');
        await origCleanupVault(root);
      });
    const origCleanupState = coordinator.cleanupLocalState.bind(coordinator);
    const cleanupStateSpy = vi
      .spyOn(coordinator, 'cleanupLocalState')
      .mockImplementation(async (p: string) => {
        calls.push('cleanup-state');
        await origCleanupState(p);
      });
    const origApply = coordinator.applyReadOnlyPull.bind(coordinator);
    const applySpy = vi
      .spyOn(coordinator, 'applyReadOnlyPull')
      .mockImplementation(async (...args: Parameters<AutoArmCoordinator['applyReadOnlyPull']>) => {
        calls.push('apply');
        return origApply(...args);
      });

    const result = await coordinator.runWorkflow({
      config: makeConfig(),
      guardedFetch: fetchMock as unknown as typeof globalThis.fetch,
    });

    expect(result.success).toBe(true);
    expect(result.triggered).toBe(true);
    expect(result.grant).toBeDefined();
    expect(cleanupVaultSpy).toHaveBeenCalledTimes(1);
    expect(cleanupStateSpy).toHaveBeenCalledTimes(1);
    // Ordering: both cleanups strictly before apply.
    expect(calls.indexOf('cleanup-vault')).toBeLessThan(calls.indexOf('apply'));
    expect(calls.indexOf('cleanup-state')).toBeLessThan(calls.indexOf('apply'));
  });

  it('plan phase timing marks are emitted through the provided logger', async () => {
    const lines: string[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/_all_docs')) {
        return okJson({ total_rows: 0, offset: 0, rows: [] });
      }
      return okJson({});
    });

    const coordinator = new AutoArmCoordinator();
    await coordinator.planReadOnlyPull(
      makeConfig(),
      fetchMock as unknown as typeof globalThis.fetch,
      makeProbeResult(),
      {
        admitted: true,
        remoteFingerprint,
        negotiatedSettingsHash: 'hash',
        negotiatedSettings: {},
        adoptedTweaks: {},
        blockers: [],
        admittedCapabilities: [],
        unsupportedCapabilities: [],
      } as never,
      (msg) => lines.push(msg)
    );

    expect(lines.some((l) => l.startsWith('[timing] inventory:') && l.includes('docs'))).toBe(true);
    expect(lines.some((l) => l.startsWith('[timing] decode:'))).toBe(true);
    expect(lines.some((l) => l.startsWith('[timing] plan:'))).toBe(true);
  });
});
