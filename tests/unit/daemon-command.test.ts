import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { createHash } from 'node:crypto';
import { parseCliArgs, CLI_HELP } from '../../src/cli/index.js';
import { runDaemonCommand } from '../../src/cli/commands/daemon.js';
import { computeFingerprint, computeSettingsHash } from '../../src/livesync/negotiation.js';
import { openDatabase } from '../../src/storage/sqlite.js';
import { AdmissionRepository } from '../../src/storage/admission-repo.js';
import { ProvenanceRepository } from '../../src/storage/provenance-repo.js';
import { WriteGrantRepo } from '../../src/storage/write-grant-repo.js';
import { EXIT_CODES } from '../../src/diagnostics/outcomes.js';

describe('CLI Daemon Command', () => {
  let tmpDir: string;
  let vaultDir: string;
  let configPath: string;
  let stateDbPath: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ols-daemon-cmd-test-'));
    vaultDir = path.join(tmpDir, 'vault');
    await fs.mkdir(vaultDir, { recursive: true });

    stateDbPath = path.join(tmpDir, 'state.sqlite');
    configPath = path.join(tmpDir, 'config.yaml');

    const configContent = `
remote:
  url: "http://127.0.0.1:5984"
  database: "testdb"
vault:
  path: "${vaultDir}"
state:
  path: "${stateDbPath}"
`;
    await fs.writeFile(configPath, configContent);

    const fingerprint = computeFingerprint('http://127.0.0.1:5984', 'testdb');

    // Seed admission
    const db = openDatabase(stateDbPath);
    const admissionRepo = new AdmissionRepository(db);
    admissionRepo.saveAdmission({
      remoteFingerprint: fingerprint,
      couchdbUrl: 'http://127.0.0.1:5984',
      databaseName: 'testdb',
      couchdbVersion: '3.5.2',
      versionInfoRev: '1-v',
      milestoneRev: '1-m',
      negotiatedSettingsHash: 'shash-123',
      negotiatedSettingsJson: '{}',
      updateSeq: '0',
      admittedAt: new Date().toISOString(),
    });
    db.close();
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('parses CLI daemon arguments correctly', () => {
    const parsed = parseCliArgs([
      'daemon',
      '-c',
      'config.yaml',
      '--write',
      '--periodic-scan-sec',
      '60',
      '--concurrency',
      '8',
      '--debounce-ms',
      '500',
    ]);

    expect(parsed.command).toBe('daemon');
    expect(parsed.options.config).toBe('config.yaml');
    expect(parsed.options.write).toBe(true);
    expect(parsed.options.periodicScanSec).toBe(60);
    expect(parsed.options.concurrency).toBe(8);
    expect(parsed.options.debounceMs).toBe(500);
  });

  it('includes daemon command in CLI help text', () => {
    expect(CLI_HELP).toContain('daemon');
    expect(CLI_HELP).toContain('--periodic-scan-sec');
    expect(CLI_HELP).toContain('--concurrency');
    expect(CLI_HELP).toContain('--debounce-ms');
  });

  it('rejects --write mode with error when no active write grant exists', async () => {
    const stdoutLines: string[] = [];
    const stderrLines: string[] = [];

    const exitCode = await runDaemonCommand({
      configPath,
      write: true,
      stdout: (msg) => stdoutLines.push(msg),
      stderr: (msg) => stderrLines.push(msg),
      registerSignalHandlers: false,
    });

    expect(exitCode).toBe(EXIT_CODES.CONFIG_ERROR);
    expect(stderrLines.some((msg) => msg.includes('No active write grant found'))).toBe(true);
  });

  it('runs read-only daemon startup cleanly when write mode is false', async () => {
    const stdoutLines: string[] = [];
    const stderrLines: string[] = [];

    // Mock fetch for catch-up pass and changes stream
    const mockFetch: typeof globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('/_changes')) {
        return {
          ok: true,
          status: 200,
          body: new ReadableStream<Uint8Array>({
            start(controller) {
              controller.close();
            },
          }),
        } as unknown as Response;
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ rows: [] }),
      } as unknown as Response;
    });

    const exitCode = await runDaemonCommand({
      configPath,
      write: false,
      fetch: mockFetch,
      stdout: (msg) => stdoutLines.push(msg),
      stderr: (msg) => stderrLines.push(msg),
      registerSignalHandlers: false,
      onEngineReady: async (engine) => {
        expect(engine.stateMachine.getState()).toBe('DEGRADED_READ_ONLY');
        await engine.stop();
      },
    });

    expect(exitCode).toBe(EXIT_CODES.SUCCESS);
    expect(stdoutLines.some((msg) => msg.includes('Read-Only (Pull Monitoring)'))).toBe(true);
    expect(stdoutLines.some((msg) => msg.includes('read-only (pull-only) mode'))).toBe(true);
    expect(stdoutLines.some((msg) => msg.includes('LIVESYNC_MODE=write'))).toBe(true);
  });

  it('rejects LIVESYNC_WRITE=true env var with error when no active write grant exists', async () => {
    const stdoutLines: string[] = [];
    const stderrLines: string[] = [];

    // Pass write via config (simulating LIVESYNC_WRITE=true in env) but NOT via CLI options.write
    // The daemon should still detect write intent from config.cli.write and fail with a clear error.
    const envConfigPath = configPath.replace('config.yaml', 'config-write.yaml');
    await fs.writeFile(
      envConfigPath,
      `
remote:
  url: "http://127.0.0.1:5984"
  database: "testdb"
vault:
  path: "${vaultDir}"
state:
  path: "${stateDbPath}"
cli:
  write: true
`
    );

    const exitCode = await runDaemonCommand({
      configPath: envConfigPath,
      write: false, // CLI flag NOT set — should still pick up write:true from config
      stdout: (msg) => stdoutLines.push(msg),
      stderr: (msg) => stderrLines.push(msg),
      registerSignalHandlers: false,
    });

    expect(exitCode).toBe(EXIT_CODES.CONFIG_ERROR);
    expect(stderrLines.some((msg) => msg.includes('No active write grant found'))).toBe(true);
    expect(stderrLines.some((msg) => msg.includes('FIX'))).toBe(true);
    expect(stderrLines.some((msg) => msg.includes('arm'))).toBe(true);
    // Banner should show Bidirectional mode because write was requested via config
    expect(stdoutLines.some((msg) => msg.includes('Bidirectional (Write Armed)'))).toBe(true);
  });
});

describe('Daemon Startup Inventory Deduplication (Phase 2)', () => {
  let tmpDir: string;
  let vaultDir: string;
  let configPath: string;
  let stateDbPath: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ols-daemon-dedup-test-'));
    vaultDir = path.join(tmpDir, 'vault');
    await fs.mkdir(vaultDir, { recursive: true });

    stateDbPath = path.join(tmpDir, 'state.sqlite');
    configPath = path.join(tmpDir, 'config.yaml');

    const configContent = `
remote:
  url: "http://127.0.0.1:5984"
  database: "testdb"
vault:
  path: "${vaultDir}"
state:
  path: "${stateDbPath}"
`;
    await fs.writeFile(configPath, configContent);
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  /**
   * Mock fetch covering the probe, auto-arm pull, engine catch-up, and
   * changes-feed endpoints. Counts full inventory requests (`_all_docs` with
   * `include_docs=true`) — each full sync pass (auto-arm pull or engine
   * catch-up) performs exactly one.
   */
  function createCountingMockFetch() {
    const calls: string[] = [];
    const fetchFn = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      calls.push(url);

      if (url.includes('/_changes')) {
        return {
          ok: true,
          status: 200,
          body: new ReadableStream<Uint8Array>({
            start(controller) {
              controller.close();
            },
          }),
        } as unknown as Response;
      }

      if (url.endsWith('/testdb') || url.endsWith('/testdb/')) {
        return new Response(
          JSON.stringify({ db_name: 'testdb', doc_count: 0, update_seq: '42' }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      if (url.includes('obsydian_livesync_version')) {
        return new Response(
          JSON.stringify({ _id: 'obsydian_livesync_version', _rev: '1-v', version: 12 }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      if (url.includes('obsydian_livesync_milestone')) {
        return new Response(
          JSON.stringify({
            _id: '_local/obsydian_livesync_milestone',
            _rev: '1-m',
            locked: false,
            tweak_values: { PREFERRED: {} },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      if (url.includes('_all_docs')) {
        return new Response(JSON.stringify({ total_rows: 0, offset: 0, rows: [] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }

      return new Response(JSON.stringify({ error: 'not_found' }), { status: 404 });
    }) as unknown as typeof globalThis.fetch;

    return {
      fetch: fetchFn,
      inventoryCallCount: () =>
        calls.filter((u) => u.includes('_all_docs') && u.includes('include_docs=true')).length,
    };
  }

  it('auto-arm trigger path: engine catch-up pass is skipped (single inventory pass)', async () => {
    const { fetch, inventoryCallCount } = createCountingMockFetch();
    const stdoutLines: string[] = [];
    const stderrLines: string[] = [];

    const exitCode = await runDaemonCommand({
      configPath,
      write: 'auto-arm',
      fetch,
      stdout: (msg) => stdoutLines.push(msg),
      stderr: (msg) => stderrLines.push(msg),
      registerSignalHandlers: false,
      onEngineReady: async (engine) => {
        expect(engine.stateMachine.getState()).toBe('HEALTHY_BIDIRECTIONAL');
        await engine.stop();
      },
    });

    expect(exitCode).toBe(EXIT_CODES.SUCCESS);
    // Auto-arm detected the empty vault, pulled, and armed.
    expect(stdoutLines.some((msg) => msg.includes('[auto-arm] Trigger condition detected'))).toBe(true);
    expect(stdoutLines.some((msg) => msg.includes('Successfully armed write grant'))).toBe(true);

    // Exactly ONE full inventory: the auto-arm pull. The engine's initial
    // catch-up pass was skipped instead of re-inventorying everything.
    expect(inventoryCallCount()).toBe(1);
    // The skip is logged so operators can see the short-circuit.
    expect(stderrLines.some((msg) => msg.includes('Initial catch-up sync skipped'))).toBe(true);
  });

  it('auto-arm did NOT trigger: catch-up pass still runs (two inventory passes total: pull + catch-up)', async () => {
    // Seed a valid vault/state/grant so checkTrigger returns shouldAutoArm=false:
    // one file on disk with matching provenance and an active write grant whose
    // binding matches what negotiation would derive for the mocked remote.
    const fingerprint = computeFingerprint('http://127.0.0.1:5984', 'testdb');
    // negotiateCompatibility builds negotiatedSettings = { databaseName, version }
    // for the mocked remote (version doc says 12, empty preferred tweaks).
    const settingsHash = computeSettingsHash({ databaseName: 'testdb', version: 12 });

    const db = openDatabase(stateDbPath);
    const provRepo = new ProvenanceRepository(db);
    const content = 'stable note content';
    const sha = createHash('sha256').update(content).digest('hex');
    provRepo.saveProvenance({
      path: 'note.md',
      remoteRevision: '1-abc',
      contentSha256: sha,
      observedMtime: Date.now(),
      remoteFingerprint: fingerprint,
      reflectedAt: new Date().toISOString(),
    });
    const grantRepo = new WriteGrantRepo(db);
    grantRepo.issueGrant({
      remoteFingerprint: fingerprint,
      vaultRoot: vaultDir,
      settingsHash,
      commonlibVersion: '0.1.21',
      bootstrapGeneration: '1-v',
    });
    db.close();
    await fs.writeFile(path.join(vaultDir, 'note.md'), content);

    const { fetch, inventoryCallCount } = createCountingMockFetch();
    const stdoutLines: string[] = [];
    const stderrLines: string[] = [];

    const exitCode = await runDaemonCommand({
      configPath,
      write: 'auto-arm',
      fetch,
      stdout: (msg) => stdoutLines.push(msg),
      stderr: (msg) => stderrLines.push(msg),
      registerSignalHandlers: false,
      onEngineReady: async (engine) => {
        expect(engine.stateMachine.getState()).toBe('HEALTHY_BIDIRECTIONAL');
        await engine.stop();
      },
    });

    expect(exitCode).toBe(EXIT_CODES.SUCCESS);
    // No trigger -> no auto-arm pull, no skip hint...
    expect(stdoutLines.some((msg) => msg.includes('[auto-arm] Trigger condition detected'))).toBe(false);
    expect(stderrLines.some((msg) => msg.includes('Initial catch-up sync skipped'))).toBe(false);
    // ...so the engine's initial catch-up pass ran its full inventory.
    expect(inventoryCallCount()).toBe(1);
  });

  it('read-only startup: behavior unchanged (catch-up pass runs its inventory)', async () => {
    const { fetch, inventoryCallCount } = createCountingMockFetch();
    const stdoutLines: string[] = [];
    const stderrLines: string[] = [];

    const exitCode = await runDaemonCommand({
      configPath,
      write: false,
      fetch,
      stdout: (msg) => stdoutLines.push(msg),
      stderr: (msg) => stderrLines.push(msg),
      registerSignalHandlers: false,
      onEngineReady: async (engine) => {
        expect(engine.stateMachine.getState()).toBe('DEGRADED_READ_ONLY');
        await engine.stop();
      },
    });

    expect(exitCode).toBe(EXIT_CODES.SUCCESS);
    expect(stderrLines.some((msg) => msg.includes('Initial catch-up sync skipped'))).toBe(false);
    expect(inventoryCallCount()).toBe(1);
  });
});
