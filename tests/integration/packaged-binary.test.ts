import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

const binaryPath = path.resolve(process.cwd(), 'dist/obsidian-livesync-headless');

interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: Error;
}

function runPackagedBinary(
  args: string[],
  envOverrides: Record<string, string> = {}
): RunResult {
  const env: NodeJS.ProcessEnv = {
    PATH: '/usr/bin:/bin',
    HOME: os.homedir(),
    TMPDIR: os.tmpdir(),
    USER: process.env.USER || 'testuser',
    ...envOverrides,
  };
  delete env.NODE_OPTIONS;
  delete env.NODE_PATH;

  const result = spawnSync(binaryPath, args, {
    env,
    encoding: 'utf-8',
    timeout: 15000,
  });

  return {
    status: result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    error: result.error,
  };
}

describe('Standalone SEA Packaged Binary Integration', () => {
  let tmpDir: string;

  beforeAll(() => {
    if (!fs.existsSync(binaryPath)) {
      execFileSync(process.execPath, ['scripts/build-sea.mjs'], {
        stdio: 'inherit',
        cwd: process.cwd(),
      });
    }
    expect(fs.existsSync(binaryPath)).toBe(true);

    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sea-pkg-test-'));
  });

  afterAll(() => {
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('executes version command in isolated PATH with human-readable banner', () => {
    const res = runPackagedBinary(['version']);
    expect(res.error).toBeUndefined();
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('OBSIDIAN LIVESYNC HEADLESS — BUILD & COMPATIBILITY IDENTITY');
    expect(res.stdout).toContain('LiveSync Compatibility:   1.0.23');
    expect(res.stdout).toContain('Commonlib Version:        0.1.21');
    expect(res.stdout).toContain('Target CouchDB:           3.5.2');
    expect(res.stdout).toContain('SEA=true');
    expect(res.stderr).not.toContain('ExperimentalWarning');
  });

  it('executes --version flag in isolated PATH with human-readable banner', () => {
    const res = runPackagedBinary(['--version']);
    expect(res.error).toBeUndefined();
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('OBSIDIAN LIVESYNC HEADLESS — BUILD & COMPATIBILITY IDENTITY');
    expect(res.stdout).toContain('SEA=true');
  });

  it('executes version --json in isolated PATH returning structured metadata', () => {
    const res = runPackagedBinary(['version', '--json']);
    expect(res.error).toBeUndefined();
    expect(res.status).toBe(0);

    const parsed = JSON.parse(res.stdout.trim());
    expect(parsed.type).toBe('version_identity');
    expect(parsed.name).toBe('obsidian-livesync-headless');
    expect(parsed.version).toBe('0.1.0');
    expect(parsed.liveSyncCompatibility).toBe('1.0.23');
    expect(parsed.commonlibVersion).toBe('0.1.21');
    expect(parsed.targetCouchDbVersion).toBe('3.5.2');
    expect(parsed.dependencyOverrides['pouchdb-core'].uuid).toBe('11.1.1');
    expect(parsed.dependencyOverrides['pouchdb-utils'].uuid).toBe('11.1.1');
    expect(parsed.runtime.sea).toBe(true);
  });

  it('executes --help in isolated PATH documenting all 7 command flows', () => {
    const res = runPackagedBinary(['--help']);
    expect(res.error).toBeUndefined();
    expect(res.status).toBe(0);

    // Verify all 7 commands
    expect(res.stdout).toContain('inspect');
    expect(res.stdout).toContain('pull');
    expect(res.stdout).toContain('arm');
    expect(res.stdout).toContain('sync');
    expect(res.stdout).toContain('daemon');
    expect(res.stdout).toContain('status');
    expect(res.stdout).toContain('version');

    // Verify CLI options
    expect(res.stdout).toContain('--config');
    expect(res.stdout).toContain('--write');
    expect(res.stdout).toContain('--periodic-scan-sec');
    expect(res.stdout).toContain('--concurrency');
    expect(res.stdout).toContain('--debounce-ms');
    expect(res.stdout).toContain('--json');
    expect(res.stdout).toContain('--dry-run');
    expect(res.stdout).toContain('--revoke');
  });

  it('executes status command on uninitialized vault returning status report', () => {
    const vaultPath = path.join(tmpDir, 'test-vault');
    fs.mkdirSync(vaultPath, { recursive: true });

    const configPath = path.join(tmpDir, 'config.yaml');
    const configContent = `
remote:
  url: "http://127.0.0.1:5984"
  database: "test-db"
  username: "admin"
  password: "password"
vault:
  path: "${vaultPath}"
`;
    fs.writeFileSync(configPath, configContent);

    // Human output
    const humanRes = runPackagedBinary(['status', '--config', configPath]);
    expect(humanRes.error).toBeUndefined();
    expect(humanRes.status).toBe(0);
    expect(humanRes.stdout).toContain('OBSIDIAN LIVESYNC VAULT STATUS');
    expect(humanRes.stdout).toContain('Unconfigured');
    expect(humanRes.stdout).toContain('NOT ADMITTED');
    expect(humanRes.stdout).toContain('INACTIVE');

    // JSON output
    const jsonRes = runPackagedBinary(['status', '--config', configPath, '--json']);
    expect(jsonRes.error).toBeUndefined();
    expect(jsonRes.status).toBe(0);
    const parsed = JSON.parse(jsonRes.stdout.trim());
    expect(parsed.type).toBe('status_report');
    expect(parsed.outcome).toBe('SUCCESS');
    expect(parsed.databaseExists).toBe(false);
    expect(parsed.admission.admitted).toBe(false);
    expect(parsed.writeGrant.active).toBe(false);
  });

  it('fails safely when required config is missing', () => {
    const res = runPackagedBinary(['status']);
    expect(res.status).toBe(1); // CONFIG_ERROR
    expect(res.stderr).toContain('Missing required configuration');
    expect(res.stderr).toContain('--config');
  });

  it('fails safely with exit code 1 on unknown command', () => {
    const res = runPackagedBinary(['nonexistent-command']);
    expect(res.status).toBe(1); // CONFIG_ERROR
    expect(res.stderr).toContain("Unknown command 'nonexistent-command'");
  });

  it('executes pull with --dry-run and fails closed with transient error when remote unreachable', () => {
    const vaultPath = path.join(tmpDir, 'dryrun-vault');
    fs.mkdirSync(vaultPath, { recursive: true });

    const configPath = path.join(tmpDir, 'dryrun-config.yaml');
    const configContent = `
remote:
  url: "http://127.0.0.1:59999"
  database: "nonexistent"
  username: "admin"
  password: "password"
vault:
  path: "${vaultPath}"
`;
    fs.writeFileSync(configPath, configContent);

    const res = runPackagedBinary(['pull', '--config', configPath, '--dry-run', '--json']);
    // Should fail closed with transient outage or auth error (exit code 2 or 5)
    expect([2, 5]).toContain(res.status);
    expect(res.stdout.length + res.stderr.length).toBeGreaterThan(0);
  });
});
