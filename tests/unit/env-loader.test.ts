import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs/promises';
import { loadConfig, ConfigValidationError } from '../../src/config/loader.js';
import { SecretRedactor } from '../../src/security/redaction.js';

describe('Environment-Driven Configuration Loader', () => {
  let tempDir: string;
  let vaultDir: string;
  let stateDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'livesync-env-test-'));
    vaultDir = path.join(tempDir, 'vault');
    stateDir = path.join(tempDir, 'state');
    await fs.mkdir(vaultDir, { recursive: true });
    await fs.mkdir(stateDir, { recursive: true });
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('synthesizes complete configuration purely from LIVESYNC_* environment variables without YAML file', async () => {
    const redactor = new SecretRedactor();
    const env: NodeJS.ProcessEnv = {
      LIVESYNC_COUCHDB_URL: 'http://127.0.0.1:5984',
      LIVESYNC_COUCHDB_DATABASE: 'my-vault-db',
      LIVESYNC_COUCHDB_USER: 'admin',
      LIVESYNC_COUCHDB_PASSWORD: 'supersecretremote',
      LIVESYNC_VAULT_PATH: vaultDir,
      LIVESYNC_STATE_PATH: path.join(stateDir, 'state.db'),
      LIVESYNC_ENCRYPTION_PASSPHRASE: 'supersecrete2ee',
      LIVESYNC_VAULT_DEDICATED: 'true',
    };

    const config = await loadConfig(undefined, env, redactor);

    expect(config.remote.url).toBe('http://127.0.0.1:5984');
    expect(config.remote.database).toBe('my-vault-db');
    expect(config.remote.username).toBe('admin');
    expect(config.resolvedSecrets.remotePassword).toBe('supersecretremote');
    expect(config.resolvedVaultPath).toBe(path.resolve(vaultDir));
    expect(config.vault.dedicated).toBe(true);
    expect(config.resolvedStatePath).toBe(path.resolve(path.join(stateDir, 'state.db')));
    expect(config.encryption?.enabled).toBe(true);
    expect(config.resolvedSecrets.encryptionPassphrase).toBe('supersecrete2ee');

    // Verify secret redaction registration
    expect(redactor.redactString('Connecting with supersecretremote and supersecrete2ee')).toBe(
      'Connecting with [REDACTED] and [REDACTED]'
    );
  });

  it('does not recognize removed fallback environment variable aliases', async () => {
    const env: NodeJS.ProcessEnv = {
      COUCHDB_URL: 'http://127.0.0.1:5984',
      COUCHDB_DATABASE: 'alias-db',
      COUCHDB_USER: 'alias-user',
      COUCHDB_PASSWORD: 'alias-password',
      VAULT_PATH: vaultDir,
      LIVESYNC_PASSPHRASE: 'alias-passphrase',
    };

    await expect(loadConfig(undefined, env)).rejects.toThrow(ConfigValidationError);
  });

  it('uses app default state path when LIVESYNC_STATE_PATH is omitted', async () => {
    const env: NodeJS.ProcessEnv = {
      LIVESYNC_COUCHDB_URL: 'http://127.0.0.1:5984',
      LIVESYNC_COUCHDB_DATABASE: 'my-vault-db',
      LIVESYNC_VAULT_PATH: vaultDir,
      HOME: tempDir,
    };

    const config = await loadConfig(undefined, env);
    const expectedDefault = path.resolve(
      path.join(tempDir, '.config/obsidian-livesync-headless/state.db')
    );
    expect(config.resolvedStatePath).toBe(expectedDefault);
  });

  it('overlays environment variables on top of an existing YAML configuration file', async () => {
    const configPath = path.join(tempDir, 'base-config.yaml');
    await fs.writeFile(
      configPath,
      `
remote:
  url: "http://yaml-host:5984"
  database: "yaml-db"
  username: "yaml-user"
vault:
  path: "${vaultDir}"
  dedicated: false
state:
  path: "${path.join(stateDir, 'yaml-state.db')}"
`
    );

    const env: NodeJS.ProcessEnv = {
      LIVESYNC_COUCHDB_URL: 'http://env-host:5984',
      LIVESYNC_COUCHDB_USER: 'env-user',
      LIVESYNC_COUCHDB_PASSWORD: 'env-password',
      LIVESYNC_VAULT_DEDICATED: '1',
    };

    const config = await loadConfig(configPath, env);

    // Overridden values
    expect(config.remote.url).toBe('http://env-host:5984');
    expect(config.remote.username).toBe('env-user');
    expect(config.resolvedSecrets.remotePassword).toBe('env-password');
    expect(config.vault.dedicated).toBe(true);

    // Retained from YAML
    expect(config.remote.database).toBe('yaml-db');
    expect(config.resolvedVaultPath).toBe(path.resolve(vaultDir));
    expect(config.resolvedStatePath).toBe(path.resolve(path.join(stateDir, 'yaml-state.db')));
  });

  it('coerces boolean environment variables correctly', async () => {
    const baseEnv: NodeJS.ProcessEnv = {
      LIVESYNC_COUCHDB_URL: 'http://127.0.0.1:5984',
      LIVESYNC_COUCHDB_DATABASE: 'test-db',
      LIVESYNC_VAULT_PATH: vaultDir,
      LIVESYNC_STATE_PATH: path.join(stateDir, 'state.db'),
    };

    // Test "true" / "1" / "false" / "0"
    const config1 = await loadConfig(undefined, { ...baseEnv, LIVESYNC_VAULT_DEDICATED: '1' });
    expect(config1.vault.dedicated).toBe(true);

    const config2 = await loadConfig(undefined, { ...baseEnv, LIVESYNC_VAULT_DEDICATED: 'true' });
    expect(config2.vault.dedicated).toBe(true);

    const config3 = await loadConfig(undefined, { ...baseEnv, LIVESYNC_VAULT_DEDICATED: '0' });
    expect(config3.vault.dedicated).toBe(false);

    const config4 = await loadConfig(undefined, { ...baseEnv, LIVESYNC_VAULT_DEDICATED: 'false' });
    expect(config4.vault.dedicated).toBe(false);
  });

  it('coerces integer CLI options and daemon parameters', async () => {
    const env: NodeJS.ProcessEnv = {
      LIVESYNC_COUCHDB_URL: 'http://127.0.0.1:5984',
      LIVESYNC_COUCHDB_DATABASE: 'test-db',
      LIVESYNC_VAULT_PATH: vaultDir,
      LIVESYNC_STATE_PATH: path.join(stateDir, 'state.db'),
      LIVESYNC_WRITE: 'true',
      LIVESYNC_PERIODIC_SCAN_SEC: '600',
      LIVESYNC_CONCURRENCY: '8',
      LIVESYNC_DEBOUNCE_MS: '500',
    };

    const config = await loadConfig(undefined, env);
    expect(config.cli?.write).toBe(true);
    expect(config.cli?.periodicScanSec).toBe(600);
    expect(config.cli?.concurrency).toBe(8);
    expect(config.cli?.debounceMs).toBe(500);
  });

  it('parses LIVESYNC_INCREMENTAL_PULL and defaults cli.incrementalPull to true', async () => {
    const baseEnv: NodeJS.ProcessEnv = {
      LIVESYNC_COUCHDB_URL: 'http://127.0.0.1:5984',
      LIVESYNC_COUCHDB_DATABASE: 'test-db',
      LIVESYNC_VAULT_PATH: vaultDir,
      LIVESYNC_STATE_PATH: path.join(stateDir, 'state.db'),
    };

    // Default when omitted (no cli block): consumers apply `?? true`.
    const defaulted = await loadConfig(undefined, { ...baseEnv });
    expect(defaulted.cli?.incrementalPull ?? true).toBe(true);

    // Explicitly enabled / disabled
    const enabled = await loadConfig(undefined, { ...baseEnv, LIVESYNC_INCREMENTAL_PULL: 'true' });
    expect(enabled.cli?.incrementalPull).toBe(true);

    const disabled = await loadConfig(undefined, { ...baseEnv, LIVESYNC_INCREMENTAL_PULL: 'false' });
    expect(disabled.cli?.incrementalPull).toBe(false);
  });

  it('enforces CONF-03 path safety on environment-derived paths', async () => {
    const baseEnv: NodeJS.ProcessEnv = {
      LIVESYNC_COUCHDB_URL: 'http://127.0.0.1:5984',
      LIVESYNC_COUCHDB_DATABASE: 'test-db',
    };

    // 1. Root vault path rejection
    await expect(
      loadConfig(undefined, { ...baseEnv, LIVESYNC_VAULT_PATH: '/' })
    ).rejects.toThrow(ConfigValidationError);

    // 2. Home directory vault rejection
    await expect(
      loadConfig(undefined, { ...baseEnv, LIVESYNC_VAULT_PATH: os.homedir() })
    ).rejects.toThrow(/Vault path cannot be the user home directory/);

    // 3. Overlapping vault and state paths rejection
    await expect(
      loadConfig(undefined, {
        ...baseEnv,
        LIVESYNC_VAULT_PATH: vaultDir,
        LIVESYNC_STATE_PATH: path.join(vaultDir, 'nested-state'),
      })
    ).rejects.toThrow(/Vault directory and state directory must not overlap/);
  });

  it('fails with clear error when required configuration is missing', async () => {
    await expect(loadConfig(undefined, {})).rejects.toThrow(ConfigValidationError);
    await expect(
      loadConfig(undefined, { LIVESYNC_COUCHDB_URL: 'http://127.0.0.1:5984' })
    ).rejects.toThrow(/Configuration validation failed/);
  });

  it('rejects CouchDB URLs with embedded credentials in environment variables', async () => {
    const env: NodeJS.ProcessEnv = {
      LIVESYNC_COUCHDB_URL: 'http://admin:secret@127.0.0.1:5984',
      LIVESYNC_COUCHDB_DATABASE: 'test-db',
      LIVESYNC_VAULT_PATH: vaultDir,
    };

    await expect(loadConfig(undefined, env)).rejects.toThrow(
      /CouchDB URL must not contain embedded username or password/
    );
  });
});
