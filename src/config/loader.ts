import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import yaml from 'yaml';
import {
  LiveSyncConfigSchema,
  type LiveSyncConfig,
  type LoadedConfig,
  type ResolvedSecrets,
} from './schema.js';
import { resolveSecret } from './secrets.js';
import type { SecretRedactor } from '../security/redaction.js';

export class ConfigValidationError extends Error {
  readonly issues?: readonly string[];

  constructor(message: string, issues?: readonly string[]) {
    super(message);
    this.name = 'ConfigValidationError';
    this.issues = issues;
  }
}

function parseBooleanEnv(val: string | undefined): boolean | undefined {
  if (val === undefined || val === '') return undefined;
  const lower = val.trim().toLowerCase();
  if (lower === 'true' || lower === '1' || lower === 'yes' || lower === 'on') return true;
  if (lower === 'false' || lower === '0' || lower === 'no' || lower === 'off') return false;
  return undefined;
}

function parseModeEnv(val: string | undefined): boolean | 'auto-arm' | undefined {
  if (val === undefined || val === '') return undefined;
  const lower = val.trim().toLowerCase();
  if (lower === 'auto-arm' || lower === 'autoarm' || lower === 'auto_arm') return 'auto-arm';
  if (
    lower === 'write' ||
    lower === 'bidirectional' ||
    lower === 'sync' ||
    lower === 'true' ||
    lower === '1' ||
    lower === 'yes' ||
    lower === 'on'
  ) {
    return true;
  }
  if (
    lower === 'read-only' ||
    lower === 'readonly' ||
    lower === 'pull' ||
    lower === 'false' ||
    lower === '0' ||
    lower === 'no' ||
    lower === 'off'
  ) {
    return false;
  }
  return undefined;
}

function parseIntegerEnv(val: string | undefined): number | undefined {
  if (val === undefined || val === '') return undefined;
  const parsed = Number(val.trim());
  if (Number.isInteger(parsed)) return parsed;
  return NaN;
}

function extractEnvConfig(env: NodeJS.ProcessEnv): Record<string, any> {
  const envConfig: Record<string, any> = {};

  // Remote mapping
  const remoteUrl = env.LIVESYNC_COUCHDB_URL;
  const remoteDatabase = env.LIVESYNC_COUCHDB_DATABASE;
  const remoteUsername = env.LIVESYNC_COUCHDB_USER;
  const remotePassword = env.LIVESYNC_COUCHDB_PASSWORD;

  const remote: Record<string, any> = {};
  if (remoteUrl !== undefined && remoteUrl !== '') remote.url = remoteUrl;
  if (remoteDatabase !== undefined && remoteDatabase !== '') remote.database = remoteDatabase;
  if (remoteUsername !== undefined && remoteUsername !== '') remote.username = remoteUsername;
  if (remotePassword !== undefined && remotePassword !== '') remote.password = remotePassword;
  if (Object.keys(remote).length > 0) envConfig.remote = remote;

  // Vault mapping
  const vaultPath = env.LIVESYNC_VAULT_PATH;
  const vaultDedicated = parseBooleanEnv(env.LIVESYNC_VAULT_DEDICATED);

  const vault: Record<string, any> = {};
  if (vaultPath !== undefined && vaultPath !== '') vault.path = vaultPath;
  if (vaultDedicated !== undefined) vault.dedicated = vaultDedicated;
  if (Object.keys(vault).length > 0) envConfig.vault = vault;

  // State mapping
  const statePath = env.LIVESYNC_STATE_PATH;
  const state: Record<string, any> = {};
  if (statePath !== undefined && statePath !== '') state.path = statePath;
  if (Object.keys(state).length > 0) envConfig.state = state;

  // Encryption mapping
  const passphrase = env.LIVESYNC_ENCRYPTION_PASSPHRASE;
  const encryptionEnabled = parseBooleanEnv(env.LIVESYNC_ENCRYPTION_ENABLED);

  const encryption: Record<string, any> = {};
  if (passphrase !== undefined && passphrase !== '') {
    encryption.passphrase = passphrase;
    encryption.enabled = encryptionEnabled ?? true;
  } else if (encryptionEnabled !== undefined) {
    encryption.enabled = encryptionEnabled;
  }
  if (Object.keys(encryption).length > 0) envConfig.encryption = encryption;

  // CLI / Daemon mode defaults (LIVESYNC_MODE: "auto-arm" | "write" | "read-only")
  const modeVal = parseModeEnv(env.LIVESYNC_MODE ?? env.LIVESYNC_WRITE);
  const periodicScanSec = parseIntegerEnv(env.LIVESYNC_PERIODIC_SCAN_SEC);
  const concurrency = parseIntegerEnv(env.LIVESYNC_CONCURRENCY);
  const debounceMs = parseIntegerEnv(env.LIVESYNC_DEBOUNCE_MS);
  const incrementalPull = parseBooleanEnv(env.LIVESYNC_INCREMENTAL_PULL);

  const cli: Record<string, any> = {};
  if (modeVal !== undefined) {
    cli.write = modeVal;
    if (modeVal === 'auto-arm') {
      cli.autoArm = true;
    }
  }
  if (periodicScanSec !== undefined) cli.periodicScanSec = periodicScanSec;
  if (concurrency !== undefined) cli.concurrency = concurrency;
  if (debounceMs !== undefined) cli.debounceMs = debounceMs;
  if (incrementalPull !== undefined) cli.incrementalPull = incrementalPull;
  if (Object.keys(cli).length > 0) envConfig.cli = cli;

  return envConfig;
}

function deepMerge(target: Record<string, any>, source: Record<string, any>): Record<string, any> {
  const result: Record<string, any> = { ...target };
  for (const [key, value] of Object.entries(source)) {
    if (
      value !== null &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      typeof result[key] === 'object' &&
      result[key] !== null &&
      !Array.isArray(result[key])
    ) {
      result[key] = deepMerge(result[key], value);
    } else if (value !== undefined) {
      result[key] = value;
    }
  }
  return result;
}

export async function loadConfig(
  configFilePath?: string,
  env: NodeJS.ProcessEnv = process.env,
  redactor?: SecretRedactor
): Promise<LoadedConfig> {
  let rawConfig: Record<string, any>;
  let configDir: string;

  const envConfig = extractEnvConfig(env);

  if (configFilePath) {
    const resolvedConfigPath = path.resolve(configFilePath);
    let fileContent: string;

    try {
      fileContent = await fs.readFile(resolvedConfigPath, 'utf-8');
    } catch (err) {
      throw new ConfigValidationError(
        `Failed to read configuration file '${configFilePath}': ${(err as Error).message}`
      );
    }

    // Parse YAML strictly
    const doc = yaml.parseDocument(fileContent, { prettyErrors: true });
    if (doc.errors && doc.errors.length > 0) {
      const errorMessages = doc.errors.map((e) => e.message);
      throw new ConfigValidationError(
        `YAML syntax error in '${configFilePath}': ${errorMessages.join('; ')}`,
        errorMessages
      );
    }

    const rawObj = doc.toJS();
    if (!rawObj || typeof rawObj !== 'object' || Array.isArray(rawObj)) {
      throw new ConfigValidationError('Configuration must be a YAML mapping');
    }

    rawConfig = deepMerge(rawObj as Record<string, any>, envConfig);
    configDir = path.dirname(resolvedConfigPath);
  } else {
    rawConfig = envConfig;
    configDir = process.cwd();
  }

  // Validate strict schema structure before resolving or path checking
  const parseResult = LiveSyncConfigSchema.safeParse(rawConfig);
  if (!parseResult.success) {
    const issues = parseResult.error.issues.map((issue) => {
      const fieldPath = issue.path.join('.');
      return fieldPath ? `${fieldPath}: ${issue.message}` : issue.message;
    });
    throw new ConfigValidationError(
      `Configuration validation failed:\n- ${issues.join('\n- ')}`,
      issues
    );
  }

  const config: LiveSyncConfig = parseResult.data;

  // Resolve secrets
  let remotePassword: string | undefined;
  try {
    remotePassword = await resolveSecret(
      config.remote.password,
      env,
      configDir
    );
  } catch (err) {
    throw new ConfigValidationError((err as Error).message);
  }

  let encryptionPassphrase: string | undefined;
  try {
    encryptionPassphrase = await resolveSecret(
      config.encryption?.passphrase,
      env,
      configDir
    );
  } catch (err) {
    throw new ConfigValidationError((err as Error).message);
  }

  // Register plaintext secrets with redactor if provided
  if (redactor) {
    if (remotePassword) {
      redactor.registerSecret(remotePassword);
    }
    if (encryptionPassphrase) {
      redactor.registerSecret(encryptionPassphrase);
    }
  }

  // Path Safety Verification (CONF-03)
  const vaultPath = path.resolve(config.vault.path);
  const defaultStateBase = env.HOME ? path.resolve(env.HOME) : os.homedir();
  const defaultStateDir = path.resolve(
    path.join(defaultStateBase, '.config/obsidian-livesync-headless/state.db')
  );
  const statePath = config.state?.path ? path.resolve(config.state.path) : defaultStateDir;

  // Reject system root: "/" or filesystem root (e.g. "/" on POSIX, "C:\\" on Windows)
  const rootDir = path.parse(vaultPath).root;
  if (vaultPath === '/' || vaultPath === rootDir) {
    throw new ConfigValidationError('Vault path cannot be the root filesystem directory');
  }

  // Reject user home directory
  const homeDirs = new Set<string>();
  homeDirs.add(path.resolve(os.homedir()));
  if (env.HOME) {
    homeDirs.add(path.resolve(env.HOME));
  }
  if (homeDirs.has(vaultPath)) {
    throw new ConfigValidationError('Vault path cannot be the user home directory');
  }

  // Reject parent directory traversal escapes that reach root
  if (vaultPath === path.parse(vaultPath).root) {
    throw new ConfigValidationError('Vault path cannot be the root filesystem directory');
  }

  // Reject overlapping directories (identical, or one is ancestor/descendant of the other)
  if (vaultPath === statePath) {
    throw new ConfigValidationError('Vault directory and state directory must not overlap');
  }
  if (statePath.startsWith(vaultPath + path.sep)) {
    throw new ConfigValidationError('Vault directory and state directory must not overlap');
  }
  if (vaultPath.startsWith(statePath + path.sep)) {
    throw new ConfigValidationError('Vault directory and state directory must not overlap');
  }

  const resolvedSecrets: ResolvedSecrets = {
    remotePassword,
    encryptionPassphrase,
  };

  return {
    ...config,
    resolvedVaultPath: vaultPath,
    resolvedStatePath: statePath,
    resolvedSecrets,
  };
}
