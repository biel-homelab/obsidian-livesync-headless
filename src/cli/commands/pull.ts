import { createHash } from 'node:crypto';
import { readdir, readFile, stat } from 'node:fs/promises';
import { join, dirname, extname } from 'node:path';
import { loadConfig, ConfigValidationError } from '../../config/loader.js';
import { SecretRedactor, defaultRedactor } from '../../security/redaction.js';
import {
  createGuardedFetch,
  MutationAttemptBlockedError,
} from '../../security/transport-guard.js';
import {
  createReadCapability,
  createVaultReflectCapability,
  isVaultReflectCapability,
  type VaultReflectCapability,
} from '../../security/capabilities.js';
import {
  probeRemoteDatabase,
  AuthenticationRequiredError,
  DatabaseNotFoundError,
  type RemoteProbeResult,
} from '../../livesync/inspector.js';
import {
  ZeroMutationVerifier,
  MutationDetectedError,
  type DatabaseSnapshot,
} from '../../livesync/zero-mutation.js';
import { verifySyncinfo } from '../../livesync/syncinfo.js';
import {
  negotiateCompatibility,
  computeFingerprint,
  type NegotiationResult,
} from '../../livesync/negotiation.js';
import { createCachedChunkFetcher, buildChunkCacheFromInventory, inventoryRemoteDocuments } from '../../livesync/inventory.js';
import {
  decodeNoteLeaf,
  isNoteType,
  isReservedChunkId,
  type DecodeOptions,
} from '../../livesync/decode-adapter.js';
import {
  buildRecoverablePullPlan,
  observationFromDecodeFailure,
  serializePullActions,
  type PullAction,
  type PullObservation,
  type LocalFileInspection,
  type ProvenanceLookup,
} from '../../domain/pull-plan.js';
import { installAtomically } from '../../filesystem/atomic-reflector.js';
import { quarantineVaultFile } from '../../filesystem/quarantine-store.js';
import { preflightVault, type VaultPreflightResult } from '../../filesystem/vault-preflight.js';
import {
  assertSafeVaultRelativePath,
  findCaseFoldCollisions,
  isReservedOrIgnoredPath,
} from '../../domain/path-policy.js';
import { openDatabase } from '../../storage/sqlite.js';
import { ProvenanceRepository } from '../../storage/provenance-repo.js';
import { QuarantineRepository } from '../../storage/quarantine-repo.js';
import { CheckpointRepository } from '../../storage/checkpoint-repo.js';
import {
  formatPullHumanReport,
  formatPullJsonLinesReport,
  type PullReport,
} from '../../diagnostics/formatters.js';
import { OutcomeCategory, EXIT_CODES } from '../../diagnostics/outcomes.js';

export interface PullCommandOptions {
  configPath?: string;
  dryRun: boolean;
  json?: boolean;
  redactor?: SecretRedactor;
  stdout?: (msg: string) => void;
}

export async function applyVerifiedPull(
  capability: VaultReflectCapability,
  options: {
    vaultRoot: string;
    actions: readonly PullAction[];
    remoteFingerprint: string;
    statePath: string;
    stateRoot?: string;
    updateSeq?: string;
  }
): Promise<void> {
  if (!isVaultReflectCapability(capability)) {
    throw new Error('Reflect capability required to apply pull actions.');
  }

  const db = openDatabase(options.statePath);
  try {
    const provenanceRepo = new ProvenanceRepository(db);
    const quarantineRepo = new QuarantineRepository(db);
    const checkpointRepo = new CheckpointRepository(db);
    const stateRoot = options.stateRoot
      ? (extname(options.stateRoot) ? dirname(options.stateRoot) : options.stateRoot)
      : dirname(options.statePath);

    for (const action of options.actions) {
      if (action.kind === 'quarantine-delete') {
        await quarantineVaultFile(
          options.vaultRoot,
          stateRoot,
          action.path,
          action.sourceRevision,
          quarantineRepo
        );
        provenanceRepo.deleteProvenance(action.path);
      } else if (action.kind === 'create') {
        await installAtomically(options.vaultRoot, action.path, action.bytes);
        const dest = join(options.vaultRoot, action.path);
        const fileStat = await stat(dest);
        provenanceRepo.saveProvenance({
          path: action.path,
          remoteRevision: action.sourceRevision,
          contentSha256: createHash('sha256').update(action.bytes).digest('hex'),
          observedMtime: fileStat.mtimeMs,
          remoteFingerprint: options.remoteFingerprint,
          reflectedAt: new Date().toISOString(),
        });
      }
    }

    if (options.updateSeq) {
      checkpointRepo.saveCheckpoint({
        remoteFingerprint: options.remoteFingerprint,
        lastUpdateSeq: options.updateSeq,
        completedAt: new Date().toISOString(),
      });
    }
  } finally {
    db.close();
  }
}

function exitForBlockActions(actions: readonly PullAction[]): number {
  const hasConflict = actions.some(
    (action) =>
      action.kind === 'block' &&
      (action.code === 'CONFLICT' ||
        action.code === 'UNRESOLVED_LEAVES' ||
        action.code.startsWith('CONFLICT'))
  );
  if (hasConflict) {
    return EXIT_CODES.CONFLICT;
  }

  const hasPreflight = actions.some(
    (action) =>
      action.kind === 'block' &&
      (action.code === 'VAULT_NOT_EMPTY' ||
        action.code === 'UNSAFE_SYMLINK' ||
        action.code === 'UNPROVEN_LOCAL_FILE')
  );
  return hasPreflight ? EXIT_CODES.CONFIG_ERROR : EXIT_CODES.CORRUPTION;
}

function outcomeForExit(exitCode: number): OutcomeCategory {
  const match = (Object.entries(EXIT_CODES) as [OutcomeCategory, number][]).find(
    ([, code]) => code === exitCode
  );
  return match?.[0] ?? OutcomeCategory.CORRUPTION;
}

function listProvenancePaths(statePath: string): string[] {
  const db = openDatabase(statePath);
  try {
    const rows = db.prepare('SELECT path FROM file_provenance').all() as { path?: string }[];
    return rows.map((row) => String(row.path ?? '')).filter((path) => path.length > 0);
  } finally {
    db.close();
  }
}

function applyPathPolicyToPlan(actions: readonly PullAction[], caseInsensitive: boolean): PullAction[] {
  const next: PullAction[] = [];
  const createPaths: string[] = [];

  for (const action of actions) {
    if (action.kind === 'quarantine-delete') {
      try {
        assertSafeVaultRelativePath(action.path);
        next.push(action);
      } catch (err) {
        next.push({
          kind: 'block',
          id: action.path,
          path: action.path,
          code: 'UNSAFE_PATH',
          message: (err as Error).message,
        });
      }
      continue;
    }

    if (action.kind !== 'create') {
      next.push(action);
      continue;
    }

    if (isReservedOrIgnoredPath(action.path)) {
      next.push({ kind: 'skip-ignored', path: action.path });
      continue;
    }

    try {
      assertSafeVaultRelativePath(action.path);
    } catch (err) {
      next.push({
        kind: 'block',
        id: action.path,
        path: action.path,
        code: 'UNSAFE_PATH',
        message: (err as Error).message,
      });
      continue;
    }

    createPaths.push(action.path);
    next.push(action);
  }

  const colliding = new Set(findCaseFoldCollisions(createPaths, caseInsensitive).flat());
  if (colliding.size === 0) {
    return next;
  }

  return next.map((action) => {
    if (action.kind !== 'create' || !colliding.has(action.path)) {
      return action;
    }
    return {
      kind: 'block',
      id: action.path,
      path: action.path,
      code: 'CASE_FOLD_COLLISION',
      message: `Path '${action.path}' collides with another remote path when case-folded`,
      suggestion: 'Rename or resolve the colliding remote files; neither path is materialized',
    };
  });
}

async function scanLocalFiles(vaultPath: string): Promise<Map<string, LocalFileInspection>> {
  const map = new Map<string, LocalFileInspection>();

  async function scanDir(dir: string, prefix = ''): Promise<void> {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        await scanDir(full, rel);
      } else if (entry.isFile()) {
        try {
          const buf = await readFile(full);
          const h = createHash('sha256').update(new Uint8Array(buf)).digest('hex');
          map.set(rel, { exists: true, contentSha256: h });
        } catch {
          map.set(rel, { exists: true });
        }
      }
    }
  }

  await scanDir(vaultPath);
  return map;
}

function mergePreflightBlocks(actions: PullAction[], preflight: VaultPreflightResult): PullAction[] {
  if (preflight.ok) {
    return [...actions];
  }

  const merged = [...actions];
  if (preflight.blocks.length === 0) {
    merged.push({
      kind: 'block',
      id: preflight.code,
      code: preflight.code,
      message: preflight.message,
    });
    return merged;
  }

  for (const block of preflight.blocks) {
    merged.push({
      kind: 'block',
      id: block.path,
      path: block.path,
      code: block.code,
      message: block.message,
    });
  }
  return merged;
}

function decodeOptionsFromAdmission(
  negotiatedSettings: Record<string, unknown>,
  preferredTweaks: Record<string, unknown>,
  encryptionPassphrase: string | undefined,
  pbkdf2salt: string | undefined
): DecodeOptions {
  const encrypt = Boolean(negotiatedSettings.encrypt ?? preferredTweaks.encrypt);
  const algorithm =
    typeof negotiatedSettings.E2EEAlgorithm === 'string'
      ? negotiatedSettings.E2EEAlgorithm
      : typeof preferredTweaks.E2EEAlgorithm === 'string'
        ? preferredTweaks.E2EEAlgorithm
        : encrypt
          ? 'v2'
          : undefined;

  return {
    handleFilenameCaseSensitive: Boolean(negotiatedSettings.handleFilenameCaseSensitive),
    usePathObfuscation: Boolean(negotiatedSettings.usePathObfuscation),
    useDynamicIterationCount: Boolean(negotiatedSettings.useDynamicIterationCount),
    encryptionPassphrase,
    algorithm,
    pbkdf2salt,
  };
}

async function observationsFromInventory(
  inventory: Awaited<ReturnType<typeof inventoryRemoteDocuments>>,
  decodeOptions: DecodeOptions
): Promise<PullObservation[]> {
  const observations: PullObservation[] = [];

  for (const item of inventory) {
    if (item.kind === 'chunk' || isReservedChunkId(item.id)) {
      observations.push({ kind: 'special', id: item.id, type: 'leaf' });
      continue;
    }

    if (item.kind === 'tombstone') {
      observations.push({
        kind: 'note',
        path: item.id,
        sourceRevision: item.rev,
        type: 'unknown',
        deleted: true,
        bytes: new Uint8Array(),
      });
      continue;
    }

    const doc = item.document;
    const type = typeof doc.type === 'string' ? doc.type : 'unknown';

    if (doc._deleted === true || doc.deleted === true) {
      observations.push({
        kind: 'note',
        path: typeof doc.path === 'string' ? doc.path : doc._id,
        sourceRevision: doc._rev,
        type,
        deleted: true,
        bytes: new Uint8Array(),
      });
      continue;
    }

    if (!isNoteType(type)) {
      observations.push({ kind: 'special', id: doc._id, type });
      continue;
    }

    const decoded = await decodeNoteLeaf(doc, decodeOptions);
    if (!decoded.ok) {
      if (decoded.code === 'IGNORED') {
        observations.push({ kind: 'ignored', path: decoded.path ?? doc._id });
        continue;
      }
      observations.push(observationFromDecodeFailure(decoded));
      continue;
    }

    observations.push({
      kind: 'note',
      path: decoded.path,
      sourceRevision: decoded.sourceRevision,
      type: decoded.type,
      deleted: decoded.deleted,
      bytes: decoded.bytes,
    });
  }

  return observations;
}

export async function runPullCommand(options: PullCommandOptions): Promise<number> {
  const redactor = options.redactor ?? defaultRedactor;
  const writeStdout = options.stdout ?? ((msg: string) => process.stdout.write(msg));

  function emitReport(report: PullReport): void {
    const text = options.json ? formatPullJsonLinesReport(report) : formatPullHumanReport(report);
    writeStdout(text);
  }

  let config;
  try {
    config = await loadConfig(options.configPath, process.env, redactor);
  } catch (err) {
    emitReport({
      type: 'pull_report',
      outcome: OutcomeCategory.CONFIG_ERROR,
      dryRun: options.dryRun,
      remoteFingerprint: '',
      negotiatedSettingsHash: '',
      adoptedTweaks: {},
      actions: [],
      blockers: [
        {
          code: err instanceof ConfigValidationError ? 'CONFIG_VALIDATION_ERROR' : 'CONFIG_LOAD_ERROR',
          message: (err as Error).message,
        },
      ],
      zeroMutationVerified: false,
    });
    return EXIT_CODES.CONFIG_ERROR;
  }

  const rawUrl = new URL(config.remote.url);
  const allowedBaseUrl = new URL(`${rawUrl.protocol}//${rawUrl.host}`);
  const databaseName = config.remote.database;
  const credentials =
    config.remote.username || config.resolvedSecrets.remotePassword
      ? { username: config.remote.username, password: config.resolvedSecrets.remotePassword }
      : undefined;

  const guardedFetch = createGuardedFetch({
    allowedBaseUrl,
    databaseName,
  });
  const readCapability = createReadCapability(allowedBaseUrl, databaseName);
  void readCapability;

  const fingerprint = computeFingerprint(allowedBaseUrl.href, databaseName);

  let preSnapshot: DatabaseSnapshot | undefined;
  let postSnapshot: DatabaseSnapshot | undefined;
  let probeResult: RemoteProbeResult | undefined;
  let actions: PullAction[] = [];
  let adoptedTweaks: Record<string, unknown> = {};
  let negotiatedSettingsHash = '';
  let remoteFingerprint = fingerprint;
  let negotiation: NegotiationResult | undefined;

  try {
    preSnapshot = await ZeroMutationVerifier.captureSnapshot(
      guardedFetch,
      allowedBaseUrl,
      databaseName,
      credentials
    );

    probeResult = await probeRemoteDatabase(
      guardedFetch,
      allowedBaseUrl,
      databaseName,
      credentials
    );

    const syncinfoResult = await verifySyncinfo(
      probeResult.syncinfoDoc,
      probeResult.syncParamsDoc,
      config.resolvedSecrets.encryptionPassphrase
    );
    negotiation = negotiateCompatibility(
      probeResult,
      config,
      syncinfoResult.verified
    );
    adoptedTweaks = negotiation.adoptedTweaks;
    negotiatedSettingsHash = negotiation.negotiatedSettingsHash;
    remoteFingerprint = negotiation.remoteFingerprint;

    if (negotiation.admitted) {
      const inventory = await inventoryRemoteDocuments(
        guardedFetch,
        allowedBaseUrl,
        databaseName,
        credentials
      );
      const authHeader =
        credentials?.username || credentials?.password
          ? `Basic ${Buffer.from(`${credentials.username ?? ''}:${credentials.password ?? ''}`).toString('base64')}`
          : undefined;
      const chunkCache = buildChunkCacheFromInventory(inventory);
      const fetchChunk = createCachedChunkFetcher(
        guardedFetch,
        allowedBaseUrl,
        databaseName,
        authHeader,
        chunkCache
      );
      const preferredTweaks = probeResult.milestoneDoc?.tweak_values?.PREFERRED ?? {};
      const decodeOptions = decodeOptionsFromAdmission(
        negotiation.negotiatedSettings,
        preferredTweaks,
        config.resolvedSecrets.encryptionPassphrase,
        typeof probeResult.syncParamsDoc?.pbkdf2salt === 'string'
          ? probeResult.syncParamsDoc.pbkdf2salt
          : undefined
      );
      const observations = await observationsFromInventory(inventory, {
        ...decodeOptions,
        fetchChunk,
      });

      let existingProvenanceMap = new Map<string, ProvenanceLookup>();
      const db = openDatabase(config.resolvedStatePath);
      try {
        const pRepo = new ProvenanceRepository(db);
        existingProvenanceMap = pRepo.getAllAsMap();
      } finally {
        db.close();
      }

      const localFilesMap = await scanLocalFiles(config.resolvedVaultPath);

      actions = applyPathPolicyToPlan(
        buildRecoverablePullPlan(observations, existingProvenanceMap, localFilesMap),
        !Boolean(decodeOptions.handleFilenameCaseSensitive)
      );

      const preflight = await preflightVault(
        config.resolvedVaultPath,
        Boolean(config.vault.dedicated),
        () => listProvenancePaths(config.resolvedStatePath)
      );
      actions = mergePreflightBlocks(actions, preflight);

      const blockActions = actions.filter((action) => action.kind === 'block');
      if (!options.dryRun && blockActions.length === 0 && preflight.ok) {
        const reflectCapability = createVaultReflectCapability(
          allowedBaseUrl,
          databaseName,
          config.resolvedVaultPath
        );
        await applyVerifiedPull(reflectCapability, {
          vaultRoot: config.resolvedVaultPath,
          actions,
          remoteFingerprint,
          statePath: config.resolvedStatePath,
          stateRoot: dirname(config.resolvedStatePath),
          updateSeq: preSnapshot?.updateSeq,
        });
      }
    }

    postSnapshot = await ZeroMutationVerifier.captureSnapshot(
      guardedFetch,
      allowedBaseUrl,
      databaseName,
      credentials
    );
    ZeroMutationVerifier.assertNoMutation(preSnapshot, postSnapshot);
  } catch (err) {
    if (err instanceof AuthenticationRequiredError) {
      emitReport({
        type: 'pull_report',
        outcome: OutcomeCategory.AUTHENTICATION_ERROR,
        dryRun: options.dryRun,
        remoteFingerprint,
        negotiatedSettingsHash,
        adoptedTweaks,
        actions: serializePullActions(actions),
        blockers: [
          {
            code: 'AUTHENTICATION_REQUIRED',
            message: err.message,
            suggestion: 'Verify remote.username and remote.password in your configuration',
          },
        ],
        zeroMutationVerified: true,
        preUpdateSeq: preSnapshot?.updateSeq,
        postUpdateSeq: postSnapshot?.updateSeq,
      });
      return EXIT_CODES.AUTHENTICATION_ERROR;
    }

    if (err instanceof DatabaseNotFoundError) {
      emitReport({
        type: 'pull_report',
        outcome: OutcomeCategory.NOT_FOUND,
        dryRun: options.dryRun,
        remoteFingerprint,
        negotiatedSettingsHash,
        adoptedTweaks,
        actions: serializePullActions(actions),
        blockers: [
          {
            code: 'DATABASE_NOT_FOUND',
            message: err.message,
            suggestion: 'Verify remote.database exists in CouchDB',
          },
        ],
        zeroMutationVerified: true,
        preUpdateSeq: preSnapshot?.updateSeq,
        postUpdateSeq: postSnapshot?.updateSeq,
      });
      return EXIT_CODES.NOT_FOUND;
    }

    if (err instanceof MutationDetectedError || err instanceof MutationAttemptBlockedError) {
      emitReport({
        type: 'pull_report',
        outcome: OutcomeCategory.MUTATION_VIOLATION,
        dryRun: options.dryRun,
        remoteFingerprint,
        negotiatedSettingsHash,
        adoptedTweaks,
        actions: serializePullActions(actions),
        blockers: [
          {
            code: 'MUTATION_VIOLATION',
            message: err.message,
            suggestion: 'Pull strictly forbids modifying remote state',
          },
        ],
        zeroMutationVerified: false,
        preUpdateSeq: preSnapshot?.updateSeq,
        postUpdateSeq: postSnapshot?.updateSeq,
      });
      return EXIT_CODES.MUTATION_VIOLATION;
    }

    const errorMsg = (err as Error).message || String(err);
    const isNetworkOutage =
      errorMsg.includes('ECONNREFUSED') ||
      errorMsg.includes('ENOTFOUND') ||
      errorMsg.includes('fetch failed');

    if (isNetworkOutage) {
      emitReport({
        type: 'pull_report',
        outcome: OutcomeCategory.TRANSIENT_OUTAGE,
        dryRun: options.dryRun,
        remoteFingerprint,
        negotiatedSettingsHash,
        adoptedTweaks,
        actions: serializePullActions(actions),
        blockers: [
          {
            code: 'NETWORK_OUTAGE',
            message: `Could not connect to CouchDB server at ${allowedBaseUrl.origin}: ${errorMsg}`,
            suggestion: 'Check CouchDB server status, network connectivity, and URL',
          },
        ],
        zeroMutationVerified: false,
        preUpdateSeq: preSnapshot?.updateSeq,
        postUpdateSeq: postSnapshot?.updateSeq,
      });
      return EXIT_CODES.TRANSIENT_OUTAGE;
    }

    emitReport({
      type: 'pull_report',
      outcome: OutcomeCategory.CORRUPTION,
      dryRun: options.dryRun,
      remoteFingerprint,
      negotiatedSettingsHash,
      adoptedTweaks,
      actions: serializePullActions(actions),
      blockers: [
        {
          code: 'DATA_CORRUPTION',
          message: `Unexpected error during pull: ${errorMsg}`,
        },
      ],
      zeroMutationVerified: false,
      preUpdateSeq: preSnapshot?.updateSeq,
      postUpdateSeq: postSnapshot?.updateSeq,
    });
    return EXIT_CODES.CORRUPTION;
  }

  if (negotiation && !negotiation.admitted) {
    const hasAuthBlocker = negotiation.blockers.some((b) => b.code === 'AUTHENTICATION_ERROR');
    emitReport({
      type: 'pull_report',
      outcome: hasAuthBlocker ? OutcomeCategory.AUTHENTICATION_ERROR : OutcomeCategory.INCOMPATIBLE,
      dryRun: options.dryRun,
      remoteFingerprint,
      negotiatedSettingsHash,
      adoptedTweaks,
      actions: [],
      blockers: negotiation.blockers,
      zeroMutationVerified: true,
      preUpdateSeq: preSnapshot?.updateSeq,
      postUpdateSeq: postSnapshot?.updateSeq,
    });
    return hasAuthBlocker ? EXIT_CODES.AUTHENTICATION_ERROR : EXIT_CODES.INCOMPATIBLE;
  }

  const blockActions = actions.filter((action) => action.kind === 'block');
  if (blockActions.length > 0) {
    const exitCode = exitForBlockActions(actions);
    emitReport({
      type: 'pull_report',
      outcome: outcomeForExit(exitCode),
      dryRun: options.dryRun,
      remoteFingerprint,
      negotiatedSettingsHash,
      adoptedTweaks,
      actions: serializePullActions(actions),
      blockers: blockActions.map((action) => ({
        code: action.code,
        message: action.message,
      })),
      zeroMutationVerified: true,
      preUpdateSeq: preSnapshot?.updateSeq,
      postUpdateSeq: postSnapshot?.updateSeq,
    });
    return exitCode;
  }

  emitReport({
    type: 'pull_report',
    outcome: OutcomeCategory.SUCCESS,
    dryRun: options.dryRun,
    remoteFingerprint,
    negotiatedSettingsHash,
    adoptedTweaks,
    actions: serializePullActions(actions),
    blockers: [],
    zeroMutationVerified: true,
    preUpdateSeq: preSnapshot?.updateSeq,
    postUpdateSeq: postSnapshot?.updateSeq,
  });
  return EXIT_CODES.SUCCESS;
}
