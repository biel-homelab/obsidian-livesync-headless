import fs from 'node:fs/promises';
import existsSync from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { VaultScanner } from '../filesystem/vault-scanner.js';
import { isReservedOrIgnoredPath } from './path-policy.js';
import { openDatabase } from '../storage/sqlite.js';
import { ProvenanceRepository } from '../storage/provenance-repo.js';
import { WriteGrantRepo, type WriteGrantRecord } from '../storage/write-grant-repo.js';
import { AdmissionRepository } from '../storage/admission-repo.js';
import { CheckpointRepository } from '../storage/checkpoint-repo.js';
import {
  probeRemoteDatabase,
  type RemoteProbeResult,
} from '../livesync/inspector.js';
import { verifySyncinfo } from '../livesync/syncinfo.js';
import {
  negotiateCompatibility,
  type NegotiationResult,
} from '../livesync/negotiation.js';
import {
  inventoryRemoteDocuments,
  buildChunkCacheFromInventory,
  createCachedChunkFetcher,
} from '../livesync/inventory.js';
import {
  decodeNoteLeaf,
  isNoteType,
  isReservedChunkId,
  looksEncryptedString,
  type DecodeOptions,
} from '../livesync/decode-adapter.js';
import { createStageTimer } from '../diagnostics/stage-timer.js';
import {
  buildRecoverablePullPlan,
  observationFromDecodeFailure,
  type PullAction,
  type PullObservation,
  type LocalFileInspection,
} from './pull-plan.js';
import { installAtomically } from '../filesystem/atomic-reflector.js';
import { createVaultReflectCapability } from '../security/capabilities.js';
import type { LoadedConfig } from '../config/schema.js';

export type AutoArmTriggerCode =
  | 'EMPTY_VAULT'
  | 'EMPTY_STATE'
  | 'EXCESSIVE_LOCAL_CHANGES'
  | 'MISSING_WRITE_GRANT'
  | 'NONE';

export interface AutoArmTriggerCheckResult {
  readonly shouldAutoArm: boolean;
  readonly code: AutoArmTriggerCode;
  readonly reason: string;
  readonly localNewCount?: number;
  readonly localDeletedCount?: number;
  readonly localTotalChanges?: number;
}

export interface AutoArmWorkflowOptions {
  readonly config: LoadedConfig;
  readonly guardedFetch: typeof globalThis.fetch;
  readonly logger?: (msg: string) => void;
  readonly threshold?: number;
}

export interface AutoArmWorkflowResult {
  readonly success: boolean;
  readonly triggered: boolean;
  readonly triggerCode: AutoArmTriggerCode;
  readonly triggerReason: string;
  readonly grant?: WriteGrantRecord;
  readonly error?: string;
}

export class AutoArmCoordinator {
  private readonly vaultScanner = new VaultScanner();

  async checkTrigger(options: {
    vaultRoot: string;
    statePath: string;
    remoteFingerprint: string;
    threshold?: number;
  }): Promise<AutoArmTriggerCheckResult> {
    const threshold = options.threshold ?? 10;
    const vaultRoot = path.resolve(options.vaultRoot);
    const statePath = path.resolve(options.statePath);

    // 1. Check if vault is empty (0 user files)
    let localFiles: Map<string, any>;
    try {
      localFiles = await this.vaultScanner.scanVault(vaultRoot);
    } catch {
      localFiles = new Map();
    }

    if (localFiles.size === 0) {
      return {
        shouldAutoArm: true,
        code: 'EMPTY_VAULT',
        reason: 'Local vault folder is empty (0 files found)',
      };
    }

    // 2. Check if state DB exists and has tables/data
    if (!existsSync.existsSync(statePath)) {
      return {
        shouldAutoArm: true,
        code: 'EMPTY_STATE',
        reason: 'State database does not exist',
      };
    }

    let provenanceMap = new Map();
    let hasActiveGrant = false;
    let db;
    try {
      db = openDatabase(statePath);
      const provRepo = new ProvenanceRepository(db);
      provenanceMap = provRepo.getAllAsMap();

      const grantRepo = new WriteGrantRepo(db);
      const activeGrant = grantRepo.getActiveGrant(
        options.remoteFingerprint,
        vaultRoot
      );
      hasActiveGrant = Boolean(activeGrant && !activeGrant.revoked);
    } catch (err) {
      return {
        shouldAutoArm: true,
        code: 'EMPTY_STATE',
        reason: `State database is corrupted or unreadable: ${(err as Error).message}`,
      };
    } finally {
      if (db) {
        db.close();
      }
    }

    if (provenanceMap.size === 0) {
      return {
        shouldAutoArm: true,
        code: 'EMPTY_STATE',
        reason: 'State database has no recorded file provenance',
      };
    }

    // 3. Check amount of changes locally since last sync
    let newFilesCount = 0;
    for (const [filePath] of localFiles) {
      if (!provenanceMap.has(filePath)) {
        newFilesCount++;
      }
    }

    let deletedFilesCount = 0;
    for (const [filePath] of provenanceMap) {
      if (!localFiles.has(filePath)) {
        deletedFilesCount++;
      }
    }

    const totalChanges = newFilesCount + deletedFilesCount;

    if (
      newFilesCount >= threshold ||
      deletedFilesCount >= threshold ||
      totalChanges > threshold
    ) {
      return {
        shouldAutoArm: true,
        code: 'EXCESSIVE_LOCAL_CHANGES',
        reason: `Local changes exceed threshold of ${threshold} files (${newFilesCount} new, ${deletedFilesCount} deleted, ${totalChanges} total)`,
        localNewCount: newFilesCount,
        localDeletedCount: deletedFilesCount,
        localTotalChanges: totalChanges,
      };
    }

    // 4. Check if write grant is present
    if (!hasActiveGrant) {
      return {
        shouldAutoArm: true,
        code: 'MISSING_WRITE_GRANT',
        reason: 'No active write grant found in auto-arm mode',
      };
    }

    return {
      shouldAutoArm: false,
      code: 'NONE',
      reason: 'State and vault are valid with active write grant and changes within threshold',
    };
  }

  async cleanupLocalVault(vaultRoot: string): Promise<void> {
    const rootAbs = path.resolve(vaultRoot);
    let entries: import('node:fs').Dirent[];
    try {
      entries = await fs.readdir(rootAbs, { withFileTypes: true });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        await fs.mkdir(rootAbs, { recursive: true });
        return;
      }
      throw err;
    }

    for (const entry of entries) {
      const name = entry.name;
      // Preserve hidden / config directories (.obsidian) if desired, but remove user files
      if (name.startsWith('.') && name !== '.trash') {
        continue;
      }
      const fullPath = path.join(rootAbs, name);
      await fs.rm(fullPath, { recursive: true, force: true });
    }
  }

  async cleanupLocalState(statePath: string): Promise<void> {
    const absPath = path.resolve(statePath);
    const filesToRemove = [
      absPath,
      `${absPath}-wal`,
      `${absPath}-shm`,
      `${absPath}-journal`,
    ];
    for (const file of filesToRemove) {
      try {
        await fs.rm(file, { force: true });
      } catch {}
    }
  }

  /**
   * Pure read phase of the auto-arm pull (Phase 4.1): inventory the remote,
   * decode every note leaf, and build the pull plan — without touching the
   * local vault, state database, or remote. Throws nothing for block
   * conditions; the plan itself carries them so the caller can abort BEFORE
   * any destructive cleanup.
   *
   * Also fails fast when the remote is encrypted (strict ciphertext or `e_`
   * flags) but no passphrase is configured: decoding every doc just to
   * rediscover that fact would be wasted work, and the resulting
   * `DECRYPT_FAILED` blocks are exactly what this phase must catch before
   * cleanup.
   */
  async planReadOnlyPull(
    config: LoadedConfig,
    guardedFetch: typeof globalThis.fetch,
    probeResult: RemoteProbeResult,
    negotiation: NegotiationResult,
    log: (msg: string) => void = () => {}
  ): Promise<{ success: boolean; actions: PullAction[]; error?: string }> {
    const timer = createStageTimer(log);
    const rawUrl = new URL(config.remote.url);
    const allowedBaseUrl = new URL(`${rawUrl.protocol}//${rawUrl.host}`);
    const databaseName = config.remote.database;
    const credentials =
      config.remote.username || config.resolvedSecrets.remotePassword
        ? {
            username: config.remote.username,
            password: config.resolvedSecrets.remotePassword,
          }
        : undefined;

    const inventory = await inventoryRemoteDocuments(
      guardedFetch,
      allowedBaseUrl,
      databaseName,
      credentials
    );
    timer.mark('inventory', `${inventory.length} docs`);

    const authHeader =
      credentials?.username || credentials?.password
        ? `Basic ${Buffer.from(
            `${credentials.username ?? ''}:${credentials.password ?? ''}`
          ).toString('base64')}`
        : undefined;

    const chunkCache = buildChunkCacheFromInventory(inventory);
    const fetchChunk = createCachedChunkFetcher(
      guardedFetch,
      allowedBaseUrl,
      databaseName,
      authHeader,
      chunkCache
    );

    const preferredTweaks =
      probeResult.milestoneDoc?.tweak_values?.PREFERRED ?? {};
    const encrypt = Boolean(
      negotiation.negotiatedSettings.encrypt ?? preferredTweaks.encrypt
    );
    const algorithm =
      typeof negotiation.negotiatedSettings.E2EEAlgorithm === 'string'
        ? negotiation.negotiatedSettings.E2EEAlgorithm
        : typeof preferredTweaks.E2EEAlgorithm === 'string'
        ? preferredTweaks.E2EEAlgorithm
        : encrypt
        ? 'v2'
        : undefined;

    // Fail-closed BEFORE any cleanup: when the remote is encrypted (e_ flags
    // or strict ciphertext shapes) and no passphrase is configured, every
    // decode would fail anyway. Abort with a clear message now.
    //
    // Note: a pbkdf2salt in the sync-parameters document is NOT an encryption
    // signal — upstream provisions the salt even for unencrypted databases.
    // Encryption is indicated by the `encrypt` tweak, `e_` flags on documents,
    // or strict ciphertext shapes on actual content.
    if (!config.resolvedSecrets.encryptionPassphrase) {
      const remoteLooksEncrypted =
        encrypt === true ||
        inventory.some(
          (item) =>
            (item.kind === 'chunk' &&
              (item.document.e_ === true ||
                looksEncryptedString(item.document.data))) ||
            (item.kind === 'document' &&
              (item.document.e_ === true ||
                looksEncryptedString(item.document.path) ||
                looksEncryptedString(item.document.data)))
        );
      if (remoteLooksEncrypted) {
        return {
          success: false,
          actions: [
            {
              kind: 'block',
              id: 'encryption-passphrase',
              code: 'MISSING_PASSPHRASE',
              message:
                'Remote database is encrypted but no encryption passphrase is configured; auto-arm cannot decode remote content',
              suggestion:
                'Set encryption.passphrase in your YAML config or LIVESYNC_ENCRYPTION_PASSPHRASE; local vault and state were NOT modified',
            },
          ],
          error:
            'Remote database is encrypted but no encryption passphrase is configured. ' +
            'Auto-arm aborted BEFORE local cleanup; provide the passphrase and retry.',
        };
      }
    }

    const decodeOptions: DecodeOptions = {
      handleFilenameCaseSensitive: Boolean(
        negotiation.negotiatedSettings.handleFilenameCaseSensitive
      ),
      usePathObfuscation: Boolean(
        negotiation.negotiatedSettings.usePathObfuscation
      ),
      useDynamicIterationCount: Boolean(
        negotiation.negotiatedSettings.useDynamicIterationCount
      ),
      encryptionPassphrase: config.resolvedSecrets.encryptionPassphrase,
      algorithm,
      pbkdf2salt:
        typeof probeResult.syncParamsDoc?.pbkdf2salt === 'string'
          ? probeResult.syncParamsDoc.pbkdf2salt
          : undefined,
      fetchChunk,
    };

    const observations: PullObservation[] = [];
    for (const item of inventory) {
      if (item.kind === 'chunk' || isReservedChunkId(item.id)) {
        observations.push({ kind: 'special', id: item.id, type: 'leaf' });
        continue;
      }
      if (item.kind === 'tombstone') {
        continue;
      }
      const doc = item.document;
      const type = typeof doc.type === 'string' ? doc.type : 'unknown';
      if (doc._deleted === true || doc.deleted === true) {
        continue;
      }
      if (!isNoteType(type)) {
        observations.push({ kind: 'special', id: doc._id, type });
        continue;
      }

      const decoded = await decodeNoteLeaf(doc, decodeOptions);
      if (!decoded.ok) {
        if (decoded.code === 'IGNORED') {
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
    timer.mark('decode', `${observations.length} observations`);

    const pullPlan = buildRecoverablePullPlan(
      observations,
      new Map(),
      new Map()
    );

    timer.mark('plan', `${pullPlan.length} actions`);

    const blockActions = pullPlan.filter((a) => a.kind === 'block');
    if (blockActions.length > 0) {
      return {
        success: false,
        actions: pullPlan,
        error: `Pull plan contained block actions: ${blockActions.map((b) => b.message).join('; ')}`,
      };
    }

    return { success: true, actions: pullPlan };
  }

  /**
   * Write phase of the auto-arm pull (Phase 4.1): materialize the already
   * computed plan's decoded bytes into the vault, record provenance, save the
   * admission record, and persist the checkpoint. Performs no remote reads —
   * the plan is applied exactly as validated by {@link planReadOnlyPull}.
   */
  async applyReadOnlyPull(
    config: LoadedConfig,
    probeResult: RemoteProbeResult,
    negotiation: NegotiationResult,
    pullPlan: PullAction[],
    log: (msg: string) => void = () => {}
  ): Promise<{ success: boolean; error?: string }> {
    const timer = createStageTimer(log);
    const rawUrl = new URL(config.remote.url);
    const allowedBaseUrl = new URL(`${rawUrl.protocol}//${rawUrl.host}`);
    const databaseName = config.remote.database;
    const vaultRoot = config.resolvedVaultPath;
    const statePath = config.resolvedStatePath;

    // Materialize files and record provenance in state DB
    const db = openDatabase(statePath);
    try {
      const provRepo = new ProvenanceRepository(db);
      const checkpointRepo = new CheckpointRepository(db);
      const admissionRepo = new AdmissionRepository(db);

      admissionRepo.saveAdmission({
        remoteFingerprint: negotiation.remoteFingerprint,
        couchdbUrl: allowedBaseUrl.href,
        databaseName,
        couchdbVersion: probeResult.databaseInfo.couchdbVersion ?? '3.5.2',
        versionInfoRev: probeResult.versionDoc?._rev || '1',
        milestoneRev: probeResult.milestoneDoc?._rev || '1',
        syncParamsRev: probeResult.syncParamsDoc?._rev ?? null,
        negotiatedSettingsHash: negotiation.negotiatedSettingsHash,
        negotiatedSettingsJson: JSON.stringify(negotiation.negotiatedSettings),
        updateSeq: probeResult.databaseInfo.updateSeq ?? '0',
        admittedAt: new Date().toISOString(),
      });

      for (const action of pullPlan) {
        if (action.kind === 'create') {
          await installAtomically(vaultRoot, action.path, action.bytes);
          const dest = path.join(vaultRoot, action.path);
          const fileStat = await fs.stat(dest);
          const sha = createHash('sha256').update(action.bytes).digest('hex');

          provRepo.saveProvenance({
            path: action.path,
            remoteRevision: action.sourceRevision,
            contentSha256: sha,
            observedMtime: fileStat.mtimeMs,
            remoteFingerprint: negotiation.remoteFingerprint,
            reflectedAt: new Date().toISOString(),
          });
        }
      }
      timer.mark('apply', `${pullPlan.length} actions`);

      if (probeResult.databaseInfo.updateSeq) {
        checkpointRepo.saveCheckpoint({
          remoteFingerprint: negotiation.remoteFingerprint,
          lastUpdateSeq: String(probeResult.databaseInfo.updateSeq),
          completedAt: new Date().toISOString(),
        });
      }
    } finally {
      db.close();
    }

    return { success: true };
  }

  async executeReadOnlyPullAndMaterialize(
    config: LoadedConfig,
    guardedFetch: typeof globalThis.fetch,
    probeResult: RemoteProbeResult,
    negotiation: NegotiationResult
  ): Promise<{ success: boolean; actions: PullAction[]; error?: string }> {
    // Backward-compatible wrapper: plan (pure read) then apply (writes).
    const planResult = await this.planReadOnlyPull(
      config,
      guardedFetch,
      probeResult,
      negotiation
    );
    if (!planResult.success) {
      return planResult;
    }
    const applyResult = await this.applyReadOnlyPull(
      config,
      probeResult,
      negotiation,
      planResult.actions
    );
    return { ...applyResult, actions: planResult.actions };
  }

  async validateSynchronization(
    vaultRoot: string,
    statePath: string,
    remoteFingerprint: string
  ): Promise<{ valid: boolean; errors: string[] }> {
    const errors: string[] = [];
    const rootAbs = path.resolve(vaultRoot);
    const absState = path.resolve(statePath);

    if (!existsSync.existsSync(absState)) {
      return { valid: false, errors: ['State database does not exist after sync'] };
    }

    let localFiles: Map<string, any>;
    try {
      localFiles = await this.vaultScanner.scanVault(rootAbs);
    } catch (err) {
      return {
        valid: false,
        errors: [`Failed to scan vault after sync: ${(err as Error).message}`],
      };
    }

    const db = openDatabase(absState);
    try {
      const provRepo = new ProvenanceRepository(db);
      const provenanceMap = provRepo.getAllAsMap();

      for (const [relPath, prov] of provenanceMap) {
        const local = localFiles.get(relPath);
        if (!local) {
          errors.push(`Provenance record '${relPath}' missing from local vault on disk`);
          continue;
        }
        if (local.contentSha256 !== prov.contentSha256) {
          errors.push(
            `Hash mismatch for '${relPath}': disk=${local.contentSha256}, prov=${prov.contentSha256}`
          );
        }
      }

      for (const [relPath] of localFiles) {
        if (!provenanceMap.has(relPath)) {
          errors.push(`Local file '${relPath}' on disk has no provenance record in state DB`);
        }
      }
    } finally {
      db.close();
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  issueWriteGrant(
    statePath: string,
    vaultRoot: string,
    probeResult: RemoteProbeResult,
    negotiation: NegotiationResult
  ): WriteGrantRecord {
    const db = openDatabase(statePath);
    try {
      const grantRepo = new WriteGrantRepo(db);
      const binding = {
        remoteFingerprint: negotiation.remoteFingerprint,
        vaultRoot: path.resolve(vaultRoot),
        settingsHash: negotiation.negotiatedSettingsHash,
        commonlibVersion: '0.1.21',
        bootstrapGeneration: probeResult.versionDoc?._rev || '1',
      };
      return grantRepo.issueGrant(binding);
    } finally {
      db.close();
    }
  }

  async runWorkflow(
    options: AutoArmWorkflowOptions
  ): Promise<AutoArmWorkflowResult> {
    const { config, guardedFetch, logger } = options;
    const log = logger ?? (() => {});
    const vaultRoot = config.resolvedVaultPath;
    const statePath = config.resolvedStatePath;

    const rawUrl = new URL(config.remote.url);
    const allowedBaseUrl = new URL(`${rawUrl.protocol}//${rawUrl.host}`);
    const databaseName = config.remote.database;
    const credentials =
      config.remote.username || config.resolvedSecrets.remotePassword
        ? {
            username: config.remote.username,
            password: config.resolvedSecrets.remotePassword,
          }
        : undefined;

    // 1. Probe & negotiate first
    const probeTimer = createStageTimer(log);
    let probeResult: RemoteProbeResult;
    try {
      probeResult = await probeRemoteDatabase(
        guardedFetch,
        allowedBaseUrl,
        databaseName,
        credentials
      );
      probeTimer.mark('probe', `${probeResult.databaseInfo.docCount} docs`);
    } catch (err) {
      return {
        success: false,
        triggered: false,
        triggerCode: 'NONE',
        triggerReason: '',
        error: `Failed to probe remote database: ${(err as Error).message}`,
      };
    }

    const syncinfoResult = await verifySyncinfo(
      probeResult.syncinfoDoc,
      probeResult.syncParamsDoc,
      config.resolvedSecrets.encryptionPassphrase
    );

    const negotiation = negotiateCompatibility(
      probeResult,
      config,
      syncinfoResult.verified
    );

    if (!negotiation.admitted) {
      return {
        success: false,
        triggered: false,
        triggerCode: 'NONE',
        triggerReason: '',
        error: `Remote database failed admission negotiation: ${negotiation.blockers.map((b) => b.message).join('; ')}`,
      };
    }

    // 2. Check trigger conditions
    const trigger = await this.checkTrigger({
      vaultRoot,
      statePath,
      remoteFingerprint: negotiation.remoteFingerprint,
      threshold: options.threshold,
    });

    if (!trigger.shouldAutoArm) {
      // Already armed and valid
      const db = openDatabase(statePath);
      let activeGrant: WriteGrantRecord | null = null;
      try {
        const grantRepo = new WriteGrantRepo(db);
        activeGrant = grantRepo.getActiveGrant(
          negotiation.remoteFingerprint,
          vaultRoot
        );
      } finally {
        db.close();
      }

      return {
        success: true,
        triggered: false,
        triggerCode: 'NONE',
        triggerReason: trigger.reason,
        grant: activeGrant ?? undefined,
      };
    }

    log(`[auto-arm] Trigger condition detected (${trigger.code}): ${trigger.reason}`);

    // Phase 4.1 ordering guarantee: validate remote readability (inventory +
    // decode + plan) BEFORE any destructive cleanup. The live incident had the
    // daemon wipe-then-fail on every restart when the remote was unreadable
    // (e.g. missing passphrase for an encrypted DB). The vault and state DB
    // are only touched once the pull plan is proven feasible (no block
    // actions, encryption resolvable).
    log(`[auto-arm] Planning read-only synchronization from remote (fail-closed pre-validation)...`);
    const planResult = await this.planReadOnlyPull(
      config,
      guardedFetch,
      probeResult,
      negotiation,
      log
    );

    if (!planResult.success) {
      return {
        success: false,
        triggered: true,
        triggerCode: trigger.code,
        triggerReason: trigger.reason,
        error: `Auto-arm aborted BEFORE local cleanup; pull plan is not feasible: ${planResult.error}`,
      };
    }

    log(
      `[auto-arm] Pull plan is feasible (${planResult.actions.length} actions). Cleaning up local vault and state database...`
    );

    // Cleanup local vault and state — only after the plan phase succeeded.
    await this.cleanupLocalVault(vaultRoot);
    await this.cleanupLocalState(statePath);

    log(`[auto-arm] Applying validated pull plan...`);

    // Apply the already-computed plan (materialize from decoded bytes — no
    // second inventory).
    const pullResult = await this.applyReadOnlyPull(
      config,
      probeResult,
      negotiation,
      planResult.actions,
      log
    );

    if (!pullResult.success) {
      return {
        success: false,
        triggered: true,
        triggerCode: trigger.code,
        triggerReason: trigger.reason,
        error: `Read-only pull failed during auto-arm: ${pullResult.error}`,
      };
    }

    log(`[auto-arm] Validating synchronization integrity...`);

    // 5. Validate synchronization
    const validation = await this.validateSynchronization(
      vaultRoot,
      statePath,
      negotiation.remoteFingerprint
    );

    if (!validation.valid) {
      return {
        success: false,
        triggered: true,
        triggerCode: trigger.code,
        triggerReason: trigger.reason,
        error: `Synchronization validation failed: ${validation.errors.join('; ')}`,
      };
    }

    log(`[auto-arm] Synchronization verified. Issuing 5-tuple write grant...`);

    // 6. Issue write grant
    const grant = this.issueWriteGrant(
      statePath,
      vaultRoot,
      probeResult,
      negotiation
    );

    log(`[auto-arm] Successfully armed write grant ${grant.grantId}. Ready for bidirectional write mode.`);

    return {
      success: true,
      triggered: true,
      triggerCode: trigger.code,
      triggerReason: trigger.reason,
      grant,
    };
  }
}
