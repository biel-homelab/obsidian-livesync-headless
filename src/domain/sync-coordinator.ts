import { createHash } from 'node:crypto';
import { stat, readFile } from 'node:fs/promises';
import { join, dirname, extname } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import { openDatabase } from '../storage/sqlite.js';
import { ProvenanceRepository } from '../storage/provenance-repo.js';
import { QuarantineRepository } from '../storage/quarantine-repo.js';
import { CheckpointRepository } from '../storage/checkpoint-repo.js';
import { WriteGrantRepo } from '../storage/write-grant-repo.js';
import { cleanupOrphanStagingFiles } from '../filesystem/orphan-cleanup.js';
import { installAtomically } from '../filesystem/atomic-reflector.js';
import { quarantineVaultFile } from '../filesystem/quarantine-store.js';
import { preflightSyncVault } from '../filesystem/vault-preflight.js';
import { VaultScanner, type VaultFileEntry } from '../filesystem/vault-scanner.js';
import {
  inventoryRemoteDocuments,
  buildChunkCacheFromInventory,
  createCachedChunkFetcher,
} from '../livesync/inventory.js';
import { decodeNoteLeaf, isNoteType, isReservedChunkId, type DecodeOptions } from '../livesync/decode-adapter.js';
import { observationFromDecodeFailure, type PullObservation } from './pull-plan.js';
import { buildSyncPlan, serializeSyncPlan, type SyncAction, type SerializedSyncPlan } from './sync-plan.js';
import { PushAdapter } from '../livesync/push-adapter.js';
import { DeletionWriter } from '../livesync/deletion-writer.js';
import type { WriteCapability, ArmedSyncCapability } from '../security/capabilities.js';
import { createArmedGuardedFetch } from '../security/transport-guard.js';

export interface SyncCoordinatorOptions {
  readonly baseUrl: URL;
  readonly databaseName: string;
  readonly vaultRoot: string;
  readonly statePath: string;
  readonly stateRoot?: string;
  readonly dryRun: boolean;
  readonly pullOnly?: boolean;
  readonly credentials?: { username?: string; password?: string };
  readonly encryptionPassphrase?: string;
  readonly algorithm?: string;
  readonly useDynamicIterationCount?: boolean;
  readonly usePathObfuscation?: boolean;
  readonly pbkdf2salt?: string;
  readonly handleFilenameCaseSensitive?: boolean;
  readonly customChunkSize?: number;
  readonly minimumChunkSize?: number;
  readonly remoteFingerprint: string;
  readonly updateSeq?: string;
  readonly fetch?: typeof globalThis.fetch;
}

export interface SyncExecutionResult {
  readonly ok: boolean;
  readonly plan: SerializedSyncPlan;
  readonly appliedActions: number;
  readonly errors: string[];
  readonly conflicts: string[];
  readonly converged: boolean;
}

export class SyncCoordinator {
  private readonly guardedFetch: typeof globalThis.fetch;

  constructor(private readonly options: SyncCoordinatorOptions) {
    this.guardedFetch = createArmedGuardedFetch(
      {
        allowedBaseUrl: options.baseUrl,
        databaseName: options.databaseName,
      },
      options.fetch ?? globalThis.fetch
    );
  }

  async sync(capability?: WriteCapability | ArmedSyncCapability): Promise<SyncExecutionResult> {
    if (!this.options.dryRun && !this.options.pullOnly && !capability) {
      throw new Error('SyncCoordinator requires WriteCapability or ArmedSyncCapability when not in dry-run mode.');
    }

    const errors: string[] = [];
    const conflicts: string[] = [];

    // Stage 1: Preflight & Staging Orphan Cleanup
    await cleanupOrphanStagingFiles(this.options.vaultRoot);
    const preflight = await preflightSyncVault(this.options.vaultRoot);
    if (!preflight.ok) {
      return {
        ok: false,
        plan: {
          summary: {
            totalActions: 0,
            pullCreates: 0,
            pullUpdates: 0,
            pullDeletes: 0,
            pushCreates: 0,
            pushUpdates: 0,
            pushDeletes: 0,
            renames: 0,
            noops: 0,
            conflicts: 1,
          },
          actions: [],
        },
        appliedActions: 0,
        errors: [`Vault preflight failed: ${preflight.message}`],
        conflicts: [],
        converged: false,
      };
    }

    // Stage 2: Remote Catch-Up (Pull phase inventory and observations)
    const inventory = await inventoryRemoteDocuments(
      this.guardedFetch,
      this.options.baseUrl,
      this.options.databaseName,
      this.options.credentials
    );

    const authHeader =
      this.options.credentials?.username || this.options.credentials?.password
        ? `Basic ${Buffer.from(`${this.options.credentials.username ?? ''}:${this.options.credentials.password ?? ''}`).toString('base64')}`
        : undefined;

    const chunkCache = buildChunkCacheFromInventory(inventory);
    const fetchChunk = createCachedChunkFetcher(
      this.guardedFetch,
      this.options.baseUrl,
      this.options.databaseName,
      authHeader,
      chunkCache
    );

    const decodeOptions: DecodeOptions = {
      handleFilenameCaseSensitive: this.options.handleFilenameCaseSensitive,
      usePathObfuscation: this.options.usePathObfuscation,
      useDynamicIterationCount: this.options.useDynamicIterationCount,
      encryptionPassphrase: this.options.encryptionPassphrase,
      algorithm: this.options.algorithm,
      pbkdf2salt: this.options.pbkdf2salt,
      fetchChunk,
    };

    const observations = await this.buildObservations(inventory, decodeOptions);

    // Stage 3: Local Vault Scan
    const scanner = new VaultScanner();
    const localFiles = await scanner.scanVault(this.options.vaultRoot);

    // Read local file contents into memory for push execution
    const localBytesMap = new Map<string, Uint8Array>();
    for (const [relPath] of localFiles.entries()) {
      try {
        const full = join(this.options.vaultRoot, relPath);
        const buf = await readFile(full);
        localBytesMap.set(relPath, new Uint8Array(buf));
      } catch {
        // Ignore read errors; handled in planning
      }
    }

    // Load Provenance Map from SQLite
    const db = openDatabase(this.options.statePath);
    let provenanceMap = new Map<string, import('../storage/provenance-repo.js').ProvenanceRecord>();
    try {
      const pRepo = new ProvenanceRepository(db);
      provenanceMap = pRepo.getAllAsMap();
    } finally {
      db.close();
    }

    // Stage 4: Safe Reconciliation & Planning
    const actions = buildSyncPlan(observations, localFiles, provenanceMap, localBytesMap);
    const serializedPlan = serializeSyncPlan(actions);

    for (const action of actions) {
      if (action.kind === 'conflict') {
        conflicts.push(`Conflict at '${action.path}': ${action.reason}`);
      }
    }

    if (this.options.dryRun || conflicts.length > 0) {
      return {
        ok: conflicts.length === 0,
        plan: serializedPlan,
        appliedActions: 0,
        errors,
        conflicts,
        converged: conflicts.length === 0 && serializedPlan.summary.totalActions === serializedPlan.summary.noops,
      };
    }

    // Stage 5: Execution (Apply Mode)
    let appliedCount = 0;
    const activeDb = openDatabase(this.options.statePath);

    try {
      const provenanceRepo = new ProvenanceRepository(activeDb);
      const quarantineRepo = new QuarantineRepository(activeDb);
      const checkpointRepo = new CheckpointRepository(activeDb);
      const stateRoot = this.options.stateRoot
        ? (extname(this.options.stateRoot) ? dirname(this.options.stateRoot) : this.options.stateRoot)
        : dirname(this.options.statePath);

      const pushAdapter = new PushAdapter({
        baseUrl: this.options.baseUrl,
        databaseName: this.options.databaseName,
        chunkSize: this.options.customChunkSize,
        minimumChunkSize: this.options.minimumChunkSize,
        encryptionPassphrase: this.options.encryptionPassphrase,
        algorithm: this.options.algorithm,
        useDynamicIterationCount: this.options.useDynamicIterationCount,
        usePathObfuscation: this.options.usePathObfuscation,
        pbkdf2salt: this.options.pbkdf2salt,
        handleFilenameCaseSensitive: this.options.handleFilenameCaseSensitive,
        credentials: this.options.credentials,
        fetch: this.guardedFetch,
      });

      const deletionWriter = new DeletionWriter({
        baseUrl: this.options.baseUrl,
        databaseName: this.options.databaseName,
        encryptionPassphrase: this.options.encryptionPassphrase,
        algorithm: this.options.algorithm,
        useDynamicIterationCount: this.options.useDynamicIterationCount,
        usePathObfuscation: this.options.usePathObfuscation,
        pbkdf2salt: this.options.pbkdf2salt,
        handleFilenameCaseSensitive: this.options.handleFilenameCaseSensitive,
        credentials: this.options.credentials,
        fetch: this.guardedFetch,
      });

      for (const action of actions) {
        if (action.kind === 'pull-create' || action.kind === 'pull-update') {
          await installAtomically(this.options.vaultRoot, action.path, action.bytes);
          const dest = join(this.options.vaultRoot, action.path);
          const fileStat = await stat(dest);
          provenanceRepo.saveProvenance({
            path: action.path,
            remoteRevision: action.sourceRevision,
            contentSha256: action.contentSha256,
            observedMtime: fileStat.mtimeMs,
            remoteFingerprint: this.options.remoteFingerprint,
            reflectedAt: new Date().toISOString(),
          });
          appliedCount++;
        } else if (action.kind === 'pull-delete') {
          await quarantineVaultFile(
            this.options.vaultRoot,
            stateRoot,
            action.path,
            action.sourceRevision,
            quarantineRepo
          );
          provenanceRepo.deleteProvenance(action.path);
          appliedCount++;
        } else if (action.kind === 'push-create') {
          if (this.options.pullOnly) {
            continue;
          }
          const pushRes = await pushAdapter.pushFile(
            {
              path: action.path,
              bytes: action.bytes,
              mtime: action.mtime,
            },
            capability!
          );
          if (!pushRes.ok) {
            errors.push(`Failed to push create '${action.path}': ${pushRes.error}`);
            continue;
          }
          provenanceRepo.saveProvenance({
            path: action.path,
            remoteRevision: pushRes.rev!,
            contentSha256: action.contentSha256,
            observedMtime: action.mtime,
            remoteFingerprint: this.options.remoteFingerprint,
            reflectedAt: new Date().toISOString(),
          });
          appliedCount++;
        } else if (action.kind === 'push-update') {
          if (this.options.pullOnly) {
            continue;
          }
          const pushRes = await pushAdapter.pushFile(
            {
              path: action.path,
              bytes: action.bytes,
              baseRev: action.baseRev,
              mtime: action.mtime,
            },
            capability!
          );
          if (!pushRes.ok) {
            errors.push(`Failed to push update '${action.path}': ${pushRes.error}`);
            continue;
          }
          provenanceRepo.saveProvenance({
            path: action.path,
            remoteRevision: pushRes.rev!,
            contentSha256: action.contentSha256,
            observedMtime: action.mtime,
            remoteFingerprint: this.options.remoteFingerprint,
            reflectedAt: new Date().toISOString(),
          });
          appliedCount++;
        } else if (action.kind === 'push-delete') {
          if (this.options.pullOnly) {
            continue;
          }
          const delRes = await deletionWriter.writeDeletion(action.path, action.baseRev, capability!);
          if (!delRes.ok) {
            errors.push(`Failed to push deletion '${action.path}': ${delRes.error}`);
            continue;
          }
          provenanceRepo.deleteProvenance(action.path);
          appliedCount++;
        } else if (action.kind === 'rename-cross') {
          // Push new path first, then write deletion for old path (SYNC-05)
          const pushRes = await pushAdapter.pushFile(
            {
              path: action.newPath,
              bytes: action.bytes,
              mtime: action.mtime,
            },
            capability!
          );
          if (!pushRes.ok) {
            errors.push(`Failed to push rename target '${action.newPath}': ${pushRes.error}`);
            continue;
          }
          provenanceRepo.saveProvenance({
            path: action.newPath,
            remoteRevision: pushRes.rev!,
            contentSha256: action.contentSha256,
            observedMtime: action.mtime,
            remoteFingerprint: this.options.remoteFingerprint,
            reflectedAt: new Date().toISOString(),
          });

          const delRes = await deletionWriter.writeDeletion(action.oldPath, action.baseRev, capability!);
          if (!delRes.ok) {
            errors.push(`Failed to retire rename source '${action.oldPath}': ${delRes.error}`);
          } else {
            provenanceRepo.deleteProvenance(action.oldPath);
          }
          appliedCount++;
        } else if (action.kind === 'rename-case') {
          const bytes = localBytesMap.get(action.newPath) ?? new Uint8Array();
          const fileEntry = localFiles.get(action.newPath);
          const pushRes = await pushAdapter.pushFile(
            {
              path: action.newPath,
              bytes,
              baseRev: action.baseRev,
              mtime: fileEntry?.mtime,
            },
            capability!
          );
          if (!pushRes.ok) {
            errors.push(`Failed to push case rename '${action.newPath}': ${pushRes.error}`);
            continue;
          }
          provenanceRepo.deleteProvenance(action.oldPath);
          provenanceRepo.saveProvenance({
            path: action.newPath,
            remoteRevision: pushRes.rev!,
            contentSha256: action.contentSha256,
            observedMtime: fileEntry?.mtime ?? Date.now(),
            remoteFingerprint: this.options.remoteFingerprint,
            reflectedAt: new Date().toISOString(),
          });
          appliedCount++;
        }
      }

      // Stage 6: Update Checkpoint (SYNC-09)
      if (this.options.updateSeq) {
        checkpointRepo.saveCheckpoint({
          remoteFingerprint: this.options.remoteFingerprint,
          lastUpdateSeq: this.options.updateSeq,
          completedAt: new Date().toISOString(),
        });
      }
    } finally {
      activeDb.close();
    }

    return {
      ok: errors.length === 0,
      plan: serializedPlan,
      appliedActions: appliedCount,
      errors,
      conflicts,
      converged: errors.length === 0,
    };
  }

  private async buildObservations(
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

  private listProvenancePaths(): string[] {
    const db = openDatabase(this.options.statePath);
    try {
      const rows = db.prepare('SELECT path FROM file_provenance').all() as { path?: string }[];
      return rows.map((row) => String(row.path ?? '')).filter((path) => path.length > 0);
    } finally {
      db.close();
    }
  }
}
