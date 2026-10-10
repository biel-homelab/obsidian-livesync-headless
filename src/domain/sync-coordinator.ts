import { createHash } from 'node:crypto';
import { stat, readFile } from 'node:fs/promises';
import { join, dirname, extname } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import { openDatabase } from '../storage/sqlite.js';
import { ProvenanceRepository } from '../storage/provenance-repo.js';
import { QuarantineRepository } from '../storage/quarantine-repo.js';
import { CheckpointRepository, type CheckpointRecord } from '../storage/checkpoint-repo.js';
import { WriteGrantRepo } from '../storage/write-grant-repo.js';
import { cleanupOrphanStagingFiles } from '../filesystem/orphan-cleanup.js';
import { installAtomically } from '../filesystem/atomic-reflector.js';
import { quarantineVaultFile } from '../filesystem/quarantine-store.js';
import { preflightSyncVault } from '../filesystem/vault-preflight.js';
import { VaultScanner, type VaultFileEntry } from '../filesystem/vault-scanner.js';
import {
  inventoryRemoteDocuments,
  inventoryChangedDocuments,
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
import { logger } from '../diagnostics/logger.js';
import { createStageTimer } from '../diagnostics/stage-timer.js';

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
  /**
   * Enable incremental pulls via `GET /{db}/_changes?since=<checkpoint>` when a
   * persisted checkpoint exists for `remoteFingerprint` (Phase 3). When no
   * checkpoint exists, when the `since` token is rejected by the remote, or
   * when the incremental query fails for any reason, the pass falls back to a
   * full inventory. Default: true (full inventory remains the first-contact
   * and fail-safe path).
   */
  readonly useIncrementalPull?: boolean;
  readonly fetch?: typeof globalThis.fetch;
  /**
   * Optional stage-timing sink (Phase 4.3). When omitted the coordinator logs
   * `[timing]` stage lines through the shared diagnostics logger. Inject a
   * no-op (`() => {}`) in tests that should stay quiet.
   */
  readonly log?: (msg: string) => void;
}

export interface SyncExecutionResult {
  readonly ok: boolean;
  readonly plan: SerializedSyncPlan;
  readonly appliedActions: number;
  readonly errors: string[];
  readonly conflicts: string[];
  readonly converged: boolean;
  /**
   * When the pull phase ran incrementally from the persisted checkpoint, the
   * last update sequence consumed by the `_changes` query. Persisted by Stage 6
   * only after a successful apply; undefined for full-inventory passes.
   */
  readonly incrementalLastSeq?: string;
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
    const timer = createStageTimer(this.options.log ?? ((msg: string) => logger.info(msg)));

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
    //
    // Data-safety: the incremental path changes only the document source. The
    // classification (collectRowsInto), decode (buildObservations), planning
    // (buildSyncPlan), and apply stages are byte-for-byte identical between
    // incremental and full passes. Any incremental failure falls back to a
    // full inventory rather than failing the pass.
    let inventory: Awaited<ReturnType<typeof inventoryRemoteDocuments>> | undefined;
    let incrementalLastSeq: string | undefined;

    // Incremental pulls are only enabled for pull-only passes. A bidirectional
    // pass must observe the COMPLETE remote state to plan pushes: a locally
    // modified file whose remote document is unchanged since the checkpoint
    // produces no `_changes` row, so an incremental source would silently drop
    // its push-update/push-delete/conflict decision. An explicit `updateSeq`
    // also forces a full inventory: the caller asked for a checkpoint pinned at
    // the probe-time sequence.
    const incrementalEligible =
      this.options.useIncrementalPull !== false &&
      this.options.pullOnly === true &&
      !this.options.updateSeq;

    if (incrementalEligible) {
      const checkpointDb = openDatabase(this.options.statePath);
      let checkpoint: CheckpointRecord | null = null;
      try {
        const checkpointRepo = new CheckpointRepository(checkpointDb);
        checkpoint = checkpointRepo.getCheckpoint(this.options.remoteFingerprint);
      } finally {
        checkpointDb.close();
      }

      if (checkpoint && checkpoint.lastUpdateSeq.length > 0) {
        try {
          const changes = await inventoryChangedDocuments(
            this.guardedFetch,
            this.options.baseUrl,
            this.options.databaseName,
            checkpoint.lastUpdateSeq,
            this.options.credentials
          );
          inventory = changes.collected;
          incrementalLastSeq = changes.lastSeq;
          timer.mark('inventory-incremental', `${inventory.length} changed docs`);
        } catch (err) {
          // Fail-safe: an opaque `since` token rejected by the remote (HTTP
          // 400), a network error, or any other _changes failure degrades to a
          // full inventory pass instead of failing the sync.
          logger.warn('Incremental pull failed; falling back to full inventory', {
            error: (err as Error).message,
          });
          incrementalLastSeq = undefined;
        }
      }
    }

    if (inventory === undefined) {
      inventory = await inventoryRemoteDocuments(
        this.guardedFetch,
        this.options.baseUrl,
        this.options.databaseName,
        this.options.credentials
      );
      timer.mark('inventory-full', `${inventory.length} docs`);
    }

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
    timer.mark('decode', `${observations.length} observations`);

    // Safety valve (Phase 3): `block` observations are decode failures the
    // planner cannot express as actions. In a full-inventory pass they are
    // re-examined on every scan; in an incremental pass advancing the
    // checkpoint past them would lose them permanently. Never persist an
    // incremental last_seq consumed over a block observation — the next pass
    // re-runs the _changes query from the previous checkpoint instead.
    const sawBlockObservations = observations.some((obs) => obs.kind === 'block');
    if (sawBlockObservations && incrementalLastSeq !== undefined) {
      logger.warn(
        'Incremental pull produced block observations; checkpoint will not advance past them',
        { blocks: observations.filter((obs) => obs.kind === 'block').length }
      );
      incrementalLastSeq = undefined;
    }

    // Stage 3: Local Vault Scan
    const scanner = new VaultScanner();
    const localFiles = await scanner.scanVault(this.options.vaultRoot);
    timer.mark('scan', `${localFiles.size} local files`);

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
    timer.mark('plan', `${actions.length} actions`);

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
        incrementalLastSeq,
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
      //
      // Partial-failure semantics: the checkpoint is only ever written after
      // the full apply loop completed, so it is never advanced over a partial
      // failure. An incremental pass persists the `_changes` `last_seq`
      // consumed by this pass; a full-inventory pass persists the caller's
      // `updateSeq` (probe-time snapshot), never the incremental token.
      timer.mark('apply', `${appliedCount} actions applied`);
      const seqToPersist = incrementalLastSeq ?? this.options.updateSeq;
      if (seqToPersist) {
        checkpointRepo.saveCheckpoint({
          remoteFingerprint: this.options.remoteFingerprint,
          lastUpdateSeq: seqToPersist,
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
      incrementalLastSeq,
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
