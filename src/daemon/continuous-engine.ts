import { EventEmitter } from 'node:events';
import { openDatabase } from '../storage/sqlite.js';
import { AdmissionRepository } from '../storage/admission-repo.js';
import { WriteGrantRepo } from '../storage/write-grant-repo.js';
import { CheckpointRepository } from '../storage/checkpoint-repo.js';
import { DaemonStateMachine } from './daemon-state.js';
import { FsWatcher, type InvalidationHint } from './fs-watcher.js';
import { ChangesConsumer, type RemoteChangeEvent } from './changes-consumer.js';
import { ReconnectionManager } from './reconnection-manager.js';
import { CheckpointWindow } from './checkpoint-window.js';
import { FileWorkerPool } from './file-worker-pool.js';
import { FileReconciler } from './file-reconciler.js';
import { SyncCoordinator } from '../domain/sync-coordinator.js';
import type { WriteCapability, ArmedSyncCapability } from '../security/capabilities.js';
import { isWriteCapability, isArmedSyncCapability } from '../security/capabilities.js';

export interface ContinuousEngineOptions {
  readonly vaultRoot: string;
  readonly statePath: string;
  readonly stateRoot?: string;
  readonly baseUrl: URL;
  readonly databaseName: string;
  readonly credentials?: { username?: string; password?: string };
  readonly encryptionPassphrase?: string;
  readonly algorithm?: string;
  readonly useDynamicIterationCount?: boolean;
  readonly usePathObfuscation?: boolean;
  readonly pbkdf2salt?: string;
  readonly handleFilenameCaseSensitive?: boolean;
  readonly customChunkSize?: number;
  readonly minimumChunkSize?: number;
  readonly periodicScanIntervalMs?: number;
  readonly debounceMs?: number;
  readonly workerConcurrency?: number;
  /**
   * Phase 3: enable incremental pulls via the persisted `lastUpdateSeq`
   * checkpoint in pull-only passes (periodic scans, read-only catch-up).
   * Bidirectional passes and explicit `updateSeq` callers always use a full
   * inventory. Default: true.
   */
  readonly useIncrementalPull?: boolean;
  readonly fetch?: typeof globalThis.fetch;
  readonly capability?: WriteCapability | ArmedSyncCapability;
  readonly readOnly?: boolean;
  /**
   * One-shot hint: skip the very first catch-up pass because a validated pull
   * already completed in this same startup (auto-arm success path). Periodic
   * and manual scans are unaffected — only the initial pass is skipped.
   */
  readonly skipInitialCatchUp?: boolean;
}

export class ContinuousEngine extends EventEmitter {
  readonly stateMachine = new DaemonStateMachine();
  private readonly fsWatcher: FsWatcher;
  private readonly changesConsumer: ChangesConsumer;
  private readonly reconnectionManager: ReconnectionManager;
  private readonly checkpointWindow = new CheckpointWindow();
  private readonly workerPool: FileWorkerPool;
  private reconciler: FileReconciler;
  private syncCoordinator: SyncCoordinator;

  private periodicTimer: NodeJS.Timeout | null = null;
  private activeCapability: WriteCapability | ArmedSyncCapability | null = null;
  private remoteFingerprint = '';
  private isShuttingDown = false;
  private initialCatchUpSkipped = false;

  constructor(private readonly options: ContinuousEngineOptions) {
    super();

    this.activeCapability = options.capability ?? null;

    this.fsWatcher = new FsWatcher({
      vaultRoot: options.vaultRoot,
      debounceMs: options.debounceMs ?? 300,
      onInvalidation: (hint) => this.onFsInvalidation(hint),
    });

    this.changesConsumer = new ChangesConsumer({
      couchDbUrl: options.baseUrl,
      databaseName: options.databaseName,
      fetchFn: options.fetch,
      authHeader:
        options.credentials?.username || options.credentials?.password
          ? `Basic ${Buffer.from(`${options.credentials.username ?? ''}:${options.credentials.password ?? ''}`).toString('base64')}`
          : undefined,
      onEvent: (event) => this.onRemoteChange(event),
      onError: (err) => this.onRemoteError(err),
    });

    this.reconnectionManager = new ReconnectionManager({
      baseDelayMs: 500,
      maxDelayMs: 30000,
      jitterFactor: 0.25,
    });

    this.reconciler = new FileReconciler({
      vaultRoot: options.vaultRoot,
      statePath: options.statePath,
      stateRoot: options.stateRoot,
      baseUrl: options.baseUrl,
      databaseName: options.databaseName,
      remoteFingerprint: '', // updated during preflight
      credentials: options.credentials,
      encryptionPassphrase: options.encryptionPassphrase,
      algorithm: options.algorithm,
      useDynamicIterationCount: options.useDynamicIterationCount,
      usePathObfuscation: options.usePathObfuscation,
      pbkdf2salt: options.pbkdf2salt,
      handleFilenameCaseSensitive: options.handleFilenameCaseSensitive,
      customChunkSize: options.customChunkSize,
      minimumChunkSize: options.minimumChunkSize,
      fetch: options.fetch,
      stateMachine: this.stateMachine,
      getCapability: () => this.activeCapability,
    });

    this.syncCoordinator = new SyncCoordinator({
      baseUrl: options.baseUrl,
      databaseName: options.databaseName,
      vaultRoot: options.vaultRoot,
      statePath: options.statePath,
      stateRoot: options.stateRoot,
      dryRun: false,
      credentials: options.credentials,
      encryptionPassphrase: options.encryptionPassphrase,
      algorithm: options.algorithm,
      useDynamicIterationCount: options.useDynamicIterationCount,
      usePathObfuscation: options.usePathObfuscation,
      pbkdf2salt: options.pbkdf2salt,
      handleFilenameCaseSensitive: options.handleFilenameCaseSensitive,
      customChunkSize: options.customChunkSize,
      minimumChunkSize: options.minimumChunkSize,
      remoteFingerprint: '', // populated in preflight
      useIncrementalPull: options.useIncrementalPull,
      fetch: options.fetch,
    });

    this.workerPool = new FileWorkerPool({
      concurrency: options.workerConcurrency ?? 4,
      workerFn: async (hint) => this.processInvalidationHint(hint),
      onOverflow: () => this.onQueueOverflow(),
    });
  }

  async start(): Promise<void> {
    this.stateMachine.transitionTo('INITIALIZING');

    // 1. Preflight: verify admission and write grant (DAEM-01)
    await this.validateAdmissionAndGrant();

    // 2. Catch-up: execute complete finite sync pass (DAEM-02)
    this.stateMachine.transitionTo('CATCHING_UP');
    await this.executeCatchUpPass();

    // 3. Transition to live state
    if (this.options.readOnly || !this.activeCapability) {
      const reason = this.options.readOnly
        ? 'read-only mode configured (LIVESYNC_WRITE not set or write grant not armed)'
        : 'no write capability available (capability was not provided to engine)';
      this.stateMachine.transitionTo('DEGRADED_READ_ONLY', reason);
    } else {
      this.stateMachine.transitionTo('HEALTHY_BIDIRECTIONAL');
    }

    // 4. Initialize checkpoint sequence in changes consumer
    const db = openDatabase(this.options.statePath);
    try {
      const checkpointRepo = new CheckpointRepository(db);
      const cp = checkpointRepo.getCheckpoint(this.remoteFingerprint);
      if (cp?.lastUpdateSeq) {
        this.changesConsumer.setSince(cp.lastUpdateSeq);
      }
    } finally {
      db.close();
    }

    // 5. Start live intake streams
    await this.fsWatcher.start();
    this.startChangesFeedStream();

    // 6. Schedule periodic convergence scans (DAEM-06)
    const scanInterval = this.options.periodicScanIntervalMs ?? 300000;
    this.periodicTimer = setInterval(() => {
      this.triggerPeriodicScan().catch((err) => {
        this.emit('error', err);
      });
    }, scanInterval);
  }

  private async validateAdmissionAndGrant(): Promise<void> {
    const db = openDatabase(this.options.statePath);
    try {
      const admissionRepo = new AdmissionRepository(db);
      const latestAdmission = admissionRepo.getLatest();
      if (!latestAdmission) {
        throw new Error('No remote admission record found. Run inspect or sync first to admit database.');
      }

      this.remoteFingerprint = latestAdmission.remoteFingerprint;

      // Enrich reconciler and coordinator with negotiated parameters from admission record if omitted
      if (latestAdmission.negotiatedSettingsJson) {
        try {
          const settings = JSON.parse(latestAdmission.negotiatedSettingsJson) as Record<string, unknown>;
          const pbkdf2salt =
            this.options.pbkdf2salt ??
            (typeof settings.pbkdf2salt === 'string' ? settings.pbkdf2salt : undefined);
          const algorithm =
            this.options.algorithm ??
            (typeof settings.E2EEAlgorithm === 'string' ? settings.E2EEAlgorithm : undefined);
          const useDynamicIterationCount =
            this.options.useDynamicIterationCount ??
            (typeof settings.useDynamicIterationCount === 'boolean' ? settings.useDynamicIterationCount : undefined);
          const usePathObfuscation =
            this.options.usePathObfuscation ??
            (typeof settings.usePathObfuscation === 'boolean' ? settings.usePathObfuscation : undefined);
          const handleFilenameCaseSensitive =
            this.options.handleFilenameCaseSensitive ??
            (typeof settings.handleFilenameCaseSensitive === 'boolean' ? settings.handleFilenameCaseSensitive : undefined);
          const customChunkSize =
            this.options.customChunkSize ??
            (typeof settings.customChunkSize === 'number' ? settings.customChunkSize : undefined);

          this.reconciler = new FileReconciler({
            vaultRoot: this.options.vaultRoot,
            statePath: this.options.statePath,
            stateRoot: this.options.stateRoot,
            baseUrl: this.options.baseUrl,
            databaseName: this.options.databaseName,
            remoteFingerprint: this.remoteFingerprint,
            credentials: this.options.credentials,
            encryptionPassphrase: this.options.encryptionPassphrase,
            algorithm,
            useDynamicIterationCount,
            usePathObfuscation,
            pbkdf2salt,
            handleFilenameCaseSensitive,
            customChunkSize,
            minimumChunkSize: this.options.minimumChunkSize,
            fetch: this.options.fetch,
            stateMachine: this.stateMachine,
            getCapability: () => this.activeCapability,
          });

          this.syncCoordinator = new SyncCoordinator({
            baseUrl: this.options.baseUrl,
            databaseName: this.options.databaseName,
            vaultRoot: this.options.vaultRoot,
            statePath: this.options.statePath,
            stateRoot: this.options.stateRoot,
            dryRun: false,
            credentials: this.options.credentials,
            encryptionPassphrase: this.options.encryptionPassphrase,
            algorithm,
            useDynamicIterationCount,
            usePathObfuscation,
            pbkdf2salt,
            handleFilenameCaseSensitive,
            customChunkSize,
            minimumChunkSize: this.options.minimumChunkSize,
            remoteFingerprint: this.remoteFingerprint,
            useIncrementalPull: this.options.useIncrementalPull,
            fetch: this.options.fetch,
          });
        } catch {
          // Keep existing reconciler/syncCoordinator
        }
      }

      if (!this.options.readOnly && this.activeCapability) {
        const grantRepo = new WriteGrantRepo(db);
        const verification = grantRepo.verifyGrantBinding(this.activeCapability.grantId, {
          remoteFingerprint: this.remoteFingerprint,
          vaultRoot: this.options.vaultRoot,
          settingsHash: latestAdmission.negotiatedSettingsHash,
          commonlibVersion: '0.1.21',
          bootstrapGeneration: latestAdmission.versionInfoRev,
        });

        if (!verification.valid) {
          // Fail closed: drop capability and run read-only (DAEM-07)
          this.activeCapability = null;
          this.emit(
            'warning',
            `Active write grant is invalid: ${verification.reason}. Falling back to read-only.`
          );
        }
      }
    } finally {
      db.close();
    }
  }

  private async executeCatchUpPass(): Promise<void> {
    // Data-safety note: a stored checkpoint only proves the remote was at this
    // update_seq at some point — it does NOT prove the local vault reflects it
    // (a crash can land between file writes and the checkpoint commit). So the
    // full sync pass is skipped ONLY on a one-shot, explicit hint from the
    // daemon when the auto-arm workflow just completed a pull AND validated
    // vault/provenance integrity in this same startup. Everything else (plain
    // restarts, periodic scans, read-only startup) still runs the full pass.
    if (this.options.skipInitialCatchUp && !this.initialCatchUpSkipped) {
      this.initialCatchUpSkipped = true;
      this.emit(
        'warning',
        'Initial catch-up sync skipped: auto-arm completed a validated pull in this startup.'
      );
      return;
    }

    const infoUrl = new URL(`/${encodeURIComponent(this.options.databaseName)}`, this.options.baseUrl);
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (this.options.credentials?.username || this.options.credentials?.password) {
      headers['Authorization'] = `Basic ${Buffer.from(`${this.options.credentials?.username ?? ''}:${this.options.credentials?.password ?? ''}`).toString('base64')}`;
    }
    let updateSeq = '0';
    try {
      const res = await (this.options.fetch ?? globalThis.fetch)(infoUrl.toString(), { headers });
      if (res.ok) {
        const info = (await res.json()) as Record<string, unknown>;
        if (info.update_seq) {
          updateSeq = String(info.update_seq);
        }
      }
    } catch {
      // Ignore network errors during info fetch; proceed with catch-up
    }

    if (this.activeCapability) {
      const result = await this.syncCoordinator.sync(this.activeCapability);
      if (!result.ok && result.conflicts.length > 0) {
        this.emit('conflicts', result.conflicts);
      }
      // With incremental pulls enabled, the coordinator already persisted the
      // _changes last_seq it consumed (Stage 6) — never clobber it with the
      // stale probe-time sequence captured before the pass.
      if (result.incrementalLastSeq === undefined) {
        this.saveProbeCheckpoint(updateSeq);
      }
    } else {
      const readOnlyCoordinator = new SyncCoordinator({
        baseUrl: this.options.baseUrl,
        databaseName: this.options.databaseName,
        vaultRoot: this.options.vaultRoot,
        statePath: this.options.statePath,
        stateRoot: this.options.stateRoot,
        dryRun: false,
        pullOnly: true,
        credentials: this.options.credentials,
        encryptionPassphrase: this.options.encryptionPassphrase,
        algorithm: this.options.algorithm,
        useDynamicIterationCount: this.options.useDynamicIterationCount,
        usePathObfuscation: this.options.usePathObfuscation,
        pbkdf2salt: this.options.pbkdf2salt,
        handleFilenameCaseSensitive: this.options.handleFilenameCaseSensitive,
        customChunkSize: this.options.customChunkSize,
        minimumChunkSize: this.options.minimumChunkSize,
        remoteFingerprint: this.remoteFingerprint,
        // With incremental pulls enabled the coordinator resolves the pull
        // checkpoint itself (and falls back to a full inventory on first
        // contact), so the probe-time update_seq would only force a redundant
        // full pass. When incremental is disabled, keep the probe-time pin.
        updateSeq: this.options.useIncrementalPull === false ? updateSeq : undefined,
        useIncrementalPull: this.options.useIncrementalPull,
        fetch: this.options.fetch,
      });
      const result = await readOnlyCoordinator.sync();
      if (!result.ok && result.conflicts.length > 0) {
        this.emit('conflicts', result.conflicts);
      }
      // Same rule for the read-only pass: incremental passes already advanced
      // the checkpoint to the consumed last_seq.
      if (result.incrementalLastSeq === undefined) {
        this.saveProbeCheckpoint(updateSeq);
      }
    }
  }

  /**
   * Persist the probe-time update sequence captured before a catch-up pass.
   * Only used by full-inventory passes; an incremental pass persists its own
   * consumed `last_seq` inside SyncCoordinator Stage 6.
   */
  private saveProbeCheckpoint(updateSeq: string): void {
    if (updateSeq !== '0' || this.remoteFingerprint) {
      const db = openDatabase(this.options.statePath);
      try {
        const checkpointRepo = new CheckpointRepository(db);
        checkpointRepo.saveCheckpoint({
          remoteFingerprint: this.remoteFingerprint,
          lastUpdateSeq: updateSeq,
          completedAt: new Date().toISOString(),
        });
      } finally {
        db.close();
      }
    }
  }

  private onFsInvalidation(hint: InvalidationHint): void {
    if (this.isShuttingDown) {
      return;
    }
    this.workerPool.enqueue(hint);
  }

  private onRemoteChange(event: RemoteChangeEvent): void {
    if (this.isShuttingDown) {
      return;
    }
    this.checkpointWindow.trackSequence(event.seq);

    const hint: InvalidationHint = {
      path: event.docId,
      source: 'remote_changes',
      remoteSeq: event.seq,
      timestamp: event.timestamp,
    };

    this.workerPool.enqueue(hint);
  }

  private onRemoteError(error: unknown): void {
    if (this.isShuttingDown) {
      return;
    }

    this.emit('warning', `Changes stream disconnected: ${(error as Error).message}. Scheduling reconnection.`);

    this.reconnectionManager
      .scheduleRetry(() => {
        this.startChangesFeedStream();
      })
      .catch((err) => {
        if (!this.isShuttingDown) {
          this.emit('error', err);
        }
      });
  }

  private startChangesFeedStream(): void {
    if (this.isShuttingDown) {
      return;
    }

    this.changesConsumer.start().then(() => {
      this.reconnectionManager.recordSuccess();
    }).catch((err) => {
      this.onRemoteError(err);
    });
  }

  private async processInvalidationHint(hint: InvalidationHint): Promise<void> {
    try {
      const result = await this.reconciler.reconcile(hint.path);

      if (hint.remoteSeq) {
        if (result.success) {
          this.checkpointWindow.markCompleted(hint.remoteSeq);
          this.commitContiguousCheckpoints();
        } else {
          this.checkpointWindow.markFailed(hint.remoteSeq, result.error);
        }
      }

      this.emit('reconciled', result);
    } catch (err: unknown) {
      if (hint.remoteSeq) {
        this.checkpointWindow.markFailed(hint.remoteSeq, err);
      }
      throw err;
    }
  }

  private commitContiguousCheckpoints(): void {
    const db = openDatabase(this.options.statePath);
    try {
      const checkpointRepo = new CheckpointRepository(db);
      this.checkpointWindow.commit(checkpointRepo, this.remoteFingerprint);
    } finally {
      db.close();
    }
  }

  private onQueueOverflow(): void {
    this.emit('warning', 'Worker queue reached capacity. Coalescing hints into full scan.');
    this.workerPool.clear();
    this.triggerPeriodicScan().catch((err) => {
      this.emit('error', err);
    });
  }

  async triggerPeriodicScan(): Promise<void> {
    if (this.isShuttingDown) {
      return;
    }

    try {
      await this.executeCatchUpPass();
    } catch (err: unknown) {
      this.emit('warning', `Periodic scan failed: ${(err as Error).message}`);
    }
  }

  async triggerManualScan(): Promise<void> {
    return this.triggerPeriodicScan();
  }

  async stop(timeoutMs = 10000): Promise<void> {
    if (this.isShuttingDown) {
      return;
    }

    this.isShuttingDown = true;
    this.stateMachine.transitionTo('STOPPING');

    if (this.periodicTimer) {
      clearInterval(this.periodicTimer);
      this.periodicTimer = null;
    }

    this.reconnectionManager.cancel();

    // 1. Close intake streams
    await this.fsWatcher.close();
    await this.changesConsumer.close();

    // 2. Drain worker pool
    try {
      await this.workerPool.drain(timeoutMs);
    } catch {
      // Timeout reached: force clear
      this.workerPool.clear();
    }

    // 3. Final checkpoint commit
    this.commitContiguousCheckpoints();

    // 4. Set terminal state
    this.stateMachine.transitionTo('STOPPED');
  }
}
