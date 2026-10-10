import { createHash } from 'node:crypto';
import { stat, readFile, unlink } from 'node:fs/promises';
import { join, dirname, extname } from 'node:path';
import { openDatabase } from '../storage/sqlite.js';
import { ProvenanceRepository } from '../storage/provenance-repo.js';
import { QuarantineRepository } from '../storage/quarantine-repo.js';
import { LoopSuppressor } from './loop-suppressor.js';
import type { DaemonStateMachine } from './daemon-state.js';
import { installAtomically } from '../filesystem/atomic-reflector.js';
import { quarantineVaultFile } from '../filesystem/quarantine-store.js';
import { PushAdapter } from '../livesync/push-adapter.js';
import { DeletionWriter } from '../livesync/deletion-writer.js';
import { decodeNoteLeaf, type DecodeOptions, isNoteType } from '../livesync/decode-adapter.js';
import { createChunkFetcher } from '../livesync/inventory.js';
import { path2id_base } from '@vrtmrz/livesync-commonlib/compat/string_and_binary/path';
import { createArmedGuardedFetch } from '../security/transport-guard.js';
import type { WriteCapability, ArmedSyncCapability } from '../security/capabilities.js';
import { isReservedOrIgnoredPath } from '../domain/path-policy.js';

export interface FileReconcilerOptions {
  readonly vaultRoot: string;
  readonly statePath: string;
  readonly stateRoot?: string;
  readonly baseUrl: URL;
  readonly databaseName: string;
  readonly remoteFingerprint: string;
  readonly credentials?: { username?: string; password?: string };
  readonly encryptionPassphrase?: string;
  readonly algorithm?: string;
  readonly useDynamicIterationCount?: boolean;
  readonly usePathObfuscation?: boolean;
  readonly pbkdf2salt?: string;
  readonly handleFilenameCaseSensitive?: boolean;
  readonly customChunkSize?: number;
  readonly minimumChunkSize?: number;
  readonly fetch?: typeof globalThis.fetch;
  readonly loopSuppressor?: LoopSuppressor;
  readonly stateMachine: DaemonStateMachine;
  readonly getCapability: () => WriteCapability | ArmedSyncCapability | null;
}

export interface ReconcileResult {
  readonly path: string;
  readonly action: 'noop' | 'pull' | 'push' | 'pull-delete' | 'push-delete' | 'conflict' | 'skipped';
  readonly success: boolean;
  readonly error?: string;
}

export class FileReconciler {
  private readonly guardedFetch: typeof globalThis.fetch;
  private readonly loopSuppressor: LoopSuppressor;
  private readonly decodeOptions: DecodeOptions;
  private readonly pushAdapter: PushAdapter;
  private readonly deletionWriter: DeletionWriter;

  constructor(private readonly options: FileReconcilerOptions) {
    this.guardedFetch = createArmedGuardedFetch(
      {
        allowedBaseUrl: options.baseUrl,
        databaseName: options.databaseName,
      },
      options.fetch ?? globalThis.fetch
    );

    this.loopSuppressor = options.loopSuppressor ?? new LoopSuppressor();

    const authHeader =
      options.credentials?.username || options.credentials?.password
        ? `Basic ${Buffer.from(`${options.credentials.username ?? ''}:${options.credentials.password ?? ''}`).toString('base64')}`
        : undefined;

    const fetchChunk = createChunkFetcher(
      this.guardedFetch,
      options.baseUrl,
      options.databaseName,
      authHeader
    );

    this.decodeOptions = {
      handleFilenameCaseSensitive: options.handleFilenameCaseSensitive,
      usePathObfuscation: options.usePathObfuscation,
      useDynamicIterationCount: options.useDynamicIterationCount,
      encryptionPassphrase: options.encryptionPassphrase,
      algorithm: options.algorithm,
      pbkdf2salt: options.pbkdf2salt,
      fetchChunk,
    };

    this.pushAdapter = new PushAdapter({
      baseUrl: options.baseUrl,
      databaseName: options.databaseName,
      chunkSize: options.customChunkSize,
      minimumChunkSize: options.minimumChunkSize,
      encryptionPassphrase: options.encryptionPassphrase,
      algorithm: options.algorithm,
      useDynamicIterationCount: options.useDynamicIterationCount,
      usePathObfuscation: options.usePathObfuscation,
      pbkdf2salt: options.pbkdf2salt,
      handleFilenameCaseSensitive: options.handleFilenameCaseSensitive,
      credentials: options.credentials,
      fetch: this.guardedFetch,
    });

    this.deletionWriter = new DeletionWriter({
      baseUrl: options.baseUrl,
      databaseName: options.databaseName,
      encryptionPassphrase: options.encryptionPassphrase,
      algorithm: options.algorithm,
      useDynamicIterationCount: options.useDynamicIterationCount,
      usePathObfuscation: options.usePathObfuscation,
      pbkdf2salt: options.pbkdf2salt,
      handleFilenameCaseSensitive: options.handleFilenameCaseSensitive,
      credentials: options.credentials,
      fetch: this.guardedFetch,
    });
  }

  async reconcile(relativePath: string): Promise<ReconcileResult> {
    if (isReservedOrIgnoredPath(relativePath)) {
      return { path: relativePath, action: 'skipped', success: true };
    }

    if (!this.options.stateMachine.isReadPermitted()) {
      return {
        path: relativePath,
        action: 'skipped',
        success: false,
        error: `Daemon is in state ${this.options.stateMachine.getState()}`,
      };
    }

    const db = openDatabase(this.options.statePath);
    try {
      const provenanceRepo = new ProvenanceRepository(db);
      const quarantineRepo = new QuarantineRepository(db);

      // 1. Authoritative remote read
      const remote = await this.fetchRemoteDocument(relativePath);
      const targetPath = remote?.path && remote.path.length > 0 ? remote.path : relativePath;

      if (isReservedOrIgnoredPath(targetPath)) {
        return { path: targetPath, action: 'skipped', success: true };
      }

      const prov = provenanceRepo.getByPath(targetPath);

      // 2. Authoritative local read
      const fullLocalPath = join(this.options.vaultRoot, targetPath);
      let localExists = false;
      let localBytes: Uint8Array | null = null;
      let localSha256 = '';
      let localMtime = 0;

      try {
        const fileStat = await stat(fullLocalPath);
        if (fileStat.isFile()) {
          localExists = true;
          localMtime = fileStat.mtimeMs;
          const buf = await readFile(fullLocalPath);
          localBytes = new Uint8Array(buf);
          localSha256 = createHash('sha256').update(localBytes).digest('hex');
        }
      } catch (err: unknown) {
        const nodeErr = err as NodeJS.ErrnoException;
        if (nodeErr.code !== 'ENOENT') {
          return {
            path: targetPath,
            action: 'skipped',
            success: false,
            error: `Failed to stat local file '${targetPath}': ${nodeErr.message}`,
          };
        }
      }

      // 3. Evaluation & Action Decision
      // Case A: File exists on both Local and Remote
      if (localExists && remote && !remote.deleted) {
        if (localSha256 === remote.contentSha256) {
          // Content identical on both sides: update provenance if needed
          if (!prov || prov.remoteRevision !== remote.sourceRevision || prov.contentSha256 !== localSha256) {
            provenanceRepo.saveProvenance({
              path: targetPath,
              remoteRevision: remote.sourceRevision,
              contentSha256: localSha256,
              observedMtime: localMtime,
              remoteFingerprint: this.options.remoteFingerprint,
              reflectedAt: new Date().toISOString(),
            });
          }
          return { path: targetPath, action: 'noop', success: true };
        }

        const remoteMatchesProv = prov && remote.sourceRevision === prov.remoteRevision;
        const localMatchesProv = prov && localSha256 === prov.contentSha256;

        if (remoteMatchesProv && !localMatchesProv) {
          // Local modified, remote unchanged: push update
          return await this.executePushUpdate(targetPath, localBytes!, localSha256, localMtime, prov.remoteRevision, provenanceRepo);
        } else if (!remoteMatchesProv && localMatchesProv) {
          // Remote modified, local unchanged: pull update
          return await this.executePull(targetPath, remote.bytes, remote.sourceRevision, remote.contentSha256, provenanceRepo);
        } else {
          // Conflict: both modified independently
          return await this.handleConflict(targetPath, localBytes!, localSha256, remote.bytes, remote.sourceRevision);
        }
      }

      // Case B: File exists locally only
      if (localExists && (!remote || remote.deleted)) {
        if (!prov) {
          // New local file: push create
          return await this.executePushCreate(targetPath, localBytes!, localSha256, localMtime, provenanceRepo);
        } else if (remote?.deleted) {
          // Remote deleted while local modified or retained
          if (localSha256 === prov.contentSha256) {
            // Local untouched: reflect remote deletion locally
            return await this.executePullDelete(targetPath, remote.sourceRevision, provenanceRepo, quarantineRepo);
          } else {
            // Local modified after remote deleted: conflict
            return await this.handleConflict(targetPath, localBytes!, localSha256, new Uint8Array(), remote.sourceRevision);
          }
        } else {
          // Prov exists but no remote: push create
          return await this.executePushCreate(targetPath, localBytes!, localSha256, localMtime, provenanceRepo);
        }
      }

      // Case C: File exists remotely only
      if (!localExists && remote && !remote.deleted) {
        if (!prov) {
          // New remote file: pull create
          return await this.executePull(targetPath, remote.bytes, remote.sourceRevision, remote.contentSha256, provenanceRepo);
        } else {
          if (remote.sourceRevision === prov.remoteRevision) {
            // Local deletion, remote untouched: push deletion
            return await this.executePushDelete(targetPath, prov.remoteRevision, provenanceRepo);
          } else {
            // Local deleted while remote modified: conflict (preserve remote by pulling)
            return await this.executePull(targetPath, remote.bytes, remote.sourceRevision, remote.contentSha256, provenanceRepo);
          }
        }
      }

      // Case D: File deleted on both sides or missing
      if (!localExists && (!remote || remote.deleted)) {
        if (prov) {
          provenanceRepo.deleteProvenance(targetPath);
        }
        return { path: targetPath, action: 'noop', success: true };
      }

      return { path: targetPath, action: 'noop', success: true };
    } finally {
      db.close();
    }
  }

  private async fetchRemoteDocument(relativePath: string): Promise<{
    path: string;
    sourceRevision: string;
    bytes: Uint8Array;
    contentSha256: string;
    deleted: boolean;
  } | null> {
    const obfuscate =
      this.options.usePathObfuscation && this.options.encryptionPassphrase
        ? this.options.encryptionPassphrase
        : false;
    const caseInsensitive = !Boolean(this.options.handleFilenameCaseSensitive);
    const expectedDocId = String(
      await path2id_base(relativePath as Parameters<typeof path2id_base>[0], obfuscate, caseInsensitive)
    );
    const targetUrl = new URL(`/${encodeURIComponent(this.options.databaseName)}/${encodeURIComponent(expectedDocId)}`, this.options.baseUrl);

    const headers: Record<string, string> = { Accept: 'application/json' };
    if (this.options.credentials?.username || this.options.credentials?.password) {
      headers['Authorization'] = `Basic ${Buffer.from(`${this.options.credentials?.username ?? ''}:${this.options.credentials?.password ?? ''}`).toString('base64')}`;
    }

    try {
      let response = await this.guardedFetch(targetUrl.toString(), {
        method: 'GET',
        headers,
      });

      if (response.status === 404 && expectedDocId !== relativePath) {
        const fallbackUrl = new URL(
          `/${encodeURIComponent(this.options.databaseName)}/${encodeURIComponent(relativePath)}`,
          this.options.baseUrl
        );
        response = await this.guardedFetch(fallbackUrl.toString(), {
          method: 'GET',
          headers,
        });
      }

      if (response.status === 404) {
        return null;
      }

      if (!response.ok) {
        throw new Error(
          `Failed to fetch remote document '${relativePath}': HTTP ${response.status} ${response.statusText}`
        );
      }

      const doc = await response.json() as Record<string, unknown>;
      const type = typeof doc.type === 'string' ? doc.type : 'unknown';

      if (doc._deleted === true || doc.deleted === true) {
        const decodedPath = typeof doc.path === 'string' ? doc.path : relativePath;
        return {
          path: decodedPath,
          sourceRevision: String(doc._rev ?? ''),
          bytes: new Uint8Array(),
          contentSha256: '',
          deleted: true,
        };
      }

      if (!isNoteType(type)) {
        return null;
      }

      const decoded = await decodeNoteLeaf(doc as any, this.decodeOptions);
      if (!decoded.ok) {
        return null;
      }

      const hash = createHash('sha256').update(decoded.bytes).digest('hex');
      return {
        path: decoded.path,
        sourceRevision: decoded.sourceRevision,
        bytes: decoded.bytes,
        contentSha256: hash,
        deleted: decoded.deleted,
      };
    } catch (err) {
      // Data safety: a failed remote read (network error, auth failure, HTTP
      // error) must be distinguishable from a genuine 404. Returning null here
      // would classify the document as deleted/absent and let the checkpoint
      // advance over a change that was never applied. Rethrow so the caller
      // records a failed reconciliation instead.
      throw new Error(
        `Remote read for '${relativePath}' failed: ${(err as Error).message}`
      );
    }
  }

  private async executePull(
    relativePath: string,
    bytes: Uint8Array,
    sourceRevision: string,
    contentSha256: string,
    provenanceRepo: ProvenanceRepository
  ): Promise<ReconcileResult> {
    try {
      await installAtomically(this.options.vaultRoot, relativePath, bytes);
      const dest = join(this.options.vaultRoot, relativePath);
      const fileStat = await stat(dest);

      provenanceRepo.saveProvenance({
        path: relativePath,
        remoteRevision: sourceRevision,
        contentSha256,
        observedMtime: fileStat.mtimeMs,
        remoteFingerprint: this.options.remoteFingerprint,
        reflectedAt: new Date().toISOString(),
      });

      return { path: relativePath, action: 'pull', success: true };
    } catch (err: unknown) {
      return {
        path: relativePath,
        action: 'pull',
        success: false,
        error: `Failed to pull '${relativePath}': ${(err as Error).message}`,
      };
    }
  }

  private async executePullDelete(
    relativePath: string,
    sourceRevision: string,
    provenanceRepo: ProvenanceRepository,
    quarantineRepo: QuarantineRepository
  ): Promise<ReconcileResult> {
    try {
      const stateRoot = this.options.stateRoot
        ? (extname(this.options.stateRoot) ? dirname(this.options.stateRoot) : this.options.stateRoot)
        : dirname(this.options.statePath);

      await quarantineVaultFile(
        this.options.vaultRoot,
        stateRoot,
        relativePath,
        sourceRevision,
        quarantineRepo
      );
      provenanceRepo.deleteProvenance(relativePath);
      return { path: relativePath, action: 'pull-delete', success: true };
    } catch (err: unknown) {
      return {
        path: relativePath,
        action: 'pull-delete',
        success: false,
        error: `Failed to pull-delete '${relativePath}': ${(err as Error).message}`,
      };
    }
  }

  private async executePushCreate(
    relativePath: string,
    bytes: Uint8Array,
    contentSha256: string,
    mtime: number,
    provenanceRepo: ProvenanceRepository
  ): Promise<ReconcileResult> {
    if (!this.options.stateMachine.isWritePermitted()) {
      return {
        path: relativePath,
        action: 'skipped',
        success: true,
        error: 'Push omitted: daemon is in read-only / degraded state',
      };
    }

    const capability = this.options.getCapability();
    if (!capability) {
      return {
        path: relativePath,
        action: 'skipped',
        success: false,
        error: 'Missing write capability',
      };
    }

    const pushRes = await this.pushAdapter.pushFile(
      { path: relativePath, bytes, mtime },
      capability
    );

    if (!pushRes.ok) {
      return {
        path: relativePath,
        action: 'push',
        success: false,
        error: pushRes.error,
      };
    }

    provenanceRepo.saveProvenance({
      path: relativePath,
      remoteRevision: pushRes.rev!,
      contentSha256,
      observedMtime: mtime,
      remoteFingerprint: this.options.remoteFingerprint,
      reflectedAt: new Date().toISOString(),
    });

    return { path: relativePath, action: 'push', success: true };
  }

  private async executePushUpdate(
    relativePath: string,
    bytes: Uint8Array,
    contentSha256: string,
    mtime: number,
    baseRev: string,
    provenanceRepo: ProvenanceRepository
  ): Promise<ReconcileResult> {
    if (!this.options.stateMachine.isWritePermitted()) {
      return {
        path: relativePath,
        action: 'skipped',
        success: true,
        error: 'Push omitted: daemon is in read-only / degraded state',
      };
    }

    const capability = this.options.getCapability();
    if (!capability) {
      return {
        path: relativePath,
        action: 'skipped',
        success: false,
        error: 'Missing write capability',
      };
    }

    const pushRes = await this.pushAdapter.pushFile(
      { path: relativePath, bytes, mtime, baseRev },
      capability
    );

    if (!pushRes.ok) {
      return {
        path: relativePath,
        action: 'push',
        success: false,
        error: pushRes.error,
      };
    }

    provenanceRepo.saveProvenance({
      path: relativePath,
      remoteRevision: pushRes.rev!,
      contentSha256,
      observedMtime: mtime,
      remoteFingerprint: this.options.remoteFingerprint,
      reflectedAt: new Date().toISOString(),
    });

    return { path: relativePath, action: 'push', success: true };
  }

  private async executePushDelete(
    relativePath: string,
    baseRev: string,
    provenanceRepo: ProvenanceRepository
  ): Promise<ReconcileResult> {
    if (!this.options.stateMachine.isWritePermitted()) {
      return {
        path: relativePath,
        action: 'skipped',
        success: true,
        error: 'Push delete omitted: daemon is in read-only / degraded state',
      };
    }

    const capability = this.options.getCapability();
    if (!capability) {
      return {
        path: relativePath,
        action: 'skipped',
        success: false,
        error: 'Missing write capability',
      };
    }

    const delRes = await this.deletionWriter.writeDeletion(relativePath, baseRev, capability);
    if (!delRes.ok) {
      return {
        path: relativePath,
        action: 'push-delete',
        success: false,
        error: delRes.error,
      };
    }

    provenanceRepo.deleteProvenance(relativePath);
    return { path: relativePath, action: 'push-delete', success: true };
  }

  private async handleConflict(
    relativePath: string,
    localBytes: Uint8Array,
    localSha256: string,
    remoteBytes: Uint8Array,
    remoteRev: string
  ): Promise<ReconcileResult> {
    // Preserve local copy as conflict file if remote exists
    if (remoteBytes.byteLength > 0) {
      const ext = extname(relativePath);
      const base = relativePath.slice(0, relativePath.length - ext.length);
      const conflictPath = `${base}.conflict-${Date.now()}${ext}`;
      try {
        await installAtomically(this.options.vaultRoot, conflictPath, localBytes);
        await installAtomically(this.options.vaultRoot, relativePath, remoteBytes);
      } catch {
        // Fall back to keeping local
      }
    }

    return {
      path: relativePath,
      action: 'conflict',
      success: true,
      error: `Conflict detected on '${relativePath}' (rev: ${remoteRev}). Preserved local conflict copy.`,
    };
  }
}
