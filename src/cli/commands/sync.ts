import { loadConfig, ConfigValidationError } from '../../config/loader.js';
import { SecretRedactor, defaultRedactor } from '../../security/redaction.js';
import {
  createGuardedFetch,
  createArmedGuardedFetch,
  MutationAttemptBlockedError,
} from '../../security/transport-guard.js';
import {
  createWriteCapability,
  type WriteCapability,
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
} from '../../livesync/negotiation.js';
import { openDatabase } from '../../storage/sqlite.js';
import { WriteGrantRepo } from '../../storage/write-grant-repo.js';
import { AdmissionRepository } from '../../storage/admission-repo.js';
import { SyncCoordinator, type SyncExecutionResult } from '../../domain/sync-coordinator.js';
import { OutcomeCategory, EXIT_CODES } from '../../diagnostics/outcomes.js';

export interface SyncCommandOptions {
  configPath?: string;
  dryRun?: boolean;
  json?: boolean;
  redactor?: SecretRedactor;
  stdout?: (msg: string) => void;
}

export function emitBackupWarningBanner(stdout: (msg: string) => void): void {
  stdout(
    `\n================================================================================\n` +
      `⚠️  WARNING: Synchronization propagates creations, updates, and deletions across\n` +
      `   all connected LiveSync clients. It is NOT an independent backup.\n` +
      `================================================================================\n\n`
  );
}

export async function runSyncCommand(options: SyncCommandOptions): Promise<number> {
  const redactor = options.redactor ?? defaultRedactor;
  const writeStdout = options.stdout ?? ((msg: string) => process.stdout.write(msg));

  // SAFE-07: Backup disclaimer warning banner
  emitBackupWarningBanner(writeStdout);

  let config;
  try {
    config = await loadConfig(options.configPath, process.env, redactor);
  } catch (err) {
    writeStdout(
      JSON.stringify({
        type: 'sync_report',
        outcome: OutcomeCategory.CONFIG_ERROR,
        dryRun: options.dryRun,
        message: (err as Error).message,
      }) + '\n'
    );
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

  const fingerprint = computeFingerprint(allowedBaseUrl.href, databaseName);

  let preSnapshot: DatabaseSnapshot | undefined;
  let postSnapshot: DatabaseSnapshot | undefined;

  try {
    if (options.dryRun) {
      preSnapshot = await ZeroMutationVerifier.captureSnapshot(
        guardedFetch,
        allowedBaseUrl,
        databaseName,
        credentials
      );
    }

    const probeResult = await probeRemoteDatabase(
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

    const negotiation = negotiateCompatibility(
      probeResult,
      config,
      syncinfoResult.verified
    );

    if (!negotiation.admitted) {
      writeStdout(
        JSON.stringify({
          type: 'sync_report',
          outcome: OutcomeCategory.INCOMPATIBLE,
          dryRun: options.dryRun,
          message: 'Remote database failed admission negotiation.',
          blockers: negotiation.blockers,
        }) + '\n'
      );
      return EXIT_CODES.INCOMPATIBLE;
    }

    let writeCapability: WriteCapability | undefined;

    if (!options.dryRun) {
      // Check write arming grant (CONF-07, CONF-08)
      const db = openDatabase(config.resolvedStatePath);
      try {
        const grantRepo = new WriteGrantRepo(db);
        const activeGrant = grantRepo.getActiveGrant(negotiation.remoteFingerprint, config.resolvedVaultPath);

        if (!activeGrant) {
          writeStdout(
            JSON.stringify({
              type: 'sync_report',
              outcome: OutcomeCategory.MUTATION_VIOLATION,
              dryRun: false,
              message: 'Write operations not armed for this remote and vault. Run `arm` command first.',
            }) + '\n'
          );
          return EXIT_CODES.MUTATION_VIOLATION;
        }

        const currentBinding = {
          remoteFingerprint: negotiation.remoteFingerprint,
          vaultRoot: config.resolvedVaultPath,
          settingsHash: negotiation.negotiatedSettingsHash,
          commonlibVersion: '0.1.21',
          bootstrapGeneration: probeResult.versionDoc?._rev || '1',
        };

        const verification = grantRepo.verifyGrantBinding(activeGrant.grantId, currentBinding);
        if (!verification.valid) {
          writeStdout(
            JSON.stringify({
              type: 'sync_report',
              outcome: OutcomeCategory.MUTATION_VIOLATION,
              dryRun: false,
              message: `Write grant invalid or auto-revoked due to evidence drift: ${verification.reason}`,
            }) + '\n'
          );
          return EXIT_CODES.MUTATION_VIOLATION;
        }

        writeCapability = createWriteCapability(
          allowedBaseUrl,
          databaseName,
          activeGrant.grantId,
          negotiation.remoteFingerprint,
          config.resolvedVaultPath
        );
      } finally {
        db.close();
      }
    }

  const db = openDatabase(config.resolvedStatePath);
  try {
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
      updateSeq: probeResult.databaseInfo.updateSeq,
      admittedAt: new Date().toISOString(),
    });
  } finally {
    db.close();
  }

    const preferredTweaks = probeResult.milestoneDoc?.tweak_values?.PREFERRED ?? {};
    const encrypt = Boolean(negotiation.negotiatedSettings.encrypt ?? preferredTweaks.encrypt);
    const algorithm =
      typeof negotiation.negotiatedSettings.E2EEAlgorithm === 'string'
        ? negotiation.negotiatedSettings.E2EEAlgorithm
        : typeof preferredTweaks.E2EEAlgorithm === 'string'
          ? preferredTweaks.E2EEAlgorithm
          : encrypt
            ? 'v2'
            : undefined;

    const coordinator = new SyncCoordinator({
      baseUrl: allowedBaseUrl,
      databaseName,
      vaultRoot: config.resolvedVaultPath,
      statePath: config.resolvedStatePath,
      dryRun: Boolean(options.dryRun),
      credentials,
      encryptionPassphrase: config.resolvedSecrets.encryptionPassphrase,
      algorithm,
      useDynamicIterationCount: Boolean(negotiation.negotiatedSettings.useDynamicIterationCount),
      usePathObfuscation: Boolean(negotiation.negotiatedSettings.usePathObfuscation),
      pbkdf2salt:
        typeof probeResult.syncParamsDoc?.pbkdf2salt === 'string'
          ? probeResult.syncParamsDoc.pbkdf2salt
          : typeof negotiation.negotiatedSettings.pbkdf2salt === 'string'
            ? (negotiation.negotiatedSettings.pbkdf2salt as string)
            : undefined,
      handleFilenameCaseSensitive: Boolean(negotiation.negotiatedSettings.handleFilenameCaseSensitive),
      customChunkSize:
        typeof negotiation.negotiatedSettings.customChunkSize === 'number'
          ? (negotiation.negotiatedSettings.customChunkSize as number)
          : undefined,
      minimumChunkSize: 20,
      remoteFingerprint: negotiation.remoteFingerprint,
      useIncrementalPull: config.cli?.incrementalPull ?? true,
      updateSeq: probeResult.databaseInfo.updateSeq ? String(probeResult.databaseInfo.updateSeq) : undefined,
    });

    const result = await coordinator.sync(writeCapability);

    if (options.dryRun && preSnapshot) {
      postSnapshot = await ZeroMutationVerifier.captureSnapshot(
        guardedFetch,
        allowedBaseUrl,
        databaseName,
        credentials
      );
      if (postSnapshot) {
        ZeroMutationVerifier.assertNoMutation(preSnapshot, postSnapshot);
      }
    }

    const report = {
      type: 'sync_report',
      outcome: result.conflicts.length > 0 ? OutcomeCategory.CONFLICT : result.ok ? OutcomeCategory.SUCCESS : OutcomeCategory.CORRUPTION,
      dryRun: options.dryRun,
      summary: result.plan.summary,
      actions: result.plan.actions,
      appliedActions: result.appliedActions,
      errors: result.errors,
      conflicts: result.conflicts,
      converged: result.converged,
      zeroMutationVerified: options.dryRun,
    };

    if (options.json) {
      writeStdout(JSON.stringify(report) + '\n');
    } else {
      writeStdout(
        `\nSynchronization Plan & Result (${options.dryRun ? 'DRY-RUN' : 'APPLY'}):\n` +
          `  Total Actions:      ${result.plan.summary.totalActions}\n` +
          `  Pull Creates:       ${result.plan.summary.pullCreates}\n` +
          `  Pull Updates:       ${result.plan.summary.pullUpdates}\n` +
          `  Pull Deletes:       ${result.plan.summary.pullDeletes}\n` +
          `  Push Creates:       ${result.plan.summary.pushCreates}\n` +
          `  Push Updates:       ${result.plan.summary.pushUpdates}\n` +
          `  Push Deletes:       ${result.plan.summary.pushDeletes}\n` +
          `  Renames:            ${result.plan.summary.renames}\n` +
          `  No-ops:             ${result.plan.summary.noops}\n` +
          `  Conflicts:          ${result.plan.summary.conflicts}\n` +
          `  Applied Actions:    ${result.appliedActions}\n` +
          `  Converged:          ${result.converged}\n\n`
      );

      if (result.conflicts.length > 0) {
        writeStdout(`⚠️  Unresolved Conflicts (preserved without overwrite):\n`);
        for (const c of result.conflicts) {
          writeStdout(`  - ${c}\n`);
        }
        writeStdout(`\n`);
      }
    }

    if (result.conflicts.length > 0) {
      return EXIT_CODES.CONFLICT;
    }

    return result.ok ? EXIT_CODES.SUCCESS : EXIT_CODES.CORRUPTION;
  } catch (err) {
    if (err instanceof MutationDetectedError || err instanceof MutationAttemptBlockedError) {
      writeStdout(
        JSON.stringify({
          type: 'sync_report',
          outcome: OutcomeCategory.MUTATION_VIOLATION,
          dryRun: options.dryRun,
          message: err.message,
        }) + '\n'
      );
      return EXIT_CODES.MUTATION_VIOLATION;
    }

    if (err instanceof AuthenticationRequiredError) {
      return EXIT_CODES.AUTHENTICATION_ERROR;
    }

    if (err instanceof DatabaseNotFoundError) {
      return EXIT_CODES.NOT_FOUND;
    }

    writeStdout(
      JSON.stringify({
        type: 'sync_report',
        outcome: OutcomeCategory.CORRUPTION,
        dryRun: options.dryRun,
        message: (err as Error).message,
      }) + '\n'
    );
    return EXIT_CODES.CORRUPTION;
  }
}
