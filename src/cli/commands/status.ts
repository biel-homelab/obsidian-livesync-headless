import fs from 'node:fs';
import { loadConfig } from '../../config/loader.js';
import { SecretRedactor, defaultRedactor } from '../../security/redaction.js';
import { openDatabase } from '../../storage/sqlite.js';
import { AdmissionRepository } from '../../storage/admission-repo.js';
import { WriteGrantRepo } from '../../storage/write-grant-repo.js';
import { CheckpointRepository } from '../../storage/checkpoint-repo.js';
import { OutcomeCategory, EXIT_CODES } from '../../diagnostics/outcomes.js';

export interface StatusCommandOptions {
  configPath?: string;
  json?: boolean;
  redactor?: SecretRedactor;
  stdout?: (msg: string) => void;
  stderr?: (msg: string) => void;
}

export interface StatusReport {
  readonly type: 'status_report';
  readonly outcome: OutcomeCategory;
  readonly vaultPath: string;
  readonly statePath: string;
  readonly databaseExists: boolean;
  readonly admission: {
    readonly admitted: boolean;
    readonly remoteFingerprint?: string;
    readonly couchdbUrl?: string;
    readonly databaseName?: string;
    readonly couchdbVersion?: string;
    readonly settingsHash?: string;
    readonly admittedAt?: string;
  };
  readonly writeGrant: {
    readonly active: boolean;
    readonly grantId?: string;
    readonly bootstrapGeneration?: string;
    readonly issuedAt?: string;
  };
  readonly checkpoint: {
    readonly hasCheckpoint: boolean;
    readonly lastUpdateSeq?: string;
    readonly completedAt?: string;
  };
  readonly stats: {
    readonly trackedFilesCount: number;
    readonly quarantineFilesCount: number;
  };
}

export function formatStatusHuman(report: StatusReport): string {
  const lines: string[] = [];
  const divider = '─'.repeat(70);

  lines.push(divider);
  lines.push(`  OBSIDIAN LIVESYNC VAULT STATUS: [${report.outcome}]`);
  lines.push(divider);
  lines.push(`  Vault Path:               ${report.vaultPath}`);
  lines.push(`  State Path:               ${report.statePath}`);
  lines.push(
    `  State Database:           ${report.databaseExists ? 'Present' : 'Not found (Clean/Unconfigured)'}`
  );

  lines.push('');
  lines.push('  Admission Status:');
  if (report.admission.admitted) {
    lines.push(`    Status:                 ADMITTED`);
    if (report.admission.remoteFingerprint) {
      lines.push(`    Remote Fingerprint:     ${report.admission.remoteFingerprint}`);
    }
    if (report.admission.couchdbUrl) {
      lines.push(`    CouchDB URL:            ${report.admission.couchdbUrl}`);
    }
    if (report.admission.databaseName) {
      lines.push(`    Database Name:          ${report.admission.databaseName}`);
    }
    if (report.admission.couchdbVersion) {
      lines.push(`    CouchDB Version:        ${report.admission.couchdbVersion}`);
    }
    if (report.admission.settingsHash) {
      lines.push(`    Settings Hash:          ${report.admission.settingsHash}`);
    }
    if (report.admission.admittedAt) {
      lines.push(`    Admitted At:            ${report.admission.admittedAt}`);
    }
  } else {
    lines.push(`    Status:                 NOT ADMITTED`);
  }

  lines.push('');
  lines.push('  Write Grant:');
  if (report.writeGrant.active) {
    lines.push(`    Status:                 ACTIVE`);
    if (report.writeGrant.grantId) {
      lines.push(`    Grant ID:               ${report.writeGrant.grantId}`);
    }
    if (report.writeGrant.bootstrapGeneration) {
      lines.push(`    Bootstrap Gen:          ${report.writeGrant.bootstrapGeneration}`);
    }
    if (report.writeGrant.issuedAt) {
      lines.push(`    Issued At:              ${report.writeGrant.issuedAt}`);
    }
  } else {
    lines.push(`    Status:                 INACTIVE / NOT ARMED`);
  }

  lines.push('');
  lines.push('  Pull Checkpoint:');
  if (report.checkpoint.hasCheckpoint) {
    lines.push(`    Status:                 PRESENT`);
    if (report.checkpoint.lastUpdateSeq) {
      lines.push(`    Last Update Seq:        ${report.checkpoint.lastUpdateSeq}`);
    }
    if (report.checkpoint.completedAt) {
      lines.push(`    Completed At:           ${report.checkpoint.completedAt}`);
    }
  } else {
    lines.push(`    Status:                 NONE`);
  }

  lines.push('');
  lines.push('  Local Statistics:');
  lines.push(`    Tracked Files:          ${report.stats.trackedFilesCount}`);
  lines.push(`    Quarantined Files:      ${report.stats.quarantineFilesCount}`);

  lines.push(divider);
  return lines.join('\n') + '\n';
}

export function formatStatusJson(report: StatusReport): string {
  return JSON.stringify(report) + '\n';
}

export async function runStatusCommand(options: StatusCommandOptions): Promise<number> {
  const redactor = options.redactor ?? defaultRedactor;
  const writeStdout = options.stdout ?? ((msg: string) => process.stdout.write(msg));
  const writeStderr = options.stderr ?? ((msg: string) => process.stderr.write(msg));

  let config;
  try {
    config = await loadConfig(options.configPath, process.env, redactor);
  } catch (err) {
    const errorMsg = (err as Error).message;
    // Diagnostics go to stderr; stdout is reserved for command output/reports.
    writeStderr(`Error loading configuration: ${errorMsg}\n`);
    if (options.json) {
      writeStdout(
        JSON.stringify({
          type: 'status_report',
          outcome: OutcomeCategory.CONFIG_ERROR,
          message: errorMsg,
        }) + '\n'
      );
    }
    return EXIT_CODES.CONFIG_ERROR;
  }

  const databaseExists = fs.existsSync(config.resolvedStatePath);

  if (!databaseExists) {
    const report: StatusReport = {
      type: 'status_report',
      outcome: OutcomeCategory.SUCCESS,
      vaultPath: config.resolvedVaultPath,
      statePath: config.resolvedStatePath,
      databaseExists: false,
      admission: {
        admitted: false,
      },
      writeGrant: {
        active: false,
      },
      checkpoint: {
        hasCheckpoint: false,
      },
      stats: {
        trackedFilesCount: 0,
        quarantineFilesCount: 0,
      },
    };

    const output = options.json ? formatStatusJson(report) : formatStatusHuman(report);
    writeStdout(output);
    return EXIT_CODES.SUCCESS;
  }

  const db = openDatabase(config.resolvedStatePath);
  try {
    const admissionRepo = new AdmissionRepository(db);
    const writeGrantRepo = new WriteGrantRepo(db);
    const checkpointRepo = new CheckpointRepository(db);

    const admission = admissionRepo.getLatest();
    let activeGrant = null;
    let checkpoint = null;

    if (admission) {
      activeGrant = writeGrantRepo.getActiveGrant(
        admission.remoteFingerprint,
        config.resolvedVaultPath
      );
      checkpoint = checkpointRepo.getCheckpoint(admission.remoteFingerprint);
    } else {
      const stmt = db.prepare(
        'SELECT grant_id FROM write_grants WHERE vault_root = ? AND revoked = 0 LIMIT 1'
      );
      const row = stmt.get(config.resolvedVaultPath) as { grant_id: string } | undefined;
      if (row) {
        activeGrant = writeGrantRepo.getGrantById(row.grant_id);
      }
    }

    let trackedFilesCount = 0;
    let quarantineFilesCount = 0;

    try {
      const provRow = db
        .prepare('SELECT COUNT(*) as count FROM file_provenance')
        .get() as { count: number } | undefined;
      trackedFilesCount = provRow?.count ?? 0;
    } catch {
      // Table might not exist or empty
    }

    try {
      const quarRow = db.prepare('SELECT COUNT(*) as count FROM quarantine').get() as
        | { count: number }
        | undefined;
      quarantineFilesCount = quarRow?.count ?? 0;
    } catch {
      // Table might not exist or empty
    }

    const report: StatusReport = {
      type: 'status_report',
      outcome: OutcomeCategory.SUCCESS,
      vaultPath: config.resolvedVaultPath,
      statePath: config.resolvedStatePath,
      databaseExists: true,
      admission: admission
        ? {
            admitted: true,
            remoteFingerprint: admission.remoteFingerprint,
            couchdbUrl: redactor.redactString(admission.couchdbUrl),
            databaseName: admission.databaseName,
            couchdbVersion: admission.couchdbVersion,
            settingsHash: admission.negotiatedSettingsHash,
            admittedAt: admission.admittedAt,
          }
        : {
            admitted: false,
          },
      writeGrant: activeGrant
        ? {
            active: !activeGrant.revoked,
            grantId: activeGrant.grantId,
            bootstrapGeneration: activeGrant.bootstrapGeneration,
            issuedAt: activeGrant.issuedAt,
          }
        : {
            active: false,
          },
      checkpoint: checkpoint
        ? {
            hasCheckpoint: true,
            lastUpdateSeq: checkpoint.lastUpdateSeq,
            completedAt: checkpoint.completedAt,
          }
        : {
            hasCheckpoint: false,
          },
      stats: {
        trackedFilesCount,
        quarantineFilesCount,
      },
    };

    const output = options.json ? formatStatusJson(report) : formatStatusHuman(report);
    writeStdout(output);
    return EXIT_CODES.SUCCESS;
  } finally {
    db.close();
  }
}
