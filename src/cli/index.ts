import { parseArgs } from 'node:util';
import { logger } from '../diagnostics/logger.js';
import { EXIT_CODES } from '../diagnostics/outcomes.js';
import { defaultRedactor } from '../security/redaction.js';
import {
  getBuildIdentity,
  formatIdentityHuman,
  formatIdentityJson,
} from '../diagnostics/identity.js';
import { runInspectCommand } from './commands/inspect.js';
import { runPullCommand } from './commands/pull.js';
import { runArmCommand } from './commands/arm.js';
import { runSyncCommand } from './commands/sync.js';
import { runDaemonCommand } from './commands/daemon.js';
import { runStatusCommand } from './commands/status.js';

// Suppress experimental node:sqlite notices
const originalEmitWarning = process.emitWarning;
process.emitWarning = ((warning: string | Error, ...args: any[]) => {
  if (typeof warning === 'string' && warning.includes('SQLite')) {
    return;
  }
  if (
    typeof warning === 'object' &&
    warning !== null &&
    'message' in warning &&
    typeof (warning as { message?: unknown }).message === 'string' &&
    (warning as { message: string }).message.includes('SQLite')
  ) {
    return;
  }
  return (originalEmitWarning as any).call(process, warning, ...args);
}) as typeof process.emitWarning;

process.on('warning', (warning) => {
  if (warning.name === 'ExperimentalWarning' && warning.message.includes('SQLite')) {
    return;
  }
});

export interface CliOptions {
  config?: string;
  json: boolean;
  dryRun: boolean;
  revoke: boolean;
  write: boolean;
  autoArm: boolean;
  periodicScanSec?: number;
  concurrency?: number;
  debounceMs?: number;
  help: boolean;
  version: boolean;
}

export interface CliParsed {
  command?: string;
  options: CliOptions;
}

export const CLI_HELP = `obsidian-livesync-headless [command] [options]

Commands:
  inspect                     Safely inspect and negotiate compatibility with CouchDB
  pull                        Materialize verified remote LiveSync files into a vault
  arm                         Issue or revoke durable 5-tuple write grant for vault & remote
  sync                        Bidirectional synchronization with chunk-first push and guard
  daemon                      Continuous unattended convergence daemon
  status                      Inspect local vault state, write grants, and pull checkpoints
  version                     Show build and compatibility identity

Options:
  -c, --config <path>         Path to YAML configuration file (optional when environment variables are set)
      --write                 Enable bidirectional synchronization in daemon mode (requires active write grant)
      --auto-arm              Enable auto-arm mode (clean/pull/validate/arm automatically before daemon write)
      --periodic-scan-sec <n> Periodic full reconciliation interval in seconds (default: 300)
      --concurrency <n>       Max concurrent file workers (default: 4)
      --debounce-ms <n>       Local filesystem watcher debounce window in ms (default: 300)
      --json                  Output structured JSON Lines report
      --dry-run               Preview synchronization actions without mutation
      --revoke                Revoke active write grant for the vault (arm command)
  -h, --help                  Show help and usage information
  -v, --version               Show version and compatibility information
`;

export const VERSION = '0.5.0';

export function parseCliArgs(args: string[] = process.argv.slice(2)): {
  command?: string;
  options: CliOptions;
} {
  const { values, positionals } = parseArgs({
    args,
    options: {
      config: {
        type: 'string',
        short: 'c',
      },
      write: {
        type: 'boolean',
        default: false,
      },
      'auto-arm': {
        type: 'boolean',
        default: false,
      },
      'periodic-scan-sec': {
        type: 'string',
      },
      concurrency: {
        type: 'string',
      },
      'debounce-ms': {
        type: 'string',
      },
      json: {
        type: 'boolean',
        default: false,
      },
      'dry-run': {
        type: 'boolean',
        default: false,
      },
      revoke: {
        type: 'boolean',
        default: false,
      },
      help: {
        type: 'boolean',
        short: 'h',
        default: false,
      },
      version: {
        type: 'boolean',
        short: 'v',
        default: false,
      },
    },
    allowPositionals: true,
  });

  return {
    command: positionals[0],
    options: {
      config: values.config,
      write: values.write ?? false,
      autoArm: values['auto-arm'] ?? false,
      periodicScanSec: values['periodic-scan-sec']
        ? parseInt(values['periodic-scan-sec'], 10)
        : undefined,
      concurrency: values.concurrency ? parseInt(values.concurrency, 10) : undefined,
      debounceMs: values['debounce-ms'] ? parseInt(values['debounce-ms'], 10) : undefined,
      json: values.json ?? false,
      dryRun: values['dry-run'] ?? false,
      revoke: values.revoke ?? false,
      help: values.help ?? false,
      version: values.version ?? false,
    },
  };
}

export async function main(args: string[] = process.argv.slice(2)): Promise<number> {
  try {
    const parsed = parseCliArgs(args);

    if (parsed.command === 'version' || parsed.options.version) {
      const identity = getBuildIdentity();
      if (parsed.options.json) {
        process.stdout.write(formatIdentityJson(identity));
      } else {
        process.stdout.write(formatIdentityHuman(identity));
      }
      return EXIT_CODES.SUCCESS;
    }

    const hasEnvConfig = Boolean(
      process.env.LIVESYNC_COUCHDB_URL ||
        process.env.LIVESYNC_VAULT_PATH
    );

    if (
      parsed.options.help ||
      (args.length === 0 && !parsed.command && !parsed.options.config && !hasEnvConfig)
    ) {
      process.stdout.write(CLI_HELP);
      return EXIT_CODES.SUCCESS;
    }

    logger.debug('CLI arguments parsed', {
      command: parsed.command,
      hasConfig: Boolean(parsed.options.config),
      json: parsed.options.json,
    });

    if (parsed.command === 'status') {
      return await runStatusCommand({
        configPath: parsed.options.config,
        json: parsed.options.json,
      });
    }

    if (parsed.command === 'daemon') {
      return await runDaemonCommand({
        configPath: parsed.options.config,
        write: parsed.options.autoArm ? 'auto-arm' : parsed.options.write,
        autoArm: parsed.options.autoArm,
        periodicScanSec: parsed.options.periodicScanSec,
        concurrency: parsed.options.concurrency,
        debounceMs: parsed.options.debounceMs,
        json: parsed.options.json,
      });
    }

    if (parsed.command === 'arm') {
      return await runArmCommand({
        configPath: parsed.options.config,
        json: parsed.options.json,
        revoke: parsed.options.revoke,
      });
    }

    if (parsed.command === 'sync') {
      return await runSyncCommand({
        configPath: parsed.options.config,
        dryRun: parsed.options.dryRun,
        json: parsed.options.json,
      });
    }

    const isPull = parsed.command === 'pull';
    if (isPull) {
      return await runPullCommand({
        configPath: parsed.options.config,
        json: parsed.options.json,
        dryRun: parsed.options.dryRun,
      });
    }

    const isInspect = !parsed.command || parsed.command === 'inspect';
    if (isInspect) {
      return await runInspectCommand({
        configPath: parsed.options.config,
        json: parsed.options.json,
      });
    }

    logger.error(`Unknown command '${parsed.command}'`);
    process.stdout.write(CLI_HELP);
    return EXIT_CODES.CONFIG_ERROR;
  } catch (error) {
    const sanitizedError = defaultRedactor.redactError(error as Error);
    logger.error('Unhandled CLI execution error', { error: sanitizedError.message });
    return EXIT_CODES.CONFIG_ERROR;
  }
}

// Direct execution entrypoint
if (
  process.argv[1] &&
  (process.argv[1].endsWith('/cli/index.js') || process.argv[1].endsWith('/cli/index.ts'))
) {
  main().then((exitCode) => {
    process.exit(exitCode);
  });
}
