export interface BuildIdentity {
  readonly name: 'obsidian-livesync-headless';
  readonly version: string;
  readonly liveSyncCompatibility: string;
  readonly commonlibVersion: string;
  readonly targetCouchDbVersion: string;
  readonly gitCommit: string;
  readonly buildTimestamp: string;
  readonly dependencyOverrides: {
    readonly 'pouchdb-core': { readonly uuid: string };
    readonly 'pouchdb-utils': { readonly uuid: string };
  };
  readonly runtime: {
    readonly nodeVersion: string;
    readonly platform: string;
    readonly arch: string;
    readonly sea: boolean;
  };
}

function detectSea(): boolean {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const sea = require('node:sea');
    if (typeof sea?.isSea === 'function') {
      return Boolean(sea.isSea());
    }
  } catch {
    // Fall back to process.isSea if available
  }
  return Boolean((process as unknown as { isSea?: () => boolean }).isSea?.());
}

export function getBuildIdentity(): BuildIdentity {
  return {
    name: 'obsidian-livesync-headless',
    version: '0.5.0',
    liveSyncCompatibility: '1.0.23',
    commonlibVersion: '0.1.21',
    targetCouchDbVersion: '3.5.2',
    gitCommit: process.env.GIT_COMMIT || 'release',
    buildTimestamp: process.env.BUILD_TIMESTAMP || '2026-09-06T00:00:00.000Z',
    dependencyOverrides: {
      'pouchdb-core': { uuid: '11.1.1' },
      'pouchdb-utils': { uuid: '11.1.1' },
    },
    runtime: {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      sea: detectSea(),
    },
  };
}

export function formatIdentityHuman(identity: BuildIdentity): string {
  const lines: string[] = [];
  const divider = '─'.repeat(70);

  lines.push(divider);
  lines.push(`  OBSIDIAN LIVESYNC HEADLESS — BUILD & COMPATIBILITY IDENTITY`);
  lines.push(divider);
  lines.push(`  Client Version:           v${identity.version}`);
  lines.push(`  LiveSync Compatibility:   ${identity.liveSyncCompatibility}`);
  lines.push(`  Commonlib Version:        ${identity.commonlibVersion}`);
  lines.push(`  Target CouchDB:           ${identity.targetCouchDbVersion}`);
  lines.push(`  Git Commit:               ${identity.gitCommit}`);
  lines.push(`  Build Timestamp:          ${identity.buildTimestamp}`);
  lines.push(
    `  Runtime:                  Node ${identity.runtime.nodeVersion} (${identity.runtime.platform} ${identity.runtime.arch}, SEA=${identity.runtime.sea})`
  );
  lines.push(`  Dependency Overrides:`);
  lines.push(`    • pouchdb-core -> uuid: ${identity.dependencyOverrides['pouchdb-core'].uuid}`);
  lines.push(`    • pouchdb-utils -> uuid: ${identity.dependencyOverrides['pouchdb-utils'].uuid}`);
  lines.push(divider);

  return lines.join('\n') + '\n';
}

export function formatIdentityJson(identity: BuildIdentity): string {
  return JSON.stringify({ type: 'version_identity', ...identity }) + '\n';
}
