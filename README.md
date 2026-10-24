# obsidian-livesync-headless

[![LiveSync Compatibility](https://img.shields.io/badge/LiveSync%20Compatibility-1.0.23-blue.svg)](https://github.com/vrtmrz/obsidian-livesync/releases/tag/1.0.23)
[![Commonlib](https://img.shields.io/badge/commonlib-0.1.21-blue.svg)](https://www.npmjs.com/package/@vrtmrz/livesync-commonlib)
[![CouchDB Target](https://img.shields.io/badge/CouchDB%20Target-3.5.2-orange.svg)](https://couchdb.apache.org/)
[![Node Version](https://img.shields.io/badge/Node.js-24%20LTS-green.svg)](https://nodejs.org/)
[![Packaging](https://img.shields.io/badge/Packaging-Node%20SEA%20Standalone-purple.svg)](https://nodejs.org/api/single-executable-applications.html)

**obsidian-livesync-headless** is a standalone, single-executable CLI application that synchronizes a local Obsidian vault directory with a Self-hosted LiveSync CouchDB database. It acts as a fully compatible headless LiveSync client for servers, containers, and automated workflows—without requiring the Obsidian desktop/mobile application or runtime GUI dependencies.

---

## Key Features & Safety Guarantees

- **Zero Destructive Remote Operations**: Static AST analysis and runtime HTTP transport guards strictly prohibit destructive CouchDB administrative endpoints (`_compact`, `_purge`, `_view_cleanup`, `_revs_limit`, `_security`, database `DELETE`).
- **Fail-Closed Admission & 5-Tuple Write Grants**: The client starts in read-only mode. Pushing local modifications to CouchDB requires explicit two-phase authorization (`arm`) verifying the exact 5-tuple `(couchdbUrl, databaseName, settingsHash, vaultPath, bootstrapGeneration)`.
- **Preservation-First Data Safety**: Unresolved conflicting leaf revisions are never silently overwritten with CouchDB's deterministic winner. Conflicting documents halt synchronization with `CONFLICT` status. Remote deletions quarantine local files instead of permanently deleting them.
- **Byte-for-Byte Interoperability**: Direct consumption of `@vrtmrz/livesync-commonlib` (0.1.21) guarantees exact compatibility with official Obsidian LiveSync clients across plain markdown, chunked binary files, End-to-End Encryption (E2EE V2 / HKDF), and path obfuscation.
- **Standalone Distribution (Node SEA)**: Distributable as a single executable binary embedding Node 24 runtime, V8 engine, and native SQLite state—runs on target systems without installing Node.js or `node_modules`.
- **Zero-Secret Disclosure**: Passwords, passphrases, and Authorization headers are automatically redacted in CLI outputs, logs, and database records.

---

---

## Installation & Deployment Options

### 1. Docker Container (Recommended for Servers & NAS)

Official minimal multi-arch (`linux/amd64`, `linux/arm64`) container images are published to GitHub Container Registry (`ghcr.io`).

#### Quickstart with Docker CLI

```bash
docker run -d \
  --name obsidian-livesync \
  --restart unless-stopped \
  --user 1000:1000 \
  -v /path/to/my/vault:/vault \
  -v /path/to/livesync-data:/data \
  -e LIVESYNC_COUCHDB_URL="https://couchdb.example.com" \
  -e LIVESYNC_COUCHDB_DATABASE="obsidian-vault" \
  -e LIVESYNC_COUCHDB_USER="sync_user" \
  -e LIVESYNC_COUCHDB_PASSWORD="secure_couchdb_password" \
  -e LIVESYNC_ENCRYPTION_PASSPHRASE="my_e2ee_passphrase" \
  -e LIVESYNC_MODE="auto-arm" \
  ghcr.io/biel-homelab/obsidian-livesync-headless:latest
# Note: /vault mounts the Obsidian vault; /data stores the SQLite state database
```

> **Rootless & Non-Root Execution:**
> The Docker image runs as an unprivileged user (`livesync`, UID/GID `1000:1000`) by default and fully supports rootless Docker, Podman, and custom user IDs via `--user <uid>:<gid>` (e.g. `--user $(id -u):$(id -g)`). Ensure mounted host directories are readable and writable by your host user.

#### Docker Compose Example (`docker-compose.yml`)

```yaml
services:
  livesync:
    image: ghcr.io/biel-homelab/obsidian-livesync-headless:latest
    container_name: obsidian-livesync
    restart: unless-stopped
    user: "1000:1000"                         # Or match your host UID:GID (e.g., "${UID}:${GID}")
    volumes:
      - /path/to/my/vault:/vault              # Obsidian vault directory (bind mount)
      - livesync-state:/data                  # Sync state database will be placed here
    environment:
      - LIVESYNC_COUCHDB_URL=https://couchdb.example.com
      - LIVESYNC_COUCHDB_DATABASE=obsidian-vault
      - LIVESYNC_COUCHDB_USER=sync_user
      - LIVESYNC_COUCHDB_PASSWORD=secure_couchdb_password
      - LIVESYNC_ENCRYPTION_PASSPHRASE=my_e2ee_passphrase
      - LIVESYNC_MODE=auto-arm                # Automatic setup & bidirectional sync

volumes:
  livesync-state:                             # Managed by Docker; survives container recreation
```

> **Auto-Arm Mode (`LIVESYNC_MODE=auto-arm`):**
> When starting fresh (empty vault or state DB) or if local changes exceed 10 files since last sync, auto-arm mode safely pulls remote documents, verifies local file integrity, automatically issues a durable 5-tuple write grant, and transitions directly into continuous bidirectional write mode.
>
> If you prefer manual authorization, set `LIVESYNC_MODE=write` (or omit to run in `read-only` mode) and issue grants manually via:
> ```bash
> docker exec -it obsidian-livesync /usr/local/bin/obsidian-livesync-headless arm
> ```

---

### 2. Standalone Executable (Single-Executable Application)

Compile the application into a standalone binary requiring zero host dependencies:

```bash
# Clone and install dev dependencies
git clone https://github.com/biel-homelab/obsidian-livesync-headless.git
cd obsidian-livesync-headless
npm ci

# Build the Single Executable Application (SEA)
npm run build:sea

# The binary is ready at dist/obsidian-livesync-headless
./dist/obsidian-livesync-headless version
```

### 3. Running from Source with Node.js

```bash
# Build TypeScript
npm run build

# Run via CLI
node dist/cli/index.js --help
```

---

## Configuration & Precedence

`obsidian-livesync-headless` supports flexible configuration with strict precedence:
1. **CLI Flags** (e.g., `--write`, `--periodic-scan-sec`, `--concurrency`)
2. **Environment Variables** (`LIVESYNC_*`)
3. **YAML Configuration File** (`-c, --config <path>`)

When environment variables are provided, the `-c, --config` parameter is optional.

### Environment Variable Reference

| Environment Variable | Config Target | Type / Description | Default / Example |
|---|---|---|---|
| `LIVESYNC_MODE` | `cli.write` | Daemon operation mode: `auto-arm`, `write`, or `read-only` | `read-only` (use `auto-arm` for Docker) |
| `LIVESYNC_COUCHDB_URL` | `remote.url` | Valid HTTP/S CouchDB endpoint URL (credentials forbidden in URL) | `https://couchdb.example.com` |
| `LIVESYNC_COUCHDB_DATABASE` | `remote.database` | CouchDB database name | `obsidian-vault` |
| `LIVESYNC_COUCHDB_USER` | `remote.username` | CouchDB authentication username | `sync_user` |
| `LIVESYNC_COUCHDB_PASSWORD` | `remote.password` | CouchDB authentication password (auto-redacted) | `secretpassword` |
| `LIVESYNC_VAULT_PATH` | `vault.path` | Local filesystem vault path | `/vault` (in Docker) |
| `LIVESYNC_VAULT_DEDICATED` | `vault.dedicated` | Boolean (`true`/`1` or `false`/`0`) indicating dedicated folder | `false` |
| `LIVESYNC_STATE_PATH` | `state.path` | Local SQLite state database path | `~/.config/obsidian-livesync-headless/state.db` |
| `LIVESYNC_ENCRYPTION_PASSPHRASE` | `encryption.passphrase` | E2EE encryption passphrase (auto-redacted) | `my-e2ee-pass` |
| `LIVESYNC_ENCRYPTION_ENABLED` | `encryption.enabled` | Enable/disable E2EE (defaults to `true` if passphrase set) | `false` |
| `LIVESYNC_PERIODIC_SCAN_SEC` | `cli.periodicScanSec` | Interval in seconds for full reconciliation scan | `300` |
| `LIVESYNC_CONCURRENCY` | `cli.concurrency` | Maximum concurrent file workers | `4` |
| `LIVESYNC_DEBOUNCE_MS` | `cli.debounceMs` | Watcher debounce window in milliseconds | `300` |

---

## Configuration File (YAML)

Configuration is defined in a YAML file (e.g., `livesync.yaml`). Secrets such as the CouchDB password and encryption passphrase can be supplied as inline strings, referenced from environment variables, or loaded from dedicated secret files.

### Configuration Example (`livesync.yaml`)

```yaml
# CouchDB Remote Database Configuration
remote:
  url: "https://couchdb.example.com"
  database: "obsidian-vault"
  username: "obsidian_sync_user"
  password:
    fromEnv: "LIVESYNC_COUCHDB_PASSWORD"     # Or: { fromFile: "/run/secrets/couchdb_password" }

# Local Obsidian Vault Configuration
vault:
  path: "/home/user/notes"
  dedicated: false                  # Set to true if folder is dedicated solely to LiveSync

# Local Durable SQLite State Path (optional, defaults to ~/.config/obsidian-livesync-headless/state.db)
state:
  path: "/home/user/.config/obsidian-livesync-headless/state.db"

# End-to-End Encryption (E2EE) Configuration (must match remote vault settings)
encryption:
  enabled: true
  passphrase:
    fromEnv: "LIVESYNC_ENCRYPTION_PASSPHRASE"  # Or: { fromFile: "/run/secrets/livesync_passphrase" }
```

### Secret Resolution Schema

| Secret Type | Example Syntax | Behavior |
|---|---|---|
| **Environment Variable** | `password: { fromEnv: "LIVESYNC_COUCHDB_PASSWORD" }` | Reads `process.env.LIVESYNC_COUCHDB_PASSWORD` at runtime. |
| **Secret File** | `passphrase: { fromFile: "/secrets/e2ee.key" }` | Reads and trims content from `/secrets/e2ee.key`. |
| **Inline String** | `password: "my-secret-password"` | Plain string (discouraged for version-controlled configs). |

---

## CLI Command Reference

```
obsidian-livesync-headless [command] [options]
```

### 1. `inspect` — Guarded Remote Admission

Performs fail-closed read-only inspection of remote CouchDB settings, PBKDF2 salt, and compatibility parameters. Records a validated admission record in local SQLite.

```bash
obsidian-livesync-headless inspect --config livesync.yaml
```

Output includes CouchDB version, LiveSync configuration hash, encryption parameters, and admission status.

---

### 2. `pull` — Materialize Remote Content

Downloads and materializes verified remote files into the local vault. Supports chunk reassembly, E2EE decryption, path de-obfuscation, and hash validation.

```bash
# Preview changes without modifying local files
obsidian-livesync-headless pull --config livesync.yaml --dry-run

# Materialize remote files
obsidian-livesync-headless pull --config livesync.yaml
```

---

### 3. `arm` — Authorize / Revoke Write Operations

Issues a durable 5-tuple write grant authorizing local modifications to be pushed to CouchDB. Required before running `sync` or `daemon --write`.

```bash
# Grant write authorization
obsidian-livesync-headless arm --config livesync.yaml

# Revoke active write authorization (returns vault to read-only safety)
obsidian-livesync-headless arm --config livesync.yaml --revoke
```

---

### 4. `sync` — Bidirectional Synchronization

Executes one-shot bidirectional convergence:
1. Reconciles local filesystem additions, edits, and deletions.
2. Performs chunk-first remote upload (storing chunks before document metadata).
3. Pulls remote updates and moves remote deletions to local quarantine.
4. Detects open conflict revisions and halts fail-closed if ambiguous branches exist.

```bash
# Preview bidirectional synchronization
obsidian-livesync-headless sync --config livesync.yaml --dry-run

# Execute one-shot bidirectional sync
obsidian-livesync-headless sync --config livesync.yaml
```

---

### 5. `daemon` — Continuous Convergence Daemon

Runs continuously in the background, listening to CouchDB `_changes` feeds and local filesystem events (via Chokidar).

```bash
# Run with automatic setup, sync validation, and continuous write mode (recommended)
obsidian-livesync-headless daemon --config livesync.yaml --auto-arm

# Run continuous pull-only daemon (safe default)
obsidian-livesync-headless daemon --config livesync.yaml

# Run continuous bidirectional sync daemon (requires existing active write grant)
obsidian-livesync-headless daemon --config livesync.yaml --write

# Custom tuning options
obsidian-livesync-headless daemon --config livesync.yaml \
  --auto-arm \
  --debounce-ms 500 \
  --periodic-scan-sec 600 \
  --concurrency 8
```

---

### 6. `status` — Offline Vault Health & State Inspection

Inspects local SQLite state (`state.db`) without making remote network calls. Reports admission status, write grant validity, pull checkpoints, tracked file count, and quarantine count.

```bash
# Human-readable table
obsidian-livesync-headless status --config livesync.yaml

# Structured JSON Lines output
obsidian-livesync-headless status --config livesync.yaml --json
```

---

### 7. `version` — Build & Compatibility Identity

Outputs exact build metadata, pinned LiveSync version, Commonlib version, target CouchDB version, dependency overrides, and runtime SEA status.

```bash
# Human-readable identity banner
obsidian-livesync-headless version

# JSON output
obsidian-livesync-headless version --json
```

---

## Global Options

| Option | Short | Description |
|---|---|---|
| `-c, --config <path>` | `-c` | Path to YAML configuration file (required for sync commands). |
| `--auto-arm` | | Automatically clean, pull, validate, and issue write grant before running daemon. |
| `--write` | | Enable bidirectional write mode in `daemon` (requires active write grant). |
| `--dry-run` | | Preview synchronization operations without modifying files or remote. |
| `--json` | | Output structured JSON Lines events instead of human formatting. |
| `--revoke` | | Revoke active write grant when running `arm`. |
| `--debounce-ms <n>` | | Filesystem watcher debounce window in milliseconds (default: `300`). |
| `--periodic-scan-sec <n>` | | Periodic full reconciliation scan interval in seconds (default: `300`). |
| `--concurrency <n>` | | Concurrent file processing workers (default: `4`). |
| `-h, --help` | `-h` | Display help information. |
| `-v, --version` | `-v` | Display version and build identity. |

---

## Production Deployment

### Systemd Service (Headless Sync Daemon)

Create `/etc/systemd/system/obsidian-livesync.service`:

```ini
[Unit]
Description=Obsidian LiveSync Headless Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=syncuser
Group=syncuser
Environment="LIVESYNC_COUCHDB_PASSWORD=your_secure_password"
Environment="LIVESYNC_ENCRYPTION_PASSPHRASE=your_encryption_passphrase"
ExecStart=/usr/local/bin/obsidian-livesync-headless daemon --config /etc/obsidian-livesync/livesync.yaml --write
Restart=on-failure
RestartSec=10s

# Hardening
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/home/syncuser/vault /home/syncuser/.config/obsidian-livesync-headless

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now obsidian-livesync
```

---

## Architecture & Compatibility Stack

```
┌─────────────────────────────────────────────────────────────┐
│                 Obsidian LiveSync Remote                    │
│           (Apache CouchDB 3.5.2 / PouchDB HTTP)             │
└──────────────────────────────▲──────────────────────────────┘
                               │
               Guarded Transport Layer
           (TransportGuard / ArmedTransportGuard)
                               │
┌──────────────────────────────┴──────────────────────────────┐
│              obsidian-livesync-headless                     │
│                                                             │
│  ┌─────────────────────────┐   ┌─────────────────────────┐  │
│  │     @vrtmrz/commonlib   │   │     Local SQLite DB     │  │
│  │   (v0.1.21 / E2EE V2)   │   │  (Admission, Grants,    │  │
│  │ (Chunking & Obfuscation)│   │   Provenance, Registry) │  │
│  └─────────────────────────┘   └─────────────────────────┘  │
│                                                             │
│  ┌─────────────────────────┐   ┌─────────────────────────┐  │
│  │    Filesystem Watcher   │   │    Conflict & Deletion  │  │
│  │  (Chokidar + Scans)     │   │    Quarantine Manager   │  │
│  └─────────────────────────┘   └─────────────────────────┘  │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                    Local Obsidian Vault                     │
│                  (/path/to/vault/markdown)                  │
└─────────────────────────────────────────────────────────────┘
```

### Pinned Compatibility Anchor

| Component | Pinned Version | Purpose |
|---|---|---|
| **Self-hosted LiveSync** | `1.0.23` | De-facto protocol & database compatibility standard |
| **@vrtmrz/livesync-commonlib** | `0.1.21` exact | Chunking, E2EE V2 HKDF cryptography, obfuscation, serialization |
| **PouchDB Protocol Packages** | `9.0.0` | Modular PouchDB adapters & change streams |
| **Dependency Overrides** | `uuid: 11.1.1` | Pinned override on `pouchdb-core` and `pouchdb-utils` |
| **Target CouchDB** | `3.5.2` | Primary server integration baseline |
| **Runtime & Packaging** | Node `24.20.0` LTS | Node Single-Executable Application (SEA) + embedded SQLite |

---

## Verification & Testing

The test suite validates unit logic, packaging, static security rules, and real CouchDB 3.5.2 interoperability:

```bash
# Run unit tests
npm run test:unit

# Run static release safety auditor (0 destructive endpoints, 0 leaked secrets)
npm run audit:release

# Build standalone SEA binary
npm run build:sea

# Run standalone binary tests in isolated environment
npx vitest run tests/integration/packaged-binary.test.ts

# Run mixed-client interoperability tests with Testcontainers CouchDB 3.5.2
npx vitest run tests/integration/mixed-client-interop.test.ts
```

---

## License

MIT License. See [LICENSE](./LICENSE) for details.
