import {
  AuthenticationRequiredError,
  fetchDocumentIfExists,
  type CouchDbDocument,
} from './inspector.js';
import { isReservedChunkId } from './decode-adapter.js';

export function createChunkFetcher(
  guardedFetch: typeof globalThis.fetch,
  baseUrl: URL,
  databaseName: string,
  authHeader?: string
): (id: string) => Promise<CouchDbDocument | null> {
  return (id) => fetchDocumentIfExists<CouchDbDocument>(guardedFetch, baseUrl, databaseName, id, authHeader);
}

/**
 * Cache-first variant of {@link createChunkFetcher} built from an inventory
 * result. Chunk documents already carry their bodies when inventory was
 * collected with `include_docs=true`, so the overwhelming majority of chunk
 * reads are served from the in-memory cache; only cache misses fall back to a
 * single-document GET (which then populates the cache).
 */
export function createCachedChunkFetcher(
  guardedFetch: typeof globalThis.fetch,
  baseUrl: URL,
  databaseName: string,
  authHeader: string | undefined,
  chunkCache: Map<string, CouchDbDocument>
): (id: string) => Promise<CouchDbDocument | null> {
  return async (id) => {
    const cached = chunkCache.get(id);
    if (cached !== undefined) {
      return cached;
    }
    const document = await fetchDocumentIfExists<CouchDbDocument>(
      guardedFetch,
      baseUrl,
      databaseName,
      id,
      authHeader
    );
    if (document) {
      chunkCache.set(id, document);
    }
    return document;
  };
}

/**
 * Extract the chunk-id → document cache from an inventory result produced by
 * {@link inventoryRemoteDocuments} (which emits chunk documents with bodies).
 */
export function buildChunkCacheFromInventory(
  inventory: readonly InventoriedDocument[]
): Map<string, CouchDbDocument> {
  const cache = new Map<string, CouchDbDocument>();
  for (const item of inventory) {
    if (item.kind === 'chunk' && item.document) {
      cache.set(item.id, item.document);
    }
  }
  return cache;
}

const ALL_DOCS_PAGE_SIZE = 100;

export interface InventoryCredentials {
  readonly username?: string;
  readonly password?: string;
}

export type InventoriedDocument =
  | { kind: 'chunk'; id: string; document: CouchDbDocument }
  | { kind: 'tombstone'; id: string; rev: string }
  | { kind: 'document'; id: string; rev: string; document: CouchDbDocument };

interface AllDocsRow {
  readonly id?: string;
  readonly value?: {
    readonly rev?: string;
    readonly deleted?: boolean;
  };
  readonly doc?: CouchDbDocument;
}

interface ChangesRow {
  readonly seq?: string | number;
  readonly id?: string;
  readonly deleted?: boolean;
  readonly changes?: readonly { readonly rev?: string }[];
  readonly doc?: CouchDbDocument;
}

interface CollectContext {
  readonly guardedFetch: typeof globalThis.fetch;
  readonly baseUrl: URL;
  readonly databaseName: string;
  readonly authHeader: string | undefined;
  readonly collected: InventoriedDocument[];
}

/**
 * Classify a page of CouchDB rows into inventoried documents. Shared by the
 * `_all_docs` full-inventory paging and the `_changes?since=...` incremental
 * paging so both document sources produce identical observations downstream
 * (Phase 3 data-safety constraint: only the source differs, never the
 * classification, decode, or planning semantics).
 */
async function collectRowsInto(rows: readonly AllDocsRow[], ctx: CollectContext): Promise<void> {
  for (const row of rows) {
    if (!row.id) {
      continue;
    }

    if (isReservedChunkId(row.id)) {
      // Chunk bodies arrived with the page (include_docs=true); keep them so
      // downstream assembly can be served from the in-memory chunk cache.
      if (row.doc) {
        ctx.collected.push({ kind: 'chunk', id: row.id, document: row.doc });
      }
      continue;
    }

    const rev = row.value?.rev ?? '';
    if (row.value?.deleted) {
      ctx.collected.push({ kind: 'tombstone', id: row.id, rev });
      continue;
    }

    const doc = row.doc;
    if (!doc) {
      // Without a body we cannot classify the row; keep the historical
      // fail-closed fallback to a per-doc conflict-leaf fetch.
      const leaves = await fetchNoteLeaves(
        ctx.guardedFetch,
        ctx.baseUrl,
        ctx.databaseName,
        row.id,
        ctx.authHeader
      );

      if (!leaves || leaves.length === 0) {
        ctx.collected.push({ kind: 'tombstone', id: row.id, rev });
        continue;
      }

      for (const leaf of leaves) {
        if (leaf._deleted === true) {
          ctx.collected.push({ kind: 'tombstone', id: row.id, rev: leaf._rev });
          continue;
        }
        ctx.collected.push({ kind: 'document', id: row.id, rev: leaf._rev, document: leaf });
      }
      continue;
    }

    // The winning body is already present. Only conflicted documents need
    // the extra per-rev leaf fetches; non-conflicted notes are done.
    const conflictRevs = conflictRevsFrom(doc);
    const leaves: CouchDbDocument[] = [doc];
    for (const rev of conflictRevs) {
      const leaf = await fetchDocumentIfExists<CouchDbDocument>(
        ctx.guardedFetch,
        ctx.baseUrl,
        ctx.databaseName,
        row.id,
        ctx.authHeader,
        { rev }
      );
      if (leaf) {
        leaves.push(leaf);
      }
    }

    for (const leaf of leaves) {
      if (leaf._deleted === true) {
        ctx.collected.push({ kind: 'tombstone', id: row.id, rev: leaf._rev });
        continue;
      }
      ctx.collected.push({ kind: 'document', id: row.id, rev: leaf._rev, document: leaf });
    }
  }
}

function buildAuthHeader(credentials?: InventoryCredentials): string | undefined {
  if (credentials?.username || credentials?.password) {
    const raw = `${credentials.username ?? ''}:${credentials.password ?? ''}`;
    return `Basic ${Buffer.from(raw).toString('base64')}`;
  }
  return undefined;
}

function conflictRevsFrom(document: CouchDbDocument): string[] {
  const raw = document._conflicts;
  if (!Array.isArray(raw)) {
    return [];
  }
  return raw.filter((rev): rev is string => typeof rev === 'string' && rev.length > 0);
}

async function fetchNoteLeaves(
  guardedFetch: typeof globalThis.fetch,
  baseUrl: URL,
  databaseName: string,
  docId: string,
  authHeader: string | undefined
): Promise<CouchDbDocument[] | null> {
  const [conflictsKey, conflictsValue] = 'conflicts=true'.split('=') as [string, string];
  const document = await fetchDocumentIfExists<CouchDbDocument>(
    guardedFetch,
    baseUrl,
    databaseName,
    docId,
    authHeader,
    { [conflictsKey]: conflictsValue }
  );
  if (!document) {
    return null;
  }

  const leaves: CouchDbDocument[] = [document];
  for (const rev of conflictRevsFrom(document)) {
    const leaf = await fetchDocumentIfExists<CouchDbDocument>(
      guardedFetch,
      baseUrl,
      databaseName,
      docId,
      authHeader,
      { rev }
    );
    if (leaf) {
      leaves.push(leaf);
    }
  }
  return leaves;
}

export async function inventoryRemoteDocuments(
  guardedFetch: typeof globalThis.fetch,
  baseUrl: URL,
  databaseName: string,
  credentials?: InventoryCredentials
): Promise<InventoriedDocument[]> {
  const authHeader = buildAuthHeader(credentials);
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (authHeader) {
    headers.Authorization = authHeader;
  }

  const collected: InventoriedDocument[] = [];
  const ctx: CollectContext = {
    guardedFetch,
    baseUrl,
    databaseName,
    authHeader,
    collected,
  };
  let startKey: string | undefined;
  let startKeyDocId: string | undefined;

  for (;;) {
    const allDocsUrl = new URL(`/${encodeURIComponent(databaseName)}/_all_docs`, baseUrl);
    allDocsUrl.searchParams.set('limit', String(ALL_DOCS_PAGE_SIZE));
    allDocsUrl.searchParams.set('include_docs', 'true');
    allDocsUrl.searchParams.set('conflicts', 'true');
    if (startKey !== undefined) {
      allDocsUrl.searchParams.set('startkey', JSON.stringify(startKey));
      if (startKeyDocId !== undefined) {
        // `startkey_docid` pins the resume position among rows sharing the same
        // key, preventing O(n²) re-scans. CouchDB returns the boundary row
        // itself again, so `skip=1` drops exactly that one repeated row.
        allDocsUrl.searchParams.set('startkey_docid', JSON.stringify(startKeyDocId));
        allDocsUrl.searchParams.set('skip', '1');
      }
    }

    const response = await guardedFetch(allDocsUrl.toString(), {
      method: 'GET',
      headers,
    });

    if (response.status === 401 || response.status === 403) {
      throw new AuthenticationRequiredError(
        response.status,
        `Access denied listing documents in '${databaseName}'.`
      );
    }

    if (!response.ok) {
      throw new Error(
        `Failed to list documents in '${databaseName}': HTTP ${response.status} ${response.statusText}`
      );
    }

    const body = (await response.json()) as { rows?: AllDocsRow[] };
    const rows = Array.isArray(body.rows) ? body.rows : [];
    if (rows.length === 0) {
      break;
    }

    await collectRowsInto(rows, ctx);

    if (rows.length < ALL_DOCS_PAGE_SIZE) {
      break;
    }

    const lastRow = rows[rows.length - 1];
    const lastId = lastRow?.id;
    if (!lastId || (lastId === startKey && lastId === startKeyDocId)) {
      break;
    }
    startKey = lastId;
    startKeyDocId = lastId;
  }

  return collected;
}

const CHANGES_PAGE_SIZE = 100;

export interface IncrementalChangesResult {
  /** Classified changed documents, identical in shape to the full inventory. */
  readonly collected: InventoriedDocument[];
  /**
   * The last update sequence consumed by this query. Persist verbatim — the
   * `since` token is opaque and meaningful only for this database. Only pass
   * this to the checkpoint after the corresponding apply commits.
   */
  readonly lastSeq: string;
}

/**
 * Fetch only the documents changed since `since` via paged
 * `GET /{db}/_changes?since=...&style=all_docs&include_docs=true&conflicts=true`.
 *
 * The result feeds the exact same classification/observation path as
 * {@link inventoryRemoteDocuments}; only the document source differs. Rows the
 * remote reports as `deleted: true` are emitted as tombstones, matching the
 * full-inventory handling of `_deleted` rows.
 *
 * Throws on HTTP failure (including 400 for a bad/unknown `since` token) so
 * the caller can fall back to a full inventory — the token is opaque and this
 * function never guesses whether it is still valid.
 */
export async function inventoryChangedDocuments(
  guardedFetch: typeof globalThis.fetch,
  baseUrl: URL,
  databaseName: string,
  since: string,
  credentials?: InventoryCredentials
): Promise<IncrementalChangesResult> {
  const authHeader = buildAuthHeader(credentials);
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (authHeader) {
    headers.Authorization = authHeader;
  }

  const collected: InventoriedDocument[] = [];
  const ctx: CollectContext = {
    guardedFetch,
    baseUrl,
    databaseName,
    authHeader,
    collected,
  };

  let cursor = since;
  let lastSeq = since;

  for (;;) {
    const changesUrl = new URL(`/${encodeURIComponent(databaseName)}/_changes`, baseUrl);
    changesUrl.searchParams.set('since', cursor);
    changesUrl.searchParams.set('style', 'all_docs');
    changesUrl.searchParams.set('include_docs', 'true');
    changesUrl.searchParams.set('conflicts', 'true');
    changesUrl.searchParams.set('limit', String(CHANGES_PAGE_SIZE));

    const response = await guardedFetch(changesUrl.toString(), {
      method: 'GET',
      headers,
    });

    if (response.status === 401 || response.status === 403) {
      throw new AuthenticationRequiredError(
        response.status,
        `Access denied reading changes in '${databaseName}'.`
      );
    }

    if (!response.ok) {
      throw new Error(
        `Failed to read changes in '${databaseName}' since '${since}': HTTP ${response.status} ${response.statusText}`
      );
    }

    const body = (await response.json()) as {
      results?: ChangesRow[];
      last_seq?: string | number;
    };
    const rows = Array.isArray(body.results) ? body.results : [];

    // Normalize `_changes` rows into the shared row shape so classification is
    // byte-identical with the `_all_docs` path. The winning rev comes from
    // `changes[0].rev` (`style=all_docs` lists every leaf; the first entry is
    // the winning branch, matching how `_all_docs` exposes `value.rev`).
    const normalized: AllDocsRow[] = rows.map((row) => ({
      id: row.id,
      value: {
        rev: row.changes?.[0]?.rev ?? '',
        deleted: Boolean(row.deleted),
      },
      doc: row.doc,
    }));

    await collectRowsInto(normalized, ctx);

    // The `since` token is opaque and database-specific: persist it verbatim.
    //
    // Paging cursor: use the seq of the LAST CONSUMED ROW, never `last_seq`,
    // while pages remain full — CouchDB's `last_seq` semantics with `limit`
    // must never cause a skipped page. On the final (short) page the feed is
    // exhausted, so `last_seq` (the database's current position, >= last row's
    // seq) is safe and lets an empty pass still advance the checkpoint.
    const lastRowSeq =
      rows.length > 0 && rows[rows.length - 1]?.seq !== undefined
        ? String(rows[rows.length - 1]!.seq)
        : undefined;
    const endSeq =
      body.last_seq !== undefined ? String(body.last_seq) : lastRowSeq ?? cursor;

    if (rows.length < CHANGES_PAGE_SIZE) {
      lastSeq = endSeq;
      break;
    }

    if (lastRowSeq === undefined || lastRowSeq === cursor) {
      // No forward progress possible; avoid an infinite loop.
      lastSeq = endSeq;
      break;
    }
    lastSeq = lastRowSeq;
    cursor = lastRowSeq;
  }

  return { collected, lastSeq };
}
