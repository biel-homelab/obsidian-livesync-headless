import { describe, it, expect, vi } from 'vitest';
import {
  inventoryRemoteDocuments,
  inventoryChangedDocuments,
  createCachedChunkFetcher,
  buildChunkCacheFromInventory,
} from '../../src/livesync/inventory.js';
import { AuthenticationRequiredError } from '../../src/livesync/inspector.js';
import type { CouchDbDocument } from '../../src/livesync/inspector.js';

const baseUrl = new URL('http://127.0.0.1:5984');
const databaseName = 'testdb';

interface MockRow {
  id: string;
  key: string;
  value: { rev: string; deleted?: boolean };
  doc?: CouchDbDocument | null;
}

function allDocsResponse(rows: MockRow[], totalRows = rows.length): Response {
  return new Response(
    JSON.stringify({ total_rows: totalRows, offset: 0, rows }),
    { status: 200, headers: { 'content-type': 'application/json' } }
  );
}

function docRow(doc: CouchDbDocument, deleted = false): MockRow {
  return {
    id: doc._id,
    key: doc._id,
    value: { rev: doc._rev, ...(deleted ? { deleted: true } : {}) },
    doc,
  };
}

function chunkDoc(id: string, data: string): CouchDbDocument {
  return { _id: id, _rev: '1-chunkrev', type: 'leaf', data } as CouchDbDocument;
}

function noteDoc(id: string, data: string): CouchDbDocument {
  return {
    _id: id,
    _rev: '1-noterev',
    type: 'plain',
    path: id,
    data,
    size: new TextEncoder().encode(data).byteLength,
    deleted: false,
    mtime: 1000,
  } as CouchDbDocument;
}

describe('inventoryRemoteDocuments (Unit)', () => {
  it('requests include_docs=true and conflicts=true on _all_docs paging', async () => {
    const requests: string[] = [];
    const mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      const urlStr = input.toString();
      requests.push(urlStr);
      return allDocsResponse([docRow(noteDoc('NoteA.md', 'alpha'))]);
    });

    await inventoryRemoteDocuments(mockFetch as unknown as typeof globalThis.fetch, baseUrl, databaseName);

    expect(requests.length).toBe(1);
    const url = new URL(requests[0]);
    expect(url.pathname).toBe(`/${databaseName}/_all_docs`);
    expect(url.searchParams.get('include_docs')).toBe('true');
    expect(url.searchParams.get('conflicts')).toBe('true');
  });

  it('emits chunk documents with bodies from the page without extra fetches', async () => {
    const chunk = chunkDoc('h:chunk-1', 'piece-one');
    const mockFetch = vi.fn(async () =>
      allDocsResponse([
        docRow(chunk),
        docRow(noteDoc('NoteA.md', 'alpha')),
      ])
    );

    const inventory = await inventoryRemoteDocuments(mockFetch as unknown as typeof globalThis.fetch, baseUrl, databaseName);

    // One page request only: no per-doc GETs for chunks or the non-conflicted note.
    expect(mockFetch).toHaveBeenCalledTimes(1);

    const chunkItems = inventory.filter((item) => item.kind === 'chunk');
    expect(chunkItems).toEqual([{ kind: 'chunk', id: 'h:chunk-1', document: chunk }]);

    const docItems = inventory.filter((item) => item.kind === 'document');
    expect(docItems).toEqual([{ kind: 'document', id: 'NoteA.md', rev: '1-noterev', document: noteDoc('NoteA.md', 'alpha') }]);
  });

  it('pages with startkey + startkey_docid and skip=1, and never duplicates the boundary row', async () => {
    // More docs than one page (page size is the module constant, 100) forces
    // at least one resume request that must use startkey_docid.
    const totalDocs = 250;
    const docs = Array.from({ length: totalDocs }, (_, i) => noteDoc(`doc${String(i).padStart(3, '0')}`, `body-${i}`));
    const requests: string[] = [];
    const mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      const urlStr = input.toString();
      const url = new URL(urlStr);
      const limit = Number(url.searchParams.get('limit') ?? '100');
      const startkey = url.searchParams.get('startkey');
      const startKeyDocId = url.searchParams.get('startkey_docid');
      const skip = Number(url.searchParams.get('skip') ?? '0');

      // Emulate CouchDB: startkey/startkey_docid are inclusive; skip removes
      // leading rows (the caller sets skip=1 to drop the repeated boundary).
      let begin = 0;
      if (startkey !== null) {
        const key = JSON.parse(startkey) as string;
        begin = docs.findIndex((d) => d._id === key);
        if (startKeyDocId !== null) {
          expect(JSON.parse(startKeyDocId)).toBe(key);
          expect(skip).toBe(1); // resume must drop the repeated boundary row
          begin += skip;
        }
      }
      const rows = docs.slice(begin, begin + limit).map((d) => docRow(d));
      requests.push(urlStr);
      return allDocsResponse(rows, totalDocs);
    });

    const inventory = await inventoryRemoteDocuments(mockFetch as unknown as typeof globalThis.fetch, baseUrl, databaseName);

    // 250 docs at page size 100 → 3 page requests (100 + 100 + 50).
    expect(requests.length).toBe(3);

    const firstUrl = new URL(requests[0]);
    expect(firstUrl.searchParams.get('limit')).toBe('100');
    expect(firstUrl.searchParams.has('startkey')).toBe(false);

    const secondUrl = new URL(requests[1]);
    expect(secondUrl.searchParams.get('startkey')).toBe(JSON.stringify('doc099'));
    expect(secondUrl.searchParams.get('startkey_docid')).toBe(JSON.stringify('doc099'));
    expect(secondUrl.searchParams.get('skip')).toBe('1');

    // Every doc appears exactly once despite inclusive-boundary resumes.
    const docIds = inventory
      .filter((item) => item.kind === 'document')
      .map((item) => (item as { id: string }).id)
      .sort();
    expect(docIds.length).toBe(totalDocs);
    expect(new Set(docIds).size).toBe(totalDocs);
    expect(docIds[0]).toBe('doc000');
    expect(docIds[totalDocs - 1]).toBe('doc249');
  });

  it('does not re-fetch per-doc leaves for non-conflicted notes', async () => {
    const mockFetch = vi.fn(async () =>
      allDocsResponse([docRow(noteDoc('NoteA.md', 'alpha'))])
    );

    const inventory = await inventoryRemoteDocuments(mockFetch as unknown as typeof globalThis.fetch, baseUrl, databaseName);

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(inventory.filter((item) => item.kind === 'document').length).toBe(1);
  });

  it('fetches conflict leaves by rev only when _conflicts is present on the winning doc', async () => {
    const winner = {
      ...noteDoc('Conflict.md', 'winner body'),
      _conflicts: ['1-otherleaf'],
    } as CouchDbDocument;
    const leaf = noteDoc('Conflict.md', 'loser body');

    const mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      const urlStr = input.toString();
      if (urlStr.includes('_all_docs')) {
        return allDocsResponse([docRow(winner)]);
      }
      // Per-rev leaf fetch
      if (urlStr.includes('rev=1-otherleaf')) {
        return new Response(JSON.stringify(leaf), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response(JSON.stringify({ error: 'not_found' }), { status: 404 });
    });

    const inventory = await inventoryRemoteDocuments(mockFetch as unknown as typeof globalThis.fetch, baseUrl, databaseName);

    expect(mockFetch).toHaveBeenCalledTimes(2); // page + one conflict leaf
    const docItems = inventory.filter((item) => item.kind === 'document');
    expect(docItems.length).toBe(2);
    expect((docItems[0] as { document: CouchDbDocument }).document.data).toBe('winner body');
    expect((docItems[1] as { document: CouchDbDocument }).document.data).toBe('loser body');
  });

  it('keeps tombstone handling unchanged for deleted rows', async () => {
    const mockFetch = vi.fn(async () =>
      allDocsResponse([docRow(noteDoc('Gone.md', 'x'), true)])
    );

    const inventory = await inventoryRemoteDocuments(mockFetch as unknown as typeof globalThis.fetch, baseUrl, databaseName);

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(inventory).toEqual([{ kind: 'tombstone', id: 'Gone.md', rev: '1-noterev' }]);
  });

  it('falls back to per-doc conflict-leaf fetch when a row has no body (defensive path)', async () => {
    const note = noteDoc('Legacy.md', 'legacy body');
    const mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      const urlStr = input.toString();
      if (urlStr.includes('_all_docs')) {
        // Row without doc body
        return allDocsResponse([
          { id: note._id, key: note._id, value: { rev: note._rev } },
        ]);
      }
      if (urlStr.includes('conflicts=true')) {
        return new Response(JSON.stringify(note), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response(JSON.stringify({ error: 'not_found' }), { status: 404 });
    });

    const inventory = await inventoryRemoteDocuments(mockFetch as unknown as typeof globalThis.fetch, baseUrl, databaseName);

    expect(mockFetch).toHaveBeenCalledTimes(2); // page + conflicts fetch
    expect(inventory).toEqual([{ kind: 'document', id: 'Legacy.md', rev: '1-noterev', document: note }]);
  });

  it('skips chunk rows without bodies rather than fabricating empty chunk entries', async () => {
    const mockFetch = vi.fn(async () =>
      allDocsResponse([
        { id: 'h:chunk-1', key: 'h:chunk-1', value: { rev: '1-x' } },
      ])
    );

    const inventory = await inventoryRemoteDocuments(mockFetch as unknown as typeof globalThis.fetch, baseUrl, databaseName);

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(inventory).toEqual([]);
  });
});

describe('createCachedChunkFetcher (Unit)', () => {
  const authHeader = 'Basic dXNlcjpwYXNz';

  it('serves cache hits with no HTTP request', async () => {
    const cached = chunkDoc('h:chunk-1', 'piece-one');
    const chunkCache = new Map<string, CouchDbDocument>([['h:chunk-1', cached]]);
    const mockFetch = vi.fn();

    const fetchChunk = createCachedChunkFetcher(
      mockFetch as unknown as typeof globalThis.fetch,
      baseUrl,
      databaseName,
      authHeader,
      chunkCache
    );

    const result = await fetchChunk('h:chunk-1');
    expect(result).toBe(cached);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('falls back to a single-doc GET on miss and populates the cache', async () => {
    const remote = chunkDoc('h:chunk-miss', 'piece-two');
    const chunkCache = new Map<string, CouchDbDocument>();
    const mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      const urlStr = input.toString();
      if (urlStr.endsWith(`/${databaseName}/h%3Achunk-miss`)) {
        return new Response(JSON.stringify(remote), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response(JSON.stringify({ error: 'not_found' }), { status: 404 });
    });

    const fetchChunk = createCachedChunkFetcher(
      mockFetch as unknown as typeof globalThis.fetch,
      baseUrl,
      databaseName,
      authHeader,
      chunkCache
    );

    const first = await fetchChunk('h:chunk-miss');
    expect(first).toEqual(remote);
    expect(chunkCache.get('h:chunk-miss')).toEqual(remote);

    // Second call is a cache hit: still exactly one HTTP request.
    const second = await fetchChunk('h:chunk-miss');
    expect(second).toEqual(remote);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('caches 404 misses as resolved without poisoning the cache with a non-doc', async () => {
    const chunkCache = new Map<string, CouchDbDocument>();
    const mockFetch = vi.fn(async () =>
      new Response(JSON.stringify({ error: 'not_found' }), { status: 404 })
    );

    const fetchChunk = createCachedChunkFetcher(
      mockFetch as unknown as typeof globalThis.fetch,
      baseUrl,
      databaseName,
      undefined,
      chunkCache
    );

    const result = await fetchChunk('h:missing');
    expect(result).toBeNull();
    expect(chunkCache.has('h:missing')).toBe(false);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});

describe('buildChunkCacheFromInventory (Unit)', () => {
  it('collects chunk documents and ignores tombstones and note documents', () => {
    const chunkA = chunkDoc('h:a', 'A');
    const chunkB = chunkDoc('e:b', 'B');
    const inventory = [
      { kind: 'chunk', id: 'h:a', document: chunkA },
      { kind: 'chunk', id: 'e:b', document: chunkB },
      { kind: 'tombstone', id: 'Gone.md', rev: '1-x' },
      { kind: 'document', id: 'NoteA.md', rev: '1-y', document: noteDoc('NoteA.md', 'alpha') },
    ] as const;

    const cache = buildChunkCacheFromInventory(inventory as never);

    expect(cache.size).toBe(2);
    expect(cache.get('h:a')).toBe(chunkA);
    expect(cache.get('e:b')).toBe(chunkB);
    expect(cache.has('NoteA.md')).toBe(false);
    expect(cache.has('Gone.md')).toBe(false);
  });

  it('returns an empty map for an inventory without chunks', () => {
    const inventory = [{ kind: 'tombstone', id: 'Gone.md', rev: '1-x' }];
    const cache = buildChunkCacheFromInventory(inventory as never);
    expect(cache.size).toBe(0);
  });
});

describe('inventoryChangedDocuments (Unit, Phase 3)', () => {
  function changesResponse(
    results: Record<string, unknown>[],
    lastSeq?: string | number
  ): Response {
    return new Response(
      JSON.stringify({ results, ...(lastSeq !== undefined ? { last_seq: lastSeq } : {}) }),
      { status: 200, headers: { 'content-type': 'application/json' } }
    );
  }

  function changeRow(
    id: string,
    seq: string | number,
    options?: { deleted?: boolean; doc?: CouchDbDocument }
  ): Record<string, unknown> {
    return {
      seq,
      id,
      changes: [{ rev: options?.doc?._rev ?? '1-x' }],
      ...(options?.deleted ? { deleted: true } : {}),
      ...(options?.doc ? { doc: options.doc } : {}),
    };
  }

  it('queries _changes with since, style=all_docs, include_docs, conflicts and limit', async () => {
    const requests: string[] = [];
    const mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      const urlStr = input.toString();
      requests.push(urlStr);
      return changesResponse([], 'seq-final');
    });

    const result = await inventoryChangedDocuments(
      mockFetch as unknown as typeof globalThis.fetch,
      baseUrl,
      databaseName,
      'seq-42'
    );

    expect(requests.length).toBe(1);
    const url = new URL(requests[0]);
    expect(url.pathname).toBe(`/${databaseName}/_changes`);
    expect(url.searchParams.get('since')).toBe('seq-42');
    expect(url.searchParams.get('style')).toBe('all_docs');
    expect(url.searchParams.get('include_docs')).toBe('true');
    expect(url.searchParams.get('conflicts')).toBe('true');
    expect(url.searchParams.get('limit')).toBe('100');
    // Empty feed still reports the current position via last_seq.
    expect(result.lastSeq).toBe('seq-final');
    expect(result.collected).toEqual([]);
  });

  it('classifies changed note and chunk rows identically to the full inventory', async () => {
    const chunk = chunkDoc('h:newchunk', 'C');
    const note = noteDoc('NoteB.md', 'beta');
    const mockFetch = vi.fn(async () =>
      changesResponse(
        [
          changeRow('h:newchunk', 11, { doc: chunk }),
          changeRow('NoteB.md', 12, { doc: note }),
          changeRow('Gone.md', 13, { deleted: true }),
        ],
        13
      )
    );

    const result = await inventoryChangedDocuments(
      mockFetch as unknown as typeof globalThis.fetch,
      baseUrl,
      databaseName,
      'seq-10'
    );

    expect(result.collected).toEqual([
      { kind: 'chunk', id: 'h:newchunk', document: chunk },
      { kind: 'document', id: 'NoteB.md', rev: '1-noterev', document: note },
      { kind: 'tombstone', id: 'Gone.md', rev: '1-x' },
    ]);
    expect(result.lastSeq).toBe('13');
  });

  it('pages via the last row seq until the feed is exhausted and reports last_seq at the end', async () => {
    const requests: string[] = [];
    const mkNote = (n: number) => noteDoc(`Note${n}.md`, `body-${n}`);
    const mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      const urlStr = input.toString();
      requests.push(urlStr);
      const url = new URL(urlStr);
      const since = url.searchParams.get('since');
      if (since === 'seq-0') {
        // Full page of 100 rows -> must re-page from the last row seq.
        const rows = Array.from({ length: 100 }, (_, i) =>
          changeRow(`Filler${String(i).padStart(3, '0')}.md`, i + 1, { doc: mkNote(i) })
        );
        return changesResponse(rows, 100);
      }
      // Second page: one row, then exhausted.
      return changesResponse([changeRow('NoteFinal.md', 101, { doc: mkNote(999) })], 101);
    });

    const result = await inventoryChangedDocuments(
      mockFetch as unknown as typeof globalThis.fetch,
      baseUrl,
      databaseName,
      'seq-0'
    );

    expect(requests.length).toBe(2);
    expect(new URL(requests[1]).searchParams.get('since')).toBe('100');
    expect(result.lastSeq).toBe('101');
    expect(result.collected.length).toBe(101);
  });

  it('throws on HTTP 400 so callers can fall back to a full inventory', async () => {
    const mockFetch = vi.fn(async () =>
      new Response(JSON.stringify({ error: 'bad_request', reason: 'Invalid since' }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      })
    );

    await expect(
      inventoryChangedDocuments(
        mockFetch as unknown as typeof globalThis.fetch,
        baseUrl,
        databaseName,
        'bogus-seq'
      )
    ).rejects.toThrow(/HTTP 400/);
  });

  it('throws AuthenticationRequiredError on 401/403', async () => {
    const mockFetch = vi.fn(async () =>
      new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401 })
    );

    await expect(
      inventoryChangedDocuments(
        mockFetch as unknown as typeof globalThis.fetch,
        baseUrl,
        databaseName,
        'seq-1'
      )
    ).rejects.toThrow(AuthenticationRequiredError);
  });

  it('sends Authorization header when credentials are supplied', async () => {
    let authHeader: string | undefined;
    const mockFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      authHeader = headers.Authorization;
      return changesResponse([], 'seq-2');
    });

    await inventoryChangedDocuments(
      mockFetch as unknown as typeof globalThis.fetch,
      baseUrl,
      databaseName,
      'seq-1',
      { username: 'user', password: 'pass' }
    );

    expect(authHeader).toBe(`Basic ${Buffer.from('user:pass').toString('base64')}`);
  });
});
