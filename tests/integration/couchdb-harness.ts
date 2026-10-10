import { CouchDBContainer, type StartedCouchDBContainer } from '@testcontainers/couchdb';
import {
  VERSIONING_DOCID,
  MILESTONE_DOCID,
  DOCID_SYNC_PARAMETERS,
  SYNCINFO_ID,
} from '../../src/livesync/inspector.js';

export class CouchDbTestHarness {
  private container?: StartedCouchDBContainer;
  private baseUrl?: URL;
  private username = 'admin';
  private password = 'password';

  async start(): Promise<void> {
    const couchContainer = new CouchDBContainer('couchdb:3.5.2.1')
      .withUsername(this.username)
      .withPassword(this.password);

    this.container = await couchContainer.start();
    const parsed = new URL(this.container.getUrl());
    // Strip userinfo from the base URL so credentials are supplied via headers
    this.baseUrl = new URL(`${parsed.protocol}//${parsed.host}`);
    this.username = this.container.getUsername();
    this.password = this.container.getPassword();
  }

  getBaseUrl(): URL {
    if (!this.baseUrl) {
      throw new Error('CouchDB container not started.');
    }
    return new URL(this.baseUrl.href);
  }

  getCredentials(): { username: string; password: string } {
    return {
      username: this.username,
      password: this.password,
    };
  }

  private getAuthHeader(): string {
    return 'Basic ' + Buffer.from(`${this.username}:${this.password}`).toString('base64');
  }

  async createDatabase(name: string): Promise<void> {
    const url = new URL(`/${encodeURIComponent(name)}`, this.getBaseUrl());
    const res = await fetch(url.toString(), {
      method: 'PUT',
      headers: {
        Authorization: this.getAuthHeader(),
        Accept: 'application/json',
      },
    });
    if (!res.ok && res.status !== 412) {
      throw new Error(`Failed to create database '${name}': HTTP ${res.status} ${res.statusText}`);
    }
  }

  private getDocUrl(dbName: string, docId: string): URL {
    if (docId.startsWith('_design/') || docId.startsWith('_local/')) {
      const slashIdx = docId.indexOf('/');
      const prefix = docId.slice(0, slashIdx);
      const rest = docId.slice(slashIdx + 1);
      return new URL(`/${encodeURIComponent(dbName)}/${prefix}/${encodeURIComponent(rest)}`, this.getBaseUrl());
    }
    return new URL(`/${encodeURIComponent(dbName)}/${encodeURIComponent(docId)}`, this.getBaseUrl());
  }

  async putDocument(
    dbName: string,
    docId: string,
    doc: Record<string, unknown>,
    query?: Record<string, string>
  ): Promise<{ rev: string }> {
    const url = this.getDocUrl(dbName, docId);
    if (query) {
      for (const [key, value] of Object.entries(query)) {
        url.searchParams.set(key, value);
      }
    }
    const res = await fetch(url.toString(), {
      method: 'PUT',
      headers: {
        Authorization: this.getAuthHeader(),
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(doc),
    });
    if (!res.ok) {
      throw new Error(
        `Failed to put document '${docId}' in '${dbName}': HTTP ${res.status} ${res.statusText}`
      );
    }
    const json = (await res.json()) as { rev: string };
    return { rev: json.rev };
  }

  async getDocument(
    dbName: string,
    docId: string
  ): Promise<Record<string, unknown> | null> {
    const url = this.getDocUrl(dbName, docId);
    const res = await fetch(url.toString(), {
      headers: {
        Authorization: this.getAuthHeader(),
        Accept: 'application/json',
      },
    });
    if (res.status === 404) {
      return null;
    }
    if (!res.ok) {
      throw new Error(
        `Failed to get document '${docId}' in '${dbName}': HTTP ${res.status} ${res.statusText}`
      );
    }
    return (await res.json()) as Record<string, unknown>;
  }

  async writeUpstreamPlainNote(
    dbName: string,
    relativePath: string,
    content: string,
    options?: {
      chunkSize?: number;
      minimumChunkSize?: number;
    }
  ): Promise<{ id: string; rev: string; children: string[] }> {
    const { path2id_base } = await import(
      '@vrtmrz/livesync-commonlib/compat/string_and_binary/path'
    );
    const { splitPieces2V2, collectGenAll } = await import(
      '@vrtmrz/livesync-commonlib/compat/string_and_binary/chunks'
    );
    const { digestHash } = await import(
      '@vrtmrz/livesync-commonlib/compat/string_and_binary/hash'
    );

    const chunkSize = options?.chunkSize ?? 50000;
    const minimumChunkSize = options?.minimumChunkSize ?? 20;
    const byteLength = new TextEncoder().encode(content).byteLength;

    let pieces: string[] = [];
    if (content.length > 0) {
      const blob = new Blob([content], { type: 'text/plain' });
      const genFn = await splitPieces2V2(blob, chunkSize, false, minimumChunkSize, relativePath);
      pieces = await collectGenAll(genFn());
    }

    const children: string[] = [];
    for (const piece of pieces) {
      const hash = await digestHash(piece);
      const chunkId = `h:${hash}`;
      try {
        await this.putDocument(dbName, chunkId, {
          _id: chunkId,
          type: 'leaf',
          data: piece,
        });
      } catch (err: any) {
        if (!err.message?.includes('409')) {
          throw err;
        }
      }
      children.push(chunkId);
    }

    const id = String(await path2id_base(relativePath, false, true));
    const existing = await this.getDocument(dbName, id);
    const { rev } = await this.putDocument(dbName, id, {
      _id: id,
      ...(existing && typeof existing._rev === 'string' ? { _rev: existing._rev } : {}),
      type: 'plain',
      path: relativePath,
      children,
      size: byteLength,
      deleted: false,
      mtime: Date.now(),
      ctime: Date.now(),
    });

    return { id, rev, children };
  }

  async writeUpstreamEncryptedNote(
    dbName: string,
    relativePath: string,
    content: string,
    passphrase: string,
    saltHex: string,
    options?: {
      chunkSize?: number;
      minimumChunkSize?: number;
    }
  ): Promise<{ id: string; rev: string; children: string[] }> {
    const { path2id_base } = await import(
      '@vrtmrz/livesync-commonlib/compat/string_and_binary/path'
    );
    const { splitPieces2V2, collectGenAll } = await import(
      '@vrtmrz/livesync-commonlib/compat/string_and_binary/chunks'
    );
    const { digestHash } = await import(
      '@vrtmrz/livesync-commonlib/compat/string_and_binary/hash'
    );
    const { encrypt: encryptHkdf } = await import('octagonal-wheels/encryption/hkdf');
    const { hexStringToUint8Array } = await import('octagonal-wheels/binary/hex');

    const saltBytes = (/^[0-9a-fA-F]+$/.test(saltHex) && saltHex.length % 2 === 0)
      ? hexStringToUint8Array(saltHex)
      : new TextEncoder().encode(saltHex);
    const chunkSize = options?.chunkSize ?? 50000;
    const minimumChunkSize = options?.minimumChunkSize ?? 20;
    const byteLength = new TextEncoder().encode(content).byteLength;

    let pieces: string[] = [];
    if (content.length > 0) {
      const blob = new Blob([content], { type: 'text/plain' });
      const genFn = await splitPieces2V2(blob, chunkSize, false, minimumChunkSize, relativePath);
      pieces = await collectGenAll(genFn());
    }

    const children: string[] = [];
    for (const piece of pieces) {
      const encryptedPiece = await encryptHkdf(piece, passphrase, saltBytes as never);
      const hash = await digestHash(encryptedPiece);
      const chunkId = `e:${hash}`;
      try {
        await this.putDocument(dbName, chunkId, {
          _id: chunkId,
          type: 'leaf',
          data: encryptedPiece,
          e_: true,
        });
      } catch (err: any) {
        if (!err.message?.includes('409')) {
          throw err;
        }
      }
      children.push(chunkId);
    }

    const meta = JSON.stringify({
      path: relativePath,
      mtime: Date.now(),
      ctime: Date.now(),
      size: byteLength,
    });
    const encryptedPath = `/\\:${await encryptHkdf(meta, passphrase, saltBytes as never)}`;
    const id = String(await path2id_base(relativePath, false, true));
    const existing = await this.getDocument(dbName, id);

    const { rev } = await this.putDocument(dbName, id, {
      _id: id,
      ...(existing && typeof existing._rev === 'string' ? { _rev: existing._rev } : {}),
      type: 'notes',
      path: encryptedPath,
      children,
      e_: true,
      size: 0,
      deleted: false,
      mtime: Date.now(),
    });

    return { id, rev, children };
  }

  async writeUpstreamObfuscatedNote(
    dbName: string,
    relativePath: string,
    content: string,
    passphrase: string,
    saltHex: string,
    options?: {
      chunkSize?: number;
      minimumChunkSize?: number;
    }
  ): Promise<{ id: string; rev: string; children: string[] }> {
    const { path2id_base } = await import(
      '@vrtmrz/livesync-commonlib/compat/string_and_binary/path'
    );
    const { splitPieces2V2, collectGenAll } = await import(
      '@vrtmrz/livesync-commonlib/compat/string_and_binary/chunks'
    );
    const { digestHash } = await import(
      '@vrtmrz/livesync-commonlib/compat/string_and_binary/hash'
    );
    const { encrypt: encryptHkdf } = await import('octagonal-wheels/encryption/hkdf');
    const { hexStringToUint8Array } = await import('octagonal-wheels/binary/hex');

    const saltBytes = (/^[0-9a-fA-F]+$/.test(saltHex) && saltHex.length % 2 === 0)
      ? hexStringToUint8Array(saltHex)
      : new TextEncoder().encode(saltHex);
    const chunkSize = options?.chunkSize ?? 50000;
    const minimumChunkSize = options?.minimumChunkSize ?? 20;
    const byteLength = new TextEncoder().encode(content).byteLength;

    let pieces: string[] = [];
    if (content.length > 0) {
      const blob = new Blob([content], { type: 'text/plain' });
      const genFn = await splitPieces2V2(blob, chunkSize, false, minimumChunkSize, relativePath);
      pieces = await collectGenAll(genFn());
    }

    const children: string[] = [];
    for (const piece of pieces) {
      const encryptedPiece = await encryptHkdf(piece, passphrase, saltBytes as never);
      const hash = await digestHash(encryptedPiece);
      const chunkId = `e:${hash}`;
      try {
        await this.putDocument(dbName, chunkId, {
          _id: chunkId,
          type: 'leaf',
          data: encryptedPiece,
          e_: true,
        });
      } catch (err: any) {
        if (!err.message?.includes('409')) {
          throw err;
        }
      }
      children.push(chunkId);
    }

    const meta = JSON.stringify({
      path: relativePath,
      mtime: Date.now(),
      ctime: Date.now(),
      size: byteLength,
    });
    const encryptedPath = `/\\:${await encryptHkdf(meta, passphrase, saltBytes as never)}`;
    const id = String(await path2id_base(relativePath, passphrase, true));
    const existing = await this.getDocument(dbName, id);

    const { rev } = await this.putDocument(dbName, id, {
      _id: id,
      ...(existing && typeof existing._rev === 'string' ? { _rev: existing._rev } : {}),
      type: 'notes',
      path: encryptedPath,
      children,
      e_: true,
      size: 0,
      deleted: false,
      mtime: Date.now(),
    });

    return { id, rev, children };
  }

  async readUpstreamNote(
    dbName: string,
    relativePath: string,
    options?: {
      passphrase?: string;
      saltHex?: string;
      isObfuscated?: boolean;
    }
  ): Promise<{
    id: string;
    rev: string;
    path: string;
    content: string;
    bytes: Uint8Array;
    deleted: boolean;
    children?: string[];
  } | null> {
    const { path2id_base } = await import(
      '@vrtmrz/livesync-commonlib/compat/string_and_binary/path'
    );
    const { decrypt: decryptHkdf } = await import('octagonal-wheels/encryption/hkdf');
    const { hexStringToUint8Array } = await import('octagonal-wheels/binary/hex');

    let docId: string;
    let doc: Record<string, unknown> | null = null;

    if (options?.isObfuscated && options?.passphrase) {
      docId = String(await path2id_base(relativePath, options.passphrase, true));
      doc = await this.getDocument(dbName, docId);
    } else if (options?.isObfuscated === false) {
      docId = String(await path2id_base(relativePath, false, true));
      doc = await this.getDocument(dbName, docId);
    } else {
      docId = String(await path2id_base(relativePath, false, true));
      doc = await this.getDocument(dbName, docId);
      if (!doc && options?.passphrase) {
        docId = String(await path2id_base(relativePath, options.passphrase, true));
        doc = await this.getDocument(dbName, docId);
      }
    }

    if (!doc) {
      return null;
    }

    const id = (doc._id as string) ?? docId;
    const rev = doc._rev as string;
    const isDeleted = Boolean(doc.deleted);

    if (isDeleted) {
      return {
        id,
        rev,
        path: relativePath,
        content: '',
        bytes: new Uint8Array(0),
        deleted: true,
      };
    }

    const isEncrypted = Boolean(doc.e_ || (typeof doc.path === 'string' && doc.path.startsWith('/\\:')));
    let realPath = relativePath;
    let content = '';

    if (isEncrypted) {
      if (!options?.passphrase) {
        throw new Error('Passphrase required to decrypt note');
      }
      const rawSalt = options.saltHex ?? 'salt-12345';
      const saltBytes = (/^[0-9a-fA-F]+$/.test(rawSalt) && rawSalt.length % 2 === 0)
        ? hexStringToUint8Array(rawSalt)
        : new TextEncoder().encode(rawSalt);

      if (typeof doc.path === 'string' && doc.path.startsWith('/\\:')) {
        const decryptedMeta = await decryptHkdf(doc.path.slice(3), options.passphrase, saltBytes as never);
        try {
          const parsedMeta = JSON.parse(decryptedMeta);
          if (parsedMeta.path) {
            realPath = parsedMeta.path;
          }
        } catch {
          // Keep relativePath
        }
      }

      if (typeof doc.data === 'string') {
        content = await decryptHkdf(doc.data, options.passphrase, saltBytes as never);
      } else if (Array.isArray(doc.children)) {
        const parts: string[] = [];
        for (const chunkId of doc.children as string[]) {
          const chunkDoc = await this.getDocument(dbName, chunkId);
          if (!chunkDoc) {
            throw new Error(`Referenced chunk '${chunkId}' not found in database '${dbName}'`);
          }
          const chunkData = (chunkDoc.data as string) ?? '';
          if (chunkDoc.e_) {
            parts.push(await decryptHkdf(chunkData, options.passphrase, saltBytes as never));
          } else {
            parts.push(chunkData);
          }
        }
        content = parts.join('');
      }
    } else {
      if (typeof doc.data === 'string') {
        content = doc.data;
      } else if (Array.isArray(doc.children)) {
        const parts: string[] = [];
        for (const chunkId of doc.children as string[]) {
          const chunkDoc = await this.getDocument(dbName, chunkId);
          if (!chunkDoc) {
            throw new Error(`Referenced chunk '${chunkId}' not found in database '${dbName}'`);
          }
          const chunkData = (chunkDoc.data as string) ?? '';
          if (chunkDoc.e_ || chunkId.startsWith('e:')) {
            if (!options?.passphrase) {
              throw new Error('Passphrase required to decrypt note chunk');
            }
            const rawSalt = options.saltHex ?? 'salt-12345';
            const saltBytes = (/^[0-9a-fA-F]+$/.test(rawSalt) && rawSalt.length % 2 === 0)
              ? hexStringToUint8Array(rawSalt)
              : new TextEncoder().encode(rawSalt);
            parts.push(await decryptHkdf(chunkData, options.passphrase, saltBytes as never));
          } else {
            parts.push(chunkData);
          }
        }
        content = parts.join('');
      }
    }

    return {
      id,
      rev,
      path: realPath,
      content,
      bytes: new TextEncoder().encode(content),
      deleted: false,
      children: doc.children as string[] | undefined,
    };
  }

  async writeUpstreamLogicalDeletion(
    dbName: string,
    relativePath: string,
    options?: {
      previousRev?: string;
      passphrase?: string;
      isObfuscated?: boolean;
    }
  ): Promise<{ id: string; rev: string }> {
    const { path2id_base } = await import(
      '@vrtmrz/livesync-commonlib/compat/string_and_binary/path'
    );
    const obfuscate = options?.isObfuscated && options?.passphrase ? options.passphrase : false;
    const docId = String(await path2id_base(relativePath, obfuscate, true));

    let previousRev = options?.previousRev;
    if (!previousRev) {
      const existing = await this.getDocument(dbName, docId);
      if (existing && typeof existing._rev === 'string') {
        previousRev = existing._rev;
      }
    }

    const { rev } = await this.putDocument(dbName, docId, {
      _id: docId,
      ...(previousRev ? { _rev: previousRev } : {}),
      type: 'notes',
      path: relativePath,
      deleted: true,
      mtime: Date.now(),
    });

    return { id: docId, rev };
  }

  async seedLiveSyncData(
    dbName: string,
    options?: {
      version?: number;
      locked?: boolean;
      pbkdf2salt?: string;
      hashAlgorithm?: string;
      syncinfo?: string;
      sampleNotes?: Record<string, string>;
      tweakValues?: Record<string, unknown>;
    }
  ): Promise<void> {
    // 1. Versioning doc
    await this.putDocument(dbName, VERSIONING_DOCID, {
      version: options?.version ?? 12,
    });

    // 2. Milestone doc
    await this.putDocument(dbName, MILESTONE_DOCID, {
      locked: options?.locked ?? false,
      tweak_values: {
        PREFERRED: {
          hashAlg: options?.hashAlgorithm ?? 'sha256',
          customChunkSize: 100,
          ...options?.tweakValues,
        },
      },
    });

    // 3. Sync parameters doc
    if (options?.pbkdf2salt || options?.hashAlgorithm) {
      await this.putDocument(dbName, DOCID_SYNC_PARAMETERS, {
        pbkdf2salt: options.pbkdf2salt ?? 'salt-12345',
        hashAlgorithm: options.hashAlgorithm ?? 'sha256',
        customChunkSize: 100,
      });
    }

    // 4. Syncinfo doc
    if (options?.syncinfo) {
      await this.putDocument(dbName, SYNCINFO_ID, {
        data: options.syncinfo,
        type: 'encrypted',
      });
    }

    // 5. Sample notes
    if (options?.sampleNotes) {
      for (const [title, content] of Object.entries(options.sampleNotes)) {
        await this.putDocument(dbName, title, {
          title,
          content,
          mtime: Date.now(),
        });
      }
    }
  }

  async seedLegacyNote(
    dbName: string,
    relativePath: string,
    body: string
  ): Promise<{ id: string; rev: string }> {
    const { path2id_base } = await import(
      '@vrtmrz/livesync-commonlib/compat/string_and_binary/path'
    );
    const id = String(await path2id_base(relativePath, false, true));
    const size = new TextEncoder().encode(body).byteLength;
    const { rev } = await this.putDocument(dbName, id, {
      type: 'notes',
      path: relativePath,
      data: body,
      size,
      deleted: false,
      mtime: Date.now(),
    });
    return { id, rev };
  }

  async seedConflictingLegacyNotes(
    dbName: string,
    relativePath: string,
    winnerBody: string,
    otherBody: string
  ): Promise<{ id: string; winnerRev: string; otherRev: string }> {
    const first = await this.seedLegacyNote(dbName, relativePath, winnerBody);
    const otherRev = '1-conflictleaf';
    await this.putDocument(
      dbName,
      first.id,
      {
        _id: first.id,
        _rev: otherRev,
        type: 'notes',
        path: relativePath,
        data: otherBody,
        size: new TextEncoder().encode(otherBody).byteLength,
        deleted: false,
        mtime: Date.now(),
      },
      { new_edits: 'false' }
    );
    return { id: first.id, winnerRev: first.rev, otherRev };
  }

  async seedChunkedPlainNote(
    dbName: string,
    relativePath: string,
    body: string
  ): Promise<{ id: string; rev: string; byteLength: number; children: string[] }> {
    const { path2id_base } = await import(
      '@vrtmrz/livesync-commonlib/compat/string_and_binary/path'
    );
    const mid = Math.max(1, Math.floor(body.length / 2));
    const parts = [body.slice(0, mid), body.slice(mid)];
    const children: string[] = [];
    for (const [index, part] of parts.entries()) {
      const chunkId = `h:plain-${relativePath.replace(/[^A-Za-z0-9]/g, '')}-${index}`;
      await this.putDocument(dbName, chunkId, {
        type: 'leaf',
        data: part,
      });
      children.push(chunkId);
    }

    const id = String(await path2id_base(relativePath, false, true));
    const byteLength = new TextEncoder().encode(body).byteLength;
    const { rev } = await this.putDocument(dbName, id, {
      type: 'plain',
      path: relativePath,
      children,
      size: byteLength,
      deleted: false,
      mtime: Date.now(),
    });
    return { id, rev, byteLength, children };
  }

  async seedNewnoteBinary(
    dbName: string,
    relativePath: string,
    body: string
  ): Promise<{ id: string; rev: string; byteLength: number; children: string[] }> {
    const { path2id_base } = await import(
      '@vrtmrz/livesync-commonlib/compat/string_and_binary/path'
    );
    const mid = Math.max(1, Math.floor(body.length / 2));
    const parts = [body.slice(0, mid), body.slice(mid)];
    const children: string[] = [];
    for (const [index, part] of parts.entries()) {
      const chunkId = `h:newnote-${relativePath.replace(/[^A-Za-z0-9]/g, '')}-${index}`;
      await this.putDocument(dbName, chunkId, {
        type: 'leaf',
        // Upstream stores binary-note chunk data base64-encoded (decodeBinary →
        // base64ToArrayBuffer for non-text documents); text ('plain') chunks stay raw.
        data: Buffer.from(part, 'utf8').toString('base64'),
      });
      children.push(chunkId);
    }

    const id = String(await path2id_base(relativePath, false, true));
    const byteLength = new TextEncoder().encode(body).byteLength;
    const { rev } = await this.putDocument(dbName, id, {
      type: 'newnote',
      path: relativePath,
      children,
      size: byteLength,
      deleted: false,
      mtime: Date.now(),
    });
    return { id, rev, byteLength, children };
  }

  async seedEncryptedV2Note(
    dbName: string,
    relativePath: string,
    body: string,
    passphrase: string,
    saltHex: string
  ): Promise<{ id: string; rev: string; byteLength: number }> {
    const { path2id_base } = await import(
      '@vrtmrz/livesync-commonlib/compat/string_and_binary/path'
    );
    const { encrypt: encryptHkdf } = await import('octagonal-wheels/encryption/hkdf');
    const { hexStringToUint8Array } = await import('octagonal-wheels/binary/hex');

    const saltBytes = hexStringToUint8Array(saltHex);
    const byteLength = new TextEncoder().encode(body).byteLength;
    const meta = JSON.stringify({
      path: relativePath,
      mtime: Date.now(),
      ctime: Date.now(),
      size: byteLength,
    });
    const encryptedPath = `/\\:${await encryptHkdf(meta, passphrase, saltBytes)}`;
    const encryptedData = await encryptHkdf(body, passphrase, saltBytes);
    const id = String(await path2id_base(relativePath, false, true));
    const { rev } = await this.putDocument(dbName, id, {
      type: 'notes',
      path: encryptedPath,
      data: encryptedData,
      e_: true,
      size: 0,
      deleted: false,
    });
    return { id, rev, byteLength };
  }

  async seedObfuscatedNote(
    dbName: string,
    relativePath: string,
    body: string,
    passphrase: string,
    saltHex: string
  ): Promise<{ id: string; rev: string; byteLength: number }> {
    const { path2id_base } = await import(
      '@vrtmrz/livesync-commonlib/compat/string_and_binary/path'
    );
    const { encrypt: encryptHkdf } = await import('octagonal-wheels/encryption/hkdf');
    const { hexStringToUint8Array } = await import('octagonal-wheels/binary/hex');

    const saltBytes = hexStringToUint8Array(saltHex);
    const byteLength = new TextEncoder().encode(body).byteLength;
    const meta = JSON.stringify({
      path: relativePath,
      mtime: Date.now(),
      ctime: Date.now(),
      size: byteLength,
    });
    const encryptedPath = `/\\:${await encryptHkdf(meta, passphrase, saltBytes)}`;
    const encryptedData = await encryptHkdf(body, passphrase, saltBytes);
    const id = String(await path2id_base(relativePath, passphrase, true));
    const { rev } = await this.putDocument(dbName, id, {
      type: 'notes',
      path: encryptedPath,
      data: encryptedData,
      e_: true,
      size: 0,
      deleted: false,
    });
    return { id, rev, byteLength };
  }

  async seedDeletedNote(
    dbName: string,
    relativePath: string,
    options?: {
      passphrase?: string;
    }
  ): Promise<{ id: string; rev: string }> {
    const { path2id_base } = await import(
      '@vrtmrz/livesync-commonlib/compat/string_and_binary/path'
    );
    const id = String(await path2id_base(relativePath, options?.passphrase ?? false, true));

    let existingRev: string | undefined;
    try {
      const url = new URL(
        `/${encodeURIComponent(dbName)}/${encodeURIComponent(id)}`,
        this.getBaseUrl()
      );
      const res = await fetch(url.toString(), {
        headers: {
          Authorization: this.getAuthHeader(),
          Accept: 'application/json',
        },
      });
      if (res.ok) {
        const json = (await res.json()) as { _rev?: string };
        existingRev = json._rev;
      }
    } catch {
      // Ignore
    }

    const { rev } = await this.putDocument(dbName, id, {
      ...(existingRev ? { _rev: existingRev } : {}),
      type: 'plain',
      path: relativePath,
      deleted: true,
      mtime: Date.now(),
    });
    return { id, rev };
  }

  async stop(): Promise<void> {
    if (this.container) {
      await this.container.stop();
      this.container = undefined;
    }
  }
}
