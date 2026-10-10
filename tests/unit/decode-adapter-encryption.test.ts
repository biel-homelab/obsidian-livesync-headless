import { describe, it, expect } from 'vitest';
import {
  encrypt as encryptHkdf,
  createPBKDF2Salt,
} from 'octagonal-wheels/encryption/hkdf';
import {
  encrypt as encryptV2Legacy,
  encryptV1,
} from 'octagonal-wheels/encryption';
import { obfuscatePath } from 'octagonal-wheels/encryption/obfuscatePath';
import { uint8ArrayToHexString } from 'octagonal-wheels/binary/hex';
import {
  looksEncryptedString,
  looksLikeV1Envelope,
  looksLikeV2Ciphertext,
  decryptIncomingDocument,
  assembleChunks,
  decodeNoteLeaf,
  path2id_base,
} from '../../src/livesync/decode-adapter.js';
import { verifySyncinfo } from '../../src/livesync/syncinfo.js';
import type { CouchDbDocument } from '../../src/livesync/inspector.js';

// The exact live failure: a plaintext markdown chunk whose body starts with a
// markdown link. Previously `looksEncryptedString` treated any `[` prefix as
// ciphertext, producing DECRYPT_FAILED and a daemon crash loop.
const LIVE_PLAINTEXT_CHUNK_A = '[this guide](https://guides.viren070.me/selfhosting/oracle)';
const LIVE_PLAINTEXT_CHUNK_B = '[Site creation confirmation](https://content.gitbook.com/)';

describe('Strict encryption-prefix validators', () => {
  it('treats markdown plaintext starting with "[" as NOT encrypted', () => {
    expect(looksEncryptedString(LIVE_PLAINTEXT_CHUNK_A)).toBe(false);
    expect(looksEncryptedString(LIVE_PLAINTEXT_CHUNK_B)).toBe(false);
    expect(looksLikeV1Envelope(LIVE_PLAINTEXT_CHUNK_A)).toBe(false);
  });

  it('treats markdown plaintext starting with "%" as NOT encrypted', () => {
    expect(looksEncryptedString('% markdown heading line\nbody')).toBe(false);
    expect(looksLikeV2Ciphertext('% markdown heading line\nbody')).toBe(false);
  });

  it('recognises a real V1 envelope produced by octagonal-wheels encryptV1', async () => {
    const ciphertext = await encryptV1('secret legacy body', 'test-passphrase', false);
    expect(looksLikeV1Envelope(ciphertext)).toBe(true);
    expect(looksEncryptedString(ciphertext)).toBe(true);
  });

  it('rejects near-miss V1 shapes', () => {
    // Wrong IV/salt lengths, missing quotes, trailing content.
    expect(looksLikeV1Envelope('["AAA","abab","abab"]')).toBe(false);
    expect(looksLikeV1Envelope('["AAA","a".repeat(32),"b"]')).toBe(false);
    expect(looksLikeV1Envelope('["AAA","abababababababababababababababab","abababababababababababababababab"] extra')).toBe(false);
    expect(looksLikeV1Envelope('["AAA","abababababababababababababababab"]')).toBe(false);
  });

  it('recognises the exact legacy V2 format emitted by octagonal-wheels encrypt()', async () => {
    // Verified from node_modules/octagonal-wheels/dist/encryption/encryption.js:
    // encrypt() returns `%` + hex(iv) + hex(salt) + base64, where the IV is
    // 16 bytes (12 semi-static + 4 nonce counter) -> 32 hex chars, and the
    // salt is 16 bytes -> 32 hex chars (64 hex chars total).
    const ciphertext = await encryptV2Legacy('secret v2 body', 'test-passphrase', false);
    expect(ciphertext.startsWith('%')).toBe(true);
    expect(looksLikeV2Ciphertext(ciphertext)).toBe(true);
    expect(looksEncryptedString(ciphertext)).toBe(true);
  });

  it('still treats HKDF "%=" and V3 "%~" prefixes as encrypted', () => {
    expect(looksEncryptedString('%=some-hkdf-payload')).toBe(true);
    expect(looksEncryptedString('%~some-v3-payload')).toBe(true);
    expect(looksEncryptedString('/\\:some-encrypted-meta')).toBe(true);
  });

  it('rejects non-string values', () => {
    expect(looksEncryptedString(undefined)).toBe(false);
    expect(looksEncryptedString(null)).toBe(false);
    expect(looksEncryptedString(42)).toBe(false);
  });

  it('recognises legacy obfuscated paths (V2-shaped) as encrypted strings', async () => {
    const obfuscated = await obfuscatePath('Notes/Secret.md', 'obf-passphrase', false);
    expect(looksEncryptedString(obfuscated)).toBe(true);
  });
});

describe('decode-adapter false-positive regression (live failure case)', () => {
  const passphrase = 'correct-e2ee-passphrase';
  const saltBytes = createPBKDF2Salt();
  const saltHex = uint8ArrayToHexString(saltBytes);

  function chunkOf(id: string, data: string): CouchDbDocument {
    return { _id: id, _rev: '1-c', type: 'leaf', data };
  }

  it('decodes plaintext chunks starting with "[" without attempting decryption', async () => {
    const body = LIVE_PLAINTEXT_CHUNK_A;
    const assembled = await assembleChunks(
      ['h:1glg4b822a6po'],
      new TextEncoder().encode(body).byteLength,
      async (id) => chunkOf(id, body)
    );
    expect(assembled.ok).toBe(true);
    if (assembled.ok) {
      expect(new TextDecoder().decode(assembled.bytes)).toBe(body);
    }
  });

  it('passes a plaintext markdown-link note through decodeNoteLeaf unmodified', async () => {
    const body = LIVE_PLAINTEXT_CHUNK_B;
    const decoded = await decodeNoteLeaf(
      {
        _id: String(await path2id_base('Links.md' as never, false, false)),
        _rev: '1-p',
        type: 'plain',
        path: 'Links.md',
        children: ['h:3bcjzxkxlakhb'],
        size: new TextEncoder().encode(body).byteLength,
      },
      {
        handleFilenameCaseSensitive: true,
        fetchChunk: async (id) => (id === 'h:3bcjzxkxlakhb' ? chunkOf(id, body) : null),
      }
    );
    expect(decoded.ok).toBe(true);
    if (decoded.ok) {
      expect(new TextDecoder().decode(decoded.bytes)).toBe(body);
    }
  });

  it('still decrypts a real V1-envelope chunk when a passphrase is available', async () => {
    const original = 'legacy encrypted chunk body';
    const ciphertext = await encryptV1(original, passphrase, false);
    const result = await decryptIncomingDocument(
      { _id: 'h:v1chunk', _rev: '1-v1', type: 'leaf', data: ciphertext },
      { encryptionPassphrase: passphrase }
    );
    expect(result.verified).toBe(true);
    if (result.verified) {
      expect(result.document.data).toBe(original);
    }
  });

  it('still decrypts a legacy V2-format chunk when a passphrase is available', async () => {
    const original = 'v2 encrypted chunk body';
    const ciphertext = await encryptV2Legacy(original, passphrase, false);
    const result = await decryptIncomingDocument(
      { _id: 'h:v2chunk', _rev: '1-v2', type: 'leaf', data: ciphertext },
      { encryptionPassphrase: passphrase, pbkdf2salt: saltHex }
    );
    expect(result.verified).toBe(true);
    if (result.verified) {
      expect(result.document.data).toBe(original);
    }
  });

  it('still decrypts HKDF "%=" chunks when a passphrase is available', async () => {
    const original = 'hkdf encrypted chunk body';
    const ciphertext = await encryptHkdf(original, passphrase, saltBytes);
    const result = await decryptIncomingDocument(
      { _id: 'h:chunk', _rev: '1-h', type: 'leaf', data: ciphertext, e_: true },
      { encryptionPassphrase: passphrase, algorithm: 'v2', pbkdf2salt: saltHex }
    );
    expect(result.verified).toBe(true);
    if (result.verified) {
      expect(result.document.data).toBe(original);
    }
  });

  it('fails closed for an e_-flagged chunk without a passphrase', async () => {
    const ciphertext = await encryptHkdf('secret', passphrase, saltBytes);
    const result = await decryptIncomingDocument(
      { _id: 'h:enc', _rev: '1-e', type: 'leaf', data: ciphertext, e_: true },
      {}
    );
    expect(result.verified).toBe(false);
    if (!result.verified) {
      expect(result.error).toContain('no passphrase was provided');
    }
  });

  it('fails closed for a strict V1-envelope chunk without a passphrase', async () => {
    const ciphertext = await encryptV1('secret legacy', passphrase, false);
    const result = await decryptIncomingDocument(
      { _id: 'h:v1enc', _rev: '1-v1', type: 'leaf', data: ciphertext },
      {}
    );
    expect(result.verified).toBe(false);
    if (!result.verified) {
      expect(result.error).toContain('no passphrase was provided');
    }
  });

  it('decrypts obfuscated-path documents as before (heuristic unaffected for real ciphertext)', async () => {
    const original = 'obfuscated note body';
    const obfuscatedPath = await obfuscatePath('Notes/Secret.md', passphrase, false);
    const result = await decryptIncomingDocument(
      { _id: 'f:abcdef', _rev: '1-o', type: 'plain', path: obfuscatedPath, data: original },
      { encryptionPassphrase: passphrase, pbkdf2salt: saltHex }
    );
    expect(result.verified).toBe(true);
    if (result.verified) {
      expect(result.document.path).toBe('Notes/Secret.md');
      expect(result.document.data).toBe(original);
    }
  });

  it('leaves plain unobfuscated paths untouched', async () => {
    const result = await decryptIncomingDocument(
      { _id: 'Welcome.md', _rev: '1-w', type: 'plain', path: 'Welcome.md', data: 'body' },
      { encryptionPassphrase: passphrase }
    );
    expect(result.verified).toBe(true);
    if (result.verified) {
      expect(result.document.path).toBe('Welcome.md');
      expect(result.document.data).toBe('body');
    }
  });
});

describe('syncinfo strict encryption detection', () => {
  const passphrase = 'correct-e2ee-passphrase';
  const saltBytes = createPBKDF2Salt();
  const saltHex = uint8ArrayToHexString(saltBytes);

  it('verifies a syncinfo doc whose data is plaintext starting with "["', async () => {
    const res = await verifySyncinfo(
      { _id: 'syncinfo', _rev: '1-s', data: '[not ciphertext just markdown]' },
      null
    );
    expect(res.verified).toBe(true);
    expect(res.decryptedData).toBe('[not ciphertext just markdown]');
  });

  it('verifies a syncinfo doc whose data is plaintext starting with "%"', async () => {
    const res = await verifySyncinfo(
      { _id: 'syncinfo', _rev: '1-s', data: '% heading not ciphertext' },
      null
    );
    expect(res.verified).toBe(true);
    expect(res.decryptedData).toBe('% heading not ciphertext');
  });

  it('still fails closed for a genuinely HKDF-encrypted syncinfo without a passphrase', async () => {
    const encryptedData = await encryptHkdf('{"vault":"v"}', passphrase, saltBytes);
    const res = await verifySyncinfo(
      { _id: 'syncinfo', _rev: '1-s', data: encryptedData },
      { _id: 'params', _rev: '1-p', pbkdf2salt: saltHex },
      undefined
    );
    expect(res.verified).toBe(false);
    expect(res.error).toContain('no passphrase was provided');
  });

  it('still authenticates a passphrase against an HKDF-encrypted syncinfo', async () => {
    const payload = '{"vault":"v"}';
    const encryptedData = await encryptHkdf(payload, passphrase, saltBytes);
    const res = await verifySyncinfo(
      { _id: 'syncinfo', _rev: '1-s', data: encryptedData },
      { _id: 'params', _rev: '1-p', pbkdf2salt: saltHex },
      passphrase
    );
    expect(res.verified).toBe(true);
    expect(res.decryptedData).toBe(payload);
  });

  it('still detects a legacy V1-envelope syncinfo as encrypted', async () => {
    const encryptedData = await encryptV1('{"vault":"v1"}', passphrase, false);
    const res = await verifySyncinfo(
      { _id: 'syncinfo', _rev: '1-s', data: encryptedData },
      null,
      undefined
    );
    expect(res.verified).toBe(false);
    expect(res.error).toContain('no passphrase was provided');
  });
});
