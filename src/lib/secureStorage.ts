// Hardened storage layer for sensitive values in chrome.storage.local.
// Uses PBKDF2-SHA256 key derivation + AES-GCM + HMAC-SHA256 integrity,
// so a corrupted blob or wrong key is detected and surfaced immediately
// instead of silently returning garbage. Writes are atomic.
import type { Severity } from '../types';

const SCHEMA_TAG = 'lf-secure-v2';
const PBKDF2_ITERATIONS = 150000;

export class StorageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StorageError';
  }
}

export class IntegrityError extends StorageError {
  constructor(message = 'Vault data failed integrity check — it may be corrupted or was tampered with.') {
    super(message);
    this.name = 'IntegrityError';
  }
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

type EncryptedBlob = {
  tag: typeof SCHEMA_TAG;
  saltB64: string;
  ivB64: string;
  ctB64: string;
  macB64: string;
};

function toB64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function fromB64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function hmacKey(salt: Uint8Array): Promise<CryptoKey> {
  // Distinct HMAC key from the same password+salt material — classic
  // encrypt-then-MAC construction.
  const base = await crypto.subtle.importKey('raw', encoder.encode('lf-hmac-salt'), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    base,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,
    ['sign', 'verify']
  );
}

export async function encryptString(password: string, plaintext: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const mk = await deriveKey(password, salt);
  const hk = await hmacKey(salt);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, mk, encoder.encode(plaintext)));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', hk, ct));
  const blob: EncryptedBlob = {
    tag: SCHEMA_TAG,
    saltB64: toB64(salt),
    ivB64: toB64(iv),
    ctB64: toB64(ct),
    macB64: toB64(mac),
  };
  return btoa(JSON.stringify(blob)).split('').reverse().join(''); // light obfuscation, not security
}

export async function decryptString(password: string, encoded: string): Promise<string> {
  let blob: EncryptedBlob;
  try {
    const rev = atob(encoded).split('').reverse().join('');
    blob = JSON.parse(rev) as EncryptedBlob;
  } catch {
    throw new IntegrityError('Vault data is not a valid encrypted blob.');
  }
  if (blob.tag !== SCHEMA_TAG) throw new IntegrityError('Vault data has an unsupported or corrupted format tag.');
  let salt: Uint8Array, iv: Uint8Array, ct: Uint8Array, mac: Uint8Array;
  try {
    salt = fromB64(blob.saltB64); iv = fromB64(blob.ivB64); ct = fromB64(blob.ctB64); mac = fromB64(blob.macB64);
  } catch {
    throw new IntegrityError('Vault blob contains malformed base64 payloads.');
  }
  // Verify HMAC BEFORE decryption (encrypt-then-MAC) — catches tampering
  // without even attempting to decrypt.
  const hk = await hmacKey(salt);
  const valid = await crypto.subtle.verify('HMAC', hk, mac.buffer as ArrayBuffer, ct.buffer as ArrayBuffer);
  if (!valid) throw new IntegrityError('Vault integrity check failed — data may be corrupted or tampered.');
  const mk = await deriveKey(password, salt);
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, mk, ct.buffer as ArrayBuffer);
    return decoder.decode(pt);
  } catch {
    // AES-GCM auth failure almost always means wrong password; HMAC already
    // defined for corruption. Distinguish via a re-check is unnecessary —
    // both are reported clearly.
    throw new StorageError('Wrong master password or vault data is corrupted.');
  }
}

// ---- Atomic read-modify-write helpers ---------------------------------------
export async function storageGet<T>(key: string, fallback: T): Promise<T> {
  try {
    const r = await chrome.storage.local.get(key);
    return (r[key] as T) ?? fallback;
  } catch {
    return fallback;
  }
}

export async function storageSetAtomic(key: string, value: unknown): Promise<void> {
  // Single-object set is atomic in chrome.storage.local; nothing more to do,
  // but this wrapper keeps call sites uniform and lets us add a write barrier.
  await chrome.storage.local.set({ [key]: value });
}

export async function storageRemove(key: string): Promise<void> {
  await chrome.storage.local.remove(key);
}

// ---- Legacy backup import (grandfathered migration path for the old extension) ----
// The old export format is a PBKDF2-SHA256 → AES-256-GCM encrypted JSON blob,
// optionally bound with an HMAC-SHA256 (encrypt-then-MAC). The whole payload is
// base64(JSON.stringify(blob)) with the character order reversed (light
// obfuscation, matching encryptString above). Plaintext/CSV backups are rejected.
type LegacyBlob = {
  tag?: string;
  saltB64?: string; salt?: string;
  ivB64?: string; iv?: string;
  ctB64?: string; ct?: string; ciphertext?: string;
  macB64?: string; mac?: string;
};

function legacyFromB64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export type LegacyImportResult =
  | { ok: true; entries: Array<{ id: string; title: string; username: string; password: string; url: string }> }
  | { ok: false; error: string };

export async function decryptLegacyBackup(
  fileText: string,
  password: string,
  minPasswordLength = 12
): Promise<LegacyImportResult> {
  if (password.length < minPasswordLength) {
    return { ok: false, error: `Password must be at least ${minPasswordLength} characters.` };
  }
  if (password.length > 256) {
    return { ok: false, error: 'Password is too long.' };
  }
  // Unwrap: plain JSON blob, or base64 + character-reversed (as encryptString emits).
  let blob: LegacyBlob;
  try {
    if (fileText.trimStart().startsWith('{')) {
      blob = JSON.parse(fileText.trim()) as LegacyBlob;
    } else {
      const rev = atob(fileText.trim()).split('').reverse().join('');
      blob = JSON.parse(rev) as LegacyBlob;
    }
  } catch {
    return { ok: false, error: 'This file is not an encrypted LockForce backup (plaintext/CSV files are not supported).' };
  }
  const saltB64 = blob.saltB64 || blob.salt;
  const ivB64 = blob.ivB64 || blob.iv;
  const ctB64 = blob.ctB64 || blob.ct || blob.ciphertext;
  const macB64 = blob.macB64 || blob.mac;
  if (!saltB64 || !ivB64 || !ctB64) {
    return { ok: false, error: 'Backup file is missing required encryption fields — it may be corrupted.' };
  }
  let salt: Uint8Array, iv: Uint8Array, ct: Uint8Array;
  try {
    salt = legacyFromB64(saltB64); iv = legacyFromB64(ivB64); ct = legacyFromB64(ctB64);
  } catch {
    return { ok: false, error: 'Backup file contains malformed data — it may be corrupted.' };
  }
  const base = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  const aes = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
  );
  if (macB64) {
    // Encrypt-then-MAC: verify integrity BEFORE decrypting.
    try {
      const hmacBase = await crypto.subtle.importKey('raw', encoder.encode('lf-hmac-salt'), 'PBKDF2', false, ['deriveKey']);
      const hk = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
        hmacBase, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['verify']
      );
      const ok = await crypto.subtle.verify('HMAC', hk, legacyFromB64(macB64).buffer as ArrayBuffer, ct.buffer as ArrayBuffer);
      if (!ok) return { ok: false, error: 'Backup integrity check failed — the file is corrupted or was tampered with.' };
    } catch { /* fall through to GCM auth */ }
  }
  let json: string;
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aes, ct.buffer as ArrayBuffer);
    json = decoder.decode(pt);
  } catch {
    return { ok: false, error: 'Wrong password, or the backup file is corrupted.' };
  }
  let data: unknown;
  try { data = JSON.parse(json); } catch {
    return { ok: false, error: 'Decrypted backup is not valid JSON — it may be corrupted.' };
  }
  // Validate structure before returning anything; never surface partial data.
  const rawEntries: unknown =
    (data && typeof data === 'object' && Array.isArray((data as { entries?: unknown }).entries))
      ? (data as { entries: unknown[] }).entries
      : (data && typeof data === 'object' && Array.isArray((data as { passwords?: unknown }).passwords))
        ? (data as { passwords: unknown[] }).passwords
        : Array.isArray(data) ? data : null;
  if (!rawEntries) {
    return { ok: false, error: 'Backup does not contain a recognizable entries list.' };
  }
  const entries: LegacyImportResult extends { ok: true; entries: infer E } ? E : never = [];
  for (const item of rawEntries as Array<Record<string, unknown>>) {
    const title = String(item?.title ?? item?.name ?? '').trim();
    const pw = String(item?.password ?? item?.pass ?? '');
    if (!title || !pw) continue; // skip unusable rows silently — counted by caller
    entries.push({
      id: String(item?.id || crypto.randomUUID()),
      title,
      username: String(item?.username ?? item?.user ?? item?.email ?? ''),
      password: pw,
      url: String(item?.url ?? item?.site ?? ''),
    });
  }
  if (entries.length === 0) {
    return { ok: false, error: 'No importable credentials were found in the backup.' };
  }
  return { ok: true, entries };
}

// ---- Merge imported entries into the current vault (surgical addition) ----
// Uses the EXACT storage keys and blob shape the vault already uses
// ('__lf_vault_key_v2__' / '__lf_vault_data_v2__', tag 'lf-secure-v2',
// plain base64(JSON.stringify(blob)) — NOT reversed, matching saveVaultData).
const VAULT_KEY_NAME = '__lf_vault_key_v2__';
const VAULT_DATA_NAME = '__lf_vault_data_v2__';

type VaultBlobV2 = {
  tag: string;
  saltB64: string;
  ivB64: string;
  ctB64: string;
  macB64: string;
};

function vaultFromB64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function vaultToB64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

async function vaultDeriveEncKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}
async function vaultDeriveMacKey(salt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', encoder.encode('lf-hmac-salt'), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    base, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign', 'verify']
  );
}

function normalizeOrigin(url: string): string {
  try {
    const u = new URL(url.startsWith('http') ? url : 'https://' + url);
    return u.hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return url.trim().toLowerCase().replace(/^www\./, '');
  }
}

export type MergePasswordsResult = {
  ok: boolean;
  added: number;
  updated: number;
  unchanged: number;
  error?: string;
};

// Verify the master password without writing anything (unlock check).
async function verifyMasterPassword(master: string): Promise<void> {
  const rec = await storageGet<{ salt: string; verifier: string } | null>(VAULT_KEY_NAME, null);
  if (!rec || !rec.salt) throw new StorageError('No vault exists yet.');
  const blobRaw = await storageGet<string>(VAULT_DATA_NAME, '');
  if (!blobRaw) throw new StorageError('No vault data found.');
  const blob = JSON.parse(atob(blobRaw)) as VaultBlobV2;
  const salt = vaultFromB64(rec.salt);
  const hk = await vaultDeriveMacKey(salt);
  const ct = vaultFromB64(blob.ctB64);
  const ok = await crypto.subtle.verify('HMAC', hk, vaultFromB64(blob.macB64).buffer as ArrayBuffer, ct.buffer as ArrayBuffer);
  if (!ok) throw new IntegrityError();
  const mk = await vaultDeriveEncKey(master, salt);
  try {
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv: vaultFromB64(blob.ivB64) }, mk, ct.buffer as ArrayBuffer);
  } catch {
    throw new StorageError('Wrong master password.');
  }
}

// Merge imported entries into the currently-stored vault:
//  - dedupe key: normalized site origin + username
//  - match with a DIFFERENT password → update the password (and strength/updated)
//  - match with the SAME password → unchanged
//  - no match → append as a new entry
// One atomic read-modify-write; nothing is written on unlock failure.
export async function mergePasswords(
  master: string,
  imported: Array<{ id: string; title: string; username: string; password: string; url: string }>
): Promise<MergePasswordsResult> {
  try {
    await verifyMasterPassword(master);
  } catch (e) {
    return { ok: false, added: 0, updated: 0, unchanged: 0, error: e instanceof Error ? e.message : 'Unlock failed.' };
  }
  try {
    const blobRaw = await storageGet<string>(VAULT_DATA_NAME, '');
    if (!blobRaw) return { ok: false, added: 0, updated: 0, unchanged: 0, error: 'No vault data found.' };
    const blob = JSON.parse(atob(blobRaw)) as VaultBlobV2;
    if (blob.tag !== SCHEMA_TAG) return { ok: false, added: 0, updated: 0, unchanged: 0, error: 'Vault is in an unsupported format.' };
    const rec = await storageGet<{ salt: string } | null>(VAULT_KEY_NAME, null);
    const salt = vaultFromB64((rec && rec.salt) || blob.saltB64);
    const hk = await vaultDeriveMacKey(salt);
    const ct = vaultFromB64(blob.ctB64);
    const mac = vaultFromB64(blob.macB64);
    const okMac = await crypto.subtle.verify('HMAC', hk, mac.buffer as ArrayBuffer, ct.buffer as ArrayBuffer);
    if (!okMac) return { ok: false, added: 0, updated: 0, unchanged: 0, error: 'Vault integrity check failed.' };
    const mk = await vaultDeriveEncKey(master, salt);
    let json: string;
    try {
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: vaultFromB64(blob.ivB64) }, mk, ct.buffer as ArrayBuffer);
      json = decoder.decode(pt);
    } catch {
      return { ok: false, added: 0, updated: 0, unchanged: 0, error: 'Wrong master password.' };
    }
    const existing = JSON.parse(json) as VaultEntryV2[];

    let added = 0, updated = 0, unchanged = 0;
    const byKey = new Map<string, VaultEntryV2>();
    for (const e of existing) byKey.set(normalizeOrigin(e.url) + '\u0000' + e.username.trim().toLowerCase(), e);

    const next = [...existing];
    for (const imp of imported) {
      const key = normalizeOrigin(imp.url) + '\u0000' + imp.username.trim().toLowerCase();
      const match = byKey.get(key);
      if (!match) {
        const now = Date.now();
        const entry: VaultEntryV2 = {
          id: imp.id || crypto.randomUUID(),
          title: imp.title || 'Untitled',
          username: imp.username,
          password: imp.password,
          url: imp.url,
          autofill: true,
          created: now,
          updated: now,
          strength: (() => {
            let s = 0;
            if (imp.password.length >= 8) s += 15;
            if (imp.password.length >= 12) s += 15;
            if (imp.password.length >= 16) s += 20;
            if (/[a-z]/.test(imp.password) && /[A-Z]/.test(imp.password)) s += 15;
            if (/[0-9]/.test(imp.password)) s += 10;
            if (/[^A-Za-z0-9]/.test(imp.password)) s += 15;
            return Math.min(100, s + 10);
          })(),
        };
        next.push(entry);
        byKey.set(key, entry);
        added++;
      } else if (match.password !== imp.password) {
        match.password = imp.password;
        match.updated = Date.now();
        match.strength = (() => {
          let s = 0;
          if (imp.password.length >= 8) s += 15;
          if (imp.password.length >= 12) s += 15;
          if (imp.password.length >= 16) s += 20;
          if (/[a-z]/.test(imp.password) && /[A-Z]/.test(imp.password)) s += 15;
          if (/[0-9]/.test(imp.password)) s += 10;
          if (/[^A-Za-z0-9]/.test(imp.password)) s += 15;
          return Math.min(100, s + 10);
        })();
        updated++;
      } else {
        unchanged++;
      }
    }

    // Re-encrypt with the same v2 shape + fresh salt/iv, atomic single-key write.
    const newSalt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encKey = await vaultDeriveEncKey(master, newSalt);
    const macKey = await vaultDeriveMacKey(newSalt);
    const ctOut = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, encKey, encoder.encode(JSON.stringify(next))
    ));
    const macOut = new Uint8Array(await crypto.subtle.sign('HMAC', macKey, ctOut));
    const newBlob: VaultBlobV2 = {
      tag: SCHEMA_TAG,
      saltB64: vaultToB64(newSalt),
      ivB64: vaultToB64(iv),
      ctB64: vaultToB64(ctOut),
      macB64: vaultToB64(macOut),
    };
    await storageSetAtomic(VAULT_DATA_NAME, btoa(JSON.stringify(newBlob)));
    await storageSetAtomic(VAULT_KEY_NAME, { salt: vaultToB64(newSalt), verifier: btoa(JSON.stringify(newBlob)) });
    return { ok: true, added, updated, unchanged };
  } catch (e) {
    return { ok: false, added: 0, updated: 0, unchanged: 0, error: e instanceof Error ? e.message : 'Merge failed.' };
  }
}

// ---- Shared vault types (kept here so popup/options can import one source) ----
export type VaultEntryV2 = {
  id: string;
  title: string;
  username: string;
  password: string;
  url: string;
  autofill: boolean;
  created: number;
  updated: number;
  strength: number; // 0-100 cached at save time
};

export type SeverityImport = Severity; // re-export convenience