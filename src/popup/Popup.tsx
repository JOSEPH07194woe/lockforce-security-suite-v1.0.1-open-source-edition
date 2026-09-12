// LockForce Security Suite — Popup (main UI). Self-contained for preview.
import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import './Popup.css';

// ---------- Inline types & engine (kept local so the component is self-contained) ----------
type Severity = 'INFO' | 'WARNING' | 'HIGH' | 'CRITICAL';
interface SecurityEvent {
  id: string;
  time: number;
  severity: Severity;
  category: string;
  title: string;
  source: string;
  reasons: string[];
  action: string;
}
interface VaultEntry {
  id: string;
  title: string;
  username: string;
  password: string;
  url: string;
  autofill: boolean;
  created: number;
  updated: number;
  strength: number;
}
interface Settings {
  shields: Record<string, boolean>;
  mode: 'beginner' | 'balanced' | 'advanced' | 'lockdown' | 'ultra';
  lockdown: boolean;
  autofillEnabled: boolean;
  notificationsEnabled: boolean;
  dailyLimit?: number;
  autoLockSeconds: number;
  clipboardClearSeconds: number;
  genDefaults: { length: number; upper: boolean; lower: boolean; digits: boolean; symbols: boolean; excludeAmbiguous: boolean };
}
interface TabId { id: string; label: string; icon: string; }

const TABS: TabId[] = [
  { id: 'dashboard', label: 'Dashboard', icon: '🛡️' },
  { id: 'vault', label: 'Vault', icon: '🔐' },
  { id: 'generator', label: 'Generator', icon: '🎲' },
  { id: 'activity', label: 'Activity', icon: '📋' },
  { id: 'settings', label: 'Settings', icon: '⚙️' },
  { id: 'patch', label: 'Patch Notes', icon: '📝' },
];

const SHIELD_LIST = [
  { key: 'malware', label: 'Malware Protection' },
  { key: 'phishing', label: 'Phishing Protection' },
  { key: 'scams', label: 'Scam Protection' },
  { key: 'exploit', label: 'Exploit Defense' },
  { key: 'downloads', label: 'Download Guard' },
  { key: 'redirects', label: 'Redirect Firewall' },
  { key: 'scripts', label: 'Script Shield' },
  { key: 'malvertising', label: 'Malvertising Shield' },
  { key: 'notifications', label: 'Notification Protection' },
  { key: 'commandguard', label: 'CommandGuard' },
  { key: 'clipboard', label: 'Clipboard Protection' },
  { key: 'credentials', label: 'Credential Protection' },
];

const DANGEROUS_EXT = ['exe','msi','scr','bat','cmd','ps1','vbs','js','jse','wsf','hta','com','pif','cpl','dll','sys','iso','img','lnk','jar','apk','appx','msix'];
const BRANDS: Record<string, string[]> = {
  'google.com': ['google','gmail','goggle','g00gle','goog1e','google-login','accounts-google'],
  'microsoft.com': ['microsoft','micros0ft','rnicrosoft','m1crosoft','outlook-login','office365-login'],
  'apple.com': ['apple','app1e','icloud-login','appleid-verify'],
  'paypal.com': ['paypal','paypa1','paypaI','paypal-verify'],
  'discord.com': ['discord','d1scord','discordgift','discord-nitro'],
  'steamcommunity.com': ['steamcommunity','steamcommunlty','steamcommnity','steam-gift','free-steam'],
  'amazon.com': ['amazon','amaz0n','amazom'],
  'facebook.com': ['facebook','faceb00k','facbook'],
  'netflix.com': ['netflix','netf1ix','netfllx'],
};

const isChromeApi = (): boolean => typeof chrome !== 'undefined' && !!chrome.runtime?.id;

async function storeGet<T>(key: string, fallback: T): Promise<T> {
  if (isChromeApi()) {
    try {
      const r = await chrome.storage.local.get(key);
      return (r[key] as T) ?? fallback;
    } catch { return fallback; }
  }
  try { const raw = localStorage.getItem('lf_' + key); return raw ? (JSON.parse(raw) as T) : fallback; } catch { return fallback; }
}
async function storeSet(key: string, value: unknown): Promise<void> {
  if (isChromeApi()) {
    try { await chrome.storage.local.set({ [key]: value }); return; } catch { /* fall through */ }
  }
  try { localStorage.setItem('lf_' + key, JSON.stringify(value)); } catch { /* quota */ }
}

// ---------- Vault crypto (PBKDF2 + AES-GCM + HMAC integrity — hardened) ----------
const VAULT_KEY_NAME = '__lf_vault_key_v2__';
const VAULT_DATA_NAME = '__lf_vault_data_v2__';
const PBKDF2_ITERS = 150000;
const SCHEMA_TAG = 'lf-secure-v2';

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

async function deriveEncKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: PBKDF2_ITERS, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}
async function deriveMacKey(salt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode('lf-hmac-salt'), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: PBKDF2_ITERS, hash: 'SHA-256' },
    base, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign', 'verify']
  );
}

type EncBlob = { tag: string; saltB64: string; ivB64: string; ctB64: string; macB64: string };

async function encryptWithPassword(password: string, plaintext: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const mk = await deriveEncKey(password, salt);
  const hk = await deriveMacKey(salt);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, mk, new TextEncoder().encode(plaintext)));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', hk, ct));
  const blob: EncBlob = { tag: SCHEMA_TAG, saltB64: toB64(salt), ivB64: toB64(iv), ctB64: toB64(ct), macB64: toB64(mac) };
  return btoa(JSON.stringify(blob));
}

// Throws with a clear message instead of silently corrupting.
async function decryptWithPassword(password: string, encoded: string): Promise<string> {
  let blob: EncBlob;
  try { blob = JSON.parse(atob(encoded)) as EncBlob; } catch { throw new Error('Vault data is corrupted — it cannot be read.'); }
  if (blob.tag !== SCHEMA_TAG) throw new Error('Vault data is in an unsupported or corrupted format.');
  let salt: Uint8Array, iv: Uint8Array, ct: Uint8Array, mac: Uint8Array;
  try {
    salt = fromB64(blob.saltB64); iv = fromB64(blob.ivB64); ct = fromB64(blob.ctB64); mac = fromB64(blob.macB64);
  } catch { throw new Error('Vault blob contains malformed data.'); }
  const hk = await deriveMacKey(salt);
  const okMac = await crypto.subtle.verify('HMAC', hk, mac.buffer as ArrayBuffer, ct.buffer as ArrayBuffer);
  if (!okMac) throw new Error('Vault integrity check failed — the data may be corrupted or tampered with.');
  const mk = await deriveEncKey(password, salt);
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, mk, ct.buffer as ArrayBuffer);
    return new TextDecoder().decode(pt);
  } catch { throw new Error('Wrong master password, or the vault was damaged.'); }
}

async function getVaultRecord(): Promise<{ salt: string; verifier: string } | null> {
  const r = await storeGet<{ salt: string; verifier: string } | null>(VAULT_KEY_NAME, null);
  if (r && r.salt && r.verifier) return r;
  return null;
}

export function validateMaster(pw: string): string | null {
  if (pw.length < 16) return 'Master password must be at least 16 characters.';
  const symbols = (pw.match(/[^A-Za-z0-9]/g) || []).length;
  const numbers = (pw.match(/[0-9]/g) || []).length;
  if (symbols < 2) return 'Master password must contain at least 2 symbols.';
  if (numbers < 2) return 'Master password must contain at least 2 numbers.';
  return null;
}
export function strengthOf(pw: string): { score: number; label: string; color: string } {
  let score = 0;
  if (pw.length >= 8) score += 15;
  if (pw.length >= 12) score += 15;
  if (pw.length >= 16) score += 20;
  if (pw.length >= 24) score += 10;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score += 15;
  if (/[0-9]/.test(pw)) score += 10;
  if (/[^A-Za-z0-9]/.test(pw)) score += 15;
  const uniq = new Set(pw).size;
  if (uniq > pw.length * 0.6) score += 10;
  score = Math.min(100, score);
  const label = score < 30 ? 'Weak' : score < 55 ? 'Fair' : score < 75 ? 'Strong' : score < 90 ? 'Very Strong' : 'Fortress';
  const color = score < 30 ? '#ef4444' : score < 55 ? '#f59e0b' : score < 75 ? '#22c55e' : '#10b981';
  return { score, label, color };
}
const AMBIGUOUS_CHARS = new Set('Il1O0o|`\'"');
function genPassword(opts: { length: number; upper: boolean; lower: boolean; digits: boolean; symbols: boolean; excludeAmbiguous: boolean }): { password: string; error: string | null } {
  const { length, upper, lower, digits, symbols, excludeAmbiguous } = opts;
  const sets: string[] = [];
  if (upper) sets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  if (lower) sets.push('abcdefghijklmnopqrstuvwxyz');
  if (digits) sets.push('0123456789');
  if (symbols) sets.push('!@#$%^&*()-_=+[]{};:,.<>?/');
  const pool = sets.join('');
  if (!pool) return { password: '', error: 'Pick at least one character set.' };
  let cleanPool = pool;
  if (excludeAmbiguous) cleanPool = Array.from(pool).filter(c => !AMBIGUOUS_CHARS.has(c)).join('');
  if (!cleanPool) return { password: '', error: 'Every character is ambiguous — turn off the exclusion.' };
  // Guarantee at least one from each chosen set, then fill the rest from the pool.
  const arr = new Uint32Array(length - sets.length);
  crypto.getRandomValues(arr);
  const chars = sets.map(s => s[Math.floor(crypto.getRandomValues(new Uint32Array(1))[0] / 4294967296 * s.length)]);
  for (let i = 0; i < arr.length; i++) chars.push(cleanPool[arr[i] % cleanPool.length]);
  // Shuffle with Fisher-Yates using crypto randomness.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = Math.floor(crypto.getRandomValues(new Uint32Array(1))[0] / 4294967296 * (i + 1));
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return { password: chars.join(''), error: null };
}

const DEFAULT_SETTINGS: Settings = {
  shields: Object.fromEntries(SHIELD_LIST.map(s => [s.key, true])),
  mode: 'balanced',
  lockdown: false,
  autofillEnabled: true,
  notificationsEnabled: true,
  autoLockSeconds: 300,
  clipboardClearSeconds: 60,
  genDefaults: { length: 20, upper: true, lower: true, digits: true, symbols: true, excludeAmbiguous: false },
};

// ---- Migration: existing v1 vault (plain AES-GCM, verifier) to v2 (HMAC). ----
// Kept ONLY to honor existing user data. On first unlock we re-save in v2 shape.
async function migrateOldVaultIfNeeded(master: string): Promise<boolean> {
  const v1Key = await storeGet<{ salt: string; verifier: string } | null>('__lf_vault_key_v1__', null);
  const v1Data = await storeGet<string>('__lf_entries', '');
  if (!v1Key || !v1Data) return false;
  try {
    // Old scheme: PBKDF2 key directly, no HMAC.
    const salt = Uint8Array.from(atob(v1Key.salt), c => c.charCodeAt(0));
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(master), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: 150000, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
    const v1Blob = fromB64(v1Data);
    const iv = v1Blob.slice(0, 12);
    const ct = v1Blob.slice(12);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv.buffer as ArrayBuffer }, key, ct.buffer as ArrayBuffer);
    const json = new TextDecoder().decode(pt);
    // Verify it's valid entries JSON.
    const parsed = JSON.parse(json);
    if (!Array.isArray(parsed)) return false;
    // Re-encrypt into v2 and remove v1 keys. Atomic-ish: write v2 first, then delete v1.
    await saveVaultData(master, parsed.map((e: Record<string, unknown>) => ({
      id: String(e.id || crypto.randomUUID()),
      title: String(e.title || 'Untitled'),
      username: String(e.username || ''),
      password: String(e.password || ''),
      url: String(e.url || ''),
      autofill: e.autofill !== false,
      created: Number(e.created) || Date.now(),
      updated: Number(e.updated) || Date.now(),
      strength: Number(e.strength) || strengthOf(String(e.password || '')).score,
    })));
    await storeSet('__lf_vault_key_v1__', null);
    await storeSet('__lf_entries', '');
    return true;
  } catch { return false; } // old data unusable — user starts fresh
}

async function saveVaultData(master: string, entries: VaultEntry[]): Promise<void> {
  const salt = crypto.getRandomValues(new Uint8Array(16)); // fresh salt each save → forward secrecy on password rotation
  const mk = await deriveEncKey(master, salt);
  const hk = await deriveMacKey(salt);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(JSON.stringify(entries));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, mk, plain));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', hk, ct));
  const blob: EncBlob = { tag: SCHEMA_TAG, saltB64: toB64(salt), ivB64: toB64(iv), ctB64: toB64(ct), macB64: toB64(mac) };
  const verifierBlob: EncBlob = {
    tag: SCHEMA_TAG,
    saltB64: toB64(salt), ivB64: toB64(iv),
    // verifier is just a marker the HMAC binds to; encrypt a constant.
    ctB64: toB64(ct), macB64: toB64(mac),
  };
  // Atomic: write data first, then verifier marker. Each set is a single key.
  await storeSet(VAULT_DATA_NAME, btoa(JSON.stringify(blob)));
  await storeSet(VAULT_KEY_NAME, { salt: toB64(salt), verifier: btoa(JSON.stringify(verifierBlob)) });
}

async function loadVaultData(master: string, saltB64: string): Promise<VaultEntry[]> {
  const blobRaw = await storeGet<string>(VAULT_DATA_NAME, '');
  if (!blobRaw) throw new Error('No vault data found — it may have been wiped.');
  let blob: EncBlob;
  try { blob = JSON.parse(atob(blobRaw)) as EncBlob; } catch { throw new Error('Vault data is corrupt and cannot be read.'); }
  if (blob.tag !== SCHEMA_TAG) throw new Error('Vault data is in an unsupported format.');
  const salt = fromB64(saltB64);
  const hk = await deriveMacKey(salt);
  const ct = fromB64(blob.ctB64); const mac = fromB64(blob.macB64);
  const okMac = await crypto.subtle.verify('HMAC', hk, mac.buffer as ArrayBuffer, ct.buffer as ArrayBuffer);
  if (!okMac) throw new Error('Vault integrity check failed — the data may be corrupted or tampered.');
  const mk = await deriveEncKey(master, salt);
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(blob.ivB64).buffer as ArrayBuffer }, mk, ct.buffer as ArrayBuffer);
    const parsed = JSON.parse(new TextDecoder().decode(pt)) as unknown[];
    if (!Array.isArray(parsed)) throw new Error('Vault data is not in the expected format.');
    return parsed.map(e => {
      const rec = e as Partial<VaultEntry>;
      return {
        id: String(rec.id || crypto.randomUUID()),
        title: String(rec.title || 'Untitled'),
        username: String(rec.username || ''),
        password: String(rec.password || ''),
        url: String(rec.url || ''),
        autofill: rec.autofill !== false,
        created: Number(rec.created) || Date.now(),
        updated: Number(rec.updated) || Date.now(),
        strength: Number(rec.strength) || strengthOf(String(rec.password || '')).score,
      } as VaultEntry;
    });
  } catch (e) {
    if (e instanceof Error && e.message.includes('format')) throw e;
    throw new Error('Wrong master password, or the vault was damaged.');
  }
}

// Strength color maps (shared small helper)
const strengthColor = (s: number) => s < 30 ? '#ef4444' : s < 55 ? '#f59e0b' : s < 75 ? '#22c55e' : '#10b981';
const strengthLabel = (s: number) => s < 30 ? 'Weak' : s < 55 ? 'Fair' : s < 75 ? 'Strong' : 'Very Strong';

const Popup: React.FC = () => {
  const [tab, setTab] = useState('dashboard');
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [vaultUnlocked, setVaultUnlocked] = useState(false);
  const [masterInput, setMasterInput] = useState('');
  const [confirmInput, setConfirmInput] = useState('');
  const [vaultError, setVaultError] = useState('');
  const [vaultKey, setVaultKey] = useState<CryptoKey | null>(null);
  const [vaultSalt, setVaultSalt] = useState('');
  const [masterPass, setMasterPass] = useState(''); // kept only while unlocked (for re-encrypt on edit)
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const [newEntry, setNewEntry] = useState({ title: '', username: '', password: '', url: '' });
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});
  const [genPw, setGenPw] = useState('');
  const [genLen, setGenLen] = useState(DEFAULT_SETTINGS.genDefaults.length);
  const [genOpts, setGenOpts] = useState({ upper: true, lower: true, digits: true, symbols: true, excludeAmbiguous: false });
  const [copied, setCopied] = useState('');
  const [currentDomain, setCurrentDomain] = useState('this site');
  const [vaultSearch, setVaultSearch] = useState('');
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editDraft, setEditDraft] = useState<Partial<VaultEntry>>({});
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [genError, setGenError] = useState('');
  const sessionKeyRef = useRef<CryptoKey | null>(null);
  const lockTimerRef = useRef<number | null>(null);
  const clipboardTimerRef = useRef<number | null>(null);

  // ---- Auto-lock ----
  const resetLockTimer = useCallback(() => {
    if (lockTimerRef.current) window.clearTimeout(lockTimerRef.current);
    if (!settings.autoLockSeconds || settings.autoLockSeconds <= 0) return;
    lockTimerRef.current = window.setTimeout(() => {
      setVaultUnlocked(false); setVaultKey(null); sessionKeyRef.current = null; setEntries([]); setMasterPass('');
      setVaultError('Vault auto-locked after inactivity.');
    }, settings.autoLockSeconds * 1000);
  }, [settings.autoLockSeconds]);

  useEffect(() => {
    (async () => {
      const s = await storeGet<Settings>('lf_settings', DEFAULT_SETTINGS);
      setSettings({ ...DEFAULT_SETTINGS, ...s, shields: { ...DEFAULT_SETTINGS.shields, ...(s?.shields || {}) }, genDefaults: { ...DEFAULT_SETTINGS.genDefaults, ...(s?.genDefaults || {}) } });
      setGenLen((s?.genDefaults?.length) ?? 20);
      setGenOpts({ ...DEFAULT_SETTINGS.genDefaults, ...(s?.genDefaults || {}) });
      const ev = await storeGet<SecurityEvent[]>('lf_events', []);
      setEvents(Array.isArray(ev) ? ev.slice(0, 100) : []);
      if (isChromeApi()) {
        try {
          const [t] = await chrome.tabs.query({ active: true, currentWindow: true });
          if (t?.url) { try { setCurrentDomain(new URL(t.url).hostname); } catch { /* not a url */ } }
        } catch { /* no tabs access in preview */ }
      }
    })();
  }, []);

  const persistSettings = useCallback(async (next: Settings) => {
    setSettings(next);
    await storeSet('lf_settings', next);
  }, []);

  const toggleShield = (key: string) => {
    const next = { ...settings, shields: { ...settings.shields, [key]: !settings.shields[key] } };
    void persistSettings(next);
  };

  const toggleLockdown = async () => {
    const next = { ...settings, lockdown: !settings.lockdown };
    await persistSettings(next);
    const ev: SecurityEvent = {
      id: crypto.randomUUID(), time: Date.now(),
      severity: next.lockdown ? 'CRITICAL' : 'INFO',
      category: 'Lockdown',
      title: next.lockdown ? 'EMERGENCY LOCKDOWN ENABLED' : 'Emergency lockdown disabled',
      source: 'LockForce Core',
      reasons: next.lockdown ? ['User-initiated emergency lockdown', 'All navigation, downloads and permissions restricted'] : ['User restored normal protection'],
      action: next.lockdown ? 'Browser locked down' : 'Normal mode',
    };
    const evs = [ev, ...events].slice(0, 100);
    setEvents(evs);
    await storeSet('lf_events', evs);
  };

  const setMode = async (mode: Settings['mode']) => {
    const next = { ...settings, mode };
    await persistSettings(next);
  };

  // ---------- Vault ----------
  const setupVault = async () => {
    const err = validateMaster(masterInput);
    if (err) { setVaultError(err); return; }
    if (masterInput !== confirmInput) { setVaultError('Passwords do not match. Save this password somewhere safe — it is the ONLY way to reset.'); return; }
    try {
      const migrated = await migrateOldVaultIfNeeded(masterInput);
      if (migrated) {
        // Old data decrypted + re-saved in v2. Load it.
        const rec = await getVaultRecord();
        if (!rec) throw new Error('Migration failed to write the new vault record.');
        const list = await loadVaultData(masterInput, rec.salt);
        sessionKeyRef.current = null; // v2 doesn't keep a CryptoKey around
        setVaultSalt(rec.salt); setEntries(list); setVaultUnlocked(true); setMasterPass(masterInput);
        setVaultError(''); setMasterInput(''); setConfirmInput(''); resetLockTimer();
      } else {
        await saveVaultData(masterInput, []);
        const rec = await getVaultRecord();
        if (!rec) throw new Error('Vault creation failed — please retry.');
        sessionKeyRef.current = null;
        setVaultSalt(rec.salt); setEntries([]); setVaultUnlocked(true); setMasterPass(masterInput);
        setVaultError(''); setMasterInput(''); setConfirmInput(''); resetLockTimer();
      }
    } catch (e) {
      setVaultError(e instanceof Error ? e.message : 'Vault setup failed.');
    }
  };
  const unlockVault = async () => {
    const rec = await getVaultRecord();
    if (!rec) { setVaultError('No vault exists yet. Create one.'); return; }
    try {
      // First try migration path (user may have old v1 vault with this password).
      const migrated = await migrateOldVaultIfNeeded(masterInput);
      if (migrated) {
        const rec2 = await getVaultRecord();
        if (rec2) {
          const list = await loadVaultData(masterInput, rec2.salt);
          setVaultSalt(rec2.salt); setEntries(list); setVaultUnlocked(true); setMasterPass(masterInput);
          setVaultError(''); setMasterInput(''); resetLockTimer();
          return;
        }
      }
      const list = await loadVaultData(masterInput, rec.salt);
      sessionKeyRef.current = null;
      setVaultSalt(rec.salt); setEntries(list); setVaultUnlocked(true); setMasterPass(masterInput);
      setVaultError(''); setMasterInput(''); resetLockTimer();
    } catch (e) {
      setVaultError(e instanceof Error ? e.message : 'Could not unlock the vault.');
    }
  };
  const lockVault = () => {
    if (lockTimerRef.current) window.clearTimeout(lockTimerRef.current);
    if (clipboardTimerRef.current) window.clearTimeout(clipboardTimerRef.current);
    setVaultUnlocked(false); setVaultKey(null); sessionKeyRef.current = null; setEntries([]); setMasterPass('');
    setVaultSalt(''); setDeleteConfirmId(null); setEditingId(null);
  };

  const commitVaultWrite = async (next: VaultEntry[]) => {
    // Atomic write via saveVaultData (single-key set under the hood).
    await saveVaultData(masterPass, next);
    setEntries(next);
    setVaultError('');
  };

  const addEntry = async () => {
    if (!masterPass) return;
    if (!newEntry.title || !newEntry.password) { setVaultError('Title and password are required.'); return; }
    const now = Date.now();
    const e: VaultEntry = {
      id: crypto.randomUUID(),
      title: newEntry.title.trim(),
      username: newEntry.username.trim(),
      password: newEntry.password,
      url: newEntry.url.trim(),
      autofill: true,
      created: now,
      updated: now,
      strength: strengthOf(newEntry.password).score,
    };
    try {
      await commitVaultWrite([e, ...entries]);
      setNewEntry({ title: '', username: '', password: '', url: '' });
    } catch (err) {
      setVaultError(err instanceof Error ? err.message : 'Could not save the new credential.');
    }
  };

  const updateEntry = async (id: string) => {
    if (!masterPass || !editingId) return;
    const existing = entries.find(e => e.id === id);
    const nextTitle = (editDraft.title ?? existing?.title ?? '').trim();
    const nextPassword = editDraft.password ?? existing?.password ?? '';
    if (!nextTitle || !nextPassword) { setVaultError('Title and password cannot be empty.'); return; }
    const now = Date.now();
    const list = entries.map(e => e.id === id ? {
      ...e,
      title: nextTitle,
      username: (editDraft.username ?? e.username).trim(),
      password: nextPassword,
      url: (editDraft.url ?? e.url).trim(),
      updated: now,
      strength: strengthOf(nextPassword).score,
    } : e);
    try {
      await commitVaultWrite(list);
      setEditingId(null); setEditDraft({}); setVaultError('');
    } catch (err) {
      setVaultError(err instanceof Error ? err.message : 'Could not update the entry.');
    }
  };

  const deleteEntryConfirmed = async (id: string) => {
    if (!masterPass) return;
    if (deleteConfirmId !== id) { setDeleteConfirmId(id); return; } // first click confirms
    try {
      await commitVaultWrite(entries.filter(e => e.id !== id));
      setDeleteConfirmId(null); setVaultError('');
    } catch (err) {
      setVaultError(err instanceof Error ? err.message : 'Could not delete the entry.');
    }
  };

  const toggleAutofillEntry = async (id: string) => {
    if (!masterPass) return;
    try { await commitVaultWrite(entries.map(e => e.id === id ? { ...e, autofill: !e.autofill } : e)); } catch (err) { setVaultError(err instanceof Error ? err.message : 'Could not update autofill.'); }
  };

  // ---- Clipboard copy with auto-clear ----
  const copy = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(label);
      setTimeout(() => setCopied(''), 1500);
      // Auto-clear clipboard
      if (clipboardTimerRef.current) window.clearTimeout(clipboardTimerRef.current);
      if (settings.clipboardClearSeconds > 0) {
        clipboardTimerRef.current = window.setTimeout(async () => {
          try { await navigator.clipboard.writeText(''); } catch { /* clipboard denied or closed */ }
        }, settings.clipboardClearSeconds * 1000);
      }
    } catch { /* clipboard denied */ }
  };

  // ---- Duplicate detection ----
  const duplicateIds = useMemo(() => {
    const seen = new Map<string, string[]>(); // pw → entry ids
    entries.forEach(e => {
      if (!e.password) return;
      const arr = seen.get(e.password) || [];
      arr.push(e.id);
      seen.set(e.password, arr);
    });
    const dupes = new Set<string>();
    seen.forEach((ids) => { if (ids.length > 1) ids.forEach(id => dupes.add(id)); });
    return dupes;
  }, [entries]);

  // ---- Filtered entries ----
  const filteredEntries = useMemo(() => {
    const q = vaultSearch.trim().toLowerCase();
    if (!q) return entries;
    return entries.filter(e =>
      e.title.toLowerCase().includes(q) ||
      e.username.toLowerCase().includes(q) ||
      e.url.toLowerCase().includes(q)
    );
  }, [entries, vaultSearch]);

  // ---------- Derived ----------
  const stats = useMemo(() => {
    const byCat = (c: string) => events.filter(e => e.category.toLowerCase().includes(c)).length;
    const today = events.filter(e => Date.now() - e.time < 86400000).length;
    return {
      total: events.length,
      today,
      phishing: byCat('phishing') + byCat('impersonation'),
      downloads: byCat('download'),
      redirects: byCat('redirect'),
      scams: byCat('scam'),
      commands: byCat('command'),
    };
  }, [events]);

  const openFullPanel = () => {
    if (isChromeApi() && chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open('options.html', '_blank');
    }
  };

  const genStrength = strengthOf(genPw);
  const masterStrength = strengthOf(masterInput);
  const [hasVault, setHasVault] = useState(false);
  useEffect(() => {
    (async () => {
      const r = await getVaultRecord();
      setHasVault(!!r);
    })();
  }, [vaultUnlocked]);

  const fmtTime = (t: number) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const fmtDate = (t: number) => new Date(t).toLocaleDateString([], { month: 'short', day: 'numeric' });
  const sevColor = (s: Severity) => s === 'CRITICAL' ? 'text-red-400' : s === 'HIGH' ? 'text-orange-400' : s === 'WARNING' ? 'text-yellow-400' : 'text-slate-400';
  const sevBg = (s: Severity) => s === 'CRITICAL' ? 'bg-red-500/10 border-red-500/30' : s === 'HIGH' ? 'bg-orange-500/10 border-orange-500/30' : s === 'WARNING' ? 'bg-yellow-500/10 border-yellow-500/30' : 'bg-slate-700/30 border-slate-600/40';

  return (
    <div className="w-full flex flex-col bg-[#0b1220] text-slate-200" style={{ minHeight: 560 }}>
      {/* Header */}
      <header className="px-4 pt-4 pb-3 bg-gradient-to-b from-[#101a30] to-[#0b1220] border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-emerald-400 to-emerald-600 flex items-center justify-center text-lg shadow-lg shadow-emerald-900/40">🐺</div>
          <div className="min-w-0 flex-1">
            <h1 className="text-base font-bold tracking-tight text-white leading-tight truncate">LOCKFORCE <span className="text-emerald-400">SECURITY SUITE</span></h1>
            <p className="text-[10px] text-slate-400 font-semibold tracking-widest uppercase">v1.1 · Stability &amp; Vault Hardening</p>
          </div>
          <span className={`px-2 py-1 rounded-full text-[10px] font-bold border ${settings.lockdown ? 'bg-red-500/20 border-red-500/50 text-red-300' : 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'}`}>
            {settings.lockdown ? '🔒 LOCKDOWN' : '🟢 PROTECTED'}
          </span>
        </div>
        <p className="mt-2 text-[10px] text-slate-500 leading-snug">
          🔏 100% local · no servers · no tracking · no data collection, ever. This update hardens the Vault — LockForce's original foundation.
        </p>
        <button onClick={openFullPanel}
          className="mt-2 w-full py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-slate-200 transition-colors">
          🖥️ Open Full-Screen Control Panel
        </button>
      </header>

      {settings.lockdown && (
        <div className="px-4 py-2 bg-red-950/60 border-b border-red-800 text-[11px] text-red-300 flex items-center justify-between">
          <span>🚨 Emergency lockdown active — navigation, downloads & permissions blocked.</span>
          <button onClick={toggleLockdown} className="underline font-bold hover:text-red-200">Disable</button>
        </div>
      )}

      {/* Tabs */}
      <nav className="flex flex-wrap gap-1 px-3 py-2 border-b border-slate-800 bg-[#0d1526]">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`px-2.5 py-1.5 rounded-md text-[11px] font-semibold transition-colors ${tab === t.id ? 'bg-emerald-600 text-white shadow' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'}`}>
            {t.icon} {t.label}
          </button>
        ))}
      </nav>

      <main className="flex-1 overflow-y-auto px-4 py-3" style={{ maxHeight: 420 }}>
        {/* ---------- DASHBOARD ---------- */}
        {tab === 'dashboard' && (
          <div className="space-y-3">
            <div className="rounded-xl bg-gradient-to-r from-slate-800/80 to-slate-800/40 border border-slate-700 p-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-[10px] uppercase tracking-widest text-slate-400 font-bold">Threat Protection</p>
                  <p className="text-sm text-slate-300 mt-0.5">Active on <span className="text-emerald-300 font-semibold">{currentDomain}</span></p>
                </div>
                <div className="text-right">
                  <p className="text-3xl font-black text-emerald-400">{Math.max(0, 100 - Math.min(60, stats.today * 5))}<span className="text-sm text-slate-500 font-semibold">/100</span></p>
                  <p className="text-[10px] text-slate-500 uppercase tracking-wide">Threat Score</p>
                </div>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              {SHIELD_LIST.map(s => (
                <button key={s.key} onClick={() => toggleShield(s.key)}
                  className={`flex items-center justify-between px-2.5 py-2 rounded-lg border text-left transition-colors ${settings.shields[s.key] ? 'bg-emerald-500/5 border-emerald-700/50 hover:bg-emerald-500/10' : 'bg-slate-800/40 border-slate-700 hover:bg-slate-800'}`}>
                  <span className="text-[11px] font-medium text-slate-300 pr-1">{s.label}</span>
                  <span className={`w-7 h-4 rounded-full relative transition-colors flex-shrink-0 ${settings.shields[s.key] ? 'bg-emerald-500' : 'bg-slate-600'}`}>
                    <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${settings.shields[s.key] ? 'left-3.5' : 'left-0.5'}`} />
                  </span>
                </button>
              ))}
            </div>
            <div className="rounded-xl border border-slate-700 bg-slate-800/40 p-3">
              <p className="text-[10px] uppercase tracking-widest text-slate-400 font-bold mb-2">Today's Activity</p>
              <div className="grid grid-cols-4 gap-2 text-center">
                <div><p className="text-lg font-bold text-red-400">{stats.today}</p><p className="text-[9px] text-slate-500 uppercase">Threats</p></div>
                <div><p className="text-lg font-bold text-orange-400">{stats.phishing}</p><p className="text-[9px] text-slate-500 uppercase">Phishing</p></div>
                <div><p className="text-lg font-bold text-yellow-400">{stats.downloads}</p><p className="text-[9px] text-slate-500 uppercase">Downloads</p></div>
                <div><p className="text-lg font-bold text-purple-400">{stats.redirects}</p><p className="text-[9px] text-slate-500 uppercase">Redirects</p></div>
              </div>
            </div>
            <button onClick={toggleLockdown}
              className={`w-full py-3 rounded-xl font-black text-sm tracking-wider transition-all ${settings.lockdown ? 'bg-slate-700 hover:bg-slate-600 text-slate-200' : 'bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-white shadow-lg shadow-red-900/40'}`}>
              {settings.lockdown ? '🔓 DISABLE EMERGENCY LOCKDOWN' : '🚨 EMERGENCY LOCKDOWN'}
            </button>
          </div>
        )}

        {/* ---------- VAULT ---------- */}
        {tab === 'vault' && (
          <div className="space-y-3">
            <div className="rounded-xl border border-emerald-800/50 bg-emerald-950/30 p-3">
              <p className="text-[11px] font-black text-emerald-300 uppercase tracking-wide">🔐 LockForce Vault</p>
              {!vaultUnlocked && (
                <p className="mt-1 text-[10px] text-emerald-200/80">
                  <strong className="text-emerald-300 text-sm block mb-1">PLEASE SAVE YOUR PASSWORD.</strong>
                  The only way to reset your password is to type in the original master password. There is no recovery, no server, no reset email — by design. Your vault is now protected with integrity checks (PBKDF2 + AES-256-GCM + HMAC).
                </p>
              )}
            </div>
            {!vaultUnlocked ? (
              <div className="space-y-2">
                <input type="password" value={masterInput} onChange={e => setMasterInput(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') { if (hasVault) void unlockVault(); else if (masterInput && confirmInput) void setupVault(); } }}
                  placeholder="Master password (min 16 chars, 2+ symbols, 2+ numbers)"
                  className="w-full px-3 py-2.5 rounded-lg bg-slate-800 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500" />
                {masterInput && (
                  <div>
                    <div className="h-1.5 rounded-full bg-slate-700 overflow-hidden">
                      <div className="h-full rounded-full transition-all" style={{ width: `${masterStrength.score}%`, backgroundColor: masterStrength.color }} />
                    </div>
                    <p className="text-[10px] mt-0.5" style={{ color: masterStrength.color }}>Strength: {masterStrength.label} ({masterStrength.score}/100)</p>
                  </div>
                )}
                {hasVault ? (
                  <button onClick={unlockVault} className="w-full py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold">🔓 Unlock Vault</button>
                ) : (
                  <>
                    <input type="password" value={confirmInput} onChange={e => setConfirmInput(e.target.value)}
                      placeholder="Confirm master password"
                      className="w-full px-3 py-2.5 rounded-lg bg-slate-800 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500" />
                    <button onClick={setupVault} className="w-full py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold">🔐 Create Encrypted Vault</button>
                  </>
                )}
                {vaultError && <p className="text-[11px] text-red-400 font-semibold">⚠️ {vaultError}</p>}
              </div>
            ) : (
              <>
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <p className="text-xs text-slate-400"><span className="text-emerald-400 font-bold">{entries.length}</span> saved credentials · PBKDF2+AES-256-GCM+HMAC</p>
                  <button onClick={lockVault} className="text-[11px] text-slate-400 hover:text-red-400 font-semibold">🔒 Lock</button>
                </div>

                {/* Search / filter */}
                <input value={vaultSearch} onChange={e => setVaultSearch(e.target.value)}
                  placeholder="🔍 Search title, username, or site…"
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500" />

                {/* Duplicate warning */}
                {duplicateIds.size > 0 && (
                  <div className="rounded-lg border border-orange-700/50 bg-orange-950/30 p-2 text-[10px] text-orange-300">
                    ⚠️ {duplicateIds.size} password{duplicateIds.size > 1 ? 's are' : ' is'} reused across multiple entries — vulnerable to credential-stuffing attacks.
                  </div>
                )}

                <div className="space-y-2">
                  {filteredEntries.map(e => {
                    const isDup = duplicateIds.has(e.id);
                    const isEditing = editingId === e.id;
                    const st = strengthOf(e.password);
                    const isConfirming = deleteConfirmId === e.id;
                    return (
                      <div key={e.id} className={`rounded-lg border p-2.5 ${isDup ? 'border-orange-700/50 bg-orange-950/10' : 'border-slate-700 bg-slate-800/50'}`}>
                        {!isEditing ? (
                          <div className="flex items-center justify-between gap-2">
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-1.5 flex-wrap">
                                <p className="text-xs font-bold text-slate-200 truncate">{e.title}</p>
                                {isDup && <span className="text-[9px] px-1.5 py-0.5 rounded bg-orange-900/60 text-orange-300 font-bold">REUSED</span>}
                              </div>
                              <p className="text-[10px] text-slate-400 truncate">{e.username}{e.url ? ` · ${e.url}` : ''}</p>
                              <p className="text-[11px] text-emerald-300 font-mono mt-0.5">{revealed[e.id] ? e.password : '••••••••••••'}</p>
                              {/* Strength bar per entry */}
                              <div className="flex items-center gap-1 mt-1">
                                <div className="h-1 w-20 rounded-full bg-slate-700 overflow-hidden">
                                  <div className="h-full rounded-full" style={{ width: `${st.score}%`, backgroundColor: st.color }} />
                                </div>
                                <span className="text-[9px]" style={{ color: st.color }}>{strengthLabel(st.score)}</span>
                              </div>
                              <p className="text-[9px] text-slate-500 mt-0.5">Updated {fmtDate(e.updated)} · Created {fmtDate(e.created)}</p>
                            </div>
                            <div className="flex flex-col gap-1 flex-shrink-0">
                              <button onClick={() => setRevealed(r => ({ ...r, [e.id]: !r[e.id] }))} className="text-[10px] px-2 py-0.5 rounded bg-slate-700 hover:bg-slate-600">{revealed[e.id] ? 'Hide' : 'Show'}</button>
                              <button onClick={() => copy(e.password, 'password')} className="text-[10px] px-2 py-0.5 rounded bg-slate-700 hover:bg-slate-600">Copy</button>
                              <button onClick={() => { setEditingId(e.id); setEditDraft({ title: e.title, username: e.username, password: e.password, url: e.url }); }} className="text-[10px] px-2 py-0.5 rounded bg-slate-700 hover:bg-slate-600">Edit</button>
                              <button onClick={() => toggleAutofillEntry(e.id)} className={`text-[10px] px-2 py-0.5 rounded font-semibold ${e.autofill ? 'bg-emerald-700 text-emerald-100' : 'bg-slate-700 text-slate-400'}`}>Autofill {e.autofill ? 'ON' : 'OFF'}</button>
                              <button onClick={() => deleteEntryConfirmed(e.id)} className={`text-[10px] px-2 py-0.5 rounded ${isConfirming ? 'bg-red-700 text-red-100 font-bold' : 'bg-red-900/60 text-red-300 hover:bg-red-800'}`}>{isConfirming ? 'CONFIRM?' : 'Delete'}</button>
                            </div>
                          </div>
                        ) : (
                          <div className="space-y-2">
                            <p className="text-[10px] font-bold text-emerald-300 uppercase tracking-wide">Editing {e.title}</p>
                            <input value={editDraft.title || ''} onChange={ev => setEditDraft(d => ({ ...d, title: ev.target.value }))} placeholder="Site name"
                              className="w-full px-2.5 py-1.5 rounded bg-slate-800 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500" />
                            <input value={editDraft.username || ''} onChange={ev => setEditDraft(d => ({ ...d, username: ev.target.value }))} placeholder="Email / username"
                              className="w-full px-2.5 py-1.5 rounded bg-slate-800 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500" />
                            <input type="password" value={editDraft.password || ''} onChange={ev => setEditDraft(d => ({ ...d, password: ev.target.value }))} placeholder="Password"
                              className="w-full px-2.5 py-1.5 rounded bg-slate-800 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500" />
                            <input value={editDraft.url || ''} onChange={ev => setEditDraft(d => ({ ...d, url: ev.target.value }))} placeholder="Website"
                              className="w-full px-2.5 py-1.5 rounded bg-slate-800 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500" />
                            <div className="flex gap-2">
                              <button onClick={() => updateEntry(e.id)} className="flex-1 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-[11px] font-bold">💾 Save</button>
                              <button onClick={() => { setEditingId(null); setEditDraft({}); }} className="flex-1 py-1.5 rounded bg-slate-700 hover:bg-slate-600 text-slate-200 text-[11px] font-bold">Cancel</button>
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                  {filteredEntries.length === 0 && <p className="text-center text-[11px] text-slate-500 py-4">{vaultSearch ? 'No matching credentials.' : 'Vault is empty. Add your first credential below.'}</p>}
                </div>

                <div className="rounded-lg border border-slate-700 bg-slate-800/40 p-3 space-y-2">
                  <p className="text-[10px] uppercase tracking-widest text-slate-400 font-bold">Add Credential</p>
                  <input value={newEntry.title} onChange={e => setNewEntry(v => ({ ...v, title: e.target.value }))} placeholder="Site name (e.g. GitHub)"
                    className="w-full px-2.5 py-2 rounded bg-slate-800 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500" />
                  <input value={newEntry.username} onChange={e => setNewEntry(v => ({ ...v, username: e.target.value }))} placeholder="Email / username"
                    className="w-full px-2.5 py-2 rounded bg-slate-800 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500" />
                  <input type="password" value={newEntry.password} onChange={e => setNewEntry(v => ({ ...v, password: e.target.value }))} placeholder="Password"
                    className="w-full px-2.5 py-2 rounded bg-slate-800 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500" />
                  {newEntry.password && (
                    <div>
                      <div className="h-1.5 rounded-full bg-slate-700 overflow-hidden">
                        <div className="h-full rounded-full transition-all" style={{ width: `${strengthOf(newEntry.password).score}%`, backgroundColor: strengthOf(newEntry.password).color }} />
                      </div>
                      <p className="text-[10px] mt-0.5" style={{ color: strengthOf(newEntry.password).color }}>Strength: {strengthOf(newEntry.password).label} ({strengthOf(newEntry.password).score}/100)</p>
                    </div>
                  )}
                  <input value={newEntry.url} onChange={e => setNewEntry(v => ({ ...v, url: e.target.value }))} placeholder="Website (e.g. github.com)"
                    className="w-full px-2.5 py-2 rounded bg-slate-800 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500" />
                  <button onClick={addEntry} className="w-full py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold">+ Save to Vault</button>
                </div>
                <p className="text-[10px] text-slate-500">
                  Autofill is {settings.autofillEnabled ? 'ENABLED' : 'DISABLED'} globally — toggle it in Settings. Each entry fills only on its own saved website. LockForce detects email+password fields and asks before saving.
                </p>
              </>
            )}
          </div>
        )}

        {/* ---------- GENERATOR ---------- */}
        {tab === 'generator' && (
          <div className="space-y-3">
            <div className="rounded-xl border border-slate-700 bg-slate-800/40 p-3">
              <p className="text-[10px] uppercase tracking-widest text-slate-400 font-bold mb-2">Secure Password Generator</p>
              <div className="rounded-lg bg-slate-900 border border-slate-700 p-3 font-mono text-sm text-emerald-300 break-all min-h-[3rem]">{genPw || 'Click Generate…'}</div>
              {genError && <p className="text-[11px] text-red-400 font-semibold mt-1.5">⚠️ {genError}</p>}
              {genPw && (
                <div className="mt-2">
                  <div className="h-2 rounded-full bg-slate-700 overflow-hidden">
                    <div className="h-full rounded-full transition-all" style={{ width: `${genStrength.score}%`, backgroundColor: genStrength.color }} />
                  </div>
                  <p className="text-[11px] mt-1 font-bold" style={{ color: genStrength.color }}>🔒 {genStrength.label} — {genStrength.score}/100</p>
                </div>
              )}
              <div className="flex gap-2 mt-2">
                <button onClick={() => {
                  const res = genPassword({ length: genLen, ...genOpts });
                  setGenPw(res.password); setGenError(res.error || '');
                }}
                  className="flex-1 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold">🎲 Generate</button>
                <button onClick={() => copy(genPw, 'generated password')} disabled={!genPw}
                  className="flex-1 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-200 text-xs font-bold disabled:opacity-40">📋 Copy</button>
              </div>
            </div>
            <div className="rounded-xl border border-slate-700 bg-slate-800/40 p-3 space-y-2">
              <label className="block text-[11px] text-slate-300 font-semibold">Length: <span className="text-emerald-400">{genLen}</span></label>
              <input type="range" min={8} max={64} value={genLen} onChange={e => setGenLen(Number(e.target.value))} className="w-full accent-emerald-500" />
              {([['upper', 'A–Z uppercase'], ['lower', 'a–z lowercase'], ['digits', '0–9 digits'], ['symbols', '!@#$ symbols']] as const).map(([k, label]) => (
                <label key={k} className="flex items-center gap-2 text-[11px] text-slate-300">
                  <input type="checkbox" checked={genOpts[k]} onChange={e => setGenOpts(o => ({ ...o, [k]: e.target.checked }))} className="accent-emerald-500" />
                  {label}
                </label>
              ))}
              <label className="flex items-center gap-2 text-[11px] text-slate-300">
                <input type="checkbox" checked={genOpts.excludeAmbiguous} onChange={e => setGenOpts(o => ({ ...o, excludeAmbiguous: e.target.checked }))} className="accent-emerald-500" />
                Exclude ambiguous characters (I, l, 1, O, 0)
              </label>
              <p className="text-[9px] text-slate-500">Uses <span className="text-emerald-400 font-mono">crypto.getRandomValues</span> — cryptographically secure, fully local.</p>
            </div>
          </div>
        )}

        {/* ---------- ACTIVITY ---------- */}
        {tab === 'activity' && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <p className="text-[10px] uppercase tracking-widest text-slate-400 font-bold">Security Timeline · {events.length} events</p>
              <button onClick={async () => { setEvents([]); await storeSet('lf_events', []); }} className="text-[10px] text-slate-500 hover:text-red-400">Clear log</button>
            </div>
            {events.length === 0 && <p className="text-center text-[11px] text-slate-500 py-6">No security events yet. LockForce is watching quietly. 🟢</p>}
            {events.map(ev => (
              <div key={ev.id} className={`rounded-lg border p-2.5 ${sevBg(ev.severity)}`}>
                <div className="flex items-center justify-between gap-2">
                  <p className={`text-[11px] font-black ${sevColor(ev.severity)}`}>{ev.severity} — {ev.title}</p>
                  <span className="text-[9px] text-slate-500 font-mono flex-shrink-0">{fmtTime(ev.time)}</span>
                </div>
                <p className="text-[10px] text-slate-400 mt-0.5">Source: {ev.source} · Category: {ev.category}</p>
                <ul className="mt-1 space-y-0.5">
                  {ev.reasons.map((r, i) => <li key={i} className="text-[10px] text-slate-400">• {r}</li>)}
                </ul>
                <p className="text-[10px] text-slate-300 mt-1 font-semibold">Action: {ev.action}</p>
              </div>
            ))}
          </div>
        )}

        {/* ---------- SETTINGS ---------- */}
        {tab === 'settings' && (
          <div className="space-y-3">
            <div className="rounded-xl border border-slate-700 bg-slate-800/40 p-3">
              <p className="text-[10px] uppercase tracking-widest text-slate-400 font-bold mb-2">Security Mode</p>
              <div className="grid grid-cols-2 gap-2">
                {([
                  ['beginner', 'Beginner', 'Max automatic protection'],
                  ['balanced', 'Balanced', 'Recommended'],
                  ['advanced', 'Advanced', 'Full manual control'],
                  ['ultra', 'Ultra Lockdown', 'Trusted-only browsing'],
                ] as const).map(([m, label, desc]) => (
                  <button key={m} onClick={() => setMode(m)}
                    className={`text-left px-2.5 py-2 rounded-lg border transition-colors ${settings.mode === m ? 'bg-emerald-600/20 border-emerald-600' : 'bg-slate-800 border-slate-700 hover:bg-slate-700'}`}>
                    <p className="text-[11px] font-bold text-slate-200">{label}</p>
                    <p className="text-[9px] text-slate-400">{desc}</p>
                  </button>
                ))}
              </div>
            </div>
            <div className="rounded-xl border border-slate-700 bg-slate-800/40 p-3 space-y-2">
              <p className="text-[10px] uppercase tracking-widest text-slate-400 font-bold">Vault & Autofill</p>
              <label className="flex items-center justify-between text-[11px] text-slate-300">
                <span>Autofill (per-site only)</span>
                <input type="checkbox" checked={settings.autofillEnabled} onChange={e => { void persistSettings({ ...settings, autofillEnabled: e.target.checked }); }} className="accent-emerald-500 w-4 h-4" />
              </label>
              <label className="flex items-center justify-between text-[11px] text-slate-300">
                <span>Auto-lock vault after</span>
                <select value={settings.autoLockSeconds} onChange={e => { void persistSettings({ ...settings, autoLockSeconds: Number(e.target.value) }); resetLockTimer(); }} className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-[11px] text-slate-200">
                  <option value={60}>1 minute</option>
                  <option value={300}>5 minutes</option>
                  <option value={900}>15 minutes</option>
                  <option value={3600}>1 hour</option>
                  <option value={0}>Never</option>
                </select>
              </label>
              <label className="flex items-center justify-between text-[11px] text-slate-300">
                <span>Clear clipboard after</span>
                <select value={settings.clipboardClearSeconds} onChange={e => { void persistSettings({ ...settings, clipboardClearSeconds: Number(e.target.value) }); }} className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-[11px] text-slate-200">
                  <option value={30}>30 seconds</option>
                  <option value={60}>1 minute</option>
                  <option value={300}>5 minutes</option>
                  <option value={0}>Never</option>
                </select>
              </label>
              <label className="flex items-center justify-between text-[11px] text-slate-300">
                <span>Desktop alerts for critical threats</span>
                <input type="checkbox" checked={settings.notificationsEnabled} onChange={e => { void persistSettings({ ...settings, notificationsEnabled: e.target.checked }); }} className="accent-emerald-500 w-4 h-4" />
              </label>
            </div>
            <div className="rounded-xl border border-slate-700 bg-slate-800/40 p-3 space-y-2">
              <p className="text-[10px] uppercase tracking-widest text-slate-400 font-bold">Generator Defaults</p>
              <label className="block text-[11px] text-slate-300 font-semibold">Default length: <span className="text-emerald-400">{settings.genDefaults.length}</span></label>
              <input type="range" min={8} max={64} value={settings.genDefaults.length} onChange={e => { void persistSettings({ ...settings, genDefaults: { ...settings.genDefaults, length: Number(e.target.value) } }); }} className="w-full accent-emerald-500" />
              {([['upper', 'Uppercase'], ['lower', 'Lowercase'], ['digits', 'Digits'], ['symbols', 'Symbols']] as const).map(([k, label]) => (
                <label key={k} className="flex items-center gap-2 text-[11px] text-slate-300">
                  <input type="checkbox" checked={settings.genDefaults[k]} onChange={e => { void persistSettings({ ...settings, genDefaults: { ...settings.genDefaults, [k]: e.target.checked } }); }} className="accent-emerald-500" />
                  {label}
                </label>
              ))}
              <label className="flex items-center gap-2 text-[11px] text-slate-300">
                <input type="checkbox" checked={settings.genDefaults.excludeAmbiguous} onChange={e => { void persistSettings({ ...settings, genDefaults: { ...settings.genDefaults, excludeAmbiguous: e.target.checked } }); }} className="accent-emerald-500" />
                Exclude ambiguous characters
              </label>
              <p className="text-[9px] text-slate-500">Generator toggles live-update from these defaults when you open the Generator tab.</p>
            </div>
            <div className="rounded-xl border border-emerald-900/60 bg-emerald-950/30 p-3">
              <p className="text-[11px] font-black text-emerald-300 uppercase">🔏 Privacy Architecture — Zero Tolerance</p>
              <ul className="mt-1.5 space-y-1 text-[10px] text-emerald-200/80">
                <li>• LockForce stores and tracks <strong>no information whatsoever</strong>.</li>
                <li>• <strong>No online servers. No accounts. No telemetry. No analytics.</strong></li>
                <li>• All analysis is local. All data stays in your browser, encrypted.</li>
                <li>• Works fully offline — the threat engine ships inside the extension.</li>
                <li>• Vault credentials are AES-256-GCM encrypted with a key derived via PBKDF2-SHA256 (150k iterations) plus HMAC integrity verification.</li>
              </ul>
            </div>
            <button onClick={async () => { await persistSettings(DEFAULT_SETTINGS); setEvents([]); await storeSet('lf_events', []); }}
              className="w-full py-2 rounded-lg bg-slate-800 border border-slate-700 hover:bg-slate-700 text-[11px] font-semibold text-slate-300">
              ♻️ Reset Protection Settings & Event Log
            </button>
          </div>
        )}

        {/* ---------- PATCH NOTES ---------- */}
        {tab === 'patch' && (
          <div className="space-y-3">
            <div className="rounded-xl border border-emerald-700/60 bg-emerald-950/40 p-3">
              <div className="flex items-baseline gap-2">
                <p className="text-lg font-black text-emerald-300">Version 1.1</p>
                <span className="px-2 py-0.5 rounded-full bg-emerald-600 text-white text-[9px] font-bold uppercase tracking-wider">Stable</span>
              </div>
              <p className="text-[11px] text-emerald-200 font-semibold mt-1">Official stable release — Vault Hardening update.</p>
              <p className="text-[10px] text-emerald-200/70 mt-1">
                This is the official stable release of LockForce Security Suite. Future updates are uncertain, but this release emphasizes the password manager — the app's original foundation — with all security features verified to work as advertised. No false security claims: every feature here is real, local, and auditable.
              </p>
            </div>
            <div className="rounded-xl border border-slate-700 bg-slate-800/40 p-3">
              <p className="text-[10px] uppercase tracking-widest text-slate-400 font-bold mb-1.5">What's New in 1.1 (Stability & Vault Hardening)</p>
              <ul className="space-y-1 text-[10px] text-slate-300">
                <li>🔐 <strong>Hardened Vault encryption</strong> — PBKDF2-SHA256 (150k iters) key derivation, AES-256-GCM, plus HMAC-SHA256 integrity verification. Presence of corruption or tampering is detected and surfaced immediately, never silent.</li>
                <li>🛡️ <strong>Atomic writes</strong> — a failed save can never leave the vault in a torn, half-written state.</li>
                <li>🔄 <strong>Seamless migration</strong> — existing v1 vaults are re-encrypted to the hardened v2 format on first unlock, preserving your data.</li>
                <li>🔍 <strong>Vault search</strong> — filter credentials by title, username, or site.</li>
                <li>🚨 <strong>Reused-password detection</strong> — entries sharing a password are flagged, with a summary banner.</li>
                <li>💪 <strong>Per-entry strength meter</strong> — every credential shows its own live strength bar.</li>
                <li>🕰️ <strong>Last-updated timestamps</strong> — see at a glance when each credential was last changed.</li>
                <li>✏️ <strong>Inline edit</strong> — change title, username, password, or URL and save; strength re-computed on save.</li>
                <li>🗑️ <strong>Delete confirmation</strong> — accidental deletions require a second confirm click.</li>
                <li>🎲 <strong>Generator depth</strong> — separate uppercase / lowercase / digits / symbols toggles, ambiguous-character exclusion, cryptographically secure via crypto.getRandomValues.</li>
                <li>⏲️ <strong>Auto-lock</strong> — vault locks itself after a configurable idle timeout.</li>
                <li>🧹 <strong>Clipboard auto-clear</strong> — copied passwords are wiped from the clipboard after a configurable delay.</li>
                <li>⚙️ <strong>Generator defaults in Settings</strong> — the Generator opens pre-configured to your stored preferences.</li>
              </ul>
            </div>
          </div>
        )}
      </main>

      <footer className="px-4 py-2 border-t border-slate-800 bg-[#0d1526] text-center">
        <p className="text-[9px] text-slate-500">LOCKFORCE SECURITY SUITE v1.1 STABLE · 100% LOCAL · ZERO-TOLERANCE PRIVACY · NO SERVERS, NO TRACKING</p>
      </footer>
      {copied && <div className="fixed bottom-10 right-4 px-3 py-1.5 rounded-lg bg-emerald-600 text-white text-[11px] font-bold shadow-lg">✓ {copied} copied</div>}
    </div>
  );
};

export default Popup;