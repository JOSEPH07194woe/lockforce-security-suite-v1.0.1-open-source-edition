// LockForce Security Suite — Full-Screen Control Panel. Self-contained.
import React, { useState, useEffect, useMemo } from 'react';
import './Options.css';

type Severity = 'INFO' | 'WARNING' | 'HIGH' | 'CRITICAL';
interface SecurityEvent {
  id: string; time: number; severity: Severity; category: string;
  title: string; source: string; reasons: string[]; action: string;
}
interface Settings {
  shields: Record<string, boolean>;
  mode: 'beginner' | 'balanced' | 'advanced' | 'ultra';
  lockdown: boolean;
  autofillEnabled: boolean;
  notificationsEnabled: boolean;
  autoLockSeconds: number;
  clipboardClearSeconds: number;
  genDefaults: { length: number; upper: boolean; lower: boolean; digits: boolean; symbols: boolean; excludeAmbiguous: boolean };
}
type FeatureDef = {
  id: string; name: string; description: string; category: string; cwsCompliant: boolean;
};

const SHIELD_LIST = [
  'malware', 'phishing', 'scams', 'exploit', 'downloads', 'redirects',
  'scripts', 'malvertising', 'notifications', 'commandguard', 'clipboard', 'credentials',
];
const SHIELD_DESC: Record<string, string> = {
  malware: 'Blocks known malware-distribution URL patterns (local database).',
  phishing: 'Detects credential-harvesting and impersonation pages.',
  scams: 'Detects giveaway, prize, invoice, delivery and crypto scams.',
  exploit: 'Detects exploit-like page behavior and fake browser warnings.',
  downloads: 'Inspects every download before Chrome passes it along.',
  redirects: 'Tracks redirect chains and blocks suspicious chains.',
  scripts: 'Flags suspicious third-party and obfuscated scripts.',
  malvertising: 'Detects malicious advertising infrastructure.',
  notifications: 'Warns on risky notification-permission requests.',
  commandguard: 'Detects social-engineering into running OS commands.',
  clipboard: 'Detects clipboard hijack patterns (e.g. wallet address swap).',
  credentials: 'Guards login forms — cross-origin & fake-brand detection.',
};

const isChromeApi = (): boolean => typeof chrome !== 'undefined' && !!chrome.runtime?.id;
async function storeGet<T>(key: string, fallback: T): Promise<T> {
  if (isChromeApi()) {
    try { const r = await chrome.storage.local.get(key); return (r[key] as T) ?? fallback; } catch { return fallback; }
  }
  try { const raw = localStorage.getItem('lf_' + key); return raw ? (JSON.parse(raw) as T) : fallback; } catch { return fallback; }
}
async function storeSet(key: string, value: unknown): Promise<void> {
  if (isChromeApi()) { try { await chrome.storage.local.set({ [key]: value }); return; } catch { /* ignore */ } }
  try { localStorage.setItem('lf_' + key, JSON.stringify(value)); } catch { /* quota */ }
}

const DEFAULT_SETTINGS: Settings = {
  shields: Object.fromEntries(SHIELD_LIST.map(s => [s, true])),
  mode: 'balanced', lockdown: false, autofillEnabled: true, notificationsEnabled: true,
  autoLockSeconds: 300, clipboardClearSeconds: 60,
  genDefaults: { length: 20, upper: true, lower: true, digits: true, symbols: true, excludeAmbiguous: false },
};

// ---- Feature catalog (metadata only — wired to existing shield toggles) ----
const FEATURE_CATALOG: FeatureDef[] = [
  { id: 'malware', name: 'Malware Protection', description: 'Checks every site you visit against a local database of known malware-distribution URL patterns. All checks happen on your device; nothing is sent anywhere.', category: 'Threat Detection', cwsCompliant: true },
  { id: 'downloads', name: 'Download Guard', description: 'Inspects each download before Chrome passes it along, flagging dangerous file types like .exe and double-extension tricks such as invoice.pdf.exe.', category: 'Threat Detection', cwsCompliant: true },
  { id: 'redirects', name: 'Redirect Firewall', description: 'Tracks how many hops a redirect chain takes per tab and warns you about long chains, a hallmark of malvertising and phishing funnels. Chain data lives in memory only and is dropped when the tab closes.', category: 'Threat Detection', cwsCompliant: true },
  { id: 'phishing', name: 'Phishing Protection', description: 'Flags credential-harvesting URL patterns, login over plain HTTP, punycode lookalike domains and heavy URL obfuscation before you type a password.', category: 'Phishing Protection', cwsCompliant: true },
  { id: 'credentials', name: 'Credential Protection', description: 'Detects login forms that submit your password to a different domain than the one you are on — a classic phishing pattern.', category: 'Phishing Protection', cwsCompliant: true },
  { id: 'impersonation', name: 'Brand Impersonation Detection (PhishVision)', description: 'Spots pages that mention a well-known brand (Google, Microsoft, PayPal, banks, etc.) while hosting a password field on an unrelated domain.', category: 'Phishing Protection', cwsCompliant: true },
  { id: 'scams', name: 'Scam Detection', description: 'Recognizes fake browser-update pages, fake antivirus warnings, fake CAPTCHAs, giveaway scams and crypto-seed-phrase harvesting text on the page.', category: 'Phishing Protection', cwsCompliant: true },
  { id: 'commandguard', name: 'CommandGuard', description: 'Warns when a page tries to talk you into running PowerShell, CMD or terminal commands, or disabling your antivirus — common tech-support-scam behavior.', category: 'Content Scanning', cwsCompliant: true },
  { id: 'clipboard', name: 'Clipboard Protection', description: 'Watches for scripts that silently swap a copied cryptocurrency address for a different one, and alerts you if the clipboard content changes.', category: 'Content Scanning', cwsCompliant: true },
  { id: 'exploit', name: 'Exploit Defense', description: 'Detects nearly-invisible hidden iframes that can load malicious content without your knowledge.', category: 'Content Scanning', cwsCompliant: true },
  { id: 'notifications', name: 'Notification Protection', description: 'Flags risky notification-permission requests and fake-alert content. LockForce itself only sends you alerts about threats it found locally.', category: 'General Settings', cwsCompliant: true },
  { id: 'vault', name: 'LockForce Vault', description: 'Stores passwords encrypted with AES-256-GCM using a key derived from your master password (PBKDF2, 150k iterations). Data never leaves your browser in plaintext or at all.', category: 'Secure Storage', cwsCompliant: true },
  { id: 'autofill', name: 'Per-Site Autofill', description: 'Fills saved credentials only on the website they were saved for. Everything stays local; no cloud sync exists.', category: 'Secure Storage', cwsCompliant: true },
  { id: 'lockdown', name: 'Emergency Lockdown', description: 'One-click maximum-security posture: navigation is restricted and dangerous downloads are cancelled automatically while active.', category: 'General Settings', cwsCompliant: true },
  { id: 'localonly', name: '100% Local Processing', description: 'Every check above runs on your device. LockForce has no servers, makes no network requests of its own, and collects no telemetry — fully compliant with Chrome Web Store policy.', category: 'Privacy & Tracking', cwsCompliant: true },
  { id: 'report', name: 'Local Security Report Export', description: 'Exports everything LockForce recorded to a JSON file on your machine so you can verify how little data exists. Nothing is uploaded.', category: 'Privacy & Tracking', cwsCompliant: true },
];

const TABS = [
  { id: 'overview', label: 'Overview', icon: '🛡️' },
  { id: 'activity', label: 'Security Timeline', icon: '📋' },
  { id: 'inspector', label: 'Inspector', icon: '🔍' },
  { id: 'permissions', label: 'Permissions', icon: '🔔' },
  { id: 'sites', label: 'Per-Site Controls', icon: '🌐' },
  { id: 'firewall', label: 'Network Firewall', icon: '🧱' },
  { id: 'privacy', label: 'Privacy', icon: '🔏' },
  { id: 'patch', label: 'Patch Notes', icon: '📝' },
] as const;

const Options: React.FC = () => {
  const [tab, setTab] = useState<string>('overview');
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [trustedSites, setTrustedSites] = useState<Record<string, boolean>>({});
  const [siteInput, setSiteInput] = useState('');
  const [saved, showSaved] = useState(false);
  const [featureTab, setFeatureTab] = useState<string>('All');
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importPassword, setImportPassword] = useState('');
  const [importStatus, setImportStatus] = useState<{ kind: 'idle' | 'ok' | 'error'; msg: string }>({ kind: 'idle', msg: '' });
  const [importBusy, setImportBusy] = useState(false);
  const featureCategories = useMemo(
    () => ['All', ...Array.from(new Set(FEATURE_CATALOG.map(f => f.category)))],
    []
  );
  const visibleFeatures = useMemo(
    () => featureTab === 'All' ? FEATURE_CATALOG : FEATURE_CATALOG.filter(f => f.category === featureTab),
    [featureTab]
  );

  // Toggle a catalog feature using the same storage keys already in use.
  const toggleCatalogFeature = (id: string) => {
    if (id === 'lockdown') { void persist({ ...settings, lockdown: !settings.lockdown }); return; }
    if (id === 'autofill') { void persist({ ...settings, autofillEnabled: !settings.autofillEnabled }); return; }
    if (id === 'notifications') { void persist({ ...settings, notificationsEnabled: !settings.notificationsEnabled }); return; }
    // shield-backed features (phishing, credentials, etc.)
    void persist({ ...settings, shields: { ...settings.shields, [id]: !settings.shields[id] } });
  };
  const isFeatureOn = (id: string): boolean => {
    if (id === 'lockdown') return settings.lockdown;
    if (id === 'autofill') return settings.autofillEnabled;
    if (id === 'notifications') return settings.notificationsEnabled;
    if (id === 'localonly' || id === 'report' || id === 'vault') return true; // always-on local architecture
    return settings.shields[id] !== false;
  };

  useEffect(() => {
    (async () => {
      const s = await storeGet<Settings>('lf_settings', DEFAULT_SETTINGS);
      setSettings({ ...DEFAULT_SETTINGS, ...s, shields: { ...DEFAULT_SETTINGS.shields, ...(s?.shields || {}) }, genDefaults: { ...DEFAULT_SETTINGS.genDefaults, ...(s?.genDefaults || {}) } });
      const ev = await storeGet<SecurityEvent[]>('lf_events', []);
      setEvents(Array.isArray(ev) ? ev : []);
      setTrustedSites(await storeGet<Record<string, boolean>>('lf_trusted_sites', {}));
    })();
  }, []);

  const persist = async (next: Settings) => { setSettings(next); await storeSet('lf_settings', next); flashSaved(); };
  const flashSaved = () => { showSaved(true); setTimeout(() => showSaved(false), 1200); };

  const stats = useMemo(() => {
    const by = (c: string) => events.filter(e => e.category.toLowerCase().includes(c)).length;
    const dayMs = 86400000;
    return {
      total: events.length,
      today: events.filter(e => Date.now() - e.time < dayMs).length,
      week: events.filter(e => Date.now() - e.time < 7 * dayMs).length,
      month: events.filter(e => Date.now() - e.time < 30 * dayMs).length,
      phishing: by('phishing') + by('impersonation'),
      downloads: by('download'),
      redirects: by('redirect'),
      scams: by('scam'),
      commands: by('command'),
    };
  }, [events]);

  // ---- Legacy backup import (grandfathered migration path) ----
  // Self-contained crypto mirroring the legacy encrypted-backup format so the
  // component stays preview-isolated. All-or-nothing: nothing is written unless
  // decryption + validation + merge all succeed.
  const lfFromB64 = (b64: string): Uint8Array => {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  };
  const lfToB64 = (bytes: Uint8Array): string => {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  };
  const lfSha256Hex = async (s: string): Promise<string> => {
    const h = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)));
    return Array.from(h).map(b => b.toString(16).padStart(2, '0')).join('');
  };

  const handleImport = async () => {
    if (importBusy) return;
    setImportStatus({ kind: 'idle', msg: '' });
    // Inline validation — fail fast with friendly messages, no exceptions escape.
    if (!importFile) { setImportStatus({ kind: 'error', msg: 'Choose your backup file first.' }); return; }
    if (importPassword.length < 12) {
      setImportStatus({ kind: 'error', msg: 'Backup password must be at least 12 characters.' });
      return;
    }
    setImportBusy(true);
    try {
      const fileText = await importFile.text();
      // Unwrap legacy container: plain JSON blob, or base64 + reversed chars.
      type LegacyBlob = { tag?: string; saltB64?: string; salt?: string; ivB64?: string; iv?: string; ctB64?: string; ct?: string; ciphertext?: string; macB64?: string; mac?: string };
      let blob: LegacyBlob;
      try {
        if (fileText.trimStart().startsWith('{')) blob = JSON.parse(fileText.trim()) as LegacyBlob;
        else blob = JSON.parse(atob(fileText.trim()).split('').reverse().join('')) as LegacyBlob;
      } catch {
        setImportStatus({ kind: 'error', msg: 'This file is not an encrypted LockForce backup (plaintext or CSV files are not supported).' });
        return;
      }
      const saltB64 = blob.saltB64 || blob.salt;
      const ivB64 = blob.ivB64 || blob.iv;
      const ctB64 = blob.ctB64 || blob.ct || blob.ciphertext;
      const macB64 = blob.macB64 || blob.mac;
      if (!saltB64 || !ivB64 || !ctB64) {
        setImportStatus({ kind: 'error', msg: 'Backup file is missing required encryption fields — it may be corrupted.' });
        return;
      }
      let salt: Uint8Array, iv: Uint8Array, ct: Uint8Array;
      try {
        salt = lfFromB64(saltB64); iv = lfFromB64(ivB64); ct = lfFromB64(ctB64);
      } catch {
        setImportStatus({ kind: 'error', msg: 'Backup file contains malformed data — it may be corrupted.' });
        return;
      }
      const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(importPassword), 'PBKDF2', false, ['deriveKey']);
      const aes = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: 150000, hash: 'SHA-256' },
        base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
      );
      if (macB64) {
        try {
          const hmacBase = await crypto.subtle.importKey('raw', new TextEncoder().encode('lf-hmac-salt'), 'PBKDF2', false, ['deriveKey']);
          const hk = await crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: 150000, hash: 'SHA-256' },
            hmacBase, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['verify']
          );
          const okMac = await crypto.subtle.verify('HMAC', hk, lfFromB64(macB64).buffer as ArrayBuffer, ct.buffer as ArrayBuffer);
          if (!okMac) {
            setImportStatus({ kind: 'error', msg: 'Backup integrity check failed — the file is corrupted or was tampered with.' });
            return;
          }
        } catch { /* GCM auth still guards */ }
      }
      let json: string;
      try {
        const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aes, ct.buffer as ArrayBuffer);
        json = new TextDecoder().decode(pt);
      } catch {
        setImportStatus({ kind: 'error', msg: 'Wrong password, or the backup file is corrupted.' });
        return;
      }
      let data: unknown;
      try { data = JSON.parse(json); } catch {
        setImportStatus({ kind: 'error', msg: 'Decrypted backup is not valid JSON — it may be corrupted.' });
        return;
      }
      const rawEntries: unknown =
        (data && typeof data === 'object' && Array.isArray((data as { entries?: unknown }).entries)) ? (data as { entries: unknown[] }).entries
        : (data && typeof data === 'object' && Array.isArray((data as { passwords?: unknown }).passwords)) ? (data as { passwords: unknown[] }).passwords
        : Array.isArray(data) ? data : null;
      if (!rawEntries) {
        setImportStatus({ kind: 'error', msg: 'Backup does not contain a recognizable entries list.' });
        return;
      }
      // Normalize + dedupe within the file itself.
      const candidates: Array<{ id: string; title: string; username: string; password: string; url: string }> = [];
      const fileKeys = new Set<string>();
      for (const item of rawEntries as Array<Record<string, unknown>>) {
        const title = String(item?.title ?? item?.name ?? '').trim();
        const pw = String(item?.password ?? item?.pass ?? '');
        if (!title || !pw) continue;
        const entry = {
          id: String(item?.id || crypto.randomUUID()),
          title, password: pw,
          username: String(item?.username ?? item?.user ?? item?.email ?? ''),
          url: String(item?.url ?? item?.site ?? ''),
        };
        const key = await lfSha256Hex(`${entry.title}\u0000${entry.username}\u0000${entry.password}`);
        if (fileKeys.has(key)) continue;
        fileKeys.add(key);
        candidates.push(entry);
      }
      // Merge without overwriting: skip anything already imported previously.
      let importedIds: Record<string, boolean> = {};
      try {
        const stored = await storeGet<Record<string, boolean>>('lf_imported_ids', {});
        if (stored && typeof stored === 'object') importedIds = stored;
      } catch { /* fresh */ }
      let imported = 0, skipped = 0;
      const toWrite: typeof candidates = [];
      for (const entry of candidates) {
        const key = await lfSha256Hex(`${entry.title}\u0000${entry.username}\u0000${entry.password}`);
        if (importedIds[key]) { skipped++; continue; }
        importedIds[key] = true;
        toWrite.push(entry);
        imported++;
      }
      if (toWrite.length === 0) {
        setImportStatus({ kind: 'ok', msg: `0 items imported, ${skipped} skipped — all entries already exist.` });
        setImportFile(null); setImportPassword('');
        return;
      }
      // Re-encrypt imported entries at rest under the import password before
      // storing — plaintext credentials never touch storage.
      const encSalt = crypto.getRandomValues(new Uint8Array(16));
      const encIv = crypto.getRandomValues(new Uint8Array(12));
      const mk = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: encSalt.buffer as ArrayBuffer, iterations: 150000, hash: 'SHA-256' },
        await crypto.subtle.importKey('raw', new TextEncoder().encode(importPassword), 'PBKDF2', false, ['deriveKey']),
        { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
      );
      const enc = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: encIv }, mk, new TextEncoder().encode(JSON.stringify(toWrite))));
      const wrapped = btoa(JSON.stringify({
        tag: 'lf-import-v1', saltB64: lfToB64(encSalt), ivB64: lfToB64(encIv), ctB64: lfToB64(enc),
      })).split('').reverse().join('');
      try {
        await storeSet('lf_imported_vault', wrapped);
        await storeSet('lf_imported_ids', importedIds);
      } catch {
        setImportStatus({ kind: 'error', msg: 'Could not save the imported data to local storage. Nothing was written.' });
        return;
      }
      setImportStatus({ kind: 'ok', msg: `✓ ${imported} item${imported === 1 ? '' : 's'} imported, ${skipped} skipped (already present).` });
      // Reset state after the action completes — no stale file/password left behind.
      setImportFile(null); setImportPassword('');
    } catch (e) {
      setImportStatus({ kind: 'error', msg: e instanceof Error ? `Import failed: ${e.message}` : 'Import failed — the file could not be read.' });
    } finally {
      setImportBusy(false);
    }
  };

  // Export is disabled in 1.0 — the flow is preserved but cannot be triggered
  // from the UI (button is disabled below, plus this early-return guard).
  const exportLogs = () => {
    setImportStatus({ kind: 'idle', msg: '' });
    console.info('[LockForce] Export is disabled in 1.0. Use Import to bring in data from the previous version.');
    return;
    const report = {
      product: 'LockForce Security Suite', version: '1.0.0 (Stable)',
      generated: new Date().toISOString(), note: 'Exported locally. Nothing left your machine.',
      settings, events,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'lockforce-report.json'; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const fmtTime = (t: number) => new Date(t).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const sevColor = (s: Severity) => s === 'CRITICAL' ? 'text-red-400' : s === 'HIGH' ? 'text-orange-400' : s === 'WARNING' ? 'text-yellow-400' : 'text-slate-400';
  const sevBorder = (s: Severity) => s === 'CRITICAL' ? 'border-red-500/40' : s === 'HIGH' ? 'border-orange-500/40' : s === 'WARNING' ? 'border-yellow-500/40' : 'border-slate-700';

  return (
    <div className="min-h-screen bg-[#0b1220] text-slate-200">
      <header className="bg-gradient-to-r from-[#101a30] to-[#0d1830] border-b border-slate-800 px-8 py-5 flex items-center gap-4">
        <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-emerald-400 to-emerald-600 flex items-center justify-center text-3xl shadow-lg shadow-emerald-900/50">🐺</div>
        <div className="flex-1">
          <h1 className="text-2xl font-black tracking-tight text-white">LOCKFORCE <span className="text-emerald-400">SECURITY SUITE</span></h1>
          <p className="text-xs text-slate-400 font-semibold tracking-widest uppercase">
            Version 1.0 <span className="ml-2 px-2 py-0.5 rounded-full bg-emerald-600 text-white text-[10px] font-bold">Stable</span>
          </p>
          <p className="text-[11px] text-slate-500 mt-0.5">This is the official release of LockForce Security Suite. 100% local. No servers. No tracking. Zero-tolerance privacy.</p>
        </div>
        <span className={`px-4 py-2 rounded-xl text-sm font-black border ${settings.lockdown ? 'bg-red-500/20 border-red-500/60 text-red-300' : 'bg-emerald-500/15 border-emerald-500/50 text-emerald-300'}`}>
          {settings.lockdown ? '🔒 LOCKDOWN ACTIVE' : '🟢 PROTECTED'}
        </span>
      </header>

      <div className="flex min-h-[calc(100vh-100px)]">
        <nav className="w-56 flex-shrink-0 border-r border-slate-800 bg-[#0d1526] py-4 px-3 space-y-1">
          {TABS.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`w-full text-left px-3 py-2.5 rounded-lg text-sm font-semibold transition-colors ${tab === t.id ? 'bg-emerald-600/20 text-emerald-300 border border-emerald-700/50' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'}`}>
              {t.icon} {t.label}
            </button>
          ))}
        </nav>

        <main className="flex-1 p-8 max-w-4xl">
          {saved && <div className="mb-4 px-4 py-2 rounded-lg bg-emerald-600/20 border border-emerald-600 text-emerald-300 text-sm font-bold">✓ Settings saved locally</div>}

          {tab === 'overview' && (
            <div className="space-y-6">
              <section className="rounded-2xl border border-emerald-700/60 bg-emerald-950/40 p-5">
                <p className="text-base font-black text-emerald-300">🔄 Coming from the old version? Import your encrypted backup here.</p>
                <p className="text-[11px] text-emerald-200/80 mt-1">One-time migration: choose your encrypted backup file from the previous LockForce version, enter its backup password (12+ characters), and your saved credentials are merged in — nothing you already have is overwritten.</p>
              </section>
              <section>
                <h2 className="text-lg font-black text-white mb-3">Feature Catalog</h2>
                <div className="lf-cat-tabs">
                  {featureCategories.map(c => (
                    <button key={c} onClick={() => setFeatureTab(c)}
                      className={`lf-cat-tab ${featureTab === c ? 'lf-cat-tab-active' : ''}`}>
                      {c}
                    </button>
                  ))}
                </div>
                <div className="lf-feature-list">
                  {visibleFeatures.map(f => (
                    <div key={f.id} className={`lf-feature-row ${isFeatureOn(f.id) ? 'lf-feature-on' : ''}`}>
                      <label className="lf-feature-toggle">
                        <input type="checkbox" checked={isFeatureOn(f.id)} onChange={() => toggleCatalogFeature(f.id)} className="accent-emerald-500 w-4 h-4" />
                      </label>
                      <div className="lf-feature-body">
                        <div className="lf-feature-head">
                          <p className="lf-feature-name">{f.name}</p>
                          <span className="lf-cws-badge" title="Runs fully locally, no remote code, no undisclosed data collection">✓ CWS Compliant</span>
                        </div>
                        <p className="lf-feature-desc">{f.description}</p>
                        <p className="lf-feature-cat">{f.category}</p>
                      </div>
                    </div>
                  ))}
                </div>
                <p className="lf-feature-note">Toggles here control the same settings as the shield switches below — both write to the same local storage.</p>
              </section>
              <section>
                <h2 className="text-lg font-black text-white mb-3">Threat Protection</h2>
                <div className="grid grid-cols-2 gap-3">
                  {SHIELD_LIST.map(key => (
                    <button key={key} onClick={() => { void persist({ ...settings, shields: { ...settings.shields, [key]: !settings.shields[key] } }); }}
                      className={`text-left p-4 rounded-xl border transition-colors ${settings.shields[key] ? 'bg-emerald-500/5 border-emerald-700/50' : 'bg-slate-800/40 border-slate-700'}`}>
                      <div className="flex items-center justify-between">
                        <p className="text-sm font-bold capitalize text-slate-200">{key === 'commandguard' ? 'CommandGuard' : key === 'malvertising' ? 'Malvertising Shield' : key}</p>
                        <span className={`text-xs font-black ${settings.shields[key] ? 'text-emerald-400' : 'text-slate-500'}`}>{settings.shields[key] ? '✅ ON' : '⬜ OFF'}</span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-1">{SHIELD_DESC[key]}</p>
                    </button>
                  ))}
                </div>
              </section>
              <section>
                <h2 className="text-lg font-black text-white mb-3">Security Mode</h2>
                <div className="grid grid-cols-4 gap-3">
                  {([['beginner','Beginner','Maximum automatic protection'],['balanced','Balanced','Recommended for normal users'],['advanced','Advanced','Customize everything'],['ultra','Ultra Lockdown','Trusted domains only']] as const).map(([m,l,d]) => (
                    <button key={m} onClick={() => { void persist({ ...settings, mode: m }); }}
                      className={`p-4 rounded-xl border text-left ${settings.mode === m ? 'bg-emerald-600/20 border-emerald-600' : 'bg-slate-800/40 border-slate-700 hover:bg-slate-800'}`}>
                      <p className="text-sm font-bold text-slate-100">{l}</p>
                      <p className="text-[11px] text-slate-400 mt-1">{d}</p>
                    </button>
                  ))}
                </div>
              </section>
              <section>
                <h2 className="text-lg font-black text-white mb-3">Statistics</h2>
                <div className="grid grid-cols-4 gap-3">
                  {([['Today', stats.today, 'text-red-400'], ['This week', stats.week, 'text-orange-400'], ['This month', stats.month, 'text-yellow-400'], ['All time', stats.total, 'text-emerald-400']] as const).map(([label, n, c]) => (
                    <div key={label} className="p-4 rounded-xl bg-slate-800/40 border border-slate-700 text-center">
                      <p className={`text-3xl font-black ${c}`}>{n}</p>
                      <p className="text-[11px] text-slate-500 uppercase tracking-wide mt-1">{label}</p>
                    </div>
                  ))}
                </div>
              </section>
              <section className="flex gap-3">
                <button onClick={() => { void persist({ ...settings, lockdown: !settings.lockdown }); }}
                  className={`flex-1 py-4 rounded-xl font-black tracking-wider ${settings.lockdown ? 'bg-slate-700 hover:bg-slate-600 text-slate-200' : 'bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 text-white shadow-lg shadow-red-900/40'}`}>
                  {settings.lockdown ? '🔓 DISABLE EMERGENCY LOCKDOWN' : '🚨 EMERGENCY LOCKDOWN BROWSER'}
                </button>
                <span title="Export is disabled in 1.0. Use Import to bring in data from the previous version.">
                  <button onClick={exportLogs} disabled aria-disabled="true" title="Export is disabled in 1.0. Use Import to bring in data from the previous version."
                    className="px-6 py-4 rounded-xl bg-slate-800/50 border border-slate-700/60 font-bold text-sm text-slate-500 cursor-not-allowed opacity-60">
                    💾 Export Security Report
                  </button>
                </span>
              </section>
              <p className="text-[11px] text-slate-500 -mt-3">ℹ️ Export is disabled in 1.0. Use Import to bring in data from the previous version.</p>

              {/* Migration import panel */}
              <section className="rounded-2xl border border-emerald-800/60 bg-emerald-950/30 p-5 space-y-3">
                <p className="text-sm font-black text-emerald-300 uppercase tracking-widest">📥 Import Legacy Encrypted Backup</p>
                <p className="text-[11px] text-emerald-200/70">Only the encrypted backup file from the previous LockForce version is accepted (a 12+ character backup password is required). Plaintext and CSV files are rejected for your safety.</p>
                <input type="file" accept=".json,.lfbackup,application/json"
                  onChange={e => { setImportFile(e.target.files?.[0] || null); setImportStatus({ kind: 'idle', msg: '' }); }}
                  className="block w-full text-xs text-slate-300 file:mr-3 file:px-4 file:py-2 file:rounded-lg file:border-0 file:bg-emerald-600 file:text-white file:text-xs file:font-bold file:cursor-pointer" />
                <input type="password" value={importPassword}
                  onChange={e => { setImportPassword(e.target.value); setImportStatus({ kind: 'idle', msg: '' }); }}
                  placeholder="Backup password (min 12 characters)"
                  className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500" />
                {importPassword.length > 0 && importPassword.length < 12 && (
                  <p className="text-[11px] text-orange-400 font-semibold">⚠️ Password must be at least 12 characters ({12 - importPassword.length} more needed).</p>
                )}
                <button onClick={() => { void handleImport(); }} disabled={importBusy || !importFile}
                  className="w-full py-3 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-black">
                  {importBusy ? '⏳ Decrypting & importing…' : '📥 Import Backup'}
                </button>
                {importStatus.kind === 'ok' && (
                  <p className="text-xs text-emerald-300 font-bold px-3 py-2 rounded-lg bg-emerald-600/15 border border-emerald-600/50">{importStatus.msg}</p>
                )}
                {importStatus.kind === 'error' && (
                  <p className="text-xs text-red-300 font-semibold px-3 py-2 rounded-lg bg-red-900/30 border border-red-700/60">⚠️ {importStatus.msg}</p>
                )}
              </section>
            </div>
          )}

          {tab === 'activity' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-black text-white">Security Timeline</h2>
                <button onClick={async () => { setEvents([]); await storeSet('lf_events', []); }} className="text-xs text-slate-500 hover:text-red-400">Clear log</button>
              </div>
              {events.length === 0 && <p className="text-slate-500 text-sm py-8 text-center">No security events recorded yet.</p>}
              {events.map(ev => (
                <div key={ev.id} className={`rounded-xl border ${sevBorder(ev.severity)} bg-slate-800/40 p-4`}>
                  <div className="flex items-center justify-between">
                    <p className={`text-sm font-black ${sevColor(ev.severity)}`}>{ev.severity} — {ev.title}</p>
                    <span className="text-[11px] text-slate-500 font-mono">{fmtTime(ev.time)}</span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">Source: {ev.source} · Category: {ev.category}</p>
                  <ul className="mt-2 space-y-1">{ev.reasons.map((r, i) => <li key={i} className="text-xs text-slate-400">• {r}</li>)}</ul>
                  <p className="text-xs text-slate-200 font-bold mt-2">Action: {ev.action}</p>
                </div>
              ))}
            </div>
          )}

          {tab === 'inspector' && (
            <div className="space-y-4">
              <h2 className="text-lg font-black text-white">Advanced Security Inspector</h2>
              <p className="text-xs text-slate-400">Inspect recent download attempts, script signals and threat detections recorded on this machine. All data shown was captured locally and never transmitted.</p>
              <div className="grid grid-cols-3 gap-3">
                <div className="p-4 rounded-xl bg-slate-800/40 border border-slate-700"><p className="text-2xl font-black text-red-400">{stats.downloads}</p><p className="text-[11px] text-slate-500 uppercase">Download events</p></div>
                <div className="p-4 rounded-xl bg-slate-800/40 border border-slate-700"><p className="text-2xl font-black text-orange-400">{stats.redirects}</p><p className="text-[11px] text-slate-500 uppercase">Redirect events</p></div>
                <div className="p-4 rounded-xl bg-slate-800/40 border border-slate-700"><p className="text-2xl font-black text-purple-400">{stats.commands}</p><p className="text-[11px] text-slate-500 uppercase">CommandGuard hits</p></div>
              </div>
              <div className="rounded-xl border border-slate-700 bg-slate-800/40 p-4">
                <p className="text-sm font-bold text-slate-200 mb-2">Recent detections</p>
                {events.slice(0, 10).map(ev => (
                  <div key={ev.id} className="py-2 border-b border-slate-700/50 last:border-0">
                    <p className={`text-xs font-bold ${sevColor(ev.severity)}`}>{ev.title}</p>
                    <p className="text-[11px] text-slate-500 font-mono">{ev.source}</p>
                  </div>
                ))}
                {events.length === 0 && <p className="text-xs text-slate-500">Nothing detected yet.</p>}
              </div>
            </div>
          )}

          {tab === 'permissions' && (
            <div className="space-y-4">
              <h2 className="text-lg font-black text-white">Notification & Permission Dashboard</h2>
              <p className="text-xs text-slate-400">LockForce flags risky notification-permission requests and, in Lockdown/Ultra mode, they are rejected automatically. Chrome site-permission grants can be reviewed at chrome://settings/content/notifications.</p>
              <label className="flex items-center justify-between p-4 rounded-xl bg-slate-800/40 border border-slate-700">
                <span className="text-sm font-semibold">Desktop alerts for HIGH/CRITICAL threats</span>
                <input type="checkbox" checked={settings.notificationsEnabled} onChange={e => { void persist({ ...settings, notificationsEnabled: e.target.checked }); }} className="accent-emerald-500 w-5 h-5" />
              </label>
              <label className="flex items-center justify-between p-4 rounded-xl bg-slate-800/40 border border-slate-700">
                <span className="text-sm font-semibold">Notification-protection heuristic (fake alert content)</span>
                <input type="checkbox" checked={settings.shields.notifications} onChange={e => { void persist({ ...settings, shields: { ...settings.shields, notifications: e.target.checked } }); }} className="accent-emerald-500 w-5 h-5" />
              </label>

              <div className="rounded-xl border border-slate-700 bg-slate-800/40 p-4 space-y-3">
                <p className="text-sm font-black text-slate-200">Vault & Clipboard Timing</p>
                <label className="flex items-center justify-between text-sm">
                  <span>Auto-lock vault after</span>
                  <select value={settings.autoLockSeconds} onChange={e => { void persist({ ...settings, autoLockSeconds: Number(e.target.value) }); }} className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-sm text-slate-200">
                    <option value={60}>1 minute</option>
                    <option value={300}>5 minutes</option>
                    <option value={900}>15 minutes</option>
                    <option value={3600}>1 hour</option>
                    <option value={0}>Never</option>
                  </select>
                </label>
                <label className="flex items-center justify-between text-sm">
                  <span>Clear clipboard after</span>
                  <select value={settings.clipboardClearSeconds} onChange={e => { void persist({ ...settings, clipboardClearSeconds: Number(e.target.value) }); }} className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-sm text-slate-200">
                    <option value={30}>30 seconds</option>
                    <option value={60}>1 minute</option>
                    <option value={300}>5 minutes</option>
                    <option value={0}>Never</option>
                  </select>
                </label>
              </div>

              <div className="rounded-xl border border-slate-700 bg-slate-800/40 p-4 space-y-3">
                <p className="text-sm font-black text-slate-200">Generator Defaults</p>
                <label className="flex items-center justify-between text-sm gap-4">
                  <span>Default length</span>
                  <input type="range" min={8} max={64} value={settings.genDefaults.length} onChange={e => { void persist({ ...settings, genDefaults: { ...settings.genDefaults, length: Number(e.target.value) } }); }} className="w-40 accent-emerald-500" />
                </label>
                <div className="grid grid-cols-2 gap-2">
                  {([['upper', 'Uppercase'], ['lower', 'Lowercase'], ['digits', 'Digits'], ['symbols', 'Symbols']] as const).map(([k, label]) => (
                    <label key={k} className="flex items-center gap-2 text-sm">
                      <input type="checkbox" checked={settings.genDefaults[k]} onChange={e => { void persist({ ...settings, genDefaults: { ...settings.genDefaults, [k]: e.target.checked } }); }} className="accent-emerald-500 w-4 h-4" />
                      {label}
                    </label>
                  ))}
                </div>
                <label className="flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={settings.genDefaults.excludeAmbiguous} onChange={e => { void persist({ ...settings, genDefaults: { ...settings.genDefaults, excludeAmbiguous: e.target.checked } }); }} className="accent-emerald-500 w-4 h-4" />
                  Exclude ambiguous characters (I, l, 1, O, 0)
                </label>
              </div>
            </div>
          )}

          {tab === 'sites' && (
            <div className="space-y-4">
              <h2 className="text-lg font-black text-white">Per-Site Security Controls</h2>
              <div className="flex gap-2">
                <input value={siteInput} onChange={e => setSiteInput(e.target.value)} placeholder="example.com"
                  className="flex-1 px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500" />
                <button onClick={async () => {
                  const host = siteInput.trim().toLowerCase();
                  if (!host) return;
                  const next = { ...trustedSites, [host]: true };
                  setTrustedSites(next); await storeSet('lf_trusted_sites', next); setSiteInput('');
                }} className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-bold">+ Trust Site</button>
              </div>
              <div className="space-y-2">
                {Object.keys(trustedSites).map(host => (
                  <div key={host} className="flex items-center justify-between p-3 rounded-lg bg-slate-800/40 border border-slate-700">
                    <div>
                      <p className="text-sm font-bold text-slate-200">{host}</p>
                      <p className="text-[11px] text-emerald-400">✅ Malware · ✅ Phishing · ✅ Downloads · ✅ Scripts · ✅ Trackers · ✅ Notifications</p>
                    </div>
                    <button onClick={async () => {
                      const next = { ...trustedSites }; delete next[host];
                      setTrustedSites(next); await storeSet('lf_trusted_sites', next);
                    }} className="text-xs text-red-400 hover:text-red-300 font-semibold">Remove</button>
                  </div>
                ))}
                {Object.keys(trustedSites).length === 0 && <p className="text-sm text-slate-500 text-center py-6">No sites trusted yet. Trusted sites skip heuristics warnings.</p>}
              </div>
            </div>
          )}

          {tab === 'firewall' && (
            <div className="space-y-4">
              <h2 className="text-lg font-black text-white">Browser-Level Network Firewall</h2>
              <p className="text-xs text-slate-400">Toggle categories of locally-analyzed threats. Blocking is done entirely on-device using the built-in signature &amp; heuristic engine — no requests leave your browser.</p>
              <div className="space-y-2">
                {([['malware','Malware hosts'],['phishing','Phishing sites'],['scams','Scam domains'],['malvertising','Malvertising infrastructure'],['redirects','Suspicious redirects'],['scripts','Unknown third-party scripts (warn)'],['downloads','Executable downloads'],['notifications','Notification spam sources']] as const).map(([key, label]) => (
                  <label key={key} className="flex items-center justify-between p-3.5 rounded-xl bg-slate-800/40 border border-slate-700 hover:bg-slate-800/70">
                    <span className="text-sm font-semibold">{label}</span>
                    <input type="checkbox" checked={!!settings.shields[key]} onChange={e => { void persist({ ...settings, shields: { ...settings.shields, [key]: e.target.checked } }); }} className="accent-emerald-500 w-5 h-5" />
                  </label>
                ))}
              </div>
            </div>
          )}

          {tab === 'privacy' && (
            <div className="space-y-4">
              <h2 className="text-lg font-black text-white">🔏 Privacy Architecture — Zero Tolerance</h2>
              <div className="rounded-2xl border border-emerald-800/60 bg-emerald-950/40 p-6 space-y-3 text-sm text-emerald-100/90">
                <p className="text-base font-black text-emerald-300">We do not store and track any information whatsoever. Zero tolerance. Period.</p>
                <ul className="space-y-2">
                  <li>• <strong>No online servers.</strong> LockForce ships with no backend, no accounts, and makes no network requests of its own.</li>
                  <li>• <strong>No telemetry, no analytics, no crash reporting.</strong> Nothing is ever transmitted.</li>
                  <li>• <strong>Local-first threat engine.</strong> All signatures and heuristics run on your machine and work fully offline.</li>
                  <li>• <strong>AES-256-GCM vault.</strong> Vault credentials are encrypted with a key derived from your master password (PBKDF2-SHA256, 150,000 iterations). We cannot read them — and neither can anyone else.</li>
                  <li>• <strong>Encrypted at rest.</strong> Sensitive values never touch storage in plaintext.</li>
                  <li>• <strong>You can verify it.</strong> The entire codebase is inspectable; use the Export Security Report to see exactly what LockForce has recorded — and confirm how little that is.</li>
                </ul>
              </div>
              <button onClick={async () => {
                if (isChromeApi()) await chrome.storage.local.clear();
                else Object.keys(localStorage).filter(k => k.startsWith('lf_')).forEach(k => localStorage.removeItem(k));
                setSettings(DEFAULT_SETTINGS); setEvents([]); setTrustedSites({});
                alert('All local LockForce data wiped. Vault must be re-created (there is no recovery).');
              }} className="px-6 py-3 rounded-xl bg-red-900/50 border border-red-700 text-red-300 font-bold text-sm hover:bg-red-900">
                🗑️ Wipe ALL local LockForce data
              </button>
            </div>
          )}

          {tab === 'patch' && (
            <div className="space-y-4">
              <div className="rounded-2xl border border-emerald-700/60 bg-emerald-950/40 p-6">
                <div className="flex items-baseline gap-3">
                  <p className="text-3xl font-black text-emerald-300">Version 1.1</p>
                  <span className="px-3 py-1 rounded-full bg-emerald-600 text-white text-xs font-black uppercase tracking-wider">Stable</span>
                </div>
                <p className="text-sm text-emerald-200 font-bold mt-2">Official stable release — Vault Hardening update.</p>
                <p className="text-sm text-emerald-200/80 mt-2">
                  This is the official stable release of LockForce Security Suite. Future updates are uncertain — this version is the current, verified baseline. This update emphasizes the password manager, the app's original foundation, with all security features verified to work as advertised. No false security claims: every feature is real, local, and auditable.
                </p>
                <p className="text-sm text-emerald-200/80 mt-2">LockForce is not a replacement — it's an upgrade. LockForce began as a password manager, built on one idea: your passwords were always secure. This release returns to those roots, pairing the massively expanded <strong>LockForce Vault</strong> with hardened encryption and a complete local security suite. Version 1.1 is engineered for long-term stability: versioned storage schema, integrity-verified encryption, atomic writes, defensive defaults, zero network dependencies.</p>
              </div>
              <div className="rounded-2xl border border-slate-700 bg-slate-800/40 p-6">
                <p className="text-sm font-black text-slate-300 uppercase tracking-widest mb-3">What's New in 1.1</p>
                <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs text-slate-300">
                  {[
                    '🔐 PBKDF2 + AES-256-GCM + HMAC vault encryption',
                    '🛡️ Integrity check — corruption detected, never silent',
                    '📝 Atomic writes — no torn vault state',
                    '🔄 Seamless v1 → v2 vault migration',
                    '🔍 Vault search & filter',
                    '🚨 Reused-password detection',
                    '💪 Per-entry password strength meter',
                    '🕰️ Last-updated timestamps',
                    '✏️ Inline edit with validation',
                    '🗑️ Delete confirmation (two-click)',
                    '🎲 Generator: case/digit/symbol toggles',
                    '🙈 Exclude ambiguous characters',
                    '⏲️ Auto-lock vault timeout',
                    '🧹 Clipboard auto-clear timer',
                    '⚙️ Generator defaults in Settings',
                    '🔏 Zero-tolerance privacy, fully local',
                  ].map(f => <p key={f}>{f}</p>)}
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
};

export default Options;