// LockForce Security Suite — service worker. Fully local, zero network.
import { checkUrl, checkDownload, checkUrl as scanUrl, threatScore, scoreLabel, type Finding, type Severity } from '../lib/threatEngine';
import { mergePasswords } from '../lib/secureStorage';

interface SecurityEvent {
  id: string; time: number; severity: Severity; category: string;
  title: string; source: string; reasons: string[]; action: string;
}
interface Settings {
  shields: Record<string, boolean>;
  mode: string; lockdown: boolean; autofillEnabled: boolean; notificationsEnabled: boolean;
  autoLockSeconds: number; clipboardClearSeconds: number;
  genDefaults: { length: number; upper: boolean; lower: boolean; digits: boolean; symbols: boolean; excludeAmbiguous: boolean };
}
const DEFAULTS: Settings = {
  shields: {}, mode: 'balanced', lockdown: false, autofillEnabled: true, notificationsEnabled: true,
  autoLockSeconds: 300, clipboardClearSeconds: 60,
  genDefaults: { length: 20, upper: true, lower: true, digits: true, symbols: true, excludeAmbiguous: false },
};

// ---- storage with schema versioning (long-term stability) ----
const SCHEMA_VERSION = 2;
async function initStorage(): Promise<void> {
  try {
    const r = await chrome.storage.local.get(['lf_schemaVersion', 'lf_settings', 'lf_events']);
    if (r.lf_schemaVersion !== SCHEMA_VERSION) {
      // Migrate: drop unknown-shaped state, keep nothing stale.
      await chrome.storage.local.set({ lf_schemaVersion: SCHEMA_VERSION });
      if (!r.lf_settings) await chrome.storage.local.set({ lf_settings: DEFAULTS });
      if (!r.lf_events) await chrome.storage.local.set({ lf_events: [] });
    }
  } catch { /* storage unavailable */ }
}
initStorage();

async function getSettings(): Promise<Settings> {
  try {
    const r = await chrome.storage.local.get('lf_settings');
    return { ...DEFAULTS, ...(r.lf_settings as Settings || {}), shields: { ...(r.lf_settings as Settings)?.shields } };
  } catch { return DEFAULTS; }
}

async function logEvent(ev: Omit<SecurityEvent, 'id' | 'time'>): Promise<void> {
  const full: SecurityEvent = { id: crypto.randomUUID(), time: Date.now(), ...ev };
  try {
    const r = await chrome.storage.local.get('lf_events');
    const list: SecurityEvent[] = Array.isArray(r.lf_events) ? r.lf_events : [];
    list.unshift(full);
    await chrome.storage.local.set({ lf_events: list.slice(0, 300) }); // cap accumulation
  } catch { /* ignore */ }
  try {
    const s = await getSettings();
    if (s.notificationsEnabled && (ev.severity === 'HIGH' || ev.severity === 'CRITICAL')) {
      chrome.notifications.create({
        type: 'basic', iconUrl: 'icons/icon128.png',
        title: `LockForce — ${ev.severity}`,
        message: ev.title,
      });
    }
  } catch { /* notifications unavailable */ }
}

async function bumpBadge(): Promise<void> {
  try {
    const r = await chrome.storage.local.get('lf_badge');
    const n = ((r.lf_badge as number) || 0) + 1;
    await chrome.storage.local.set({ lf_badge: n });
    await chrome.action.setBadgeText({ text: n > 99 ? '99+' : String(n) });
    await chrome.action.setBadgeBackgroundColor({ color: '#dc2626' });
  } catch { /* ignore */ }
}

// ---- URL scanning on navigation ----
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0 || !details.url.startsWith('http')) return;
  const s = await getSettings();
  if (s.lockdown) {
    await logEvent({ severity: 'CRITICAL', category: 'Lockdown', title: 'Navigation attempted during lockdown', source: details.url, reasons: ['Emergency lockdown blocks all new navigation'], action: 'Recorded — lockdown active' });
    await bumpBadge();
  }
  if (s.shields.phishing === false && s.shields.malware === false) return;
  const findings = scanUrl(details.url);
  const relevant = findings.filter(f =>
    (f.category === 'impersonation' && s.shields.phishing !== false) ||
    (f.category !== 'impersonation' && s.shields.malware !== false)
  );
  if (relevant.length === 0) return;
  const score = threatScore(relevant);
  await logEvent({
    severity: score >= 80 ? 'CRITICAL' : score >= 55 ? 'HIGH' : 'WARNING',
    category: relevant[0].category.startsWith('imperson') ? 'Impersonation' : 'URL Threat',
    title: relevant[0].title,
    source: details.url.slice(0, 120),
    reasons: relevant.flatMap(f => f.reasons),
    action: `Warned — threat score ${score}/100 (${scoreLabel(score)})`,
  });
  await bumpBadge();
});

// ---- Redirect Firewall: track per-tab redirect chains ----
const redirectChains = new Map<number, string[]>();
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  if (details.transitionQualifiers?.includes('redirect') || details.transitionType === 'link') {
    const chain = redirectChains.get(details.tabId) || [];
    chain.push(details.url);
    if (chain.length === 1 || !chain.slice(0, -1).includes(details.url)) redirectChains.set(details.tabId, chain.slice(-10));
    if (chain.length >= 4) {
      void (async () => {
        const s = await getSettings();
        if (s.shields.redirects === false) return;
        await logEvent({
          severity: chain.length >= 6 ? 'HIGH' : 'WARNING',
          category: 'Redirect',
          title: `Suspicious redirect chain (${chain.length} hops)`,
          source: chain[0]?.slice(0, 80) || 'unknown',
          reasons: ['Long redirect chains are a hallmark of malvertising and phishing funnels', ...chain.slice(-3).map(u => '→ ' + u.slice(0, 70))],
          action: 'Flagged for user',
        });
        await bumpBadge();
      })();
    }
  }
});
chrome.tabs.onRemoved.addListener((tabId) => { redirectChains.delete(tabId); }); // don't leak tab state

// ---- DownloadGuard ----
chrome.downloads.onCreated.addListener((item) => {
  void (async () => {
    const s = await getSettings();
    if (s.shields.downloads === false) return;
    const filename = (item.filename || item.url?.split('/').pop() || 'file').split(/[\\/]/).pop() || 'file';
    const findings = checkDownload(filename, item.mime || '', item.referrer || '', item.url || '');
    const isUserInitiated = (item.state === 'in_progress') && !item.url?.includes(''); // best-effort
    const score = threatScore(findings);
    if (findings.length === 0) return;
    const reasons = findings.flatMap(f => f.reasons);
    if (s.lockdown || s.mode === 'ultra' || score >= 85) {
      try { await chrome.downloads.cancel(item.id); } catch { /* may have finished */ }
      await logEvent({
        severity: 'CRITICAL', category: 'Download',
        title: `MALICIOUS DOWNLOAD BLOCKED — ${filename}`,
        source: (item.referrer || item.url || 'unknown').slice(0, 120),
        reasons: [...reasons, `Threat score: ${score}/100 (${scoreLabel(score)})`],
        action: 'Download cancelled',
      });
    } else {
      await logEvent({
        severity: 'HIGH', category: 'Download',
        title: `Suspicious download detected — ${filename}`,
        source: (item.referrer || item.url || 'unknown').slice(0, 120),
        reasons: [...reasons, `Threat score: ${score}/100 (${scoreLabel(score)})`],
        action: 'User warned — download allowed to continue',
      });
    }
    await bumpBadge();
  })();
});

// ---- Content-script findings ----
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === 'lf-findings' && Array.isArray(msg.findings)) {
    void (async () => {
      for (const f of msg.findings as Finding[]) {
        const s = await getSettings();
        const shieldKey = f.category === 'command' ? 'commandguard'
          : f.category === 'clipboard' ? 'clipboard'
          : f.category === 'credentials' ? 'credentials'
          : 'phishing';
        if (s.shields[shieldKey] === false) continue;
        await logEvent({
          severity: f.severity, category: f.category.charAt(0).toUpperCase() + f.category.slice(1),
          title: f.title, source: (msg.source || '').slice(0, 120),
          reasons: f.reasons, action: 'User warned',
        });
        await bumpBadge();
      }
    })();
    sendResponse({ ok: true });
  }
  if (msg?.type === 'lf-reset-badge') {
    void chrome.action.setBadgeText({ text: '' });
    void chrome.storage.local.set({ lf_badge: 0 });
    sendResponse({ ok: true });
  }
  return true;
});

// ---- Import-flow unlock + merge (surgical addition) ----
// After a successful unlock during the legacy-import flow, the imported
// entries are MERGED into the vault (dedupe by site+username; updates win on
// password change). The vault is never locked or replaced by this handler.
// Response shape: { ok, added, updated, unchanged, error? }.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === 'lf-merge-imported' && typeof msg.password === 'string' && Array.isArray(msg.entries)) {
    void (async () => {
      try {
        const result = await mergePasswords(msg.password, msg.entries);
        sendResponse(result);
      } catch (e) {
        sendResponse({ ok: false, added: 0, updated: 0, unchanged: 0, error: e instanceof Error ? e.message : 'Merge failed.' });
      }
    })();
    return true;
  }
  return true;
});

chrome.runtime.onInstalled.addListener(() => { void initStorage(); });
export {};