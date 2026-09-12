
// LockForce content script — local behavioral heuristics only. No data leaves the page.
import { checkUrl } from '../lib/threatEngine';

interface Finding { severity: string; category: string; title: string; reasons: string[]; score: number; }

if (!(window as unknown as { __lfInit?: boolean }).__lfInit) {
  (window as unknown as { __lfInit?: boolean }).__lfInit = true;

  const isContextValid = (): boolean => typeof chrome !== 'undefined' && !!chrome.runtime?.id;
  const findings: Finding[] = [];
  let flushTimer: number | undefined;

  const flush = () => {
    if (!isContextValid() || findings.length === 0) return;
    const batch = findings.splice(0, findings.length);
    try { chrome.runtime.sendMessage({ type: 'lf-findings', findings: batch, source: location.href }); } catch { /* context gone */ }
  };
  const report = (f: Finding) => { findings.push(f); window.clearTimeout(flushTimer); flushTimer = window.setTimeout(flush, 1500); };

  // Reset badge state per page is not the content script's job; skip.

  const URL_FINDINGS = checkUrl(location.href);
  URL_FINDINGS.forEach(f => report({ ...f, severity: f.severity }));

  // ---- Credential protection: login form → cross-origin / fake-brand detection ----
  function scanForms(): void {
    const forms = Array.from(document.querySelectorAll('form'));
    for (const form of forms) {
      const pw = form.querySelector('input[type="password"]');
      if (!pw) continue;
      const email = form.querySelector('input[type="email"], input[name*="user" i], input[name*="mail" i]');
      const action = form.getAttribute('action') || '';
      let dest = '';
      try { dest = new URL(action, location.href).hostname; } catch { dest = location.hostname; }
      if (email && dest && dest !== location.hostname) {
        report({ severity: 'HIGH', category: 'credentials', title: 'Cross-origin credential submission', reasons: [`This login form submits your password to a different domain: ${dest}`], score: 75 });
      }
      // Fake brand: page mentions brand + password field + wrong domain
      const text = (document.body.innerText || '').slice(0, 4000).toLowerCase();
      const brands: Array<[string, string[]]> = [
        ['Microsoft', ['microsoft', 'outlook', 'office 365']], ['Google', ['google', 'gmail', 'sign in with google']],
        ['Apple', ['apple', 'icloud']], ['Discord', ['discord']], ['Steam', ['steam']],
        ['PayPal', ['paypal']], ['your bank', ['online banking', 'internet banking']],
      ];
      for (const [brand, tokens] of brands) {
        if (tokens.some(t => text.includes(t)) && !location.hostname.includes(brand.split(' ')[0].toLowerCase().replace(/\W/g, ''))) {
          report({ severity: 'CRITICAL', category: 'impersonation', title: `⚠️ This page may be impersonating ${brand}`, reasons: [`Page mentions ${brand} but is hosted on ${location.hostname}`, 'It contains a password field'], score: 90 });
          break;
        }
      }
    }
  }

  // ---- CommandGuard: social engineering into OS commands ----
  function scanCommandInjection(): void {
    const text = document.body.innerText || '';
    const patterns: Array<[RegExp, string]> = [
      [/powershell\s+(-enc|-ep|-command|iex|\w)/i, 'PowerShell command'],
      [/\bcmd(\.exe)?\s+(\/c|\/k)/i, 'CMD command'],
      [/press\s+(windows\s*\+\s*r|win\s*\+\s*r)/i, '"Press Windows+R" instruction'],
      [/(open|run|launch)\s+(powershell|command prompt|terminal)/i, 'Instruction to open a terminal'],
      [/disable\s+(antivirus|windows defender|firewall|smartscreen)/i, 'Instruction to disable security software'],
      [/paste\s+(this|the)\s+command/i, '"Paste this command" instruction'],
    ];
    for (const [re, label] of patterns) {
      if (re.test(text)) {
        report({ severity: 'CRITICAL', category: 'command', title: '🚨 Dangerous instructions detected', reasons: [`This page asks you to execute a ${label} outside the browser`, 'Legitimate websites never need you to run OS commands'], score: 92 });
        return;
      }
    }
    // Code blocks containing OS commands
    document.querySelectorAll('code, pre').forEach(el => {
      const t = el.textContent || '';
      if (/^(powershell|curl .*\|\s*(ba)?sh|iex\s*\()/im.test(t.trim())) {
        report({ severity: 'HIGH', category: 'command', title: '⚠️ This page asks you to copy a command into your OS', reasons: ['Code block contains a system-level command'], score: 70 });
      }
    });
  }

  // ---- Scam / fake-update / fake-CAPTCA text detection ----
  function scanPageContent(): void {
    const text = (document.body.innerText || '').slice(0, 8000).toLowerCase();
    const checks: Array<[RegExp, string, string]> = [
      [/your (chrome|browser|flash player) (is )?(out of date|needs (to be )?updat)/, 'fake-update', 'This page claims your browser is out of date — fake-update pages deliver malware'],
      [/(critical )?(windows|system) (security )?(alert|warning|error)/, 'fake-warning', 'Fake system warning pattern detected'],
      [/your (computer|pc) (has been )?(is )?infected/, 'fake-antivirus', 'Fake antivirus scan pattern detected'],
      [/i am not a robot|verify you are human.*then.*(hold|press)/, 'fake-captcha', 'Suspicious fake-CAPTCHA pattern (real CAPTCHAs do not ask you to run things)'],
      [/(congratulations|you (have )?(won|selected)).*(prize|iphone|gift|reward)/, 'scam', 'Giveaway/prize scam language detected'],
      [/(invest|deposit).*(crypto|bitcoin).*(guaranteed|\d{3}%|double)/, 'scam', 'Crypto investment scam language detected'],
      [/account (has been )?(suspended|locked|compromised).*(verify|confirm)/, 'phishing', 'Fake account-suspension phishing language detected'],
      [/vault|seed phrase|recovery phrase.*(enter|input|type)/, 'phishing', 'Crypto seed-phrase harvesting pattern detected'],
    ];
    for (const [re, cat, reason] of checks) {
      if (re.test(text)) {
        report({ severity: cat === 'fake-update' || cat === 'fake-antivirus' ? 'CRITICAL' : 'HIGH', category: cat, title: cat === 'scam' ? 'Scam page detected' : cat === 'phishing' ? 'Phishing pattern detected' : 'Fake browser/system page detected', reasons: [reason], score: 80 });
      }
    }
    // Hidden tiny iframes / suspicious iframes
    document.querySelectorAll('iframe').forEach(f => {
      const cs = window.getComputedStyle(f);
      if ((parseInt(cs.width) < 5 || parseInt(cs.height) < 5 || cs.opacity === '0') && f.src && f.src.startsWith('http')) {
        report({ severity: 'WARNING', category: 'exploit', title: 'Hidden iframe detected', reasons: ['A nearly-invisible iframe can load malicious content silently'], score: 50 });
      }
    });
    // Aggressive clipboard hijack: copy listeners replacing text
  }

  // ---- Clipboard protection: watch copy hijack of wallet-like values ----
  document.addEventListener('copy', () => {
    try {
      const sel = (window.getSelection()?.toString() || '').trim();
      if (/^(bc1|[13])[a-hj-np-z0-9]{25,62}$/i.test(sel) || /^0x[a-f0-9]{40}$/i.test(sel)) {
        window.setTimeout(() => {
          navigator.clipboard.readText().then((now) => {
            if (now && now.trim() !== sel && (/^(bc1|[13])[a-hj-np-z0-9]{25,62}$/i.test(now) || /^0x[a-f0-9]{40}$/i.test(now))) {
              report({ severity: 'CRITICAL', category: 'clipboard', title: '⚠️ Clipboard hijack detected', reasons: ['A script replaced your copied crypto address with a different one'], score: 95 });
            }
          }).catch(() => { /* read permission denied — fine */ });
        }, 50);
      }
    } catch { /* ignore */ }
  }, { passive: true });

  const runAll = () => { try { scanForms(); scanCommandInjection(); scanPageContent(); } catch { /* stay silent on any DOM edge case */ } };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', runAll);
  else runAll();

  // Single narrow observer for SPA re-renders; teardown wired properly.
  const ac = new AbortController();
  const obs = new MutationObserver(() => {
    window.clearTimeout(flushTimer);
    flushTimer = window.setTimeout(runAll, 2000);
  });
  obs.observe(document.body, { childList: true, subtree: false });
  window.addEventListener('pagehide', () => { obs.disconnect(); ac.abort(); }, { once: true });
}

export {};
