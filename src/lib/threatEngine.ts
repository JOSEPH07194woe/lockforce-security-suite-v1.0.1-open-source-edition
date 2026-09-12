
// LockForce local threat engine — deterministic, fully local. No network.
export type Severity = 'INFO' | 'WARNING' | 'HIGH' | 'CRITICAL';
export interface Finding {
  severity: Severity;
  category: string;
  title: string;
  reasons: string[];
  score: number; // 0-100 threat confidence
}

const DANGEROUS_EXT = ['exe','msi','scr','bat','cmd','ps1','vbs','js','jse','wsf','hta','com','pif','cpl','dll','sys','iso','img','lnk','jar','apk','appx','msix'];
const ARCHIVE_EXT = ['zip','rar','7z','tar','gz'];

const BRAND_DOMAINS: Array<[string, string[]]> = [
  ['google.com', ['google', 'gmail', 'goggle', 'g00gle', 'goog1e', 'gooogle']],
  ['microsoft.com', ['microsoft', 'micros0ft', 'rnicrosoft', 'm1crosoft', 'micr0soft']],
  ['apple.com', ['apple', 'app1e', 'icloud', 'aple']],
  ['paypal.com', ['paypal', 'paypa1', 'pay-pal', 'paypaI']],
  ['discord.com', ['discord', 'd1scord', 'dlscord']],
  ['steamcommunity.com', ['steamcommunity', 'steamcommunlty', 'steamcommnity', 'steam-gift', 'steem']],
  ['amazon.com', ['amazon', 'amaz0n', 'amazom']],
  ['facebook.com', ['facebook', 'faceb00k', 'facbook']],
  ['netflix.com', ['netflix', 'netf1ix']],
  ['chase.com', ['chase', 'chase-bank', 'chaseverify']],
  ['wellsfargo.com', ['wellsfargo', 'we1lsfargo']],
  ['coinbase.com', ['coinbase', 'c0inbase', 'coinbse']],
  ['binance.com', ['binance', 'b1nance', 'binan ce'.replace(' ', '')]],
];

// Local known-bad URL pattern signatures (shipped offline — no cloud)
const BAD_URL_PATTERNS: Array<[RegExp, string]> = [
  [/free[-_]?(vbucks|robux|gift|nitro|skins|steam)/i, 'Free-giveaway scam pattern'],
  [/chrome[-_]?(update|installer)\.(exe|msi)/i, 'Fake browser-update download pattern'],
  [/(flash|java|driver)[-_]?(update|setup)\.(exe|msi)/i, 'Fake legacy-update download pattern'],
  [/(verify|secure|confirm)[-]?(account|login|identity)/i, 'Credential-verification phishing pattern'],
  [/(wallet|metamask|ledger)[-_]?(seed|recover|restore)/i, 'Crypto wallet seed-harvest pattern'],
  [/(tech[-_]?)?support[-_]?(number|chat|alert)/i, 'Tech-support scam pattern'],
  [/^https?:\/\/\d{1,3}(\.\d{1,3}){3}/, 'IP-address navigation (no domain)'],
  [/[a-z0-9]{30,}\.(xyz|top|click|.icu)/i, 'Long random suspicious domain'],
];

export function checkUrl(rawUrl: string): Finding[] {
  const findings: Finding[] = [];
  let url: URL;
  try { url = new URL(rawUrl); } catch { return findings; }
  const host = url.hostname.toLowerCase();

  for (const [re, label] of BAD_URL_PATTERNS) {
    if (re.test(rawUrl)) findings.push({ severity: 'HIGH', category: 'url-pattern', title: 'Suspicious URL pattern', reasons: [label], score: 70 });
  }
  // Homograph / lookalike brand check
  for (const [brand, tokens] of BRAND_DOMAINS) {
    if (host === brand || host.endsWith('.' + brand)) continue;
    for (const t of tokens) {
      if (host.includes(t) && !host.includes(brand.split('.')[0] + '.')) {
        findings.push({ severity: 'CRITICAL', category: 'impersonation', title: `Possible impersonation of ${brand}`, reasons: [`Domain "${host}" resembles ${brand}`], score: 90 });
        break;
      }
    }
  }
  // Punycode abuse
  if (/xn--/.test(host)) {
    findings.push({ severity: 'HIGH', category: 'obfuscation', title: 'Punycode domain (possible homograph attack)', reasons: [`Domain uses punycode: ${host}`], score: 65 });
  }
  // Excessive length / obfuscation
  if (rawUrl.length > 180) findings.push({ severity: 'WARNING', category: 'obfuscation', title: 'Unusually long URL', reasons: [`${rawUrl.length} characters — common in phishing kits`], score: 40 });
  if ((rawUrl.match(/%[0-9a-f]{2}/gi) || []).length > 12) findings.push({ severity: 'WARNING', category: 'obfuscation', title: 'Heavy URL encoding', reasons: ['Excessive percent-encoding may hide the true destination'], score: 45 });
  // Suspicious port
  if (url.port && !['80', '443', ''].includes(url.port)) findings.push({ severity: 'WARNING', category: 'network', title: 'Non-standard port', reasons: [`Port ${url.port}`], score: 35 });
  // Insecure credential risk
  if (url.protocol === 'http:' && /(login|signin|password|account)/i.test(rawUrl)) {
    findings.push({ severity: 'HIGH', category: 'credentials', title: 'Login over insecure HTTP', reasons: ['Credentials could be sent without encryption'], score: 75 });
  }
  return findings;
}

export function checkDownload(filename: string, mimeType: string, referrer: string, url: string): Finding[] {
  const findings: Finding[] = [];
  const lower = filename.toLowerCase();
  const parts = lower.split('.');
  const ext = parts.length > 1 ? parts[parts.length - 1] : '';

  if (DANGEROUS_EXT.includes(ext)) {
    findings.push({ severity: ext === 'exe' || ext === 'msi' || ext === 'scr' || ext === 'hta' ? 'CRITICAL' : 'HIGH', category: 'download', title: 'Dangerous file type', reasons: [`.${ext} files can execute code on your computer`], score: 85 });
  }
  // Double extension: invoice.pdf.exe
  if (parts.length >= 3 && DANGEROUS_EXT.includes(ext)) {
    const prior = parts[parts.length - 2];
    if (['pdf','doc','docx','xls','xlsx','jpg','png','txt','mp4'].includes(prior)) {
      findings.push({ severity: 'CRITICAL', category: 'download', title: 'Double-extension trick', reasons: [`"${filename}" hides an executable behind a .${prior} extension — classic malware disguise`], score: 95 });
    }
  }
  // Suspicious names
  if (/(chrome|edge|firefox|adobe|flash|driver|antivirus)[-_ ]?(update|setup|install)/i.test(lower) && DANGEROUS_EXT.includes(ext)) {
    findings.push({ severity: 'CRITICAL', category: 'download', title: 'Fake software update pattern', reasons: [`"${filename}" matches fake-update malware naming`], score: 92 });
  }
  if (/(free|crack|keygen|cheat|hack|mod)[-_]?\w*\.(exe|msi|scr|bat|apk)/i.test(lower)) {
    findings.push({ severity: 'CRITICAL', category: 'download', title: 'Piracy/cheat malware pattern', reasons: [`"${filename}" matches cracked-software / game-cheat malware naming`], score: 90 });
  }
  // Executable inside archive name
  if (ARCHIVE_EXT.includes(ext) && /\.(exe|scr|bat|cmd|vbs|ps1|jar|lnk|hta)\.(zip|rar|7z|tar|gz)$/i.test(lower.replace(ext, ext))) {
    findings.push({ severity: 'HIGH', category: 'download', title: 'Executable packed inside archive', reasons: [`${filename} appears to contain an executable`], score: 80 });
  }
  // MIME mismatch
  if (DANGEROUS_EXT.includes(ext) && mimeType && /^image\/|^text\/plain|^video\//.test(mimeType)) {
    findings.push({ severity: 'HIGH', category: 'download', title: 'File type mismatch', reasons: [`Server claims "${mimeType}" but file is .${ext}`], score: 75 });
  }
  return findings;
}

export function threatScore(findings: Finding[]): number {
  return Math.min(100, findings.reduce((a, f) => Math.max(a, f.score), 0) + Math.floor(findings.length * 3));
}
export function scoreLabel(score: number): string {
  if (score >= 80) return 'Dangerous';
  if (score >= 55) return 'High Risk';
  if (score >= 30) return 'Suspicious';
  if (score >= 10) return 'Unverified';
  return 'Trusted';
}
