import * as fs from 'fs';
import * as path from 'path';
import {
  ThemeFinding,
  ThemeFindingType,
  ThemeRiskLevel,
  ThemeIntelResult,
  ExternalDomain,
  Base64Decoded,
} from '../types';
import { isDomainSafe, isDomainSuspicious } from '../rules/domain-allowlist';

let findingCounter = 0;

function genId(): string {
  return `ti-${Date.now()}-${++findingCounter}`;
}

const PHP_EXTENSIONS = ['.php', '.phtml', '.php5', '.php7', '.php8', '.inc'];

function walkPhpFiles(dir: string): string[] {
  const results: string[] = [];
  if (!fs.existsSync(dir)) return results;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkPhpFiles(full));
    } else if (PHP_EXTENSIONS.includes(path.extname(entry.name).toLowerCase())) {
      results.push(full);
    }
  }
  return results;
}

function parseStyleCss(cssPath: string): ThemeIntelResult['styleMetadata'] {
  if (!fs.existsSync(cssPath)) return undefined;
  try {
    const content = fs.readFileSync(cssPath, 'utf-8');
    const meta: Record<string, string> = {};
    const patterns: Array<[RegExp, string]> = [
      [/Theme Name:\s*(.+)/i, 'name'],
      [/Theme Version:\s*(.+)/i, 'version'],
      [/Theme URI:\s*(.+)/i, 'uri'],
      [/Author:\s*(.+)/i, 'author'],
      [/Author URI:\s*(.+)/i, 'authorUri'],
      [/Description:\s*(.+)/i, 'description'],
      [/Text Domain:\s*(.+)/i, 'textDomain'],
    ];
    for (const [re, key] of patterns) {
      const m = content.match(re);
      if (m) (meta as any)[key] = m[1].trim();
    }
    return {
      name: meta.name,
      version: meta.version,
      author: meta.author,
      description: meta.description,
      textDomain: meta.textDomain,
    };
  } catch {
    return undefined;
  }
}

const URL_REGEX = /https?:\/\/[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+/g;
const DOMAIN_REGEX = /(?:https?:\/\/)([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)/g;

const WP_REMOTE_REGEX = /\b(wp_remote_(?:get|post|head|request))\s*\(\s*['"`]/gi;
const CURL_EXEC_REGEX = /\bcurl_exec\s*\(\s*/gi;
const FILE_GET_REGEX = /\bfile_get_contents\s*\(\s*(?:['"`]http|['"`]https|\$_)/gi;
const FOPEN_REGEX = /\bfopen\s*\(\s*['"`]https?:/gi;

const MALWARE_PATTERNS: Array<{
  re: RegExp;
  type: ThemeFindingType;
  severity: ThemeRiskLevel;
  message: string;
  confidence: number;
  recommendation: string;
}> = [
  { re: /eval\s*\(\s*base64_decode\s*\(/gi, type: 'malware', severity: 'critical', message: 'eval(base64_decode()) — obfuscated malicious code', confidence: 95, recommendation: 'Remove this file immediately. It contains obfuscated backdoor code.' },
  { re: /eval\s*\(\s*\$[a-zA-Z_]/gi, type: 'backdoor', severity: 'critical', message: 'eval() with variable — code execution backdoor', confidence: 90, recommendation: 'Review the variable source. If user-controlled, this is a backdoor.' },
  { re: /\bsystem\s*\(\s*\$/gi, type: 'backdoor', severity: 'critical', message: 'system() with variable — OS command execution', confidence: 95, recommendation: 'Remove or sanitize. OS command execution is almost always malicious.' },
  { re: /\bexec\s*\(\s*\$/gi, type: 'backdoor', severity: 'critical', message: 'exec() with variable — OS command execution', confidence: 90, recommendation: 'Review and remove. Command execution in themes is suspicious.' },
  { re: /\bpassthru\s*\(\s*\$/gi, type: 'backdoor', severity: 'critical', message: 'passthru() — OS command passthrough', confidence: 90, recommendation: 'Remove immediately. This is a common backdoor function.' },
  { re: /\bshell_exec\s*\(\s*\$/gi, type: 'backdoor', severity: 'critical', message: 'shell_exec() — shell command execution', confidence: 90, recommendation: 'Remove immediately. Shell execution in themes is dangerous.' },
  { re: /\bproc_open\s*\(/gi, type: 'backdoor', severity: 'critical', message: 'proc_open() — process execution', confidence: 85, recommendation: 'Review context. proc_open is rare in legitimate themes.' },
  { re: /\bpreg_replace\s*\(\s*['"`]\/.*\/e['"]/gi, type: 'malware', severity: 'critical', message: 'preg_replace /e modifier — code execution', confidence: 95, recommendation: 'Remove. The /e modifier allows arbitrary code execution.' },
  { re: /\bcreate_function\s*\(/gi, type: 'backdoor', severity: 'high', message: 'create_function() — dynamic code execution', confidence: 80, recommendation: 'Review context. create_function is deprecated and often used for obfuscation.' },
  { re: /\bassert\s*\(\s*\$/gi, type: 'backdoor', severity: 'high', message: 'assert() with variable — code assertion backdoor', confidence: 85, recommendation: 'Remove. assert with variables can execute arbitrary code.' },
  { re: /\$_(?:GET|POST|REQUEST|COOKIE)\s*\[.*\]\s*\(\s*\)/gi, type: 'backdoor', severity: 'critical', message: 'User input used as function call — remote code execution', confidence: 98, recommendation: 'Critical backdoor! User input is being called as a function.' },
  { re: /\bfile_put_contents\s*\(\s*\$_(?:GET|POST|REQUEST)/gi, type: 'backdoor', severity: 'critical', message: 'file_put_contents with user input — file upload backdoor', confidence: 95, recommendation: 'Critical! Allows attackers to write arbitrary files.' },
  { re: /\bmove_uploaded_file\s*\(/gi, type: 'suspicious_pattern', severity: 'high', message: 'move_uploaded_file — file upload handler', confidence: 70, recommendation: 'Review. File upload in themes is suspicious unless part of theme options.' },
  { re: /\bbase64_decode\s*\(\s*\$/gi, type: 'base64_payload', severity: 'high', message: 'base64_decode with variable — dynamic decode', confidence: 75, recommendation: 'Review the variable source. Dynamic base64 decode is often used for evasion.' },
  { re: /\beval\s*\(\s*\$/gi, type: 'backdoor', severity: 'critical', message: 'eval() with variable — dynamic code execution', confidence: 92, recommendation: 'Remove. eval with variables is a critical backdoor.' },
];

const NULL_KEYWORDS = [
  /\bnulled\b/i,
  /\bcracked\b/i,
  /\bwarez\b/i,
  /\bpirated?\b/i,
  /\bfree\s+download\b/i,
  /\b(gpl|gplv2|gplv3)\b.*\bfree\b/i,
  /\blicense\s*bypass\b/i,
  /\bactivate\s+without\s+license\b/i,
  /\bsans\s+licence\b/i,
  /\bthème\s+gratuit\b/i,
  /\bnull\s+theme\b/i,
];

const NULL_FILENAMES = [
  /license.*null/i,
  /null.*license/i,
  /nulled/i,
  /cracked/i,
  /warez/i,
  /activator/i,
  /bypass\.php/i,
  /unlock\.php/i,
  /patch\.php/i,
];

function extractUrls(content: string): string[] {
  const urls: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = URL_REGEX.exec(content)) !== null) {
    urls.push(m[0]);
  }
  return urls;
}

function extractDomains(content: string): string[] {
  const domains: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = DOMAIN_REGEX.exec(content)) !== null) {
    domains.push(m[1]);
  }
  return [...new Set(domains)];
}

function safeBase64Decode(str: string): string | null {
  try {
    const cleaned = str.replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/=]+$/.test(cleaned)) return null;
    if (cleaned.length < 8) return null;
    const buf = Buffer.from(cleaned, 'base64');
    const decoded = buf.toString('utf-8');
    if (!/[\x20-\x7E\r\n]/.test(decoded) || decoded.length < 5) return null;
    if (decoded === str) return null;
    return decoded;
  } catch {
    return null;
  }
}

function detectExternalDomainsInFile(
  content: string,
  relativePath: string,
  findings: ThemeFinding[],
  domainMap: Map<string, { urls: Set<string>; files: Array<{ file: string; line: number }> }>
): void {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    for (const re of [WP_REMOTE_REGEX, CURL_EXEC_REGEX, FILE_GET_REGEX, FOPEN_REGEX]) {
      re.lastIndex = 0;
      if (re.test(line)) {
        findings.push({
          id: genId(),
          file: relativePath,
          line: i + 1,
          type: 'external_domain',
          severity: 'medium',
          message: `External HTTP request: ${line.trim().substring(0, 120)}`,
          matchedText: line.trim(),
          confidence: 70,
          recommendation: 'Review why this theme makes external HTTP requests.',
        });
      }
    }

    const urls = extractUrls(line);
    for (const url of urls) {
      const domainMatch = url.match(DOMAIN_REGEX);
      if (domainMatch) {
        for (const dm of [domainMatch[0].replace(/^https?:\/\//, '')]) {
          if (!domainMap.has(dm)) {
            domainMap.set(dm, { urls: new Set(), files: [] });
          }
          const entry = domainMap.get(dm)!;
          entry.urls.add(url);
          const exists = entry.files.some(f => f.file === relativePath && f.line === i + 1);
          if (!exists) entry.files.push({ file: relativePath, line: i + 1 });
        }
      }
    }
  }
}

function detectNulledInFile(
  content: string,
  relativePath: string,
  filename: string,
  findings: ThemeFinding[]
): void {
  for (const re of NULL_KEYWORDS) {
    re.lastIndex = 0;
    const match = content.match(re);
    if (match) {
      findings.push({
        id: genId(),
        file: relativePath,
        line: 1,
        type: 'nulled',
        severity: 'high',
        message: `Nulled/pirated theme indicator: "${match[0]}"`,
        matchedText: match[0],
        confidence: 80,
        recommendation: 'This theme may be nulled/pirated. Use only genuine, licensed themes.',
      });
    }
  }

  const basename = path.basename(relativePath).toLowerCase();
  for (const re of NULL_FILENAMES) {
    if (re.test(basename)) {
      findings.push({
        id: genId(),
        file: relativePath,
        line: 1,
        type: 'nulled',
        severity: 'high',
        message: `Suspicious filename for nulled theme: ${filename}`,
        matchedText: filename,
        confidence: 85,
        recommendation: 'File name suggests nulled/pirated theme. Remove and use genuine copy.',
      });
    }
  }
}

function detectMalwareInFile(
  content: string,
  relativePath: string,
  findings: ThemeFinding[]
): void {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pattern of MALWARE_PATTERNS) {
      pattern.re.lastIndex = 0;
      if (pattern.re.test(line)) {
        findings.push({
          id: genId(),
          file: relativePath,
          line: i + 1,
          type: pattern.type,
          severity: pattern.severity,
          message: pattern.message,
          matchedText: line.trim().substring(0, 200),
          confidence: pattern.confidence,
          recommendation: pattern.recommendation,
        });
      }
    }
  }
}

function detectBase64Payloads(
  content: string,
  relativePath: string,
  results: Base64Decoded[]
): void {
  const b64Matches = content.matchAll(/\b(?:base64_decode\s*\(\s*['"])([A-Za-z0-9+/=]{20,})['"]/gi);
  for (const match of b64Matches) {
    const decoded = safeBase64Decode(match[1]);
    if (decoded) {
      const extractedUrls = extractUrls(decoded);
      const extractedDomains = extractDomains(decoded);
      if (extractedUrls.length > 0 || extractedDomains.length > 0 || /eval|exec|system|assert|file_put/i.test(decoded)) {
        results.push({
          file: relativePath,
          line: content.substring(0, match.index || 0).split('\n').length,
          decoded: decoded.substring(0, 500),
          extractedUrls,
          extractedDomains,
        });
      }
    }
  }
}

export function analyzeTheme(themesPath: string, themeName: string): ThemeIntelResult {
  const themeDir = path.join(themesPath, themeName);
  const phpFiles = walkPhpFiles(themeDir);

  const stylePath = path.join(themeDir, 'style.css');
  const styleMetadata = parseStyleCss(stylePath);

  const allMalwareFindings: ThemeFinding[] = [];
  const allNulledFindings: ThemeFinding[] = [];
  const allExternalFindings: ThemeFinding[] = [];
  const domainMap = new Map<string, { urls: Set<string>; files: Array<{ file: string; line: number }> }>();
  const allBase64Decoded: Base64Decoded[] = [];

  for (const filePath of phpFiles) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const relativePath = path.relative(themeDir, filePath).replace(/\\/g, '/');

      detectMalwareInFile(content, relativePath, allMalwareFindings);
      detectNulledInFile(content, relativePath, path.basename(filePath), allNulledFindings);
      detectExternalDomainsInFile(content, relativePath, allExternalFindings, domainMap);
      detectBase64Payloads(content, relativePath, allBase64Decoded);
    } catch {
      // skip unreadable files
    }
  }

  const externalDomains: ExternalDomain[] = Array.from(domainMap.entries()).map(([domain, data]) => ({
    domain,
    urls: Array.from(data.urls),
    files: data.files,
    isSuspicious: isDomainSuspicious(domain) || (!isDomainSafe(domain) && allMalwareFindings.length > 0),
  }));

  const allFindings = [...allMalwareFindings, ...allNulledFindings, ...allExternalFindings];
  const critical = allFindings.filter(f => f.severity === 'critical').length;
  const high = allFindings.filter(f => f.severity === 'high').length;
  const medium = allFindings.filter(f => f.severity === 'medium').length;
  const low = allFindings.filter(f => f.severity === 'low').length;

  let riskScore = 0;
  riskScore += critical * 30;
  riskScore += high * 15;
  riskScore += medium * 5;
  riskScore += low * 1;
  riskScore += allBase64Decoded.length * 8;
  riskScore += externalDomains.filter(d => d.isSuspicious).length * 10;
  if (allNulledFindings.length > 0) riskScore += 20;

  riskScore = Math.min(riskScore, 100);

  let riskLevel: ThemeRiskLevel = 'clean';
  if (riskScore >= 75) riskLevel = 'critical';
  else if (riskScore >= 50) riskLevel = 'high';
  else if (riskScore >= 25) riskLevel = 'medium';
  else if (riskScore > 0) riskLevel = 'low';

  return {
    themeName,
    themePath: themeDir,
    styleMetadata,
    externalDomains,
    nulledIndicators: allNulledFindings,
    malwarePatterns: allMalwareFindings,
    base64Decoded: allBase64Decoded,
    riskScore,
    riskLevel,
    summary: {
      totalFindings: allFindings.length + allBase64Decoded.length,
      critical,
      high,
      medium,
      low,
    },
  };
}

export function analyzeAllThemes(themesPath: string): ThemeIntelResult[] {
  if (!fs.existsSync(themesPath)) return [];
  const entries = fs.readdirSync(themesPath, { withFileTypes: true });
  const themes = entries.filter(e => e.isDirectory()).map(e => e.name);
  return themes.map(name => analyzeTheme(themesPath, name));
}
