import * as fs from 'fs';
import * as path from 'path';
import { CheckResult, Finding, Severity, CheckCategory, ScanSummary } from '../types';
import { v4 as uuidv4 } from 'uuid';
import { getEnabledCustomRules, type CustomRule } from '../db/database';
import { calculateRiskScore } from '../rules/scorer';
import { extractAllPayloads } from './deobfuscator';
import { scanSupplyChain } from './supply-chain';

interface FileContext {
  path: string;
  relativePath: string;
  content: string;
  lines: string[];
  size: number;
  extension: string;
  mtime: Date;
  isPhp: boolean;
}

const PHP_EXT = ['.php', '.phtml', '.php5', '.php7', '.php8', '.inc'];
const SKIP_DIRS = ['node_modules', '.git', '.svn', '.hg', '__MACOSX', '.DS_Store'];

function readDir(dir: string, base: string, ignore: string[]): FileContext[] {
  const results: FileContext[] = [];
  let entries: fs.Dirent[];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return results; }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.includes(e.name) || ignore.some(p => e.name.includes(p))) continue;
      results.push(...readDir(full, base, ignore));
    } else if (e.isFile()) {
      if (ignore.some(p => full.includes(p))) continue;
      const ext = path.extname(e.name).toLowerCase();
      try {
        const stat = fs.statSync(full);
        const content = fs.readFileSync(full, 'utf-8');
        results.push({
          path: full,
          relativePath: path.relative(base, full),
          content, lines: content.split(/\r?\n/),
          size: stat.size, extension: ext,
          mtime: stat.mtime, isPhp: PHP_EXT.includes(ext),
        });
      } catch {}
    }
  }
  return results;
}

function f(file: string, line: number, col: number, code: string, msg: string, det: string): Finding {
  return { file, line, column: col, code: code.substring(0, 150), message: msg, details: det };
}

function runChecks(files: FileContext[]): CheckResult[] {
  const phpFiles = files.filter(f => f.isPhp);
  const allFiles = files;
  const results: CheckResult[] = [];

  // Helper to scan lines
  function scanLines(pattern: RegExp, category: CheckCategory, severity: Severity, id: string, name: string, desc: string, msgFn: (line: string, m: RegExpMatchArray) => string, detFn: () => string): void {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        const m = file.lines[i].match(pattern);
        if (m) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), msgFn(file.lines[i], m), detFn()));
      }
    }
    if (findings.length > 0) results.push({ checkId: id, checkName: name, category, severity, description: desc, findings });
  }

  // OBF-001: eval()
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\beval\s*\(/i.test(file.lines[i])) {
          findings.push(f(file.relativePath, i + 1, file.lines[i].indexOf('eval'), file.lines[i].trim().substring(0, 150), 'eval() detected - potential code injection risk', 'eval() executes arbitrary PHP code and is commonly used in obfuscated malicious code.'));
        }
      }
    }
    results.push({ checkId: 'OBF-001', checkName: 'eval() Usage', category: 'obfuscation', severity: 'critical', description: 'Detects use of eval()', findings });
  }

  // OBF-002: base64
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\bbase64_decode\s*\(/i.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'base64_decode() detected', 'base64_decode is commonly used to hide malicious payloads.'));
        else if (/\bbase64_encode\s*\(/i.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'base64_encode() detected', 'base64_encode used to encode data.'));
      }
    }
    results.push({ checkId: 'OBF-002', checkName: 'Base64 Patterns', category: 'obfuscation', severity: 'high', description: 'Detects base64 encode/decode usage', findings });
  }

  // OBF-003: gzinflate
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\bgz(inflate|uncompress|decode)\s*\(/i.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'gzinflate/gzuncompress detected', 'Compression functions chained with base64_decode to obfuscate payloads.'));
      }
    }
    results.push({ checkId: 'OBF-003', checkName: 'GZ Compression', category: 'obfuscation', severity: 'high', description: 'Detects gzinflate/gzuncompress', findings });
  }

  // OBF-004: str_rot13
  scanLines(/\bstr_rot13\s*\(/i, 'obfuscation', 'medium', 'OBF-004', 'str_rot13 Encoding', 'Detects str_rot13()', (l) => 'str_rot13() detected', () => 'Basic character rotation encoding.');

  // OBF-005: preg_replace /e
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/preg_replace\s*\(\s*['"`]\/[^'"`]*\/e\s*['"`]/i.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'preg_replace with /e modifier', 'Deprecated code execution in regex.'));
      }
    }
    results.push({ checkId: 'OBF-005', checkName: 'preg_replace /e', category: 'obfuscation', severity: 'critical', description: 'Detects deprecated preg_replace /e', findings });
  }

  // OBF-006: create_function
  scanLines(/\bcreate_function\s*\(/i, 'obfuscation', 'critical', 'OBF-006', 'create_function()', 'Deprecated dynamic function creation', (l) => 'create_function() detected', () => 'Deprecated since PHP 7.2.');

  // OBF-007: Dynamic calls
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        const m = file.lines[i].match(/\$(\w+)\s*\(/);
        if (m && !/^\s*\$/.test(file.lines[i].trim()) && /=\s*\$/.test(file.lines[i])) continue;
        if (m) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), `Dynamic function call: $${m[1]}()`, 'Variable function calls can hide the actual function.'));
      }
    }
    results.push({ checkId: 'OBF-007', checkName: 'Dynamic Calls', category: 'obfuscation', severity: 'high', description: 'Detects dynamic function calls', findings });
  }

  // OBF-008: Hex encoding
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        const hex = file.lines[i].match(/\\x[0-9a-fA-F]{2}/g);
        if (hex && hex.length >= 3) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), `Hex encoding (${hex.length} sequences)`, 'Hex-encoded characters suggest obfuscation.'));
      }
    }
    results.push({ checkId: 'OBF-008', checkName: 'Hex Encoding', category: 'obfuscation', severity: 'medium', description: 'Detects hex-encoded strings', findings });
  }

  // OBF-009: chr concat
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        const chr = file.lines[i].match(/\bchr\s*\(\s*0x[0-9a-fA-F]+\s*\)/gi);
        if (chr && chr.length >= 2) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), `chr() concatenation (${chr.length} calls)`, 'Building strings with chr(0x..) to hide payloads.'));
      }
    }
    results.push({ checkId: 'OBF-009', checkName: 'chr() Concat', category: 'obfuscation', severity: 'high', description: 'Detects chr() concatenation', findings });
  }

  // OBF-010: ionCube
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      if (file.content.includes('ioncube') || file.content.includes('ionCube')) findings.push(f(file.relativePath, 1, 0, 'ionCube reference', 'ionCube encoder detected', 'Commercial PHP encoder.'));
    }
    results.push({ checkId: 'OBF-010', checkName: 'ionCube', category: 'obfuscation', severity: 'info', description: 'Detects ionCube encoding', findings });
  }

  // OBF-011: Zend Guard
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      if (file.content.includes('Zend Guard') || file.content.includes('zend_optimized')) findings.push(f(file.relativePath, 1, 0, 'Zend Guard reference', 'Zend Guard detected', 'Zend Technologies encoder.'));
    }
    results.push({ checkId: 'OBF-011', checkName: 'Zend Guard', category: 'obfuscation', severity: 'info', description: 'Detects Zend Guard encoding', findings });
  }

  // OBF-012: SourceGuardian
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      if (file.content.includes('SourceGuardian') || file.content.includes('sg_load')) findings.push(f(file.relativePath, 1, 0, 'SourceGuardian reference', 'SourceGuardian detected', 'PHP encoder.'));
    }
    results.push({ checkId: 'OBF-012', checkName: 'SourceGuardian', category: 'obfuscation', severity: 'info', description: 'Detects SourceGuardian', findings });
  }

  // OBF-013: Multi-layer encoding
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const indicators: string[] = [];
      if (/base64_decode/i.test(file.content)) indicators.push('base64_decode');
      if (/gzinflate/i.test(file.content)) indicators.push('gzinflate');
      if (/gzuncompress/i.test(file.content)) indicators.push('gzuncompress');
      if (/str_rot13/i.test(file.content)) indicators.push('str_rot13');
      if (/strrev\s*\(/i.test(file.content)) indicators.push('strrev');
      if (/convert_uudecode/i.test(file.content)) indicators.push('uudecode');
      if (indicators.length >= 3) findings.push(f(file.relativePath, 1, 0, indicators.join(' -> '), `Multi-layer encoding (${indicators.length} layers)`, 'Chain of encoding: ' + indicators.join(' -> ')));
      else if (indicators.length === 2) findings.push(f(file.relativePath, 1, 0, indicators.join(' -> '), `Double encoding (${indicators.length} layers)`, 'Encoding functions: ' + indicators.join(' -> ')));
    }
    results.push({ checkId: 'OBF-013', checkName: 'Multi-Layer Encoding', category: 'obfuscation', severity: 'high', description: 'Detects multiple encoding layers', findings });
  }

  // OBF-014: XOR
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\$\w+\s*\[\s*\d+\s*\]\s*\^\s*\d+/.test(file.lines[i]) || /\bfor\s*\(.*\$\w+\s*\[\s*\$\w+\s*\]\s*\^/.test(file.lines[i])) {
          findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'XOR encryption pattern', 'XOR with string and variable is common obfuscation.'));
        }
      }
    }
    results.push({ checkId: 'OBF-014', checkName: 'XOR Encryption', category: 'obfuscation', severity: 'high', description: 'Detects XOR encryption patterns', findings });
  }

  // OBF-015: Variable obfuscation
  {
    const findings: Finding[] = [];
    const common = new Set(['i','j','k','n','x','y','id','db','tmp','val','key','str','arr','obj','res','req','ret','opt','args','len','idx','num','err','msg','buf','pos','end','max','min','fn','cb','el','ctx','url','src','dst']);
    for (const file of phpFiles) {
      const vars: string[] = [];
      for (const m of file.content.matchAll(/\$(\w+)\s*=/g)) vars.push(m[1]);
      const short = vars.filter(v => v.length <= 2 && !common.has(v.toLowerCase()));
      if (short.length >= 5) findings.push(f(file.relativePath, 1, 0, short.slice(0, 10).join(', '), `Variable obfuscation (${short.length} short names)`, 'Non-meaningful variable names suggest obfuscation.'));
    }
    results.push({ checkId: 'OBF-015', checkName: 'Variable Obfuscation', category: 'obfuscation', severity: 'medium', description: 'Detects meaningless variable names', findings });
  }

  // EXT-001: file_get_contents URL
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        const m = file.lines[i].matchAll(/file_get_contents\s*\(\s*['"]https?:\/\/[^'"]+['"]/gi);
        for (const match of m) findings.push(f(file.relativePath, i + 1, match.index || 0, file.lines[i].trim().substring(0, 150), 'file_get_contents() with external URL', 'Fetching remote content can be used for data exfiltration.'));
      }
    }
    results.push({ checkId: 'EXT-001', checkName: 'file_get_contents URL', category: 'external-access', severity: 'medium', description: 'Detects file_get_contents with URLs', findings });
  }

  // EXT-002: cURL
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\bcurl_(init|exec|setopt)\s*\(/i.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'cURL function call', 'Used for HTTP requests to external servers.'));
      }
    }
    results.push({ checkId: 'EXT-002', checkName: 'cURL Usage', category: 'external-access', severity: 'medium', description: 'Detects cURL usage', findings });
  }

  // EXT-003: fopen URL
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/fopen\s*\(\s*['"]https?:\/\//i.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'fopen() with external URL', 'Opening external URLs.'));
      }
    }
    results.push({ checkId: 'EXT-003', checkName: 'fopen URL', category: 'external-access', severity: 'medium', description: 'Detects fopen with URLs', findings });
  }

  // EXT-004: WP Remote
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        const m = file.lines[i].match(/\bwp_(safe_)?remote_(get|post|request)\s*\(\s*['"]([^'"]+)['"]/i);
        if (m) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), `WordPress HTTP API call: ${m[3]}`, 'WordPress HTTP API for external requests.'));
      }
    }
    results.push({ checkId: 'EXT-004', checkName: 'WP Remote', category: 'external-access', severity: 'medium', description: 'Detects WordPress HTTP API calls', findings });
  }

  // EXT-005: get_headers
  scanLines(/\bget_headers\s*\(/i, 'external-access', 'low', 'EXT-005', 'get_headers()', 'Detects get_headers() usage', (l) => 'get_headers() call', () => 'Sends HTTP HEAD requests.');

  // EXT-006: External domains
  {
    const findings: Finding[] = [];
    const domainMap = new Map<string, { file: string; line: number; count: number }>();
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const m of file.lines[i].matchAll(/https?:\/\/([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})/gi)) {
          const d = m[1].toLowerCase();
          if (d.includes('localhost') || d.includes('example.com')) continue;
          if (!domainMap.has(d)) domainMap.set(d, { file: file.relativePath, line: i + 1, count: 0 });
          domainMap.get(d)!.count++;
        }
      }
    }
    const suspicious = /telemetry|tracking|phishing|malware|bit\.ly|tinyurl|pastebin|\.tk|\.ml|\.ga/i;
    for (const [domain, info] of domainMap) {
      const isSusp = suspicious.test(domain);
      if (info.count >= 3 || isSusp) findings.push(f(info.file, info.line, 0, domain, isSusp ? `Suspicious domain: ${domain}` : `External domain: ${domain} (${info.count}x)`, isSusp ? 'Suspicious domain pattern.' : `Referenced ${info.count} times.`));
    }
    results.push({ checkId: 'EXT-006', checkName: 'External Domains', category: 'external-access', severity: 'medium', description: 'Detects external domain references', findings });
  }

  // EXT-007: License check
  {
    const findings: Finding[] = [];
    const pat = /license[_\s]*verif|verify[_\s]*license|purchase[_\s]*code|codecanyon|themeforest|envato/i;
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (pat.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'License verification code', 'License validation code may contact external servers.'));
      }
    }
    results.push({ checkId: 'EXT-007', checkName: 'License Check', category: 'external-access', severity: 'low', description: 'Detects license verification', findings });
  }

  // EXT-008: Font loading
  {
    const findings: Finding[] = [];
    const pat = /fonts\.googleapis\.com|fonts\.gstatic\.com|typekit\.net|@font-face.*url.*https/i;
    for (const file of allFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (pat.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'External font loading', 'External fonts can track users.'));
      }
    }
    results.push({ checkId: 'EXT-008', checkName: 'Font Loading', category: 'external-access', severity: 'low', description: 'Detects external font loading', findings });
  }

  // EXT-009: External CSS/JS
  {
    const findings: Finding[] = [];
    const pat = /wp_enqueue_(script|style)\s*\([^)]*['"]https?:\/\//i;
    for (const file of allFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (pat.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'External CSS/JS loading', 'Loading external resources.'));
      }
    }
    results.push({ checkId: 'EXT-009', checkName: 'External CSS/JS', category: 'external-access', severity: 'low', description: 'Detects external CSS/JS loading', findings });
  }

  // EXT-010: DNS queries
  scanLines(/\b(dns_get_record|checkdnsrr|getmxrr)\s*\(/i, 'external-access', 'medium', 'EXT-010', 'DNS Queries', 'Detects DNS query functions', (l) => 'DNS query function', () => 'DNS queries can be used for exfiltration.');

  // EXT-011: Webhooks
  {
    const findings: Finding[] = [];
    const pat = /webhook|slack\.com\/services|discord\.com\/api\/webhooks|hooks\.zapier\.com|telegram\.org\/bot/i;
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (pat.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Webhook endpoint', 'Webhook URLs can send data externally.'));
      }
    }
    results.push({ checkId: 'EXT-011', checkName: 'Webhook URLs', category: 'external-access', severity: 'medium', description: 'Detects webhook endpoints', findings });
  }

  // EXT-012: API endpoints
  {
    const findings: Finding[] = [];
    const pat = /\/api\/v\d+|\/rest\/v\d+|\/graphql|wp_ajax_|wp_rest_|admin[_-]?ajax\.php/i;
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        const m = file.lines[i].match(pat);
        if (m) findings.push(f(file.relativePath, i + 1, m.index || 0, file.lines[i].trim().substring(0, 150), `API endpoint: ${m[0]}`, 'API endpoint reference.'));
      }
    }
    results.push({ checkId: 'EXT-012', checkName: 'API Endpoints', category: 'external-access', severity: 'low', description: 'Detects API endpoint references', findings });
  }

  // SEC-001: SQL Injection
  {
    const findings: Finding[] = [];
    const pats = [
      /\$wpdb\s*->\s*(query|get_results|get_var)\s*\(\s*['"].*\$_/i,
      /\$_(GET|POST|REQUEST).*\bWHERE\b/i,
      /SELECT\s+.*\$_(GET|POST|REQUEST)/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'SQL injection vulnerability', 'Direct user input in SQL without escaping.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-001', checkName: 'SQL Injection', category: 'security', severity: 'critical', description: 'Detects SQL injection vulnerabilities', findings });
  }

  // SEC-002: XSS
  {
    const findings: Finding[] = [];
    const pats = [/echo\s+\$_(GET|POST|REQUEST)/i, /<\?=\s*\$_(GET|POST|REQUEST)/i, /print\s+\$_(GET|POST|REQUEST)/i];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'XSS vulnerability - unescaped user input', 'User input echoed without esc_html().')); break; } }
      }
    }
    results.push({ checkId: 'SEC-002', checkName: 'XSS', category: 'security', severity: 'critical', description: 'Detects XSS vulnerabilities', findings });
  }

  // SEC-003: CSRF
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const hasNonce = /wp_nonce_field|wp_create_nonce|wp_verify_nonce|check_admin_referer/i.test(file.content);
      const hasPost = /<form[^>]*method\s*=\s*['"]post['"]/i.test(file.content) || /admin[_-]?ajax\.php/i.test(file.content);
      if (hasPost && !hasNonce) {
        const lines = file.content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (/<form[^>]*method\s*=\s*['"]post['"]/i.test(lines[i]) || /admin[_-]?ajax/i.test(lines[i])) { findings.push(f(file.relativePath, i + 1, 0, lines[i].trim().substring(0, 150), 'Missing CSRF nonce', 'POST form without nonce verification.')); break; }
        }
      }
    }
    results.push({ checkId: 'SEC-003', checkName: 'CSRF', category: 'security', severity: 'high', description: 'Detects missing CSRF protection', findings });
  }

  // SEC-004: File upload
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\$_FILES\s*\[/.test(file.lines[i]) && /move_uploaded_file/i.test(file.content)) {
          const safe = /sanitize_file_name|wp_check_filetype/i.test(file.content);
          findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), safe ? 'File upload (some sanitization)' : 'File upload without sanitization', safe ? 'Verify completeness.' : 'No file type validation.'));
          break;
        }
      }
    }
    results.push({ checkId: 'SEC-004', checkName: 'File Upload', category: 'security', severity: 'high', description: 'Detects file upload vulnerabilities', findings });
  }

  // SEC-005: Directory traversal
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\$_(GET|POST|REQUEST).*\.\.\//i.test(file.lines[i]) || /file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)/i.test(file.lines[i])) {
          findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Directory traversal', 'User input in file operations without sanitization.'));
        }
      }
    }
    results.push({ checkId: 'SEC-005', checkName: 'Directory Traversal', category: 'security', severity: 'critical', description: 'Detects directory traversal', findings });
  }

  // SEC-006: Backdoor
  {
    const findings: Finding[] = [];
    const pats = [
      /eval\s*\(\s*\$_(GET|POST|REQUEST)/i,
      /exec\s*\(\s*\$_(GET|POST|REQUEST)/i,
      /system\s*\(\s*\$_(GET|POST|REQUEST)/i,
      /passthru\s*\(\s*\$_(GET|POST|REQUEST)/i,
      /shell_exec\s*\(\s*\$_(GET|POST|REQUEST)/i,
      /eval\s*\(\s*base64_decode/i,
      /exec\s*\(\s*base64_decode/i,
      /system\s*\(\s*base64_decode/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Backdoor pattern', 'Common backdoor pattern for RCE.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-006', checkName: 'Backdoor', category: 'security', severity: 'critical', description: 'Detects backdoor patterns', findings });
  }

  // SEC-007: Webshell
  {
    const findings: Finding[] = [];
    const shellPat = /\b(eval|assert)\s*\(\s*\$_(GET|POST|REQUEST)/i;
    const namePat = /c99|r57|b374k|wso|phpspy|FilesMan|Ani-Shell/i;
    for (const file of phpFiles) {
      if (namePat.test(file.content)) findings.push(f(file.relativePath, 1, 0, 'Known webshell signature', 'Known webshell name detected', 'Matches c99, r57, wso, etc.'));
      for (let i = 0; i < file.lines.length; i++) { if (shellPat.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Webshell pattern', 'Remote server control pattern.')); } }
    }
    results.push({ checkId: 'SEC-007', checkName: 'Webshell', category: 'security', severity: 'critical', description: 'Detects webshell patterns', findings });
  }

  // SEC-008: Privilege escalation
  {
    const findings: Finding[] = [];
    const pats = [
      /\bupdate_option\s*\(\s*['"]user_roles['"]/i,
      /\$wpdb\s*->\s*query\s*\(\s*['"].*UPDATE.*user.*role/i,
      /\badd_user_meta\s*\(.*wp_capabilities.*administrator/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Privilege escalation', 'Attempts to elevate privileges.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-008', checkName: 'Privilege Escalation', category: 'security', severity: 'critical', description: 'Detects privilege escalation', findings });
  }

  // SEC-009: Data exfiltration
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\b(wp_mail|mail)\s*\(\s*['"][^'"]+@/i.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Data exfiltration via email', 'Sending data to external email.'));
      }
    }
    results.push({ checkId: 'SEC-009', checkName: 'Data Exfiltration', category: 'security', severity: 'critical', description: 'Detects data exfiltration', findings });
  }

  // SEC-010: RCE
  {
    const findings: Finding[] = [];
    const pats = [/\beval\s*\(\s*\$_(GET|POST|REQUEST)/i, /\bexec\s*\(\s*\$_(GET|POST|REQUEST)/i, /\bsystem\s*\(\s*\$_(GET|POST|REQUEST)/i, /\bpassthru\s*\(\s*\$_(GET|POST|REQUEST)/i, /\bshell_exec\s*\(\s*\$_(GET|POST|REQUEST)/i, /\beval\s*\(\s*base64_decode/i, /\bexec\s*\(\s*base64_decode/i];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Remote code execution', 'Executes arbitrary code from external input.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-010', checkName: 'Remote Code Exec', category: 'security', severity: 'critical', description: 'Detects RCE vulnerabilities', findings });
  }

  // SEC-011: LFI/RFI
  {
    const findings: Finding[] = [];
    const pats = [/\b(include|include_once|require|require_once)\s*\(\s*\$_(GET|POST|REQUEST)/i, /\binclude\s*\(\s*['"]https?:\/\//i, /\brequire\s*\(\s*['"]https?:\/\//i];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'LFI/RFI vulnerability', 'Dynamic file inclusion with user input.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-011', checkName: 'LFI/RFI', category: 'security', severity: 'critical', description: 'Detects file inclusion vulnerabilities', findings });
  }

  // SEC-012: Unserialize
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\bunserialize\s*\(/i.test(file.lines[i])) {
          const userInput = /\$_(GET|POST|COOKIE|REQUEST)/i.test(file.lines[i]);
          findings.push(f(file.relativePath, i + 1, file.lines[i].indexOf('unserialize'), file.lines[i].trim().substring(0, 150), userInput ? 'unserialize() with user input' : 'unserialize() usage', userInput ? 'Object Injection RCE.' : 'Verify data source.'));
        }
      }
    }
    results.push({ checkId: 'SEC-012', checkName: 'Unserialize', category: 'security', severity: 'high', description: 'Detects unsafe unserialize', findings });
  }

  // SEC-013: Dangerous functions
  {
    const findings: Finding[] = [];
    const fns = ['exec', 'system', 'passthru', 'shell_exec', 'popen', 'proc_open', 'pcntl_exec'];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const fn of fns) {
          if (new RegExp('\\b' + fn + '\\s*\\(', 'i').test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), `Dangerous function: ${fn}()`, `${fn}() can execute system commands.`));
        }
      }
    }
    results.push({ checkId: 'SEC-013', checkName: 'Dangerous Functions', category: 'security', severity: 'high', description: 'Detects dangerous system functions', findings });
  }

  // SEC-014: ob_start
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\bob_start\s*\(\s*['"][^'"]+['"]/i.test(file.lines[i]) || /\bob_start\s*\(\s*\$/i.test(file.lines[i]) || /\bob_start\s*\(\s*function/i.test(file.lines[i])) {
          findings.push(f(file.relativePath, i + 1, file.lines[i].indexOf('ob_start'), file.lines[i].trim().substring(0, 150), 'ob_start() with callback', 'Output buffering callback can inject content.'));
        }
      }
    }
    results.push({ checkId: 'SEC-014', checkName: 'ob_start Callback', category: 'security', severity: 'high', description: 'Detects ob_start with callbacks', findings });
  }

  // SEC-015: .htaccess
  {
    const findings: Finding[] = [];
    const pats = [/\bfile_put_contents\s*\(\s*['"].*\.htaccess/i, /\bfwrite\s*\(.*\.htaccess/i, /\bunlink\s*\(\s*['"].*\.htaccess/i];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), '.htaccess modification', 'Modifying .htaccess alters Apache config.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-015', checkName: '.htaccess Modify', category: 'security', severity: 'high', description: 'Detects .htaccess modification', findings });
  }

  // SEC-016: ini_set
  {
    const findings: Finding[] = [];
    const pats = [
      { p: /\bini_set\s*\(\s*['"]allow_url_include['"]/i, d: 'Enabling remote file inclusion' },
      { p: /\bini_set\s*\(\s*['"]allow_url_fopen['"]/i, d: 'Enabling remote fopen' },
      { p: /\bini_set\s*\(\s*['"]disable_functions['"]/i, d: 'Changing disabled functions' },
      { p: /\bini_set\s*\(\s*['"]open_basedir['"]/i, d: 'Changing open_basedir' },
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const { p, d } of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, file.lines[i].indexOf('ini_set'), file.lines[i].trim().substring(0, 150), `ini_set: ${d}`, d)); break; } }
      }
    }
    results.push({ checkId: 'SEC-016', checkName: 'ini_set Modify', category: 'security', severity: 'medium', description: 'Detects ini_set security changes', findings });
  }

  // SEC-017: Error suppression
  {
    const findings: Finding[] = [];
    let count = 0;
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        const m = file.lines[i].match(/@\s*(file_get_contents|fopen|fwrite|fread|unlink|rename|chmod|copy|include|require|session_start|mkdir|file_put_contents)\s*\(/gi);
        if (m) { count += m.length; if (findings.length < 20) findings.push(f(file.relativePath, i + 1, file.lines[i].indexOf('@'), file.lines[i].trim().substring(0, 150), `Error suppression on ${m[0].replace('@', '').trim().split('(')[0]}`, 'Hides errors and security issues.')); }
      }
    }
    results.push({ checkId: 'SEC-017', checkName: 'Error Suppression', category: 'security', severity: 'medium', description: 'Detects error suppression abuse', findings });
  }

  // SEC-018: Hardcoded creds
  {
    const findings: Finding[] = [];
    const pats = [/(password|passwd|pass)\s*=\s*['"][^'"]{3,}['"]/i, /(api[_-]?key|apikey)\s*=\s*['"][^'"]{8,}['"]/i, /(secret|private[_-]?key|auth[_-]?token)\s*=\s*['"][^'"]{8,}['"]/i];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 60) + '...', 'Hardcoded credential', 'Use environment variables.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-018', checkName: 'Hardcoded Creds', category: 'security', severity: 'critical', description: 'Detects hardcoded credentials', findings });
  }

  // SEC-019: Weak hashing
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\bmd5\s*\(/i.test(file.lines[i]) && !/\.md5\b/i.test(file.lines[i])) {
          const pass = /password|pass|auth|token|secret/i.test(file.lines[i]);
          findings.push(f(file.relativePath, i + 1, file.lines[i].indexOf('md5'), file.lines[i].trim().substring(0, 150), pass ? 'md5 for passwords - INSECURE' : 'md5() usage', pass ? 'Use password_hash().' : 'md5 is for checksums only.'));
        }
        if (/\bsha1\s*\(/i.test(file.lines[i])) {
          const pass = /password|pass|auth|token|secret/i.test(file.lines[i]);
          findings.push(f(file.relativePath, i + 1, file.lines[i].indexOf('sha1'), file.lines[i].trim().substring(0, 150), pass ? 'sha1 for passwords - INSECURE' : 'sha1() usage', pass ? 'Use password_hash().' : 'SHA-1 has collisions.'));
        }
      }
    }
    results.push({ checkId: 'SEC-019', checkName: 'Weak Hashing', category: 'security', severity: 'medium', description: 'Detects weak hashing algorithms', findings });
  }

  // SEC-020: Debug code
  {
    const findings: Finding[] = [];
    const fns = [
      { p: /\bvar_dump\s*\(/i, n: 'var_dump()' },
      { p: /\bprint_r\s*\(/i, n: 'print_r()' },
      { p: /\bdebug_backtrace\s*\(/i, n: 'debug_backtrace()' },
      { p: /\bdebug_print_backtrace\s*\(/i, n: 'debug_print_backtrace()' },
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const { p, n } of fns) { if (p.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), `Debug code: ${n}`, 'Debug functions leak info.')); }
      }
    }
    results.push({ checkId: 'SEC-020', checkName: 'Debug Code', category: 'security', severity: 'low', description: 'Detects debug functions in production', findings });
  }

  // PAT-001: Minified
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      if (file.lines.length < 10) continue;
      let longLines = 0, totalLen = 0;
      for (const l of file.lines) { totalLen += l.length; if (l.length > 200) longLines++; }
      const avg = totalLen / file.lines.length;
      if (longLines / file.lines.length > 0.3 && avg > 100) findings.push(f(file.relativePath, 1, 0, `${longLines}/${file.lines.length} lines > 200 chars`, `Minified code (avg: ${Math.round(avg)} chars)`, 'Code appears minified.'));
    }
    results.push({ checkId: 'PAT-001', checkName: 'Minified Code', category: 'code-pattern', severity: 'medium', description: 'Detects minified code', findings });
  }

  // PAT-002: Custom encoding
  {
    const findings: Finding[] = [];
    const pats = [/function\s+encode\w*\s*\(/i, /function\s+decode\w*\s*\(/i, /function\s+crypt\w*\s*\(/i, /function\s+decrypt\w*\s*\(/i];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Custom encode/decode function', 'May be used for obfuscation.')); }
      }
    }
    results.push({ checkId: 'PAT-002', checkName: 'Custom Encoding', category: 'code-pattern', severity: 'medium', description: 'Detects custom encoding functions', findings });
  }

  // PAT-003: XOR loops
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\$\w+\s*\[\s*\d+\s*\]\s*\^\s*\d+/.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'XOR decryption loop', 'Character-by-character XOR decryption.'));
      }
    }
    results.push({ checkId: 'PAT-003', checkName: 'XOR Loops', category: 'code-pattern', severity: 'high', description: 'Detects XOR decryption loops', findings });
  }

  // PAT-004: String concat
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        const c = file.lines[i].match(/\.\s*['"]/g);
        if (c && c.length >= 6) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), `Heavy string concat (${c.length} segments)`, 'Excessive concatenation hides code intent.'));
      }
    }
    results.push({ checkId: 'PAT-004', checkName: 'String Concat', category: 'code-pattern', severity: 'medium', description: 'Detects string concatenation obfuscation', findings });
  }

  // PAT-005: Unicode bypass
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/mb_convert_encoding\s*\([^)]*UTF-?7/i.test(file.lines[i]) || /\\u[0-9a-fA-F]{4}/.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Unicode bypass attempt', 'Alternate encodings bypass filters.'));
      }
    }
    results.push({ checkId: 'PAT-005', checkName: 'Unicode Bypass', category: 'code-pattern', severity: 'medium', description: 'Detects Unicode bypass attempts', findings });
  }

  // PAT-006: Null byte
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\\x00|%00/i.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, file.lines[i].search(/\\x00|%00/i), file.lines[i].trim().substring(0, 150), 'Null byte injection', 'Null bytes truncate strings and bypass checks.'));
      }
    }
    results.push({ checkId: 'PAT-006', checkName: 'Null Byte', category: 'code-pattern', severity: 'high', description: 'Detects null byte injection', findings });
  }

  // PAT-007: Dead code
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const idx = file.content.lastIndexOf('?>');
      if (idx !== -1 && file.content.substring(idx + 2).trim().length > 10) findings.push(f(file.relativePath, 1, 0, 'Code after closing ?>', 'Code after closing tag', 'Can be used to hide code.'));
    }
    results.push({ checkId: 'PAT-007', checkName: 'Dead Code', category: 'code-pattern', severity: 'low', description: 'Detects dead/unreachable code', findings });
  }

  // PAT-008: Closing tag
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      if (/\?>\s*$/.test(file.content.trimEnd())) {
        const lines = file.content.split('\n');
        for (let i = lines.length - 1; i >= 0; i--) { if (lines[i].includes('?>')) { findings.push(f(file.relativePath, i + 1, lines[i].indexOf('?>'), lines[i].trim(), 'Closing PHP tag', 'WordPress standards recommend omitting ?>')); break; } }
      }
    }
    results.push({ checkId: 'PAT-008', checkName: 'Closing Tag', category: 'code-pattern', severity: 'info', description: 'Detects closing PHP tags', findings });
  }

  // PAT-009: Suspicious comments
  {
    const findings: Finding[] = [];
    const pat = /(?:hack|exploit|bypass|backdoor|malware|rootkit|trojan|virus|hide|secret|stealth)/i;
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/(?:\/\/|#|\/\*)/.test(file.lines[i]) && pat.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Suspicious comment', 'Comment with suspicious keywords.'));
      }
    }
    results.push({ checkId: 'PAT-009', checkName: 'Suspicious Comments', category: 'code-pattern', severity: 'low', description: 'Detects suspicious comments', findings });
  }

  // PAT-010: Mixed content
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const phpCount = (file.content.match(/<\?php/gi) || []).length;
      const htmlCount = (file.content.match(/<[a-zA-Z][^>]*>/g) || []).length;
      if (phpCount >= 5 && htmlCount >= 10) findings.push(f(file.relativePath, 1, 0, `${phpCount} PHP blocks, ${htmlCount} HTML tags`, `Heavy mixed PHP/HTML (${phpCount} blocks)`, 'Mixing PHP blocks with HTML can obfuscate code.'));
    }
    results.push({ checkId: 'PAT-010', checkName: 'Mixed Content', category: 'code-pattern', severity: 'info', description: 'Detects mixed PHP/HTML', findings });
  }

  // FILE-001: Permissions
  {
    const findings: Finding[] = [];
    for (const file of allFiles) {
      try {
        const stat = fs.statSync(file.path);
        const mode = '0' + (stat.mode & 0o777).toString(8);
        if ((stat.mode & 0o777) === 0o777) findings.push(f(file.relativePath, 1, 0, `Permissions: ${mode}`, 'World-writable (777)', 'Insecure permissions.'));
        else if ((stat.mode & 0o022) !== 0) findings.push(f(file.relativePath, 1, 0, `Permissions: ${mode}`, `Too permissive (${mode})`, 'Recommended: 644 for files.'));
      } catch {}
    }
    results.push({ checkId: 'FILE-001', checkName: 'Permissions', category: 'file-analysis', severity: 'high', description: 'Checks file permissions', findings });
  }

  // FILE-002: Hidden files
  {
    const findings: Finding[] = [];
    for (const file of allFiles) { if (path.basename(file.path).startsWith('.')) findings.push(f(file.relativePath, 1, 0, path.basename(file.path), `Hidden file: ${path.basename(file.path)}`, 'Hidden files may contain malicious code.')); }
    results.push({ checkId: 'FILE-002', checkName: 'Hidden Files', category: 'file-analysis', severity: 'low', description: 'Detects hidden files', findings });
  }

  // FILE-003: Large files
  {
    const findings: Finding[] = [];
    for (const file of allFiles) {
      const mb = file.size / (1024 * 1024);
      if (mb > 10) findings.push(f(file.relativePath, 1, 0, `${mb.toFixed(1)} MB`, `Very large file: ${mb.toFixed(1)} MB`, 'May contain embedded payloads.'));
      else if (file.size / 1024 > 1000) findings.push(f(file.relativePath, 1, 0, `${(file.size / 1024).toFixed(0)} KB`, `Large file: ${(file.size / 1024).toFixed(0)} KB`, 'Review for hidden content.'));
    }
    results.push({ checkId: 'FILE-003', checkName: 'Large Files', category: 'file-analysis', severity: 'medium', description: 'Detects large files', findings });
  }

  // FILE-004: Recent modified
  {
    const findings: Finding[] = [];
    const now = Date.now();
    for (const file of allFiles) {
      const age = now - file.mtime.getTime();
      if (age < 86400000) findings.push(f(file.relativePath, 1, 0, file.mtime.toISOString(), 'Modified within 24h', 'Recent changes.'));
      else if (age < 604800000) findings.push(f(file.relativePath, 1, 0, file.mtime.toISOString(), 'Modified within 7 days', 'Review recent changes.'));
    }
    results.push({ checkId: 'FILE-004', checkName: 'Recent Modified', category: 'file-analysis', severity: 'info', description: 'Detects recently modified files', findings });
  }

  // FILE-005: Unusual extensions
  {
    const findings: Finding[] = [];
    const known = ['.php', '.phtml', '.php5', '.php7', '.php8', '.inc', '.js', '.css', '.html', '.htm', '.txt', '.xml', '.json', '.svg', '.png', '.jpg', '.jpeg', '.gif', '.woff', '.woff2', '.ttf', '.otf', '.eot', '.po', '.mo', '.pot', '.md', '.cfg', '.ini', '.yml', '.yaml'];
    for (const file of allFiles) { if (file.extension && !known.includes(file.extension)) findings.push(f(file.relativePath, 1, 0, `Extension: ${file.extension}`, `Unusual extension: ${file.extension}`, 'Investigate this file.')); }
    results.push({ checkId: 'FILE-005', checkName: 'Unusual Extensions', category: 'file-analysis', severity: 'low', description: 'Detects unusual file extensions', findings });
  }

  // FILE-006: Backup files
  {
    const findings: Finding[] = [];
    const bpats = [/\.(bak|backup|old|orig|save|swp|tmp|temp|copy)$/i, /~$/, /\.php\d+$/i];
    for (const file of allFiles) {
      const bn = path.basename(file.path);
      for (const p of bpats) { if (p.test(bn)) { findings.push(f(file.relativePath, 1, 0, bn, `Backup file: ${bn}`, 'Should not be in production.')); break; } }
    }
    results.push({ checkId: 'FILE-006', checkName: 'Backup Files', category: 'file-analysis', severity: 'medium', description: 'Detects backup files', findings });
  }

  // FILE-007: Structure integrity
  {
    const findings: Finding[] = [];
    const hasReadme = files.some(f => /readme|changelog|license/i.test(path.basename(f.path)));
    const hasPhp = files.some(f => f.isPhp);
    if (!hasReadme && files.length > 5) findings.push(f('', 1, 0, 'No README/changelog', 'Missing documentation', 'Legitimate plugins have docs.'));
    if (!hasPhp && files.length > 0) findings.push(f('', 1, 0, 'No PHP files', 'No PHP files found', 'WordPress theme/plugin should have PHP.'));
    results.push({ checkId: 'FILE-007', checkName: 'Structure Integrity', category: 'file-analysis', severity: 'info', description: 'Checks theme/plugin structure', findings });
  }

  // FILE-008: Version mismatch
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const versions = file.content.match(/(?:version|Version)\s*[:=]\s*['"]([^'"]+)['"]/g);
      if (versions && versions.length > 1) findings.push(f(file.relativePath, 1, 0, versions.join(' | '), `Multiple versions (${versions.length})`, 'Inconsistent version declarations.'));
    }
    results.push({ checkId: 'FILE-008', checkName: 'Version Mismatch', category: 'file-analysis', severity: 'low', description: 'Detects version mismatches', findings });
  }

  // FILE-009: License files
  {
    const findings: Finding[] = [];
    const lpats = [/license|licence|gpl|mit|apache|codecanyon|themeforest|envato|purchase[_-]?code/i];
    for (const file of allFiles) {
      const bn = path.basename(file.path).toLowerCase();
      if (lpats.some(p => p.test(bn))) {
        if (file.isPhp && /eval|base64_decode|gzinflate|ioncube/i.test(file.content)) findings.push(f(file.relativePath, 1, 0, 'Encrypted license file', 'License file has obfuscated code', 'May be backdoor.'));
        if (/purchase|buyer|envato|codecanyon/i.test(bn)) findings.push(f(file.relativePath, 1, 0, bn, 'Commercial license file', 'Check for external verification.'));
      }
    }
    results.push({ checkId: 'FILE-009', checkName: 'License Files', category: 'file-analysis', severity: 'low', description: 'Analyzes license files', findings });
  }

  // FILE-010: Empty files
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      if (file.size === 0) findings.push(f(file.relativePath, 1, 0, 'Empty file (0 bytes)', 'Empty PHP file', 'No purpose, could be placeholder.'));
      else if (file.size < 50) { const c = file.content.trim(); if (c === '<?php' || c === '<?php ?>' || c === '<?php\n') findings.push(f(file.relativePath, 1, 0, c, 'PHP file with no code', 'Only PHP tags, no code.')); }
    }
    results.push({ checkId: 'FILE-010', checkName: 'Empty Files', category: 'file-analysis', severity: 'info', description: 'Detects empty PHP files', findings });
  }

  // WP-001: Non-standard hooks
  {
    const findings: Finding[] = [];
    const suspicious = /wp_head|wp_footer|init|admin_init|shutdown/i;
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        const m = file.lines[i].match(/\b(add_action|add_filter)\s*\(\s*['"]([^'"]+)['"]/i);
        if (m && suspicious.test(m[2]) && !['init', 'admin_init', 'wp_head', 'wp_footer', 'admin_head', 'admin_footer', 'plugins_loaded', 'after_setup_theme'].includes(m[2].toLowerCase())) {
          findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), `Suspicious hook: ${m[1]} on "${m[2]}"`, 'Verify this is intentional.'));
        }
      }
    }
    results.push({ checkId: 'WP-001', checkName: 'Non-Standard Hooks', category: 'wordpress', severity: 'medium', description: 'Detects suspicious WordPress hooks', findings });
  }

  // WP-002: WP version compat
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const tested = file.content.match(/Tested up to:\s*(.+)/i);
      if (tested) {
        const v = tested[1].trim();
        if (/^\d+\.?\d*$/.test(v) && parseInt(v) < 6) findings.push(f(file.relativePath, 1, 0, `Tested up to: ${v}`, `Only tested up to WP ${v}`, 'Not tested with newer WordPress.'));
      }
      const reqWp = file.content.match(/Requires at least:\s*(.+)/i);
      if (reqWp) {
        const v = reqWp[1].trim();
        if (/^[2-4]\./.test(v) && parseFloat(v) < 5.0) findings.push(f(file.relativePath, 1, 0, `Requires: ${v}`, `Targets old WP version: ${v}`, 'May use deprecated functions.'));
      }
    }
    results.push({ checkId: 'WP-002', checkName: 'WP Version Compat', category: 'wordpress', severity: 'info', description: 'Checks WordPress version compatibility', findings });
  }

  // WP-003: Abandoned/Deprecated
  {
    const findings: Finding[] = [];
    const dep = [
      { p: /\bget_currentuserinfo\s*\(/i, m: 'get_currentuserinfo() deprecated since WP 4.5' },
      { p: /\bget_bloginfo\s*\(\s*['"]siteurl['"]/i, m: 'Use site_url() instead' },
      { p: /\buser_level\b/i, m: 'user_level is deprecated' },
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const { p, m } of dep) { if (p.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), m, 'Deprecated WordPress API.')); }
      }
    }
    results.push({ checkId: 'WP-003', checkName: 'Abandoned Plugin', category: 'wordpress', severity: 'medium', description: 'Detects deprecated WordPress APIs', findings });
  }

  // WP-004: Known vulns
  {
    const findings: Finding[] = [];
    const pats = [
      { p: /extract\s*\(\s*\$_(GET|POST|REQUEST)/i, id: 'extract() vuln', d: 'extract() with user input - variable overwrite' },
      { p: /\beval\s*\(\s*\$_(GET|POST|REQUEST)/i, id: 'RCE', d: 'eval() with user input - RCE' },
      { p: /\bfile_get_contents\s*\(\s*\$_(GET|POST|REQUEST)/i, id: 'LFI', d: 'file_get_contents with user input' },
      { p: /\bexec\s*\(\s*\$_(GET|POST|REQUEST)/i, id: 'CMD Injection', d: 'exec() with user input' },
      { p: /\bunserialize\s*\(\s*\$_(GET|POST|COOKIE)/i, id: 'Object Injection', d: 'unserialize with user input' },
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const { p, id, d } of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), `Known vuln: ${id}`, d)); break; } }
      }
    }
    results.push({ checkId: 'WP-004', checkName: 'Known Vulns', category: 'wordpress', severity: 'critical', description: 'Detects known vulnerability patterns', findings });
  }

  // WP-005: Insecure WP API
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\$wpdb\s*->\s*(query|get_results|get_var)\s*\(\s*['"].*\$/i.test(file.lines[i]) && !/\$wpdb\s*->\s*prepare/i.test(file.lines[i]) && !/\$wpdb\s*->\s*prepare/i.test(file.lines[i - 1] || '')) {
          findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'SQL without $wpdb->prepare', 'Use prepare() for SQL with variables.'));
        }
      }
    }
    results.push({ checkId: 'WP-005', checkName: 'Insecure WP API', category: 'wordpress', severity: 'critical', description: 'Detects insecure WordPress API usage', findings });
  }

  // =====================================================================
  // OBF-016: Non-executable function calls (call_user_func, etc.)
  {
    const findings: Finding[] = [];
    const pats = [/\bcall_user_func\s*\(/i, /\bcall_user_func_array\s*\(/i, /\bregister_shutdown_function\s*\(/i, /\bset_error_handler\s*\(/i, /\bassert\s*\(/i];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), `Indirect function call: ${file.lines[i].trim().match(p)?.[0] || 'call'}`, 'Indirect calls can hide actual function execution.')); break; } }
      }
    }
    results.push({ checkId: 'OBF-016', checkName: 'Indirect Function Calls', category: 'obfuscation', severity: 'high', description: 'Detects call_user_func, assert, and indirect execution', findings });
  }

  // OBF-017: String-based function execution
  {
    const findings: Finding[] = [];
    const pats = [/\$\w+\s*\(\s*\$/i, /\$\w+\s*\(\s*['"]/i, /\barray_map\s*\(\s*['"]\w+['"]/i, /\barray_filter\s*\(\s*.*,\s*['"]\w+['"]/i, /\busort\s*\(\s*.*,\s*['"]\w+['"]/i];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'String-based function execution', 'Function name as string enables dynamic execution.')); break; } }
      }
    }
    results.push({ checkId: 'OBF-017', checkName: 'String Execution', category: 'obfuscation', severity: 'high', description: 'Detects function calls via string names', findings });
  }

  // OBF-018: High entropy strings (possible encoded payloads)
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        const m = file.lines[i].match(/['"]([A-Za-z0-9+/=]{60,})['"]/);
        if (m) {
          const s = m[1];
          const unique = new Set(s.split('')).size;
          const ratio = unique / s.length;
          if (ratio > 0.4 && /[A-Z]/.test(s) && /[a-z]/.test(s) && /[0-9]/.test(s)) {
            findings.push(f(file.relativePath, i + 1, 0, s.substring(0, 40) + '...', `High entropy string (${s.length} chars, ratio: ${ratio.toFixed(2)})`, 'High entropy strings may be encoded payloads.'));
          }
        }
      }
    }
    results.push({ checkId: 'OBF-018', checkName: 'High Entropy Strings', category: 'obfuscation', severity: 'medium', description: 'Detects high-entropy strings that may be encoded data', findings });
  }

  // OBF-019: Dynamic class instantiation
  {
    const findings: Finding[] = [];
    const pats = [/\bnew\s+\$\w+/i, /\bReflectionClass\s*\(/i, /\bclass_exists\s*\(\s*\$/i, /\bstrpos\s*\(.*class/i];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Dynamic class instantiation', 'Dynamic class loading can hide malicious classes.')); break; } }
      }
    }
    results.push({ checkId: 'OBF-019', checkName: 'Dynamic Classes', category: 'obfuscation', severity: 'medium', description: 'Detects dynamic class creation and reflection', findings });
  }

  // OBF-020: Obfuscated PHP tags
  {
    const findings: Finding[] = [];
    const pats = [/\bcreate_function\s*\(/i, /\bpreg_replace\s*\(\s*['"]\/.*\/e/i, /\bassert\s*\(/i, /\b__halt_compiler\s*\(/i];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Code execution pattern', 'This pattern can execute arbitrary code.')); break; } }
      }
    }
    results.push({ checkId: 'OBF-020', checkName: 'Code Execution', category: 'obfuscation', severity: 'critical', description: 'Detects patterns that execute arbitrary code', findings });
  }

  // =====================================================================
  // EXT-013: WebSocket connections
  {
    const findings: Finding[] = [];
    const pats = [/wss?:\/\//i, /\bwebsocket\b/i, /\bsocket_create\b/i, /\bfsockopen\s*\(/i];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'WebSocket/Socket connection', 'WebSocket or raw socket connections to external servers.')); break; } }
      }
    }
    results.push({ checkId: 'EXT-013', checkName: 'WebSocket/Socket', category: 'external-access', severity: 'medium', description: 'Detects WebSocket and raw socket connections', findings });
  }

  // EXT-014: External image/iframe embedding
  {
    const findings: Finding[] = [];
    const pats = [/<img[^>]+src\s*=\s*['"]https?:\/\//i, /<iframe[^>]+src\s*=\s*['"]https?:\/\//i, /\bwp_get_attachment_image_src\b.*https/i];
    for (const file of allFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'External content embedding', 'External images or iframes may track users.')); break; } }
      }
    }
    results.push({ checkId: 'EXT-014', checkName: 'External Embeds', category: 'external-access', severity: 'low', description: 'Detects external image and iframe embedding', findings });
  }

  // EXT-015: External AJAX/Fetch calls
  {
    const findings: Finding[] = [];
    const pats = [/\.ajax\s*\(\s*\{[^}]*url\s*:/i, /\bfetch\s*\(\s*['"]https?:\/\//i, /\bXMLHttpRequest/i, /\baxios\.(get|post|put|delete)\s*\(\s*['"]https?:\/\//i];
    for (const file of allFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'External AJAX/Fetch call', 'AJAX requests to external URLs.')); break; } }
      }
    }
    results.push({ checkId: 'EXT-015', checkName: 'External AJAX', category: 'external-access', severity: 'low', description: 'Detects external AJAX and fetch calls', findings });
  }

  // EXT-016: Third-party analytics/tracking
  {
    const findings: Finding[] = [];
    const pats = [/google-analytics\.com|googletagmanager\.com|gtag\s*\(/i, /facebook\.net\/tr|fbevents\.js/i, /hotjar\.com|heap\.io|mixpanel\.com|segment\.com|amplitude\.com/i, /doubleclick\.net|adsense|adsbygoogle/i, /pixel\.facebook\.com|connect\.facebook\.net/i];
    for (const file of allFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Third-party tracking detected', 'Analytics/tracking scripts can collect user data.')); break; } }
      }
    }
    results.push({ checkId: 'EXT-016', checkName: 'Tracking Scripts', category: 'external-access', severity: 'low', description: 'Detects third-party analytics and tracking', findings });
  }

  // =====================================================================
  // SEC-021: Reflected XSS (more patterns)
  {
    const findings: Finding[] = [];
    const pats = [
      /echo\s+.*\$_(GET|POST|REQUEST|COOKIE)/i,
      /<\?=\s*\$_(GET|POST|REQUEST|COOKIE)/i,
      /print\s+.*\$_(GET|POST|REQUEST|COOKIE)/i,
      /printf\s*\([^)]*\$_(GET|POST|REQUEST)/i,
      /sprintf\s*\([^)]*\$_(GET|POST|REQUEST)/i,
      /\becho\b.*\.\s*\$_(GET|POST|REQUEST)/i,
      /document\.write\s*\(\s*\$_/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Reflected XSS - user input echoed', 'Unescaped user input in HTML output.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-021', checkName: 'Reflected XSS', category: 'security', severity: 'critical', description: 'Detects reflected XSS vulnerabilities', findings });
  }

  // SEC-022: Stored XSS (saving unsanitized user input)
  {
    const findings: Finding[] = [];
    const pats = [
      /\$wpdb\s*->\s*insert\s*\([^)]*\$_(GET|POST|REQUEST)/i,
      /\$wpdb\s*->\s*query\s*\([^)]*INSERT[^)]*\$_(GET|POST|REQUEST)/i,
      /\bupdate_post_meta\s*\([^)]*\$_(GET|POST|REQUEST)/i,
      /\bupdate_option\s*\([^)]*\$_(GET|POST|REQUEST)/i,
      /\$_POST\s*\[.*\]\s*;\s*\n?\s*\$wpdb/i,
      /\$_GET\s*\[.*\]\s*;\s*\n?\s*\$wpdb/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Stored XSS - unsanitized input to DB', 'User input stored without sanitization.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-022', checkName: 'Stored XSS', category: 'security', severity: 'critical', description: 'Detects stored XSS via database writes', findings });
  }

  // SEC-023: DOM-based XSS (JS patterns)
  {
    const findings: Finding[] = [];
    const pats = [/innerHTML\s*=/i, /document\.write\s*\(/i, /\.html\s*\(\s*\$/i, /eval\s*\(\s*\$/i, /setTimeout\s*\(\s*['"]/i, /setInterval\s*\(\s*['"]/i, /\blocation\s*=/i, /\blocation\.href\s*=/i, /\bwindow\.name\b/i];
    for (const file of allFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'DOM-based XSS pattern', 'DOM manipulation that may allow XSS.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-023', checkName: 'DOM XSS', category: 'security', severity: 'high', description: 'Detects DOM-based XSS patterns', findings });
  }

  // SEC-024: SQL Injection via string concatenation
  {
    const findings: Finding[] = [];
    const pats = [
      /\$wpdb\s*->\s*(query|get_results|get_var|get_col)\s*\(\s*['"][^'"]*\.\s*\$/i,
      /\$wpdb\s*->\s*(query|get_results|get_var|get_col)\s*\(\s*['"][^'"]*\{\$/i,
      /\$wpdb\s*->\s*(query|get_results|get_var|get_col)\s*\(\s*["'][^'"]*\$/i,
      /SELECT\s+.*FROM\s+.*\.\s*\$/i,
      /INSERT\s+INTO\s+.*VALUES\s*\([^)]*\.\s*\$/i,
      /UPDATE\s+.*SET\s+.*\.\s*\$/i,
      /DELETE\s+FROM\s+.*WHERE\s+.*\.\s*\$/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'SQL injection - string concatenation', 'SQL query built with string concatenation.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-024', checkName: 'SQL Concat Injection', category: 'security', severity: 'critical', description: 'Detects SQL injection via string concatenation', findings });
  }

  // SEC-025: SQL Injection via variable interpolation
  {
    const findings: Finding[] = [];
    const pats = [
      /\$wpdb\s*->\s*(query|get_results|get_var)\s*\(\s*"\s*[^"]*\$/i,
      /mysql_query\s*\(\s*['"][^'"]*\.\s*\$/i,
      /mysqli_query\s*\([^,]+,\s*['"][^'"]*\.\s*\$/i,
      /\bquery\s*\(\s*['"][^'"]*\{\$/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'SQL injection - variable interpolation', 'SQL query uses variable interpolation in strings.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-025', checkName: 'SQL Interpolation', category: 'security', severity: 'critical', description: 'Detects SQL injection via variable interpolation', findings });
  }

  // SEC-026: Open Redirect
  {
    const findings: Finding[] = [];
    const pats = [
      /\bheader\s*\(\s*['"]Location:\s*.*\$_(GET|POST|REQUEST)/i,
      /\bwp_redirect\s*\(\s*\$_(GET|POST|REQUEST)/i,
      /\bwp_redirect\s*\(\s*['"][^'"]*\.\s*\$_(GET|POST|REQUEST)/i,
      /\bheader\s*\(\s*['"]Location:\s*\s*\.\s*\$/i,
      /\bredirect\s*\(\s*\$_(GET|POST|REQUEST)/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Open redirect vulnerability', 'User input in redirect URL.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-026', checkName: 'Open Redirect', category: 'security', severity: 'high', description: 'Detects open redirect vulnerabilities', findings });
  }

  // SEC-027: SSRF (Server-Side Request Forgery)
  {
    const findings: Finding[] = [];
    const pats = [
      /file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)/i,
      /curl_setopt\s*\([^)]*CURLOPT_URL\s*,\s*\$_/i,
      /fopen\s*\(\s*\$_(GET|POST|REQUEST)/i,
      /\bwp_remote_get\s*\(\s*\$_(GET|POST|REQUEST)/i,
      /\bwp_remote_post\s*\(\s*\$_(GET|POST|REQUEST)/i,
      /\bget_headers\s*\(\s*\$_(GET|POST|REQUEST)/i,
      /\bstream_context_create\s*\(.*\$_/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'SSRF vulnerability', 'User-controlled URL in server-side request.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-027', checkName: 'SSRF', category: 'security', severity: 'critical', description: 'Detects Server-Side Request Forgery', findings });
  }

  // SEC-028: Unsafe Deserialization
  {
    const findings: Finding[] = [];
    const pats = [
      /\bunserialize\s*\(\s*\$_/i,
      /\bunserialize\s*\(\s*file_get_contents/i,
      /\bunserialize\s*\(\s*\$/i,
      /\bjson_decode\s*\(\s*\$_(GET|POST|REQUEST)/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Unsafe deserialization', 'Deserialization of untrusted data.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-028', checkName: 'Unsafe Deserialization', category: 'security', severity: 'critical', description: 'Detects unsafe deserialization patterns', findings });
  }

  // SEC-029: LDAP Injection
  {
    const findings: Finding[] = [];
    const pats = [/\bldap_search\s*\([^)]*\$_/i, /\bldap_bind\s*\([^)]*\$_/i, /\bldap_modify\s*\([^)]*\$_/i];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'LDAP injection', 'User input in LDAP query.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-029', checkName: 'LDAP Injection', category: 'security', severity: 'high', description: 'Detects LDAP injection vulnerabilities', findings });
  }

  // SEC-030: XML/XXE Injection
  {
    const findings: Finding[] = [];
    const pats = [
      /\bSimpleXMLElement\s*\(\s*\$_/i,
      /\bsimplexml_load_string\s*\(\s*\$_/i,
      /\bDOMDocument\s*\(\s*\).*loadXML\s*\(\s*\$_/i,
      /\bxml_parse\s*\([^)]*\$_/i,
      /\blibxml_disable_entity_loader\s*\(\s*false\s*\)/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'XML/XXE injection', 'XML parsing with user input or entities enabled.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-030', checkName: 'XML/XXE Injection', category: 'security', severity: 'high', description: 'Detects XML external entity injection', findings });
  }

  // SEC-031: HTTP Header Injection
  {
    const findings: Finding[] = [];
    const pats = [
      /\bheader\s*\(\s*\$_/i,
      /\bheader\s*\(\s*['"][^'"]*\.\s*\$_/i,
      /\bsetcookie\s*\([^)]*\$_/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'HTTP header injection', 'User input in HTTP headers.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-031', checkName: 'Header Injection', category: 'security', severity: 'high', description: 'Detects HTTP header injection', findings });
  }

  // SEC-032: Information Disclosure
  {
    const findings: Finding[] = [];
    const pats = [
      /\bphpinfo\s*\(/i,
      /\bvar_dump\s*\(\s*\$/i,
      /\bprint_r\s*\(\s*\$/i,
      /\berror_reporting\s*\(\s*E_ALL\s*\)/i,
      /\bdisplay_errors\s*=>?\s*['"]?1/i,
      /\bini_set\s*\(\s*['"]display_errors['"]\s*,\s*['"]1['"]/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Information disclosure', 'Exposes server configuration or variables.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-032', checkName: 'Info Disclosure', category: 'security', severity: 'high', description: 'Detects information disclosure patterns', findings });
  }

  // SEC-033: Insecure Session Handling
  {
    const findings: Finding[] = [];
    const pats = [
      /\bsession_start\s*\(\s*\)/i,
      /\bsetcookie\s*\([^)]*(?!.*httponly)(?!.*secure)/i,
      /\$_SESSION\s*\[.*\]\s*=\s*\$_(GET|POST|REQUEST)/i,
      /\bsession_id\s*\(\s*\$_(GET|POST|REQUEST)/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Insecure session handling', 'Session may lack security flags.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-033', checkName: 'Insecure Sessions', category: 'security', severity: 'medium', description: 'Detects insecure session handling', findings });
  }

  // SEC-034: Weak Random Number Generation
  {
    const findings: Finding[] = [];
    const pats = [/\brand\s*\(/i, /\bmt_rand\s*\(/i, /\bsrand\s*\(/i, /\bmt_srand\s*\(/i];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Weak random number', 'Non-cryptographic random for security.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-034', checkName: 'Weak Random', category: 'security', severity: 'medium', description: 'Detects weak random number generation', findings });
  }

  // SEC-035: Code Injection via eval/assert
  {
    const findings: Finding[] = [];
    const pats = [
      /\beval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i,
      /\bassert\s*\(\s*\$_(GET|POST|REQUEST)/i,
      /\beval\s*\(\s*base64_decode/i,
      /\bassert\s*\(\s*base64_decode/i,
      /\beval\s*\(\s*gzinflate/i,
      /\beval\s*\(\s*gzuncompress/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Code injection', 'Direct code execution from external input.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-035', checkName: 'Code Injection', category: 'security', severity: 'critical', description: 'Detects direct code injection', findings });
  }

  // SEC-036: Command Injection (more patterns)
  {
    const findings: Finding[] = [];
    const pats = [
      /\bexec\s*\(\s*\$_/i,
      /\bsystem\s*\(\s*\$_/i,
      /\bpassthru\s*\(\s*\$_/i,
      /\bshell_exec\s*\(\s*\$_/i,
      /\bpopen\s*\(\s*\$_/i,
      /\bproc_open\s*\(\s*\$_/i,
      /\bpcntl_exec\s*\(\s*\$_/i,
      /\b`[^`]*\$_(GET|POST|REQUEST)/i,
      /\bexec\s*\(\s*['"][^'"]*\.\s*\$/i,
      /\bsystem\s*\(\s*['"][^'"]*\.\s*\$/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Command injection', 'OS command execution with user input.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-036', checkName: 'Command Injection', category: 'security', severity: 'critical', description: 'Detects OS command injection', findings });
  }

  // SEC-037: Insecure File Operations
  {
    const findings: Finding[] = [];
    const pats = [
      /\bchmod\s*\(\s*\$_/i,
      /\bchmod\s*\(\s*['"][^'"]*\.\s*\$/i,
      /\bunlink\s*\(\s*\$_/i,
      /\brename\s*\(\s*\$_/i,
      /\bfile_put_contents\s*\(\s*\$_/i,
      /\bfwrite\s*\([^)]*\$_/i,
      /\bcopy\s*\(\s*\$_/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Insecure file operation', 'File operation with user-controlled path.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-037', checkName: 'Insecure File Ops', category: 'security', severity: 'high', description: 'Detects insecure file operations with user input', findings });
  }

  // SEC-038: Hardcoded Tokens/Keys (more patterns)
  {
    const findings: Finding[] = [];
    const pats = [
      /define\s*\(\s*['"](SECRET|API|KEY|TOKEN|PASSWORD)['"]/i,
      /define\s*\(\s*['"](DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY)['"]/i,
      /\bAWS_ACCESS_KEY[_ID]*\s*=\s*['"][^'"]+['"]/i,
      /\bAWS_SECRET[_ACCESS]*_KEY\s*=\s*['"][^'"]+['"]/i,
      /\bSTRIPE_(SECRET|PUBLIC)_KEY\s*=\s*['"][^'"]+['"]/i,
      /\bSENDGRID_API_KEY\s*=\s*['"][^'"]+['"]/i,
      /\bTWILIO_(ACCOUNT_SID|AUTH_TOKEN)\s*=\s*['"][^'"]+['"]/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 80) + '...', 'Hardcoded secret/key', 'Sensitive credentials in source code.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-038', checkName: 'Hardcoded Secrets', category: 'security', severity: 'critical', description: 'Detects hardcoded API keys, tokens, and secrets', findings });
  }

  // SEC-039: Insecure TLS/SSL
  {
    const findings: Finding[] = [];
    const pats = [
      /\bCURLOPT_SSL_VERIFYPEER\s*=>?\s*(false|0)/i,
      /\bCURLOPT_SSL_VERIFYHOST\s*=>?\s*(false|0)/i,
      /\bstream_context_set_option\s*\([^)]*verify_peer\s*=>?\s*(false|0)/i,
      /\bverify_peer\s*=>?\s*(false|0)/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'TLS verification disabled', 'SSL/TLS certificate verification disabled.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-039', checkName: 'Insecure TLS', category: 'security', severity: 'high', description: 'Detects disabled TLS certificate verification', findings });
  }

  // SEC-040: Unsafe PHP Serialization
  {
    const findings: Finding[] = [];
    const pats = [
      /\b__wakeup\s*\(\s*\)/i,
      /\b__destruct\s*\(\s*\)/i,
      /\b__serialize\s*\(\s*\)/i,
      /\b__unserialize\s*\(/i,
    ];
    for (const file of phpFiles) {
      const hasUnserialize = /\bunserialize\s*\(/i.test(file.content);
      if (hasUnserialize) {
        for (let i = 0; i < file.lines.length; i++) {
          for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Magic method in serializable class', 'Magic methods can be exploited via deserialization.')); break; } }
        }
      }
    }
    results.push({ checkId: 'SEC-040', checkName: 'Deserialization Magic', category: 'security', severity: 'high', description: 'Detects magic methods in files with unserialize', findings });
  }

  // SEC-041: Path Traversal (more patterns)
  {
    const findings: Finding[] = [];
    const pats = [
      /\.\.\//i,
      /\.\.\\\//i,
      /\brealpath\s*\(\s*\$_/i,
      /\bbasename\s*\(\s*\$_/i,
      /\bdirname\s*\(\s*\$_/i,
      /\bfile_get_contents\s*\(\s*['"]\.\.\//i,
      /\bfile_put_contents\s*\(\s*['"]\.\.\//i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i]) && /\$_(GET|POST|REQUEST|COOKIE)/i.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Path traversal with user input', 'User input in file path operations.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-041', checkName: 'Path Traversal+', category: 'security', severity: 'critical', description: 'Detects path traversal with additional patterns', findings });
  }

  // SEC-042: IDOR (Insecure Direct Object Reference)
  {
    const findings: Finding[] = [];
    const pats = [
      /\bget_post\s*\(\s*\$_(GET|POST|REQUEST)/i,
      /\bget_user_by\s*\(\s*['"]id['"]\s*,\s*\$_/i,
      /\$wpdb\s*->\s*get_var\s*\(\s*['"].*WHERE.*\$_/i,
      /\bget_comment\s*\(\s*\$_/i,
      /\bget_option\s*\(\s*\$_/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Potential IDOR', 'Direct object reference without authorization check.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-042', checkName: 'IDOR', category: 'security', severity: 'medium', description: 'Detects Insecure Direct Object References', findings });
  }

  // SEC-043: Insecure CORS
  {
    const findings: Finding[] = [];
    const pats = [
      /\bheader\s*\(\s*['"]Access-Control-Allow-Origin/i,
      /\bheader\s*\(\s*['"]Access-Control-Allow-Origin\s*:\s*\*\s*/i,
      /\$GLOBALS\s*\[\s*['"]HTTP_ORIGIN/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Insecure CORS', 'Overly permissive CORS policy.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-043', checkName: 'CORS Misconfig', category: 'security', severity: 'medium', description: 'Detects insecure CORS configuration', findings });
  }

  // SEC-044: Deprecated PHP Functions
  {
    const findings: Finding[] = [];
    const pats = [
      { p: /\bereg\s*\(/i, m: 'ereg() - deprecated' },
      { p: /\beregi\s*\(/i, m: 'eregi() - deprecated' },
      { p: /\bereg_replace\s*\(/i, m: 'ereg_replace() - deprecated' },
      { p: /\bsplit\s*\(/i, m: 'split() - deprecated' },
      { p: /\bspliti\s*\(/i, m: 'spliti() - deprecated' },
      { p: /\bmysql_connect\s*\(/i, m: 'mysql_connect() - removed in PHP 7' },
      { p: /\bmysql_query\s*\(/i, m: 'mysql_query() - removed in PHP 7' },
      { p: /\bmysql_fetch_array\s*\(/i, m: 'mysql_fetch_array() - removed in PHP 7' },
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const { p, m } of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), m, 'Deprecated PHP function.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-044', checkName: 'Deprecated PHP', category: 'security', severity: 'medium', description: 'Detects deprecated and removed PHP functions', findings });
  }

  // SEC-045: Unsafe Extract
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\bextract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i.test(file.lines[i])) {
          findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Unsafe extract()', 'extract() with user input creates variables from untrusted data.'));
        }
      }
    }
    results.push({ checkId: 'SEC-045', checkName: 'Unsafe Extract', category: 'security', severity: 'critical', description: 'Detects extract() with user input', findings });
  }

  // SEC-046: eval() with base64/obfuscation chains
  {
    const findings: Finding[] = [];
    const pats = [
      /\beval\s*\(\s*gzinflate\s*\(\s*base64_decode/i,
      /\beval\s*\(\s*gzuncompress\s*\(\s*base64_decode/i,
      /\beval\s*\(\s*gzdecode\s*\(\s*base64_decode/i,
      /\beval\s*\(\s*str_rot13\s*\(\s*gzinflate/i,
      /\beval\s*\(\s*base64_decode\s*\(\s*gzinflate/i,
      /\bpreg_replace\s*\(\s*['"]\/.*\/e['"]\s*,.*base64_decode/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Chained obfuscation + eval', 'Multi-step obfuscation leading to code execution.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-046', checkName: 'Obfuscated Eval', category: 'security', severity: 'critical', description: 'Detects eval() with obfuscation chains', findings });
  }

  // SEC-047: Potential Backdoor Patterns
  {
    const findings: Finding[] = [];
    const pats = [
      /\bstr_rot13\s*\(\s*['"]preg/i,
      /base64_decode\s*\(\s*['"][A-Za-z0-9+/=]{40,}['"]/i,
      /\bshell_exec\s*\(\s*\$/i,
      /\bproc_open\s*\(\s*\$/i,
      /\bpcntl_exec\s*\(/i,
      /\bfsockopen\s*\(/i,
      /\bstream_socket_client\s*\(/i,
      /\bproc_nice\s*\(/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Suspicious backdoor pattern', 'Pattern commonly found in backdoors.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-047', checkName: 'Backdoor Patterns', category: 'security', severity: 'critical', description: 'Detects common backdoor patterns', findings });
  }

  // SEC-048: WordPress Admin Bypass
  {
    const findings: Finding[] = [];
    const pats = [
      /\bcurrent_user_can\s*\(\s*['"]administrator['"]/i,
      /\bget_current_user_id\s*\(\s*\).*===?\s*['"]1['"]/i,
      /\bwp_get_current_user\s*\(\s*\).*roles.*administrator/i,
      /\bis_admin\s*\(\s*\).*die/i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Admin check pattern', 'Hardcoded admin check may be bypassable.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-048', checkName: 'Admin Bypass', category: 'security', severity: 'high', description: 'Detects hardcoded admin privilege checks', findings });
  }

  // SEC-049: Exposed Sensitive Files
  {
    const findings: Finding[] = [];
    const sensitiveNames = ['wp-config.php', '.env', 'config.php', 'database.php', 'db.php', 'settings.php', '.htpasswd', 'credentials.php', 'secrets.php', 'backup.sql', 'dump.sql', '.gitconfig', 'id_rsa', 'id_ed25519', '.ssh'];
    for (const file of allFiles) {
      const bn = path.basename(file.path).toLowerCase();
      if (sensitiveNames.includes(bn)) findings.push(f(file.relativePath, 1, 0, bn, `Sensitive file present: ${bn}`, 'This file should not be in production.'));
    }
    results.push({ checkId: 'SEC-049', checkName: 'Exposed Files', category: 'security', severity: 'critical', description: 'Detects exposed sensitive files', findings });
  }

  // SEC-050: Insecure include/require with user input
  {
    const findings: Finding[] = [];
    const pats = [
      /\b(include|include_once|require|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i,
      /\b(include|include_once|require|require_once)\s*\(\s*\$[a-zA-Z_]+\s*\)/i,
      /\b(include|include_once|require|require_once)\s*\(\s*['"]\.\.\//i,
    ];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        for (const p of pats) { if (p.test(file.lines[i])) { findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Insecure include/require', 'Dynamic file inclusion with variable or user input.')); break; } }
      }
    }
    results.push({ checkId: 'SEC-050', checkName: 'Insecure Include', category: 'security', severity: 'critical', description: 'Detects insecure include/require statements', findings });
  }

  // =====================================================================
  // PAT-011: Variable Variables (PHP)
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\$\$\w+/.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Variable variable ($$var)', 'Variable variables make code harder to audit.'));
      }
    }
    results.push({ checkId: 'PAT-011', checkName: 'Variable Variables', category: 'code-pattern', severity: 'medium', description: 'Detects PHP variable variables', findings });
  }

  // PAT-012: Dynamic include
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\b(include|require|include_once|require_once)\s*\(\s*\$/i.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Dynamic include', 'File inclusion with variable path.'));      }
    }
    results.push({ checkId: 'PAT-012', checkName: 'Dynamic Include', category: 'code-pattern', severity: 'medium', description: 'Detects dynamic file inclusion with variables', findings });
  }

  // PAT-013: Suspicious function names
  {
    const findings: Finding[] = [];
    const suspiciousFn = /\bfunction\s+['"]\w*(?:shell|exec|eval|system|cmd|backdoor|hack|exploit|inject)\w*['"]\s*\(/i;
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (suspiciousFn.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Suspicious function name', 'Function name contains security-sensitive keywords.'));
      }
    }
    results.push({ checkId: 'PAT-013', checkName: 'Suspicious Functions', category: 'code-pattern', severity: 'low', description: 'Detects function names with suspicious keywords', findings });
  }

  // =====================================================================
  // FILE-011: Duplicate files (exact content hash)
  {
    const findings: Finding[] = [];
    const contentHash = new Map<string, string[]>();
    for (const file of allFiles) {
      const h = file.content.length > 1000 ? require('crypto').createHash('md5').update(file.content).digest('hex') : file.content;
      if (!contentHash.has(h)) contentHash.set(h, []);
      contentHash.get(h)!.push(file.relativePath);
    }
    for (const [, paths] of contentHash) {
      if (paths.length > 1 && paths[0] !== '') findings.push(f(paths[0], 1, 0, paths.join(', '), `Duplicate files (${paths.length})`, 'Multiple files with identical content.'));
    }
    results.push({ checkId: 'FILE-011', checkName: 'Duplicate Files', category: 'file-analysis', severity: 'low', description: 'Detects files with identical content', findings });
  }

  // FILE-012: Binary/Executable files
  {
    const findings: Finding[] = [];
    const execExts = ['.exe', '.dll', '.so', '.dylib', '.bat', '.cmd', '.com', '.msi', '.scr', '.pif', '.jar', '.class', '.pyc'];
    for (const file of allFiles) {
      if (execExts.includes(file.extension)) findings.push(f(file.relativePath, 1, 0, `Extension: ${file.extension}`, `Executable file: ${file.extension}`, 'Executable files should not be in themes/plugins.'));
    }
    results.push({ checkId: 'FILE-012', checkName: 'Executable Files', category: 'file-analysis', severity: 'high', description: 'Detects executable and binary files', findings });
  }

  // FILE-013: Archive files inside archive
  {
    const findings: Finding[] = [];
    const archiveExts = ['.zip', '.tar', '.gz', '.rar', '.7z', '.bz2', '.xz'];
    for (const file of allFiles) {
      if (archiveExts.includes(file.extension)) findings.push(f(file.relativePath, 1, 0, `Archive: ${file.extension}`, `Nested archive file`, 'Archives inside themes/plugins may hide malicious files.'));
    }
    results.push({ checkId: 'FILE-013', checkName: 'Nested Archives', category: 'file-analysis', severity: 'medium', description: 'Detects archive files within the package', findings });
  }

  // =====================================================================
  // WP-006: Database prefix
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const content = file.content;
      if (/table_prefix\s*=\s*['"]wp_['"]/i.test(content)) {
        findings.push(f(file.relativePath, 1, 0, "table_prefix = 'wp_'", 'Default wp_ table prefix', 'Use a unique database prefix.'));
        break;
      }
    }
    results.push({ checkId: 'WP-006', checkName: 'DB Prefix', category: 'wordpress', severity: 'low', description: 'Detects default WordPress table prefix', findings });
  }

  // WP-007: Direct database queries
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\bmysql_query\s*\(/i.test(file.lines[i]) || /\bmysqli_query\s*\(/i.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Direct MySQL query', 'Raw MySQL queries bypass WordPress API.'));
      }
    }
    results.push({ checkId: 'WP-007', checkName: 'Direct DB Query', category: 'wordpress', severity: 'medium', description: 'Detects direct MySQL queries instead of $wpdb', findings });
  }

  // WP-008: Missing nonces on AJAX
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const hasAjax = /wp_ajax_/i.test(file.content);
      const hasNonce = /wp_verify_nonce|check_ajax_referer/i.test(file.content);
      if (hasAjax && !hasNonce) {
        const lines = file.content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (/wp_ajax_/i.test(lines[i])) { findings.push(f(file.relativePath, i + 1, 0, lines[i].trim().substring(0, 150), 'AJAX without nonce', 'AJAX handler missing nonce verification.')); break; }
        }
      }
    }
    results.push({ checkId: 'WP-008', checkName: 'AJAX No Nonce', category: 'wordpress', severity: 'high', description: 'Detects AJAX handlers without nonce verification', findings });
  }

  // WP-009: Insecure wp_options usage
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\badd_option\s*\(\s*['"].*active_plugins/i.test(file.lines[i])) findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Options table manipulation', 'Direct manipulation of active_plugins option.'));
      }
    }
    results.push({ checkId: 'WP-009', checkName: 'Options Manipulation', category: 'wordpress', severity: 'critical', description: 'Detects direct WordPress options table manipulation', findings });
  }

  // WP-010: Missing WordPress security headers
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const hasSendHeaders = /\bsend_headers\s*\(/i.test(file.content) || /\bheader\s*\(\s*['"]X-/i.test(file.content);
      if (file.relativePath.toLowerCase().includes('functions.php') && !hasSendHeaders && file.content.length > 500) {
        findings.push(f(file.relativePath, 1, 0, 'No security headers', 'Missing security headers in functions.php', 'Add X-Content-Type-Options, X-Frame-Options headers.'));
      }
    }
    results.push({ checkId: 'WP-010', checkName: 'Security Headers', category: 'wordpress', severity: 'medium', description: 'Detects missing security headers in WordPress themes', findings });
  }

  // ===== PHASE 1: ENHANCED DETECTION - WEB SHELL SIGNATURES =====

  // SEC-051: Known webshell file names
  {
    const findings: Finding[] = [];
    const shellNames = ['c99', 'r57', 'b374k', 'webshell', 'FilesMan', 'WSOS', 'PHPMeter', 'CyberShell', 'WSO', 'b374k.php', 'cmd.php', ' FileType', 'shell.php', 'xleet', 'alpha', 'antichat'];
    for (const file of files) {
      const base = path.basename(file.path).toLowerCase();
      if (shellNames.some(s => base.includes(s.toLowerCase())) && file.isPhp) {
        findings.push(f(file.relativePath, 1, 0, `File name matches known webshell: ${base}`, 'Known webshell signature detected', `File "${base}" matches known webshell naming pattern. Immediate investigation recommended.`));
      }
    }
    results.push({ checkId: 'SEC-051', checkName: 'Known Webshell Names', category: 'security', severity: 'critical', description: 'Detects files matching known webshell naming patterns', findings });
  }

  // SEC-052: c99/r57 shell patterns
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/c99_shell|c99\s*shell/i, /r57_shell|r57\s*shell/i, / FilesMan|FilesMan\s*\(/i, /WSO\s*\d|WSO\s*shell/i, /B374k|b374k/i, /PHPShell|phpshell/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Webshell function/pattern detected', `Pattern "${p.source}" found. This is a signature of known webshell variants.`));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-052', checkName: 'Webshell Patterns', category: 'security', severity: 'critical', description: 'Detects code patterns from known webshell families (c99, r57, WSO, b374k)', findings });
  }

  // SEC-053: Webshell with file manager capabilities
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/\bfilemanager\b/i, /\breadfile\s*\(\s*\$/i, /\bwritefile\s*\(\s*\$/i, /\bfile_put_contents\s*\(\s*\$\w+\s*,\s*\$content/i, /\bmove_uploaded_file\s*\(/i, /\bcopy\s*\(\s*\$\w+\s*,\s*\$_/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Webshell file manager capability', 'Detects read/write file operations combined with user input, typical of webshell file managers.'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-053', checkName: 'Webshell File Manager', category: 'security', severity: 'critical', description: 'Detects file manager operations typical of webshell backdoors', findings });
  }

  // SEC-054: Webshell with command execution
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/\bshell_exec\s*\(\s*\$/i, /\bexec\s*\(\s*\$/i, /\bsystem\s*\(\s*\$/i, /\bpassthru\s*\(\s*\$/i, /\bpcntl_exec\s*\(/i, /`.*\$_(GET|POST|REQUEST|COOKIE).*`/];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Shell command execution with user input', 'Executes OS commands with user-controlled input, a primary webshell capability.'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-054', checkName: 'Webshell Command Exec', category: 'security', severity: 'critical', description: 'Detects OS command execution fed by user input (webshell capability)', findings });
  }

  // SEC-055: Webshell with database access
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      if (/mysql_connect|mysqli_connect|new\s*PDO|new\s*mysqli/i.test(file.content)) {
        const hasUserInput = /\$_(GET|POST|REQUEST|COOKIE)/i.test(file.content);
        const hasQuery = /query\s*\(|exec\s*\(|prepare\s*\(/i.test(file.content);
        if (hasUserInput && hasQuery) {
          const lines = file.content.split(/\r?\n/);
          for (let i = 0; i < lines.length; i++) {
            if (/mysql_connect|mysqli_connect|new\s*PDO|new\s*mysqli/i.test(lines[i])) {
              findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Database access with user input', 'Database connection combined with user-controlled queries in the same file — typical of database webshells.'));
              break;
            }
          }
        }
      }
    }
    results.push({ checkId: 'SEC-055', checkName: 'Webshell DB Access', category: 'security', severity: 'critical', description: 'Detects database access shells that accept user-controlled queries', findings });
  }

  // SEC-056: Obfuscated webshell loader
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const hasObfusc = /base64_decode|gzinflate|gzuncompress|str_rot13|eval\s*\(\s*gz/i.test(file.content);
      const hasExec = /\b(eval|assert|preg_replace|call_user_func|create_function)\s*\(/i.test(file.content);
      if (hasObfusc && hasExec) {
        const lines = file.content.split(/\r?\n/);
        for (let i = 0; i < lines.length; i++) {
          if (/base64_decode\s*\(\s*(gzinflate|gzuncompress|str_rot13)/i.test(lines[i]) || /eval\s*\(\s*gz/i.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Obfuscated webshell loader', 'Combination of encoding + eval is a classic webshell loader pattern.'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-056', checkName: 'Obfuscated Shell Loader', category: 'security', severity: 'critical', description: 'Detects obfuscated webshell loader chains (encode+eval)', findings });
  }

  // SEC-057: Webshell with process listing
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/\bproc_open\s*\(/i, /\bpopen\s*\(/i, /\bget_process_list\b/i, /\bposix_getpid\b/i, /\bproc_nice\b/i, /ps\s+-aux|tasklist|tasklist\.exe/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Process management functions', 'Process listing/control functions found, often used in advanced webshells.'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-057', checkName: 'Webshell Process Control', category: 'security', severity: 'high', description: 'Detects process management functions used in advanced webshells', findings });
  }

  // SEC-058: Webshell with network capabilities
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/\bfsockopen\s*\(/i, /\bsocket_create\s*\(/i, /\bstream_socket_client\s*\(/i, /\bproc_open\s*\(.*pipe/i, /\bfwrite\s*\(\s*\$[fh]/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Network socket functions', 'Raw socket/network functions can be used by webshells for reverse shells or data exfiltration.'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-058', checkName: 'Webshell Network', category: 'security', severity: 'high', description: 'Detects raw network socket functions used in reverse shells and data exfiltration', findings });
  }

  // SEC-059: Hidden PHP in non-standard locations
  {
    const findings: Finding[] = [];
    const suspiciousDirs = ['uploads', 'upload', 'cache', 'tmp', 'temp', 'backup', 'bak', 'old', 'log', 'logs', 'img', 'images', 'assets', 'static', 'media', 'data'];
    for (const file of phpFiles) {
      const relLower = file.relativePath.toLowerCase();
      if (suspiciousDirs.some(d => relLower.includes('/' + d + '/')) && file.size < 50000) {
        const lines = file.content.split(/\r?\n/);
        const hasExec = /eval\s*\(|exec\s*\(|shell_exec|system\s*\(|passthru|base64_decode\s*\(/i.test(file.content);
        if (hasExec || file.size < 500) {
          findings.push(f(file.relativePath, 1, 0, `PHP file in suspicious directory: ${file.relativePath}`, 'PHP file found in non-standard upload/cache directory', `File "${file.relativePath}" is a PHP file in a directory that typically should not contain executable code.`));
        }
      }
    }
    results.push({ checkId: 'SEC-059', checkName: 'Hidden PHP', category: 'security', severity: 'critical', description: 'Detects PHP files hidden in upload, cache, or other non-executable directories', findings });
  }

  // SEC-060: Webshell with file upload capability
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const hasUpload = /\$_FILES\s*\[/i.test(file.content) || /\bmove_uploaded_file\s*\(/i.test(file.content);
      const hasExec = /\b(eval|exec|system|passthru|shell_exec)\s*\(/i.test(file.content);
      if (hasUpload && hasExec) {
        const lines = file.content.split(/\r?\n/);
        for (let i = 0; i < lines.length; i++) {
          if (/\$_FILES\s*\[/i.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'File upload + code execution', 'File upload combined with code execution in the same file — likely a webshell dropper.'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-060', checkName: 'Webshell Dropper', category: 'security', severity: 'critical', description: 'Detects files that combine file upload with code execution (dropper pattern)', findings });
  }

  // SEC-061: PHP shell command obfuscation
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/\$\w+\s*=\s*['"]\s*sh\s+['"]/i, /\$\w+\s*=\s*['"]\s*\/bin\/sh/i, /\$\w+\s*=\s*['"]\s*cmd\.exe/i, /system\s*\(\s*base64_decode/i, /exec\s*\(\s*gzinflate/i, /passthru\s*\(\s*base64_decode/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Obfuscated shell command', 'Obfuscated system command — encoding shell commands to evade detection.'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-061', checkName: 'Obfuscated Shell Cmd', category: 'security', severity: 'critical', description: 'Detects obfuscated shell commands using encoding to evade detection', findings });
  }

  // SEC-062: PHP runtime environment tampering
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/\bini_set\s*\(\s*['"]disable_functions['"]/i, /\bini_set\s*\(\s*['"]open_basedir['"].*['"]['"]\s*\)/i, /\bapache_setenv\s*\(/i, /\bphp_uname\s*\(\s*\)/i, /\bphpversion\s*\(\s*\)/i, /\bget_loaded_extensions\s*\(\s*\)/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'PHP environment tampering', 'Detects attempts to modify PHP runtime environment or enumerate loaded extensions.'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-062', checkName: 'PHP Env Tampering', category: 'security', severity: 'high', description: 'Detects PHP runtime environment modification and enumeration', findings });
  }

  // SEC-063: Webshell persistence mechanisms
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/\bregister_shutdown_function\s*\(/i, /\bset_include_path\s*\(\s*\$/i, /\b__autoload\s*\(/i, /\bspl_autoload_register\s*\(\s*['"]\$/i, /\berror_reporting\s*\(\s*0\s*\)/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Persistence mechanism', 'Functions commonly abused for webshell persistence (auto-loading, shutdown hooks, error suppression).'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-063', checkName: 'Persistence Mechanism', category: 'security', severity: 'high', description: 'Detects PHP functions commonly abused for webshell persistence', findings });
  }

  // SEC-064: Encoded payload in variable assignment
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/\$\w+\s*=\s*['"]\s*[A-Za-z0-9+/]{100,}={0,2}\s*['"]/];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            const len = lines[i].length;
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), `Long encoded string (${len} chars)`, 'Very long base64-looking string assigned to a variable — possible encoded payload.'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-064', checkName: 'Encoded Payload', category: 'security', severity: 'high', description: 'Detects long encoded strings that may contain hidden payloads', findings });
  }

  // SEC-065: Reverse shell patterns
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/fsockopen\s*\(\s*['"]\w+['"],\s*\d+/i, /socket_connect\s*\(\s*\$.*,\s*gethostbyname/i, /stream_socket_client\s*\(\s*['"]tcp:\/\//i, /\bbind\s*\(\s*\$.*,\s*INADDR_ANY/i, /proc_open\s*\(.*\/bin\/sh/i, /proc_open\s*\(.*\/bin\/bash/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Reverse shell pattern', 'Network connection pattern consistent with reverse shell backdoors.'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-065', checkName: 'Reverse Shell', category: 'security', severity: 'critical', description: 'Detects reverse shell connection patterns', findings });
  }

  // ===== PHASE 1: SUSPICIOUS INCLUDE/REQUIRE =====

  // SEC-066: Dynamic include with user input
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/\b(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/i, /\b(include|require|include_once|require_once)\s*\(\s*\$[\w]+\s*\.\s*\$_(GET|POST|REQUEST)/i, /\b(include|require|include_once|require_once)\s*\(\s*\$\{\s*\$_/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Dynamic include with user input', 'File inclusion using user-controlled input — potential LFI/RFI vulnerability.'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-066', checkName: 'Dynamic Include', category: 'security', severity: 'critical', description: 'Detects file inclusion with user-controlled input (LFI/RFI)', findings });
  }

  // SEC-067: Remote include
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/\b(include|require|include_once|require_once)\s*\(\s*['"]https?:\/\//i, /\b(include|require|include_once|require_once)\s*\(\s*\$\w+\s*\.\s*['"]https?:\/\//i, /\bfile_get_contents\s*\(\s*['"]https?:\/\/.*\)/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Remote file inclusion', 'File loaded from remote URL — potential RFI vulnerability or supply chain attack.'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-067', checkName: 'Remote Include', category: 'security', severity: 'critical', description: 'Detects file inclusion from remote URLs (RFI)', findings });
  }

  // SEC-068: Include with variable path
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/\b(include|require|include_once|require_once)\s*\(\s*\$\w+\s*\.\s*\.\s*\.\s*\$/i, /\b(include|require|include_once|require_once)\s*\(\s*\$[\w]+\s*\)/i, /\b(include|require|include_once|require_once)\s*\(\s*\$\{[\w]+\}/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            const isSafe = /ABSPATH|plugin_dir|theme_dir|__DIR__|__FILE__|WPINC/i.test(lines[i]);
            if (!isSafe) {
              findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Include with variable path', 'File inclusion using a variable — path may be attacker-controllable.'));
            }
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-068', checkName: 'Variable Include', category: 'security', severity: 'high', description: 'Detects file inclusion with variable paths (potential LFI)', findings });
  }

  // SEC-069: Include from temp/upload directories
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/\b(include|require|include_once|require_once)\s*\(\s*['"].*(tmp|temp|upload|cache|log).*['"]/i, /\b(include|require|include_once|require_once)\s*\(\s*\$\w+\s*\.\s*['"].*(tmp|temp|upload|cache).*['"]/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Include from temp/upload directory', 'Including files from temp/upload directories suggests attacker-controlled file inclusion.'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-069', checkName: 'Include Temp Path', category: 'security', severity: 'critical', description: 'Detects file inclusion from temporary/upload directories', findings });
  }

  // SEC-070: Null byte in include path
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/\b(include|require|include_once|require_once)\s*\(\s*['"].*\x00/i, /\b(include|require|include_once|require_once)\s*\(\s*[\$\w]+\s*\.\s*['"].*\x00/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Null byte injection', 'Null bytes in include paths can truncate file extensions and bypass security checks.'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-070', checkName: 'Null Byte Include', category: 'security', severity: 'critical', description: 'Detects null byte injection in file inclusion paths', findings });
  }

  // ===== PHASE 4: SECRETS & CREDENTIAL SCAN =====

  // SEC-071: AWS access keys
  {
    const findings: Finding[] = [];
    for (const file of files) {
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        if (/AKIA[0-9A-Z]{16}/i.test(lines[i])) {
          findings.push(f(file.relativePath, i + 1, 0, 'AWS Access Key detected', 'Hardcoded AWS access key found', 'AWS access keys in source code can lead to unauthorized cloud resource access. Move to environment variables.'));
        }
      }
    }
    results.push({ checkId: 'SEC-071', checkName: 'AWS Key', category: 'security', severity: 'critical', description: 'Detects hardcoded AWS access keys', findings });
  }

  // SEC-072: Google API keys
  {
    const findings: Finding[] = [];
    for (const file of files) {
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        if (/AIza[0-9A-Za-z\-_]{35}/i.test(lines[i])) {
          findings.push(f(file.relativePath, i + 1, 0, 'Google API Key detected', 'Hardcoded Google API key found', 'Google API keys should be stored in environment variables, not in source code.'));
        }
      }
    }
    results.push({ checkId: 'SEC-072', checkName: 'Google API Key', category: 'security', severity: 'high', description: 'Detects hardcoded Google API keys', findings });
  }

  // SEC-073: Stripe secret keys
  {
    const findings: Finding[] = [];
    for (const file of files) {
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        if (/(sk_live|sk_test|rk_live|rk_test)_[0-9a-zA-Z]{24,}/i.test(lines[i])) {
          findings.push(f(file.relativePath, i + 1, 0, 'Stripe secret key detected', 'Hardcoded Stripe API key found', 'Stripe secret keys provide full access to payment processing. Must be in environment variables.'));
        }
      }
    }
    results.push({ checkId: 'SEC-073', checkName: 'Stripe Key', category: 'security', severity: 'critical', description: 'Detects hardcoded Stripe API secret keys', findings });
  }

  // SEC-074: GitHub tokens
  {
    const findings: Finding[] = [];
    for (const file of files) {
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        if (/ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}/i.test(lines[i])) {
          findings.push(f(file.relativePath, i + 1, 0, 'GitHub token detected', 'Hardcoded GitHub personal access token found', 'GitHub tokens provide repository access. Rotate immediately and use environment variables.'));
        }
      }
    }
    results.push({ checkId: 'SEC-074', checkName: 'GitHub Token', category: 'security', severity: 'critical', description: 'Detects hardcoded GitHub personal access tokens', findings });
  }

  // SEC-075: Telegram bot tokens
  {
    const findings: Finding[] = [];
    for (const file of files) {
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        if (/\b[0-9]{8,10}:[A-Za-z0-9_-]{35}/i.test(lines[i]) && /telegram|bot|tg|token/i.test(lines[i])) {
          findings.push(f(file.relativePath, i + 1, 0, 'Telegram bot token detected', 'Hardcoded Telegram bot token found', 'Telegram bot tokens can be abused to send spam or access chat data. Use environment variables.'));
        }
      }
    }
    results.push({ checkId: 'SEC-075', checkName: 'Telegram Token', category: 'security', severity: 'high', description: 'Detects hardcoded Telegram bot tokens', findings });
  }

  // SEC-076: Slack webhooks/tokens
  {
    const findings: Finding[] = [];
    for (const file of files) {
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        if (/T[0-9A-Z]{8,}-B[0-9A-Z]{8,}|xox[bpas]-[0-9]{10,}-[a-zA-Z0-9-]+/i.test(lines[i])) {
          findings.push(f(file.relativePath, i + 1, 0, 'Slack token/webhook detected', 'Hardcoded Slack token found', 'Slack tokens can post messages to channels. Use environment variables.'));
        }
      }
    }
    results.push({ checkId: 'SEC-076', checkName: 'Slack Token', category: 'security', severity: 'high', description: 'Detects hardcoded Slack tokens and webhooks', findings });
  }

  // SEC-077: Database credentials outside config
  {
    const findings: Finding[] = [];
    const configFiles = ['wp-config.php', 'config.php', 'database.php', 'db.php', '.env', 'settings.php'];
    for (const file of phpFiles) {
      const isConfig = configFiles.some(c => file.relativePath.toLowerCase().includes(c));
      if (isConfig) continue;
      const patterns = [/\bDB_PASSWORD\s*=\s*['"][^'"]+['"]/i, /\bDB_USER\s*=\s*['"][^'"]+['"]/i, /['"]password['"]\s*=>\s*['"][^'"]{3,}['"]/i, /\$dbpass\s*=\s*['"][^'"]+['"]/i, /\$db_password\s*=\s*['"][^'"]+['"]/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Database credentials in non-config file', 'Database password found outside of config files — possible credential leak.'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-077', checkName: 'DB Credentials Leak', category: 'security', severity: 'critical', description: 'Detects database credentials hardcoded in non-config files', findings });
  }

  // SEC-078: Generic secret patterns
  {
    const findings: Finding[] = [];
    for (const file of files) {
      const patterns = [/(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key)\s*=\s*['"][A-Za-z0-9+/=_\-]{16,}['"]/i, /(?:password|passwd|pwd)\s*=\s*['"][^'"]{6,}['"]/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            const isComment = /^\s*(\/\/|#|\/\*|\*|--)/.test(lines[i]);
            if (!isComment) {
              findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Hardcoded secret detected', 'Generic API key or password pattern found in source code.'));
            }
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-078', checkName: 'Hardcoded Secrets', category: 'security', severity: 'critical', description: 'Detects generic API keys, passwords, and secret tokens in source code', findings });
  }

  // SEC-079: Private key files
  {
    const findings: Finding[] = [];
    for (const file of files) {
      const base = file.path.toLowerCase();
      if (/\.(pem|key|p12|pfx|p8|keystore)$/i.test(base) && !base.includes('node_modules')) {
        findings.push(f(file.relativePath, 1, 0, `Private key file: ${path.basename(file.path)}`, 'Private key or certificate file detected', 'Private key files in web-accessible directories can expose SSL/TLS credentials.'));
      }
    }
    results.push({ checkId: 'SEC-079', checkName: 'Private Key Files', category: 'security', severity: 'critical', description: 'Detects private key and certificate files in web directories', findings });
  }

  // SEC-080: Hardcoded IP addresses and internal URLs
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        if (/\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b/.test(lines[i]) && !/^\s*(\/\/|#|\*)/.test(lines[i])) {
          const isConfig = /wp-config|config|database/i.test(file.relativePath);
          if (!isConfig) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Internal IP address in code', 'Hardcoded internal/private IP address found in source code.'));
          }
        }
      }
    }
    results.push({ checkId: 'SEC-080', checkName: 'Internal IP Leak', category: 'security', severity: 'medium', description: 'Detects hardcoded internal/private IP addresses in source code', findings });
  }

  // SEC-081: JWT tokens
  {
    const findings: Finding[] = [];
    for (const file of files) {
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        if (/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/i.test(lines[i])) {
          findings.push(f(file.relativePath, i + 1, 0, 'JWT token hardcoded', 'Hardcoded JSON Web Token found', 'Hardcoded JWT tokens can provide unauthorized access. Use signing keys and generate tokens dynamically.'));
        }
      }
    }
    results.push({ checkId: 'SEC-081', checkName: 'JWT Token Leak', category: 'security', severity: 'critical', description: 'Detects hardcoded JSON Web Tokens in source code', findings });
  }

  // SEC-082: Hardcoded encryption keys
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/\bdefine\s*\(\s*['"](?:AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)['"]\s*,\s*['"][^'"]+['"]/i, /\$encryption_key\s*=\s*['"][^'"]+['"]/i, /\$secret\s*=\s*['"][^'"]{8,}['"]/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            const isConfig = /wp-config/i.test(file.relativePath);
            if (!isConfig) {
              findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Hardcoded encryption key', 'Encryption keys/salts hardcoded outside wp-config.php.'));
            }
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-082', checkName: 'Encryption Key Leak', category: 'security', severity: 'high', description: 'Detects hardcoded encryption keys and salts outside config files', findings });
  }

  // SEC-083: Password in URL/query string
  {
    const findings: Finding[] = [];
    for (const file of files) {
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        if (/password\s*=\s*['"][^'"]+['"]\s*\.\s*['"]&/i.test(lines[i]) || /['"]\?.*password=[^&'"]+/i.test(lines[i]) || /mysql:.*password=/i.test(lines[i])) {
          findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Password in connection string/URL', 'Password embedded in a connection string or URL — sensitive data exposure risk.'));
        }
      }
    }
    results.push({ checkId: 'SEC-083', checkName: 'Password in URL', category: 'security', severity: 'critical', description: 'Detects passwords in connection strings and URLs', findings });
  }

  // SEC-084: .env file exposure
  {
    const findings: Finding[] = [];
    for (const file of files) {
      if (file.path.toLowerCase().endsWith('.env') && !file.path.toLowerCase().includes('node_modules')) {
        findings.push(f(file.relativePath, 1, 0, '.env file found', '.env file in web directory', '.env files may contain database credentials, API keys, and other secrets. Ensure they are not web-accessible.'));
      }
    }
    results.push({ checkId: 'SEC-084', checkName: '.env Exposure', category: 'security', severity: 'critical', description: 'Detects .env files that may expose sensitive configuration', findings });
  }

  // SEC-085: Bearer token patterns
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/['"]Authorization['"]\s*=>\s*['"]Bearer\s+[A-Za-z0-9\-._~+/]+=*['"]/i, /curl_opt.*-H.*Bearer\s+[A-Za-z0-9\-._~+/]+=*/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Hardcoded Bearer token', 'Bearer token hardcoded in source — provides unauthorized API access.'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'SEC-085', checkName: 'Bearer Token Leak', category: 'security', severity: 'critical', description: 'Detects hardcoded Bearer tokens in source code', findings });
  }

  // ===== PHASE 1: PHP IN SUSPICIOUS PATHS =====

  // FILE-014: PHP in upload directories
  {
    const findings: Finding[] = [];
    const uploadDirs = ['uploads', 'upload', 'files', 'media', 'attachments', 'import'];
    for (const file of phpFiles) {
      const relLower = file.relativePath.toLowerCase();
      if (uploadDirs.some(d => relLower.includes('/' + d + '/'))) {
        findings.push(f(file.relativePath, 1, 0, `PHP in upload directory: ${file.relativePath}`, 'PHP file found in upload directory', 'PHP files in upload directories are suspicious — they may be webshells uploaded through a vulnerability.'));
      }
    }
    results.push({ checkId: 'FILE-014', checkName: 'PHP in Uploads', category: 'file-analysis', severity: 'critical', description: 'Detects PHP files in upload/media directories', findings });
  }

  // FILE-015: PHP in cache/temp directories
  {
    const findings: Finding[] = [];
    const tempDirs = ['cache', 'tmp', 'temp', 'log', 'logs', 'backup', 'bak', 'old', 'archive'];
    for (const file of phpFiles) {
      const relLower = file.relativePath.toLowerCase();
      if (tempDirs.some(d => relLower.includes('/' + d + '/'))) {
        findings.push(f(file.relativePath, 1, 0, `PHP in temp/cache directory: ${file.relativePath}`, 'PHP file found in cache/temp directory', 'PHP files in temporary directories may be droppers or persistence mechanisms.'));
      }
    }
    results.push({ checkId: 'FILE-015', checkName: 'PHP in Temp', category: 'file-analysis', severity: 'high', description: 'Detects PHP files in cache/temp/log directories', findings });
  }

  // ===== PHASE 3: POST-EXPLOITATION INDICATORS =====

  // WP-011: Suspicious wp-config modifications
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      if (/wp-config/i.test(file.path)) {
        const patterns = [/\bdefine\s*\(\s*['"]WP_DEBUG['"]\s*,\s*true/i, /\bdefine\s*\(\s*['"]WP_DEBUG_LOG['"]\s*,\s*true/i, /\bdefine\s*\(\s*['"]WP_DEBUG_DISPLAY['"]\s*,\s*true/i, /\bdefine\s*\(\s*['"]DISALLOW_FILE_EDIT['"]\s*,\s*false/i, /\bdefine\s*\(\s*['"]DISALLOW_FILE_MODS['"]\s*,\s*false/i, /error_reporting\s*\(\s*E_ALL/i];
        const lines = file.content.split(/\r?\n/);
        for (let i = 0; i < lines.length; i++) {
          for (const p of patterns) {
            if (p.test(lines[i])) {
              findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Insecure wp-config setting', 'Debug mode enabled or file editing unrestricted — weakens WordPress security.'));
              break;
            }
          }
        }
      }
    }
    results.push({ checkId: 'WP-011', checkName: 'WP Config Weak', category: 'wordpress', severity: 'high', description: 'Detects insecure WordPress configuration settings', findings });
  }

  // WP-012: Suspicious hooks (init, wp_loaded, admin_init)
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/add_action\s*\(\s*['"]init['"]\s*,\s*['"][^'"]*['"].*\b(eval|exec|system|passthru|shell_exec|file_get_contents|wp_redirect|header\s*\()/i, /add_action\s*\(\s*['"]wp_loaded['"]\s*,\s*['"][^'"]*['"].*\b(eval|exec|system|passthru|shell_exec|wp_redirect|header\s*\()/i, /add_action\s*\(\s*['"]admin_init['"]\s*,\s*['"][^'"]*['"].*\b(eval|exec|system|passthru|shell_exec|wp_redirect|header\s*\()/i, /add_action\s*\(\s*['"]shutdown['"]\s*,\s*['"][^'"]*['"].*\b(eval|exec|system|passthru|shell_exec)/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Suspicious hook with dangerous callback', 'WordPress hook with dangerous function callback — potential backdoor.'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'WP-012', checkName: 'Suspicious Hooks', category: 'wordpress', severity: 'critical', description: 'Detects WordPress hooks with dangerous function callbacks', findings });
  }

  // WP-013: Cron job suspicious patterns
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/\bschedule_event\s*\(\s*time\s*\(\s*\)\s*\+\s*\d+/i, /\bwp_schedule_single_event\s*\(/i, /\bcron_add\s*\(/i, /\bsystem\s*\(\s*['"]crontab/i, /\bfile_put_contents\s*\(\s*['"].*\/etc\/cron/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Suspicious cron/scheduling', 'Suspicious scheduling or cron manipulation detected.'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'WP-013', checkName: 'Suspicious Cron', category: 'wordpress', severity: 'high', description: 'Detects suspicious cron job scheduling and manipulation', findings });
  }

  // WP-014: Hidden redirects and JS/iframe injection
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/\bwp_redirect\s*\(\s*\$[^)]+\)/i, /\bheader\s*\(\s*['"]Location:\s*http/i, /<script[^>]*src\s*=\s*['"]https?:\/\/[^'"]+['"]/i, /<iframe[^>]*src\s*=\s*['"]https?:\/\/[^'"]+['"]/i, /\becho\s+['"]<script/i, /\bdocument\.write\s*\(\s*['"]<script/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            const isExternal = /https?:\/\/(?!localhost|127\.0\.0\.1)/.test(lines[i]);
            if (isExternal || /wp_redirect|Location/.test(lines[i])) {
              findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Hidden redirect/injection', 'External redirect or script/iframe injection detected — potential malware injection.'));
            }
            break;
          }
        }
      }
    }
    results.push({ checkId: 'WP-014', checkName: 'Hidden Redirect', category: 'wordpress', severity: 'critical', description: 'Detects hidden redirects and script/iframe injection in WordPress files', findings });
  }

  // WP-015: User role manipulation
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/\b\$wp_roles\s*->add_role\s*\(/i, /\badd_role\s*\(\s*['"]administrator['"]/i, /\bwp_update_user\s*\(\s*array\s*\(\s*['"]role['"]\s*=>\s*['"]administrator['"]/i, /\$user->set_role\s*\(\s*['"]administrator['"]/i, /\bupdate_user_meta\s*\(\s*\$.*role['"]\s*,\s*['"]administrator['"]/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Admin role manipulation', 'Code that grants administrator privileges — potential privilege escalation backdoor.'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'WP-015', checkName: 'Role Escalation', category: 'wordpress', severity: 'critical', description: 'Detects code that manipulates WordPress user roles and privileges', findings });
  }

  // WP-016: Nonce/permission bypass
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/add_action\s*\(\s*['"]wp_ajax_/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            const block = file.content.substring(Math.max(0, file.content.indexOf(lines[i]) - 200), Math.min(file.content.length, file.content.indexOf(lines[i]) + 800));
            const hasNonce = /wp_verify_nonce|check_ajax_referer|check_admin_referer/i.test(block);
            const hasPermission = /current_user_can|is_admin/i.test(block);
            if (!hasNonce && !hasPermission) {
              findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'AJAX without nonce/permission', 'AJAX handler registered without nonce verification or permission check.'));
            }
            break;
          }
        }
      }
    }
    results.push({ checkId: 'WP-016', checkName: 'AJAX No Auth', category: 'wordpress', severity: 'high', description: 'Detects AJAX handlers without nonce verification or permission checks', findings });
  }

  // WP-017: Double extension uploads
  {
    const findings: Finding[] = [];
    for (const file of files) {
      const base = path.basename(file.path).toLowerCase();
      const doubleExt = /\.(php|phtml|php5|php7|php8|inc)\.(jpg|jpeg|png|gif|bmp|svg|txt|pdf|zip|rar|tar|gz|mp3|mp4|doc|docx)/i;
      if (doubleExt.test(base)) {
        findings.push(f(file.relativePath, 1, 0, `Double extension file: ${base}`, 'File with double extension detected', `File "${base}" uses double extension — may be an attempt to bypass upload filters and execute PHP.`));
      }
    }
    results.push({ checkId: 'WP-017', checkName: 'Double Extension', category: 'wordpress', severity: 'critical', description: 'Detects files with double extensions used to bypass upload filters', findings });
  }

  // WP-018: Non-standard database queries
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      const patterns = [/\$wpdb\s*->\s*query\s*\(\s*['"].*\$_(GET|POST|REQUEST)/i, /\$wpdb\s*->\s*query\s*\(\s*\$\w+\s*\.\s*\$/i, /\$wpdb\s*->\s*prepare\s*\(\s*['"].*\$_(GET|POST|REQUEST)/i];
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const p of patterns) {
          if (p.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].substring(0, 150), 'Direct DB query with user input', 'WordPress $wpdb query with user-controlled input — potential SQL injection.'));
            break;
          }
        }
      }
    }
    results.push({ checkId: 'WP-018', checkName: 'WP SQL Injection', category: 'wordpress', severity: 'critical', description: 'Detects WordPress database queries with user-controlled input', findings });
  }

  // ===== EVASION DETECTION =====

  // EVD-001: User-Agent Cloaking
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\$_SERVER\s*\[\s*['"]HTTP_USER_AGENT['"]\s*\]/i.test(file.lines[i]) && /if\s*\(|elseif\s*\(|\?/.test(file.lines[i])) {
          findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'User-Agent cloaking detected', 'Conditional execution based on HTTP_USER_AGENT — used to hide malicious behavior from security scanners.'));
        }
      }
    }
    results.push({ checkId: 'EVD-001', checkName: 'UA Cloaking', category: 'evasion', severity: 'high', description: 'Detects conditional code execution based on User-Agent header', findings });
  }

  // EVD-002: Referer-based Activation
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\$_SERVER\s*\[\s*['"]HTTP_REFERER['"]\s*\]/i.test(file.lines[i]) && /if\s*\(|elseif\s*\(|\?/.test(file.lines[i])) {
          findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Referer-based activation', 'Conditional execution based on HTTP_REFERER — used to activate malware only on specific referrer traffic.'));
        }
      }
    }
    results.push({ checkId: 'EVD-002', checkName: 'Referer Activation', category: 'evasion', severity: 'high', description: 'Detects conditional code execution based on HTTP Referer header', findings });
  }

  // EVD-003: Time-based Activation
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\btime\s*\(\s*\)/.test(file.lines[i]) && /if\s*\(|elseif\s*\(|>|\s<|\?/.test(file.lines[i])) {
          findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Time-based activation', 'Conditional execution based on time() — used to activate malware only during specific time windows.'));
        }
        if (/\bdate\s*\(\s*/.test(file.lines[i]) && /if\s*\(|elseif\s*\(|\?/.test(file.lines[i])) {
          findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Date-based activation', 'Conditional execution based on date() — used to schedule malicious behavior.'));
        }
      }
    }
    results.push({ checkId: 'EVD-003', checkName: 'Time-based Activation', category: 'evasion', severity: 'medium', description: 'Detects conditional code execution based on time/date functions', findings });
  }

  // EVD-004: IP-based Cloaking
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\$_SERVER\s*\[\s*['"]REMOTE_ADDR['"]\s*\]/i.test(file.lines[i]) && /if\s*\(|elseif\s*\(|\?/.test(file.lines[i])) {
          findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'IP-based cloaking (REMOTE_ADDR)', 'Conditional execution based on REMOTE_ADDR — used to hide malware from specific IP addresses.'));
        }
        if (/\$_SERVER\s*\[\s*['"]HTTP_X_FORWARDED_FOR['"]\s*\]/i.test(file.lines[i]) && /if\s*\(|elseif\s*\(|\?/.test(file.lines[i])) {
          findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'IP-based cloaking (X-Forwarded-For)', 'Conditional execution based on X-Forwarded-For — used to evade detection via proxy headers.'));
        }
      }
    }
    results.push({ checkId: 'EVD-004', checkName: 'IP Cloaking', category: 'evasion', severity: 'high', description: 'Detects conditional code execution based on client IP address', findings });
  }

  // EVD-005: Cookie-based Triggers
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/\$_COOKIE\s*\[\s*['"][^'"]+['"]\s*\]/i.test(file.lines[i]) && /if\s*\(|elseif\s*\(|\?/.test(file.lines[i])) {
          findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Cookie-based trigger', 'Conditional execution based on cookie value — used as a secret trigger to activate hidden malware.'));
        }
      }
    }
    results.push({ checkId: 'EVD-005', checkName: 'Cookie Trigger', category: 'evasion', severity: 'medium', description: 'Detects conditional code execution based on cookie values', findings });
  }

  // ===== SPAM INJECTION =====

  // SPM-001: Hidden Text
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        if (/display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0/i.test(line) && /style\s*=/i.test(line)) {
          findings.push(f(file.relativePath, i + 1, 0, line.trim().substring(0, 150), 'Hidden text via CSS', 'CSS hidden text detected — commonly used for SEO spam injection.'));
        }
      }
    }
    results.push({ checkId: 'SPM-001', checkName: 'Hidden Text', category: 'spam', severity: 'medium', description: 'Detects CSS hidden text used for spam injection', findings });
  }

  // SPM-002: SEO Spam Links
  {
    const findings: Finding[] = [];
    const spamKeywords = /viagra|cialis|casino|payday\s*loan|pharmacy|buy\s*now|free\s*money|gambling|poker|slots/i;
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        if (/(echo|print)\s+.*<a\s/i.test(line) && /href\s*=\s*['"]https?:\/\//i.test(line) && spamKeywords.test(line)) {
          findings.push(f(file.relativePath, i + 1, 0, line.trim().substring(0, 150), 'SEO spam link injection', 'PHP-generated spam links with suspicious anchor text — SEO spam injection.'));
        }
      }
    }
    results.push({ checkId: 'SPM-002', checkName: 'SEO Spam Links', category: 'spam', severity: 'medium', description: 'Detects PHP-generated spam links with suspicious anchor text', findings });
  }

  // SPM-003: Hidden iframes
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        if (/<iframe[^>]*(width\s*=\s*['"]?0|height\s*=\s*['"]?0|display\s*:\s*none|visibility\s*:\s*hidden)/i.test(line)) {
          findings.push(f(file.relativePath, i + 1, 0, line.trim().substring(0, 150), 'Hidden iframe detected', 'Hidden iframe (zero dimensions or display:none) — used for malicious content injection.'));
        }
      }
    }
    results.push({ checkId: 'SPM-003', checkName: 'Hidden Iframes', category: 'spam', severity: 'high', description: 'Detects hidden iframes used for malicious content injection', findings });
  }

  // SPM-004: Casino/Pharma Keywords
  {
    const findings: Finding[] = [];
    const spamPattern = /\b(viagra|cialis|casino|slot\s*machine|blackjack|poker\s*online|payday\s*loan|pharmacy|buy\s*viagra|online\s*casino|gambling|betting\s*odds)\b/i;
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        const m = file.lines[i].match(spamPattern);
        if (m) {
          findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), `Spam keyword: "${m[1]}"`, 'Casino/pharma spam keywords detected in file content — indicates spam injection.'));
        }
      }
    }
    results.push({ checkId: 'SPM-004', checkName: 'Spam Keywords', category: 'spam', severity: 'medium', description: 'Detects casino, pharmaceutical, and gambling spam keywords in content', findings });
  }

  // SPM-005: Silent Spam Injection via preg_replace /e
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      for (let i = 0; i < file.lines.length; i++) {
        if (/preg_replace\s*\(\s*['"`]\/.*\/e\s*['"`]/i.test(file.lines[i]) && /(echo|print|content|html|inject)/i.test(file.lines[i])) {
          findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'preg_replace /e for content injection', 'preg_replace with /e modifier used for silent content injection — code execution via deprecated regex.'));
        }
      }
    }
    results.push({ checkId: 'SPM-005', checkName: 'Silent Spam Inject', category: 'spam', severity: 'high', description: 'Detects preg_replace with /e modifier used for content injection', findings });
  }

  // ===== JS MALWARE =====

  // JS-001: document.write injection
  {
    const findings: Finding[] = [];
    for (const file of allFiles) {
      if (file.extension === '.js') {
        for (let i = 0; i < file.lines.length; i++) {
          if (/document\.write\s*\(\s*(atob|decodeURIComponent|unescape|String\.fromCharCode)/i.test(file.lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'document.write with decoded content', 'document.write combined with decoding function — injects obfuscated content into pages.'));
          }
        }
      }
    }
    results.push({ checkId: 'JS-001', checkName: 'DocWrite Inject', category: 'js-malware', severity: 'high', description: 'Detects document.write with decoded/obfuscated content injection', findings });
  }

  // JS-002: eval + atob combo
  {
    const findings: Finding[] = [];
    for (const file of allFiles) {
      if (file.extension === '.js') {
        for (let i = 0; i < file.lines.length; i++) {
          if (/\beval\s*\(\s*atob\s*\(/i.test(file.lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'eval(atob()) detected', 'eval(atob(...)) executes base64-decoded JavaScript — classic malware obfuscation pattern.'));
          }
        }
      }
    }
    results.push({ checkId: 'JS-002', checkName: 'Eval Atob', category: 'js-malware', severity: 'critical', description: 'Detects eval(atob(...)) pattern used to execute obfuscated JavaScript', findings });
  }

  // JS-003: Crypto Mining Scripts
  {
    const findings: Finding[] = [];
    for (const file of allFiles) {
      if (file.extension === '.js') {
        for (let i = 0; i < file.lines.length; i++) {
          if (/\b(coinhive|coin-hive|cryptonight|coinimp|webmineploy|crypto-loot|minero\.cc|authedmine|coinlab)\b/i.test(file.lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Crypto mining script', 'Cryptocurrency mining script detected — unauthorized browser-based mining.'));
          }
        }
      }
    }
    results.push({ checkId: 'JS-003', checkName: 'Crypto Miner', category: 'js-malware', severity: 'critical', description: 'Detects cryptocurrency mining scripts (CoinHive, CoinIMP, etc.)', findings });
  }

  // JS-004: Keylogger Patterns
  {
    const findings: Finding[] = [];
    for (const file of allFiles) {
      if (file.extension === '.js') {
        for (let i = 0; i < file.lines.length; i++) {
          if (/\b(onkeydown|onkeypress|addEventListener\s*\(\s*['"](keydown|keypress)['"])/i.test(file.lines[i]) && /(fetch|XMLHttpRequest|ajax|\.post\(|\.get\(|navigator\.sendBeacon|https?:\/\/)/i.test(file.lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Keylogger pattern', 'Keystroke capture combined with network request — potential keylogger exfiltrating data.'));
          }
        }
      }
    }
    results.push({ checkId: 'JS-004', checkName: 'Keylogger', category: 'js-malware', severity: 'critical', description: 'Detects keylogger patterns that capture keystrokes and send to external URLs', findings });
  }

  // JS-005: Obfuscated JS redirects
  {
    const findings: Finding[] = [];
    for (const file of allFiles) {
      if (file.extension === '.js') {
        for (let i = 0; i < file.lines.length; i++) {
          if (/window\.location\s*[=.]\s*(atob|eval|decodeURIComponent|unescape|String\.fromCharCode|Buffer\.from)/i.test(file.lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Obfuscated JS redirect', 'window.location assignment from decoded/evaluated value — obfuscated redirect to malicious site.'));
          }
        }
      }
    }
    results.push({ checkId: 'JS-005', checkName: 'JS Redirect', category: 'js-malware', severity: 'high', description: 'Detects obfuscated JavaScript redirects using base64/eval', findings });
  }

  // ===== INTEGRITY CHECKS =====

  // INT-001: Modified wp-config.php
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      if (/wp-config/i.test(file.path)) {
        const content = file.content;
        const closingPhp = content.lastIndexOf('?>');
        if (closingPhp > 0 && closingPhp < content.length - 1) {
          const afterClosing = content.substring(closingPhp + 2).trim();
          if (afterClosing.length > 0 && afterClosing !== '\n' && afterClosing !== '\r\n') {
            findings.push(f(file.relativePath, 1, 0, afterClosing.substring(0, 150), 'Code after closing PHP tag', 'Non-standard code found after the closing ?> tag in wp-config.php — potential backdoor injection.'));
          }
        }
      }
    }
    results.push({ checkId: 'INT-001', checkName: 'WP Config Modified', category: 'integrity', severity: 'critical', description: 'Detects non-standard code after the closing PHP tag in wp-config.php', findings });
  }

  // INT-002: Modified .htaccess
  {
    const findings: Finding[] = [];
    for (const file of allFiles) {
      if (file.path.toLowerCase().endsWith('.htaccess')) {
        const nonWpDirectives = /^\s*(RewriteRule|RewriteCond|Redirect|RedirectMatch|Alias|ScriptAlias|ProxyPass|SetEnvIf|Deny|Allow|Order|Require|ErrorDocument|Header|ModSecurity)/im;
        const wpStandard = /^\s*(# BEGIN WordPress|# END WordPress|RewriteEngine On|RewriteBase|RewriteRule \^index\.php|RewriteRule \^\._|RewriteCond %\{REQUEST_FILENAME\}|RewriteCond %\{REQUEST_URI\})/im;
        const lines = file.content.split(/\r?\n/);
        for (let i = 0; i < lines.length; i++) {
          if (nonWpDirectives.test(lines[i]) && !wpStandard.test(lines[i])) {
            findings.push(f(file.relativePath, i + 1, 0, lines[i].trim().substring(0, 150), 'Non-WordPress .htaccess directive', 'Non-standard directive in .htaccess — may be used for redirection or access control bypass.'));
          }
        }
      }
    }
    results.push({ checkId: 'INT-002', checkName: 'HTACCESS Modified', category: 'integrity', severity: 'high', description: 'Detects non-WordPress directives in .htaccess files', findings });
  }

  // INT-003: PHP Files in Uploads
  {
    const findings: Finding[] = [];
    for (const file of phpFiles) {
      if (/wp-content[\/\\]uploads/i.test(file.relativePath)) {
        findings.push(f(file.relativePath, 1, 0, `PHP in uploads: ${file.path}`, 'PHP file in uploads directory', 'PHP files in wp-content/uploads/ are suspicious — likely webshells or droppers.'));
      }
    }
    results.push({ checkId: 'INT-003', checkName: 'PHP in Uploads', category: 'integrity', severity: 'critical', description: 'Detects .php files in wp-content/uploads/', findings });
  }

  // INT-004: Suspicious file timestamps
  {
    const findings: Finding[] = [];
    for (const file of allFiles) {
      const now = Date.now();
      const mtimeMs = file.mtime.getTime();
      const ageDays = (now - mtimeMs) / (1000 * 60 * 60 * 24);
      if (ageDays > 365 * 5) {
        findings.push(f(file.relativePath, 1, 0, `Modified: ${file.mtime.toISOString()}`, 'Extremely old file timestamp', `File last modified ${Math.floor(ageDays)} days ago — may indicate a stale or abandoned file that could be exploited.`));
      }
    }
    results.push({ checkId: 'INT-004', checkName: 'Old Timestamps', category: 'integrity', severity: 'low', description: 'Detects files with extremely old modification timestamps', findings });
  }

  // INT-005: Core file modification
  {
    const findings: Finding[] = [];
    const corePatterns = [/\beval\s*\(/i, /\bexec\s*\(/i, /\bsystem\s*\(/i, /\bpassthru\s*\(/i, /\bshell_exec\s*\(/i, /\bbase64_decode\s*\(/i, /\bfile_get_contents\s*\(\s*['"]https?:\/\//i, /\bfile_put_contents\s*\(/i, /\bcurl_exec\s*\(/i];
    for (const file of phpFiles) {
      if (/wp-includes|wp-admin/i.test(file.relativePath)) {
        for (let i = 0; i < file.lines.length; i++) {
          for (const p of corePatterns) {
            if (p.test(file.lines[i])) {
              findings.push(f(file.relativePath, i + 1, 0, file.lines[i].trim().substring(0, 150), 'Suspicious pattern in core file', 'Dangerous function found in WordPress core file — core files should not contain these patterns.'));
              break;
            }
          }
        }
      }
    }
    results.push({ checkId: 'INT-005', checkName: 'Core Modified', category: 'integrity', severity: 'critical', description: 'Detects suspicious patterns in WordPress core files (wp-includes, wp-admin)', findings });
  }

  return results;
}

export function runScan(targetPath: string, sourceType: 'path' | 'upload' = 'path'): ScanSummary {
  const startTime = Date.now();
  const id = uuidv4();
  const files = readDir(targetPath, targetPath, []);
  const phpFiles = files.filter(f => f.isPhp);
  const results = runChecks(files);

  // Run deobfuscation analysis
  try {
    const allDeobResults: { file: string; payload: ReturnType<typeof extractAllPayloads>[number] }[] = [];
    for (const file of files) {
      const payloads = extractAllPayloads(file.content);
      for (const payload of payloads) {
        allDeobResults.push({ file: file.relativePath, payload });
      }
    }
    if (allDeobResults.length > 0) {
      const findings: Finding[] = allDeobResults.map(d => ({
        file: d.file,
        line: 0,
        column: 0,
        code: d.payload.decoded.substring(0, 150),
        message: `Deobfuscated payload found via ${d.payload.method} (depth: ${d.payload.depth})`,
        details: `Decoded content contains ${d.payload.urls.length} URLs, ${d.payload.domains.length} domains, ${d.payload.suspiciousKeywords.length} suspicious keywords`,
      }));
      results.push({ checkId: 'OBF-DEOB', checkName: 'Deobfuscated Payloads', category: 'obfuscation', severity: 'high', description: 'Payloads decoded from obfuscated code', findings });
    }
  } catch {}

  // Run supply chain analysis
  try {
    const scResults = scanSupplyChain(targetPath);
    if (scResults.length > 0) {
      const findings: Finding[] = scResults.map(sc => ({
        file: sc.file,
        line: sc.line || 0,
        column: 0,
        code: sc.matchedText?.substring(0, 150) || '',
        message: sc.message,
        details: sc.recommendation,
      }));
      results.push({ checkId: 'SUP-001', checkName: 'Supply Chain Analysis', category: 'supply-chain', severity: scResults[0]?.severity || 'medium', description: 'Dependency and vendor analysis', findings });
    }
  } catch {}

  // Run custom rules (enhanced: multi-pattern, path patterns, target files, scoring)
  const customRules = getEnabledCustomRules();
  for (const rule of customRules) {
    const findings: Finding[] = [];
    const fileGlob = rule.filePattern || '*';
    const isAllFiles = fileGlob === '*';
    const exts = isAllFiles ? [] : fileGlob.split(',').map(e => e.trim().toLowerCase());

    // Collect all patterns: patterns array + legacy pattern field
    const allPatterns: string[] = rule.patterns.length > 0 ? rule.patterns : (rule.pattern ? [rule.pattern] : []);
    if (allPatterns.length === 0 && rule.pathPatterns.length === 0 && rule.targetFiles.length === 0) continue;

    for (const file of files) {
      // Extension filtering
      if (!isAllFiles) {
        const ext = file.extension.toLowerCase();
        if (!exts.some(e => ext === e || ext === '.' + e)) continue;
      }

      // Target file filtering: if rule specifies targetFiles, file must match one
      if (rule.targetFiles.length > 0) {
        const basename = require('path').basename(file.path).toLowerCase();
        if (!rule.targetFiles.some(tf => basename === tf.toLowerCase())) continue;
      }

      // Path pattern filtering: if rule specifies pathPatterns, file path must match at least one
      if (rule.pathPatterns.length > 0) {
        const relPath = file.relativePath;
        const matchesPath = rule.pathPatterns.some(pp => {
          try { return new RegExp(pp, 'i').test(relPath); } catch { return false; }
        });
        if (!matchesPath) continue;
      }

      // Pattern matching
      try {
        for (const pattern of allPatterns) {
          if (rule.isRegex) {
            const regex = new RegExp(pattern, 'gm');
            const lines = file.content.split(/\r?\n/);
            for (let i = 0; i < lines.length; i++) {
              if (regex.test(lines[i])) {
                const matchedCode = lines[i].substring(0, 150);
                findings.push(f(file.relativePath, i + 1, 0, matchedCode, rule.description || `Custom rule: ${rule.name}`, `Matched: ${pattern}`));
                regex.lastIndex = 0;
              }
            }
          } else {
            const lines = file.content.split(/\r?\n/);
            for (let i = 0; i < lines.length; i++) {
              if (lines[i].includes(pattern)) {
                const matchedCode = lines[i].substring(0, 150);
                findings.push(f(file.relativePath, i + 1, 0, matchedCode, rule.description || `Custom rule: ${rule.name}`, `Matched: ${pattern}`));
              }
            }
          }
        }
      } catch {}
    }

    if (findings.length > 0) {
      // Calculate risk scores for findings from this rule
      const scoredFindings = findings.map(finding => {
        const fileCtx = files.find(f => f.relativePath === finding.file);
        const mtime = fileCtx?.mtime || new Date();
        const { score } = calculateRiskScore(rule.severity, finding.file, finding.code, mtime, rule.scoringModifiers);
        return {
          ...finding,
          riskScore: score,
          confidence: rule.confidence,
          recommendation: rule.recommendation,
          tags: rule.tags,
          ruleId: rule.id,
        };
      });

      results.push({
        checkId: rule.id,
        checkName: rule.name,
        category: rule.category as CheckCategory,
        severity: rule.severity as Severity,
        description: rule.description,
        findings: scoredFindings,
      });
    }
  }

  // Add context lines (±3 lines) to each finding
  const fileLineMap = new Map<string, string[]>();
  for (const file of files) {
    fileLineMap.set(file.relativePath, file.lines);
  }
  for (const result of results) {
    for (const finding of result.findings) {
      const lines = fileLineMap.get(finding.file);
      if (lines && finding.line > 0) {
        const start = Math.max(0, finding.line - 4);
        const end = Math.min(lines.length, finding.line + 3);
        const ctxLines: string[] = [];
        for (let i = start; i < end; i++) {
          const marker = i === finding.line - 1 ? '>>>' : '   ';
          ctxLines.push(`${marker} ${String(i + 1).padStart(4)} | ${lines[i]}`);
        }
        finding.context = ctxLines.join('\n');
      }
    }
  }

  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byCategory: Record<CheckCategory | string, number> = { obfuscation: 0, 'external-access': 0, security: 0, 'code-pattern': 0, 'file-analysis': 0, wordpress: 0, evasion: 0, 'supply-chain': 0, spam: 0, 'js-malware': 0, integrity: 0 };

  for (const r of results) {
    bySeverity[r.severity] += r.findings.length;
    byCategory[r.category] = (byCategory[r.category] || 0) + r.findings.length;
  }

  const totalFindings = Object.values(bySeverity).reduce((a, b) => a + b, 0);

  return {
    id,
    targetName: path.basename(targetPath),
    scanDate: new Date().toISOString(),
    duration: Date.now() - startTime,
    totalFiles: files.length,
    phpFiles: phpFiles.length,
    totalFindings,
    bySeverity,
    byCategory,
    results,
    status: 'completed',
  };
}
