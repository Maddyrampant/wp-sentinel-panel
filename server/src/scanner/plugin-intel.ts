import * as fs from 'fs';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { isDomainSafe, isDomainSuspicious } from '../rules/domain-allowlist';

let findingCounter = 0;

function genId(): string {
  return `pi-${Date.now()}-${++findingCounter}`;
}

export interface PluginFinding {
  id: string;
  file: string;
  line: number;
  column?: number;
  type: 'malware' | 'backdoor' | 'nulled' | 'external_domain' | 'base64_payload' | 'suspicious_pattern' | 'vulnerability' | 'outdated_api' | 'weak_crypto';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'clean';
  message: string;
  matchedText: string;
  confidence: number;
  recommendation?: string;
}

export interface PluginExternalDomain {
  domain: string;
  urls: string[];
  files: Array<{ file: string; line: number }>;
  isSuspicious: boolean;
}

export interface PluginBase64Decoded {
  file: string;
  line: number;
  decoded: string;
  extractedUrls: string[];
  extractedDomains: string[];
}

export interface PluginMetadata {
  name?: string;
  version?: string;
  author?: string;
  description?: string;
  textDomain?: string;
  requiresPhp?: string;
  requiresWp?: string;
  testedUpTo?: string;
  license?: string;
}

export interface PluginIntelResult {
  pluginName: string;
  pluginPath: string;
  metadata?: PluginMetadata;
  externalDomains: PluginExternalDomain[];
  nulledIndicators: PluginFinding[];
  malwarePatterns: PluginFinding[];
  base64Decoded: PluginBase64Decoded[];
  vulnerabilityPatterns: PluginFinding[];
  riskScore: number;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'clean';
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
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

const URL_REGEX = /https?:\/\/[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+/g;
const DOMAIN_REGEX = /(?:https?:\/\/)([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)/g;

const WP_REMOTE_REGEX = /\b(wp_remote_(?:get|post|head|request))\s*\(\s*['"`]/gi;
const CURL_EXEC_REGEX = /\bcurl_exec\s*\(\s*/gi;
const FILE_GET_REGEX = /\bfile_get_contents\s*\(\s*(?:['"`]http|['"`]https|\$_)/gi;
const FOPEN_REGEX = /\bfopen\s*\(\s*['"`]https?:/gi;

const MALWARE_PATTERNS: Array<{
  re: RegExp;
  type: PluginFinding['type'];
  severity: PluginFinding['severity'];
  message: string;
  confidence: number;
  recommendation: string;
}> = [
  // 1. eval(base64_decode) chains
  { re: /eval\s*\(\s*base64_decode\s*\(/gi, type: 'malware', severity: 'critical', message: 'eval(base64_decode()) — obfuscated malicious code', confidence: 95, recommendation: 'Remove this file immediately. It contains obfuscated backdoor code.' },
  // 2. eval($var) direct eval
  { re: /eval\s*\(\s*\$[a-zA-Z_]/gi, type: 'backdoor', severity: 'critical', message: 'eval() with variable — code execution backdoor', confidence: 90, recommendation: 'Review the variable source. If user-controlled, this is a backdoor.' },
  // 3. system($), exec($), passthru($), shell_exec($)
  { re: /\bsystem\s*\(\s*\$/gi, type: 'backdoor', severity: 'critical', message: 'system() with variable — OS command execution', confidence: 95, recommendation: 'Remove or sanitize. OS command execution is almost always malicious.' },
  { re: /\bexec\s*\(\s*\$/gi, type: 'backdoor', severity: 'critical', message: 'exec() with variable — OS command execution', confidence: 90, recommendation: 'Review and remove. Command execution in plugins is suspicious.' },
  { re: /\bpassthru\s*\(\s*\$/gi, type: 'backdoor', severity: 'critical', message: 'passthru() — OS command passthrough', confidence: 90, recommendation: 'Remove immediately. This is a common backdoor function.' },
  { re: /\bshell_exec\s*\(\s*\$/gi, type: 'backdoor', severity: 'critical', message: 'shell_exec() — shell command execution', confidence: 90, recommendation: 'Remove immediately. Shell execution in plugins is dangerous.' },
  // 4. proc_open, popen
  { re: /\bproc_open\s*\(/gi, type: 'backdoor', severity: 'critical', message: 'proc_open() — process execution', confidence: 85, recommendation: 'Review context. proc_open is rare in legitimate plugins.' },
  { re: /\bpopen\s*\(/gi, type: 'backdoor', severity: 'high', message: 'popen() — process open for execution', confidence: 80, recommendation: 'Review context. popen is rarely needed in legitimate plugins.' },
  // 5. preg_replace /e modifier
  { re: /\bpreg_replace\s*\(\s*['"`]\/.*\/e['"]/gi, type: 'malware', severity: 'critical', message: 'preg_replace /e modifier — code execution', confidence: 95, recommendation: 'Remove. The /e modifier allows arbitrary code execution.' },
  // 6. create_function deprecated
  { re: /\bcreate_function\s*\(/gi, type: 'backdoor', severity: 'high', message: 'create_function() — dynamic code execution (deprecated)', confidence: 80, recommendation: 'Review context. create_function is deprecated and often used for obfuscation.' },
  // 7. assert($)
  { re: /\bassert\s*\(\s*\$/gi, type: 'backdoor', severity: 'high', message: 'assert() with variable — code assertion backdoor', confidence: 85, recommendation: 'Remove. assert with variables can execute arbitrary code.' },
  // 8. $_GET/POST/REQUEST/COOKIE direct usage in eval/exec
  { re: /\$_(?:GET|POST|REQUEST|COOKIE)\s*\[.*\]\s*\(\s*\)/gi, type: 'backdoor', severity: 'critical', message: 'User input used as function call — remote code execution', confidence: 98, recommendation: 'Critical backdoor! User input is being called as a function.' },
  // 9. file_put_contents($_...) writing user-controlled content
  { re: /\bfile_put_contents\s*\(\s*\$_(?:GET|POST|REQUEST)/gi, type: 'backdoor', severity: 'critical', message: 'file_put_contents with user input — file upload backdoor', confidence: 95, recommendation: 'Critical! Allows attackers to write arbitrary files.' },
  // 10. move_uploaded_file file upload
  { re: /\bmove_uploaded_file\s*\(/gi, type: 'suspicious_pattern', severity: 'medium', message: 'move_uploaded_file — file upload handler', confidence: 60, recommendation: 'Review. File upload in plugins may be legitimate but verify the handler.' },
  // 11. base64_decode($var) dynamic decode
  { re: /\bbase64_decode\s*\(\s*\$/gi, type: 'base64_payload', severity: 'high', message: 'base64_decode with variable — dynamic decode', confidence: 75, recommendation: 'Review the variable source. Dynamic base64 decode is often used for evasion.' },
  // 12. call_user_func / call_user_func_array dynamic dispatch
  { re: /\bcall_user_func\s*\(\s*\$/gi, type: 'backdoor', severity: 'high', message: 'call_user_func with variable — dynamic function dispatch', confidence: 75, recommendation: 'Review the callback source. Variable callbacks enable code execution.' },
  { re: /\bcall_user_func_array\s*\(\s*\$/gi, type: 'backdoor', severity: 'high', message: 'call_user_func_array with variable — dynamic function dispatch', confidence: 75, recommendation: 'Review the callback source. Variable callbacks enable code execution.' },
  // 13. ReflectionClass dynamic class loading
  { re: /\bReflectionClass\s*\(\s*\$/gi, type: 'suspicious_pattern', severity: 'high', message: 'ReflectionClass with variable — dynamic class loading', confidence: 70, recommendation: 'Review context. Dynamic class instantiation can bypass type checks.' },
  // 14. register_shutdown_function persistence
  { re: /\bregister_shutdown_function\s*\(\s*\$/gi, type: 'suspicious_pattern', severity: 'medium', message: 'register_shutdown_function with variable — persistence mechanism', confidence: 65, recommendation: 'Review. Shutdown functions can persist after request ends.' },
  // 15. set_error_handler error suppression
  { re: /\bset_error_handler\s*\(/gi, type: 'suspicious_pattern', severity: 'medium', message: 'set_error_handler — error handler override', confidence: 55, recommendation: 'Review context. Custom error handlers can suppress security warnings.' },
  // 16. ob_start with callback (output buffering attack)
  { re: /\bob_start\s*\(\s*\$/gi, type: 'suspicious_pattern', severity: 'high', message: 'ob_start with variable callback — output buffering attack', confidence: 75, recommendation: 'Review. Dynamic output buffering callbacks can inject malicious content.' },
  // 17. extract($_...) variable overwriting
  { re: /\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/gi, type: 'vulnerability', severity: 'high', message: 'extract() with user input — variable overwriting vulnerability', confidence: 85, recommendation: 'Remove or use EXTR_SKIP. extract() with user input can overwrite critical variables.' },
  // 18. unserialize($_...) object injection
  { re: /\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/gi, type: 'vulnerability', severity: 'critical', message: 'unserialize() with user input — object injection vulnerability', confidence: 95, recommendation: 'Critical vulnerability! Replace with json_decode() or use allowed_classes restriction.' },
  // 19. file_get_contents with HTTP URLs
  { re: /\bfile_get_contents\s*\(\s*['"`]https?:/gi, type: 'external_domain', severity: 'medium', message: 'file_get_contents with HTTP URL — external data fetch', confidence: 60, recommendation: 'Review. External HTTP requests in plugins should be validated.' },
  // 20. curl_exec with user-controlled URLs
  { re: /\bcurl_exec\s*\(\s*\$/gi, type: 'external_domain', severity: 'high', message: 'curl_exec with variable — potentially user-controlled request', confidence: 75, recommendation: 'Review URL source. User-controlled URLs enable SSRF.' },
  // 21. fsockopen / socket_create network access
  { re: /\bfsockopen\s*\(\s*\$/gi, type: 'external_domain', severity: 'high', message: 'fsockopen with variable — raw network access', confidence: 75, recommendation: 'Review. Raw socket connections can bypass HTTP security controls.' },
  { re: /\bsocket_create\s*\(/gi, type: 'external_domain', severity: 'high', message: 'socket_create — raw socket creation', confidence: 75, recommendation: 'Review context. Raw sockets bypass standard HTTP security.' },
  // 22. chmod / chown permission modification
  { re: /\bchmod\s*\(\s*\$/gi, type: 'backdoor', severity: 'high', message: 'chmod with variable — permission modification', confidence: 80, recommendation: 'Review. Dynamic permission changes can weaken server security.' },
  { re: /\bchown\s*\(\s*\$/gi, type: 'backdoor', severity: 'high', message: 'chown with variable — ownership modification', confidence: 80, recommendation: 'Review. Dynamic ownership changes can escalate privileges.' },
  // 23. unlink / rmdir file deletion
  { re: /\bunlink\s*\(\s*\$/gi, type: 'suspicious_pattern', severity: 'high', message: 'unlink with variable — dynamic file deletion', confidence: 70, recommendation: 'Review. Dynamic file deletion can destroy evidence or damage the site.' },
  { re: /\brmdir\s*\(\s*\$/gi, type: 'suspicious_pattern', severity: 'high', message: 'rmdir with variable — dynamic directory deletion', confidence: 70, recommendation: 'Review. Dynamic directory deletion can destroy evidence or damage the site.' },
  // 24. rename / copy file manipulation
  { re: /\brename\s*\(\s*\$/gi, type: 'suspicious_pattern', severity: 'high', message: 'rename with variable — dynamic file renaming', confidence: 65, recommendation: 'Review. Dynamic file renaming can move or overwrite files.' },
  { re: /\bcopy\s*\(\s*\$/gi, type: 'suspicious_pattern', severity: 'medium', message: 'copy with variable — dynamic file copying', confidence: 55, recommendation: 'Review context. File copy operations may be legitimate or malicious.' },
  // 25. PHP environment tampering
  { re: /\bini_set\s*\(\s*['"`](?:disable_functions|open_basedir|safe_mode|allow_url_include|allow_url_fopen)/gi, type: 'backdoor', severity: 'critical', message: 'ini_set — PHP security directive tampering', confidence: 92, recommendation: 'Critical! Attempting to disable PHP security restrictions.' },
  { re: /\bphp_uname\s*\(\s*\)/gi, type: 'suspicious_pattern', severity: 'medium', message: 'php_uname() — system information disclosure', confidence: 50, recommendation: 'Review context. System fingerprinting may be reconnaissance.' },
  { re: /\bget_loaded_extensions\s*\(\s*\)/gi, type: 'suspicious_pattern', severity: 'low', message: 'get_loaded_extensions() — environment enumeration', confidence: 40, recommendation: 'Review context. Extension enumeration is often reconnaissance.' },
];

const NULL_KEYWORDS = [
  /\bnulled\b/i,
  /\bcracked\b/i,
  /\bwarez\b/i,
  /\bpirated?\b/i,
  /\bfree\s+download\b/i,
  /\blicense\s*bypass\b/i,
  /\bactivate\s+without\s+license\b/i,
  /\bsans\s+licence\b/i,
  /\btheme\s+gratuit\b/i,
  /\bnull\s+theme\b/i,
  /\bcodecanyon\s+free\b/i,
  /\bthemeforest\s+free\b/i,
  /\bgpl\s+license\s+bypass\b/i,
  /\bnulled\s+script\b/i,
  /\bnull\s+plugin\b/i,
];

const NULL_FILENAMES = [
  /license.*null/i,
  /nulled\.php/i,
  /cracked\.php/i,
  /warez\.php/i,
  /activator\.php/i,
  /bypass\.php/i,
  /unlock\.php/i,
  /patch\.php/i,
  /keygen\.php/i,
  /crack\.php/i,
];

const VULNERABILITY_PATTERNS: Array<{
  re: RegExp;
  type: 'vulnerability';
  severity: PluginFinding['severity'];
  message: string;
  confidence: number;
  recommendation: string;
}> = [
  // 1. SQL injection: $wpdb->query/prepare with direct variable
  { re: /\$wpdb->(?:query|prepare)\s*\(\s*['"`].*\$\w+/gi, type: 'vulnerability', severity: 'high', message: 'Potential SQL injection — variable in $wpdb query/prepare', confidence: 75, recommendation: 'Use parameterized queries with proper placeholders.' },
  // 2. XSS: echo/print with unescaped user input
  { re: /\b(?:echo|print)\s+\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/gi, type: 'vulnerability', severity: 'high', message: 'Potential XSS — unescaped user input in output', confidence: 85, recommendation: 'Escape output with esc_html(), esc_attr(), or wp_kses().' },
  // 3. CSRF: nonce verification missing patterns
  { re: /\$_POST\s*\[(?!.*wp_verify_nonce)(?!.*check_ajax_referer).*\]/gi, type: 'vulnerability', severity: 'medium', message: 'Potential CSRF — POST handling without visible nonce check', confidence: 50, recommendation: 'Add wp_verify_nonce() or check_ajax_referer() for CSRF protection.' },
  // 4. IDOR: direct ID from $_GET/POST without validation
  { re: /\b(?:user_id|post_id|user_id|comment_id)\s*=\s*\$_(?:GET|POST)\s*\[/gi, type: 'vulnerability', severity: 'medium', message: 'Potential IDOR — direct ID from user input', confidence: 55, recommendation: 'Validate and sanitize IDs. Check current_user_can() for authorization.' },
  // 5. File inclusion: include/require with variable path
  { re: /\b(?:include|require|include_once|require_once)\s*\(\s*\$/gi, type: 'vulnerability', severity: 'critical', message: 'Potential file inclusion — variable path', confidence: 90, recommendation: 'Remove variable file inclusion. Use whitelisted file paths.' },
  // 6. Open redirect: wp_redirect/header with user input
  { re: /\b(?:wp_redirect|header)\s*\(\s*\$_(?:GET|POST|REQUEST)/gi, type: 'vulnerability', severity: 'high', message: 'Potential open redirect — user-controlled redirect URL', confidence: 85, recommendation: 'Validate redirect URLs against a whitelist of allowed domains.' },
  // 7. Privilege escalation: current_user_can bypass patterns
  { re: /\badd_filter\s*\(\s*['"`]user_has_cap['"`]\s*,\s*['"`]\w+['"`].*\$/gi, type: 'vulnerability', severity: 'high', message: 'Potential privilege escalation — user_has_cap filter manipulation', confidence: 70, recommendation: 'Review capability grants. Ensure they follow least-privilege principle.' },
  // 8. Unsafe deserialization: unserialize with user input
  { re: /\bunserialize\s*\(\s*(?!\s*['"`])(?!\s*json_)/gi, type: 'vulnerability', severity: 'critical', message: 'Unsafe deserialization — potential object injection', confidence: 85, recommendation: 'Use json_decode() instead of unserialize(), or restrict allowed_classes.' },
  // 9. SSRF: file_get_contents/curl with user input
  { re: /\b(?:file_get_contents|curl_setopt.*CURLOPT_URL)\s*.*\$_(?:GET|POST|REQUEST)/gi, type: 'vulnerability', severity: 'high', message: 'Potential SSRF — user-controlled URL in HTTP request', confidence: 80, recommendation: 'Validate and whitelist target URLs. Prevent internal network access.' },
  // 10. Hardcoded credentials
  { re: /\b(?:password|passwd|api_key|secret_key|token)\s*=\s*['"`][A-Za-z0-9+/=_-]{8,}['"]/gi, type: 'vulnerability', severity: 'high', message: 'Potential hardcoded credential', confidence: 65, recommendation: 'Move credentials to environment variables or encrypted options.' },
];

const OUTDATED_API_PATTERNS: Array<{
  re: RegExp;
  type: 'outdated_api';
  severity: PluginFinding['severity'];
  message: string;
  confidence: number;
  recommendation: string;
}> = [
  { re: /\bget_currentuserinfo\s*\(/gi, type: 'outdated_api', severity: 'low', message: 'get_currentuserinfo() — deprecated since WP 4.5', confidence: 90, recommendation: 'Replace with wp_get_current_user().' },
  { re: /\buser_level\b/gi, type: 'outdated_api', severity: 'low', message: 'user_level meta key — deprecated', confidence: 70, recommendation: 'Replace with capability checks using current_user_can().' },
  { re: /\bwp_get_single_post\s*\(/gi, type: 'outdated_api', severity: 'low', message: 'wp_get_single_post() — deprecated', confidence: 85, recommendation: 'Replace with get_post().' },
  { re: /\bis_comments_popup\s*\(\s*\)/gi, type: 'outdated_api', severity: 'low', message: 'is_comments_popup() — deprecated', confidence: 90, recommendation: 'Replace with is_singular() or is_comments_popup from conditionals.' },
  { re: /\bWP_Query\b.*\b(?:caller_get_posts|suppress_filters)\b/gi, type: 'outdated_api', severity: 'low', message: 'WP_Query deprecated parameter', confidence: 75, recommendation: 'Remove deprecated parameters from WP_Query.' },
];

const WEAK_CRYPTO_PATTERNS: Array<{
  re: RegExp;
  type: 'weak_crypto';
  severity: PluginFinding['severity'];
  message: string;
  confidence: number;
  recommendation: string;
}> = [
  { re: /\bmd5\s*\(\s*\$/gi, type: 'weak_crypto', severity: 'medium', message: 'md5() for password/data hashing — cryptographically weak', confidence: 70, recommendation: 'Replace with password_hash() and password_verify(). md5 is broken for security.' },
  { re: /\bsha1\s*\(\s*\$/gi, type: 'weak_crypto', severity: 'medium', message: 'sha1() for password/data hashing — cryptographically weak', confidence: 70, recommendation: 'Replace with password_hash() and password_verify(). sha1 is not secure for hashing.' },
  { re: /\buniqid\s*\(\s*\)/gi, type: 'weak_crypto', severity: 'medium', message: 'uniqid() for token generation — predictable', confidence: 65, recommendation: 'Replace with random_bytes() or bin2hex(random_bytes(32)) for secure tokens.' },
  { re: /\bmt_rand\s*\(\s*\)/gi, type: 'weak_crypto', severity: 'medium', message: 'mt_rand() for security tokens — not cryptographically secure', confidence: 60, recommendation: 'Replace with random_int() or random_bytes() for security-sensitive randomness.' },
  { re: /\btime\s*\(\s*\)\s*\+\s*\d+/gi, type: 'weak_crypto', severity: 'low', message: 'time() used for nonce/expiration generation — predictable', confidence: 50, recommendation: 'Use wp_generate_password() or random_bytes() for nonces and tokens.' },
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

export function parseReadmeTxt(readmePath: string): PluginMetadata {
  if (!fs.existsSync(readmePath)) return {};
  try {
    const content = fs.readFileSync(readmePath, 'utf-8');
    const meta: PluginMetadata = {};
    const patterns: Array<[RegExp, keyof PluginMetadata]> = [
      [/Plugin Name:\s*(.+)/i, 'name'],
      [/Version:\s*(.+)/i, 'version'],
      [/Author:\s*(.+)/i, 'author'],
      [/Description:\s*(.+)/i, 'description'],
      [/Text Domain:\s*(.+)/i, 'textDomain'],
      [/Requires PHP:\s*(.+)/i, 'requiresPhp'],
      [/Requires at least:\s*(.+)/i, 'requiresWp'],
      [/Tested up to:\s*(.+)/i, 'testedUpTo'],
      [/License:\s*(.+)/i, 'license'],
    ];
    for (const [re, key] of patterns) {
      const m = content.match(re);
      if (m) (meta as any)[key] = m[1].trim();
    }
    return meta;
  } catch {
    return {};
  }
}

function parsePluginHeader(mainFile: string): PluginMetadata {
  if (!fs.existsSync(mainFile)) return {};
  try {
    const content = fs.readFileSync(mainFile, 'utf-8');
    const headerMatch = content.match(/\/\*\*[\s\S]*?\*\//);
    if (!headerMatch) return {};
    const header = headerMatch[0];
    const meta: PluginMetadata = {};
    const patterns: Array<[RegExp, keyof PluginMetadata]> = [
      [/Plugin Name:\s*(.+)/i, 'name'],
      [/Version:\s*(.+)/i, 'version'],
      [/Author:\s*(.+)/i, 'author'],
      [/Description:\s*(.+)/i, 'description'],
      [/Text Domain:\s*(.+)/i, 'textDomain'],
      [/Requires PHP:\s*(.+)/i, 'requiresPhp'],
      [/Requires at least:\s*(.+)/i, 'requiresWp'],
      [/Tested up to:\s*(.+)/i, 'testedUpTo'],
      [/License:\s*(.+)/i, 'license'],
    ];
    for (const [re, key] of patterns) {
      const m = header.match(re);
      if (m) (meta as any)[key] = m[1].trim();
    }
    return meta;
  } catch {
    return {};
  }
}

function detectExternalDomainsInFile(
  content: string,
  relativePath: string,
  findings: PluginFinding[],
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
          recommendation: 'Review why this plugin makes external HTTP requests.',
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
  findings: PluginFinding[]
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
        message: `Nulled/pirated plugin indicator: "${match[0]}"`,
        matchedText: match[0],
        confidence: 80,
        recommendation: 'This plugin may be nulled/pirated. Use only genuine, licensed plugins.',
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
        message: `Suspicious filename for nulled plugin: ${filename}`,
        matchedText: filename,
        confidence: 85,
        recommendation: 'File name suggests nulled/pirated plugin. Remove and use genuine copy.',
      });
    }
  }
}

function detectMalwareInFile(
  content: string,
  relativePath: string,
  findings: PluginFinding[]
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

function detectVulnerabilitiesInFile(
  content: string,
  relativePath: string,
  findings: PluginFinding[]
): void {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pattern of VULNERABILITY_PATTERNS) {
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

function detectOutdatedApiInFile(
  content: string,
  relativePath: string,
  findings: PluginFinding[]
): void {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pattern of OUTDATED_API_PATTERNS) {
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

function detectWeakCryptoInFile(
  content: string,
  relativePath: string,
  findings: PluginFinding[]
): void {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pattern of WEAK_CRYPTO_PATTERNS) {
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
  results: PluginBase64Decoded[]
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

export function analyzePlugin(pluginPath: string, pluginName: string): PluginIntelResult {
  const pluginDir = path.join(pluginPath, pluginName);
  const phpFiles = walkPhpFiles(pluginDir);

  // Parse metadata from readme.txt or main plugin file
  const readmePath = path.join(pluginDir, 'readme.txt');
  let metadata = parseReadmeTxt(readmePath);

  // Try to find and parse the main plugin file if readme.txt had no luck
  if (!metadata.name) {
    const mainFile = path.join(pluginDir, `${pluginName}.php`);
    if (fs.existsSync(mainFile)) {
      metadata = parsePluginHeader(mainFile);
    } else {
      // Fallback: find any PHP file with a plugin header
      for (const filePath of phpFiles) {
        const headerMeta = parsePluginHeader(filePath);
        if (headerMeta.name) {
          metadata = headerMeta;
          break;
        }
      }
    }
  }

  const allMalwareFindings: PluginFinding[] = [];
  const allNulledFindings: PluginFinding[] = [];
  const allExternalFindings: PluginFinding[] = [];
  const allVulnerabilityFindings: PluginFinding[] = [];
  const allOutdatedApiFindings: PluginFinding[] = [];
  const allWeakCryptoFindings: PluginFinding[] = [];
  const domainMap = new Map<string, { urls: Set<string>; files: Array<{ file: string; line: number }> }>();
  const allBase64Decoded: PluginBase64Decoded[] = [];

  for (const filePath of phpFiles) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const relativePath = path.relative(pluginDir, filePath).replace(/\\/g, '/');

      detectMalwareInFile(content, relativePath, allMalwareFindings);
      detectNulledInFile(content, relativePath, path.basename(filePath), allNulledFindings);
      detectExternalDomainsInFile(content, relativePath, allExternalFindings, domainMap);
      detectBase64Payloads(content, relativePath, allBase64Decoded);
      detectVulnerabilitiesInFile(content, relativePath, allVulnerabilityFindings);
      detectOutdatedApiInFile(content, relativePath, allOutdatedApiFindings);
      detectWeakCryptoInFile(content, relativePath, allWeakCryptoFindings);
    } catch {
      // skip unreadable files
    }
  }

  const externalDomains: PluginExternalDomain[] = Array.from(domainMap.entries()).map(([domain, data]) => ({
    domain,
    urls: Array.from(data.urls),
    files: data.files,
    isSuspicious: isDomainSuspicious(domain) || (!isDomainSafe(domain) && allMalwareFindings.length > 0),
  }));

  const allFindings = [
    ...allMalwareFindings,
    ...allNulledFindings,
    ...allExternalFindings,
    ...allVulnerabilityFindings,
    ...allOutdatedApiFindings,
    ...allWeakCryptoFindings,
  ];
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

  let riskLevel: PluginIntelResult['riskLevel'] = 'clean';
  if (riskScore >= 75) riskLevel = 'critical';
  else if (riskScore >= 50) riskLevel = 'high';
  else if (riskScore >= 25) riskLevel = 'medium';
  else if (riskScore > 0) riskLevel = 'low';

  return {
    pluginName,
    pluginPath: pluginDir,
    metadata: metadata.name ? metadata : undefined,
    externalDomains,
    nulledIndicators: allNulledFindings,
    malwarePatterns: allMalwareFindings,
    base64Decoded: allBase64Decoded,
    vulnerabilityPatterns: allVulnerabilityFindings,
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

export function analyzeAllPlugins(pluginsPath: string): PluginIntelResult[] {
  if (!fs.existsSync(pluginsPath)) return [];
  const entries = fs.readdirSync(pluginsPath, { withFileTypes: true });
  const plugins = entries.filter(e => e.isDirectory()).map(e => e.name);
  return plugins.map(name => analyzePlugin(pluginsPath, name));
}
