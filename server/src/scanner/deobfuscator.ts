import { URL } from 'url';

export interface DeobfuscationConfig {
  maxDepth: number;
  maxOutputSize: number;
  extractUrls: boolean;
  extractDomains: boolean;
  extractPhpFunctions: boolean;
  extractKeywords: boolean;
}

const DEFAULT_CONFIG: DeobfuscationConfig = {
  maxDepth: 5,
  maxOutputSize: 1048576,
  extractUrls: true,
  extractDomains: true,
  extractPhpFunctions: true,
  extractKeywords: true,
};

export interface DecodedPayload {
  original: string;
  decoded: string;
  method: string;
  depth: number;
  urls: string[];
  domains: string[];
  phpFunctions: string[];
  suspiciousKeywords: string[];
}

function tryBase64(str: string): string | null {
  try {
    const cleaned = str.replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/=]{8,}$/.test(cleaned)) return null;
    const buf = Buffer.from(cleaned, 'base64');
    const result = buf.toString('utf-8');
    if (result === str) return null;
    if (!/[\x20-\x7E\r\n\t]/.test(result)) return null;
    return result;
  } catch { return null; }
}

function tryHex(str: string): string | null {
  try {
    const hexPattern = /\\x([0-9a-fA-F]{2})/g;
    if (!hexPattern.test(str)) return null;
    hexPattern.lastIndex = 0;
    return str.replace(hexPattern, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  } catch { return null; }
}

function tryUrlDecode(str: string): string | null {
  try {
    if (!/%[0-9a-fA-F]{2}/.test(str)) return null;
    const decoded = decodeURIComponent(str);
    if (decoded === str) return null;
    return decoded;
  } catch { return null; }
}

function tryRot13(str: string): string | null {
  const result = str.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
  if (result === str) return null;
  return result;
}

function tryGzinflate(str: string): string | null {
  try {
    const zlib = require('zlib');
    const input = Buffer.from(str, 'base64');
    const result = zlib.inflateSync(input);
    return result.toString('utf-8');
  } catch { return null; }
}

function tryGzuncompress(str: string): string | null {
  try {
    const zlib = require('zlib');
    const input = Buffer.from(str, 'base64');
    const result = zlib.uncompressSync(input);
    return result.toString('utf-8');
  } catch { return null; }
}

function tryAtob(str: string): string | null {
  try {
    const cleaned = str.replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/=]{8,}$/.test(cleaned)) return null;
    const buf = Buffer.from(cleaned, 'base64');
    return buf.toString('utf-8');
  } catch { return null; }
}

function tryFromCharCode(str: string): string | null {
  try {
    const pattern = /String\.fromCharCode\s*\(([^)]+)\)/g;
    if (!pattern.test(str)) return null;
    pattern.lastIndex = 0;
    let result = '';
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(str)) !== null) {
      const codes = m[1].split(',').map(s => parseInt(s.trim(), 10));
      result += codes.map(c => String.fromCharCode(c)).join('');
    }
    return result || null;
  } catch { return null; }
}

function tryGzdecode(str: string): string | null {
  try {
    const zlib = require('zlib');
    const input = Buffer.from(str, 'base64');
    const result = zlib.gunzipSync(input);
    return result.toString('utf-8');
  } catch { return null; }
}

const DECODERS = [
  { name: 'base64', fn: tryBase64 },
  { name: 'hex', fn: tryHex },
  { name: 'url', fn: tryUrlDecode },
  { name: 'rot13', fn: tryRot13 },
  { name: 'gzinflate', fn: tryGzinflate },
  { name: 'gzuncompress', fn: tryGzuncompress },
  { name: 'gzdecode', fn: tryGzdecode },
  { name: 'atob', fn: tryAtob },
  { name: 'fromCharCode', fn: tryFromCharCode },
];

function extractUrls(str: string): string[] {
  const urls: string[] = [];
  const re = /https?:\/\/[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(str)) !== null) urls.push(m[0]);
  return [...new Set(urls)];
}

function extractDomains(str: string): string[] {
  const domains: string[] = [];
  const re = /(?:https?:\/\/)([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(str)) !== null) domains.push(m[1]);
  return [...new Set(domains)];
}

function extractPhpFunctions(str: string): string[] {
  const fns: string[] = [];
  const re = /\b(eval|exec|system|passthru|shell_exec|file_get_contents|file_put_contents|fopen|fwrite|curl_exec|base64_decode|gzinflate|gzuncompress|str_rot13|preg_replace|assert|proc_open|pcntl_exec)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(str)) !== null) fns.push(m[1]);
  return [...new Set(fns)];
}

function extractSuspiciousKeywords(str: string): string[] {
  const keywords: string[] = [];
  const patterns = [
    /\b(shell|backdoor|exploit|hack|crack|keylog|rootkit|trojan|virus|malware)\b/i,
    /\b(password|passwd|credentials|secret|token|api_key|private_key)\b/i,
    /\b(nulled|cracked|warez|pirated)\b/i,
  ];
  for (const p of patterns) {
    const m = str.match(p);
    if (m) keywords.push(m[1].toLowerCase());
  }
  return [...new Set(keywords)];
}

export function deobfuscateAll(
  input: string,
  config: Partial<DeobfuscationConfig> = {}
): DecodedPayload {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const methods: string[] = [];
  let current = input;
  let depth = 0;

  while (depth < cfg.maxDepth) {
    let decoded = false;
    for (const decoder of DECODERS) {
      if (current.length > cfg.maxOutputSize) break;
      const result = decoder.fn(current);
      if (result && result !== current && result.length > 0) {
        methods.push(decoder.name);
        current = result;
        decoded = true;
        depth++;
        break;
      }
    }
    if (!decoded) break;
  }

  const urls = cfg.extractUrls ? extractUrls(current) : [];
  const domains = cfg.extractDomains ? extractDomains(current) : [];
  const phpFunctions = cfg.extractPhpFunctions ? extractPhpFunctions(current) : [];
  const suspiciousKeywords = cfg.extractKeywords ? extractSuspiciousKeywords(current) : [];

  return {
    original: input,
    decoded: current,
    method: methods.join(' → ') || 'none',
    depth,
    urls,
    domains,
    phpFunctions,
    suspiciousKeywords,
  };
}

export function extractAllPayloads(content: string): DecodedPayload[] {
  const payloads: DecodedPayload[] = [];
  const patterns = [
    /base64_decode\s*\(\s*['"]([A-Za-z0-9+/=]{20,})['"]/gi,
    /gzinflate\s*\(\s*base64_decode\s*\(\s*['"]([A-Za-z0-9+/=]{20,})['"]/gi,
    /gzuncompress\s*\(\s*base64_decode\s*\(\s*['"]([A-Za-z0-9+/=]{20,})['"]/gi,
    /gzdecode\s*\(\s*base64_decode\s*\(\s*['"]([A-Za-z0-9+/=]{20,})['"]/gi,
    /eval\s*\(\s*gzinflate\s*\(\s*base64_decode\s*\(\s*['"]([A-Za-z0-9+/=]{20,})['"]/gi,
    /rot13\s*\(\s*['"]([A-Za-z0-9+/=]{20,})['"]/gi,
  ];

  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(content)) !== null) {
      const result = deobfuscateAll(m[1]);
      if (result.depth > 0 && (result.urls.length > 0 || result.domains.length > 0 || result.phpFunctions.length > 0 || result.suspiciousKeywords.length > 0)) {
        payloads.push(result);
      }
    }
  }
  return payloads;
}
