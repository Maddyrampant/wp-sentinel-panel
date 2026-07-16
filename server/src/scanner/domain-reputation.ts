import { isDomainSafe } from '../rules/domain-allowlist';

export type DomainFlag =
  | 'suspicious-tld'
  | 'ip-as-domain'
  | 'recent-registered'
  | 'free-hosting'
  | 'dynamic-dns'
  | 'punycode'
  | 'long-subdomain-chain'
  | 'no-https'
  | 'typosquatting'
  | 'known-malware-domain'
  | 'dark-web-listed';

export interface DomainReputation {
  domain: string;
  overallScore: number;
  flags: DomainFlag[];
  whois?: {
    registrar?: string;
    createdDate?: string;
    expiresDate?: string;
    ageDays?: number;
  };
  dns?: {
    aRecords: string[];
    mxRecords: string[];
    nsRecords: string[];
    cnameRecords: string[];
  };
  tls?: {
    hasHttps: boolean;
    issuer?: string;
    validFrom?: string;
    validTo?: string;
  };
  similarity?: {
    nearestKnownDomain: string;
    distance: number;
    isTyposquat: boolean;
  };
}

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'cc', 'pw', 'top', 'club',
  'work', 'buzz', 'icu', 'monster', 'cfd', 'sbs', 'rest', 'cam',
  'lol', 'sbs', 'uno', 'cyou', 'bond', 'cfd', 'mom',
]);

const FREE_HOSTING_PATTERNS = [
  /\.blogspot\./,
  /\.wordpress\.com/,
  /\.netlify\.app/,
  /\.vercel\.app/,
  /\.herokuapp\.com/,
  /\.github\.io/,
  /\.pages\.dev/,
  /\.workers\.dev/,
];

const DYNAMIC_DNS_PATTERNS = [
  /\.no-ip\./,
  /\.dyndns\./,
  /\.duckdns\.org/,
  /\.freedns\.afraid\.org/,
  /\.changeip\.com/,
  /\.zapt\.me/,
];

const KNOWN_BRANDS = [
  'wordpress', 'woocommerce', 'google', 'facebook', 'twitter', 'github',
  'microsoft', 'amazon', 'apple', 'xtemos', 'envato', 'themeforest',
  'codecanyon', 'elementor', 'divi', 'avada', 'flavor', 'flavor',
  'woodmart', 'flavor', 'flavor', 'flavor',
];

function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return dp[m][n];
}

function findTyposquat(domain: string): { nearest: string; distance: number } | null {
  const baseDomain = domain.split('.')[0].toLowerCase();
  let nearest = '';
  let minDist = Infinity;
  for (const brand of KNOWN_BRANDS) {
    const d = levenshteinDistance(baseDomain, brand);
    if (d < minDist && d > 0) {
      minDist = d;
      nearest = brand;
    }
  }
  if (minDist <= 2 && baseDomain.length > 3) {
    return { nearest, distance: minDist };
  }
  return null;
}

export function checkDomainReputation(domain: string): DomainReputation {
  const flags: DomainFlag[] = [];
  let score = 60;

  if (isDomainSafe(domain)) {
    score = 95;
    return { domain, overallScore: score, flags: [] };
  }

  const ipRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  if (ipRegex.test(domain)) {
    flags.push('ip-as-domain');
    score -= 40;
  }

  const tld = domain.split('.').pop()?.toLowerCase() || '';
  if (SUSPICIOUS_TLDS.has(tld)) {
    flags.push('suspicious-tld');
    score -= 30;
  }

  if (FREE_HOSTING_PATTERNS.some(p => p.test(domain))) {
    flags.push('free-hosting');
    score -= 15;
  }

  if (DYNAMIC_DNS_PATTERNS.some(p => p.test(domain))) {
    flags.push('dynamic-dns');
    score -= 20;
  }

  if (/xn--/.test(domain)) {
    flags.push('punycode');
    score -= 20;
  }

  const parts = domain.split('.');
  if (parts.length > 4) {
    flags.push('long-subdomain-chain');
    score -= 10;
  }

  if (domain.includes('http://')) {
    flags.push('no-https');
    score -= 15;
  }

  const typosquat = findTyposquat(domain);
  if (typosquat) {
    flags.push('typosquatting');
    score -= 35;
  }

  score = Math.max(0, Math.min(100, score));

  return {
    domain,
    overallScore: score,
    flags,
    similarity: typosquat ? {
      nearestKnownDomain: typosquat.nearest + '.com',
      distance: typosquat.distance,
      isTyposquat: true,
    } : undefined,
  };
}
