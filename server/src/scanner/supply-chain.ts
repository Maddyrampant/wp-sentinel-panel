import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

export interface SupplyChainFile {
  type: 'composer_json' | 'composer_lock' | 'package_json' | 'package_lock' | 'vendor_php' | 'vendor_js' | 'lockfile';
  path: string;
  relativePath: string;
}

export interface SupplyChainFinding {
  id: string;
  file: string;
  line?: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: string;
  message: string;
  matchedText?: string;
  confidence: number;
  recommendation: string;
}

const SUSPICIOUS_COMPOSER_PACKAGES = [
  'eval-stdin', 'php-utility', 'monolog/rce', 'guzzle/rce',
  'symfony/rce', 'laravel/rce', 'phpunit/rce',
];

const KNOWN_PACKAGES: Record<string, string> = {
  'lodash': 'Lodash utility library',
  'jquery': 'jQuery library',
  'react': 'React framework',
  'vue': 'Vue.js framework',
  'angular': 'Angular framework',
  'axios': 'HTTP client',
  'express': 'Express.js server',
  'moment': 'Date library',
  'underscore': 'Utility library',
  'backbone': 'MVC framework',
};

function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  return dp[m][n];
}

function detectTypoSquat(name: string, knownList: Record<string, string>): { known: string; distance: number } | null {
  let nearest = '';
  let minDist = Infinity;
  for (const known of Object.keys(knownList)) {
    const d = levenshtein(name, known);
    if (d < minDist && d > 0) {
      minDist = d;
      nearest = known;
    }
  }
  if (minDist <= 2 && name.length > 3) return { known: nearest, distance: minDist };
  return null;
}

function scanComposerJson(filePath: string, relativePath: string): SupplyChainFinding[] {
  const findings: SupplyChainFinding[] = [];
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const pkg = JSON.parse(content);
    const allDeps = { ...(pkg.require || {}), ...(pkg['require-dev'] || {}) };

    for (const [name] of Object.entries(allDeps)) {
      if (SUSPICIOUS_COMPOSER_PACKAGES.includes(name)) {
        findings.push({
          id: `supply-composer-suspicious-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
          file: relativePath,
          severity: 'critical',
          type: 'suspicious_composer_package',
          message: `Known malicious Composer package: ${name}`,
          matchedText: name,
          confidence: 95,
          recommendation: `Remove package "${name}" immediately. This is a known malicious package.`,
        });
      }
      const typo = detectTypoSquat(name.split('/').pop() || name, KNOWN_PACKAGES);
      if (typo) {
        findings.push({
          id: `supply-composer-typo-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
          file: relativePath,
          severity: 'high',
          type: 'typosquatting_composer',
          message: `Possible typosquatting: "${name}" resembles "${typo.known}" (distance: ${typo.distance})`,
          matchedText: name,
          confidence: 70,
          recommendation: `Verify that "${name}" is a legitimate package. It closely resembles "${typo.known}".`,
        });
      }
    }
  } catch {}
  return findings;
}

function scanPackageJson(filePath: string, relativePath: string): SupplyChainFinding[] {
  const findings: SupplyChainFinding[] = [];
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const pkg = JSON.parse(content);
    const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };

    for (const [name] of Object.entries(allDeps)) {
      const typo = detectTypoSquat(name, KNOWN_PACKAGES);
      if (typo) {
        findings.push({
          id: `supply-npm-typo-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
          file: relativePath,
          severity: 'high',
          type: 'typosquatting_npm',
          message: `Possible typosquatting: "${name}" resembles "${typo.known}" (distance: ${typo.distance})`,
          matchedText: name,
          confidence: 70,
          recommendation: `Verify that "${name}" is a legitimate npm package. It closely resembles "${typo.known}".`,
        });
      }
    }
  } catch {}
  return findings;
}

function scanVendorPhp(dir: string, baseDir: string): SupplyChainFinding[] {
  const findings: SupplyChainFinding[] = [];
  if (!fs.existsSync(dir)) return findings;

  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      findings.push(...scanVendorPhp(fullPath, baseDir));
    } else if (entry.name.endsWith('.php')) {
      try {
        const content = fs.readFileSync(fullPath, 'utf-8');
        const relativePath = path.relative(baseDir, fullPath).replace(/\\/g, '/');
        const suspiciousPatterns = [
          { re: /\beval\s*\(/gi, msg: 'eval() in vendor PHP' },
          { re: /\bexec\s*\(\s*\$/gi, msg: 'exec() with variable in vendor PHP' },
          { re: /\bsystem\s*\(\s*\$/gi, msg: 'system() with variable in vendor PHP' },
          { re: /\bfile_get_contents\s*\(\s*['"]https?:/gi, msg: 'External HTTP request in vendor PHP' },
          { re: /\$_(GET|POST|REQUEST|COOKIE)\s*\[/gi, msg: 'User input access in vendor PHP' },
        ];
        for (const { re, msg } of suspiciousPatterns) {
          re.lastIndex = 0;
          if (re.test(content)) {
            findings.push({
              id: `supply-vendor-suspicious-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
              file: relativePath,
              severity: 'high',
              type: 'suspicious_vendor_php',
              message: `${msg}: ${relativePath}`,
              matchedText: msg,
              confidence: 75,
              recommendation: `Review vendor PHP file. Vendor directories should rarely contain executable PHP.`,
            });
          }
        }
      } catch {}
    }
  }
  return findings;
}

function scanJsForDomains(dir: string, baseDir: string): SupplyChainFinding[] {
  const findings: SupplyChainFinding[] = [];
  if (!fs.existsSync(dir)) return findings;

  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      findings.push(...scanJsForDomains(fullPath, baseDir));
    } else if (entry.name.endsWith('.js') && !entry.name.endsWith('.min.js.map')) {
      try {
        const content = fs.readFileSync(fullPath, 'utf-8');
        const relativePath = path.relative(baseDir, fullPath).replace(/\\/g, '/');
        const urlRe = /https?:\/\/[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+/g;
        const domainRe = /(?:https?:\/\/)([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)/g;
        let m: RegExpExecArray | null;
        while ((m = domainRe.exec(content)) !== null) {
          const domain = m[1];
          if (!/googleapis|cloudflare|jsdelivr|unpkg|cdnjs|jquery\.com|github\.com/.test(domain)) {
            findings.push({
              id: `supply-js-domain-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
              file: relativePath,
              severity: 'medium',
              type: 'external_domain_in_vendor_js',
              message: `External domain in vendor JS: ${domain}`,
              matchedText: domain,
              confidence: 60,
              recommendation: `Review why this external domain is referenced in vendor JavaScript.`,
            });
          }
        }
      } catch {}
    }
  }
  return findings;
}

export function scanSupplyChain(baseDir: string): SupplyChainFinding[] {
  const findings: SupplyChainFinding[] = [];

  const composerJsonPath = path.join(baseDir, 'composer.json');
  if (fs.existsSync(composerJsonPath)) {
    findings.push(...scanComposerJson(composerJsonPath, 'composer.json'));
  }

  const packageJsonPath = path.join(baseDir, 'package.json');
  if (fs.existsSync(packageJsonPath)) {
    findings.push(...scanPackageJson(packageJsonPath, 'package.json'));
  }

  const vendorDir = path.join(baseDir, 'vendor');
  if (fs.existsSync(vendorDir)) {
    findings.push(...scanVendorPhp(vendorDir, baseDir));
  }

  const nodeModulesDir = path.join(baseDir, 'node_modules');
  if (fs.existsSync(nodeModulesDir)) {
    findings.push(...scanJsForDomains(nodeModulesDir, baseDir));
  }

  const assetsDir = path.join(baseDir, 'assets', 'js');
  if (fs.existsSync(assetsDir)) {
    findings.push(...scanJsForDomains(assetsDir, baseDir));
  }

  return findings;
}
