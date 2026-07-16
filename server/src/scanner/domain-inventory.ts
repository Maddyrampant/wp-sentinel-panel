import { isDomainSafe, isDomainSuspicious } from '../rules/domain-allowlist';
import { DomainReputation, checkDomainReputation } from './domain-reputation';

export interface DomainInventoryEntry {
  domain: string;
  tld: string;
  firstSeen: string;
  files: Array<{ file: string; line: number }>;
  urls: string[];
  isSafe: boolean;
  isSuspicious: boolean;
  reputationScore: number;
  flags: string[];
  reputation?: DomainReputation;
}

const URL_RE = /https?:\/\/[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+/g;
const DOMAIN_RE = /(?:https?:\/\/)([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)/g;

function extractDomainsAndUrls(content: string): Array<{ domain: string; url: string }> {
  const results: Array<{ domain: string; url: string }> = [];
  const lines = content.split('\n');
  for (const line of lines) {
    let urlMatch: RegExpExecArray | null;
    const urlRe = new RegExp(URL_RE.source, 'g');
    while ((urlMatch = urlRe.exec(line)) !== null) {
      const url = urlMatch[0];
      const domainRe = new RegExp(DOMAIN_RE.source, 'g');
      let domainMatch: RegExpExecArray | null;
      while ((domainMatch = domainRe.exec(url)) !== null) {
        results.push({ domain: domainMatch[1], url });
      }
    }
  }
  return results;
}

export function buildDomainInventory(
  files: Array<{ path: string; relativePath: string; content: string }>
): DomainInventoryEntry[] {
  const domainMap = new Map<string, DomainInventoryEntry>();

  for (const file of files) {
    const matches = extractDomainsAndUrls(file.content);
    for (const { domain, url } of matches) {
      if (!domainMap.has(domain)) {
        const tld = domain.split('.').pop()?.toLowerCase() || '';
        domainMap.set(domain, {
          domain,
          tld,
          firstSeen: new Date().toISOString(),
          files: [],
          urls: [],
          isSafe: isDomainSafe(domain),
          isSuspicious: isDomainSuspicious(domain),
          reputationScore: 50,
          flags: [],
        });
      }
      const entry = domainMap.get(domain)!;
      const fileExists = entry.files.some(f => f.file === file.relativePath);
      if (!fileExists) entry.files.push({ file: file.relativePath, line: 0 });
      if (!entry.urls.includes(url)) entry.urls.push(url);
    }
  }

  const entries = Array.from(domainMap.values());

  for (const entry of entries) {
    const rep = checkDomainReputation(entry.domain);
    entry.reputation = rep;
    entry.reputationScore = rep.overallScore;
    entry.flags = rep.flags;
    if (entry.isSafe) entry.reputationScore = Math.max(entry.reputationScore, 70);
    if (entry.flags.includes('suspicious-tld') || entry.flags.includes('ip-as-domain')) {
      entry.isSuspicious = true;
    }
  }

  return entries.sort((a, b) => a.reputationScore - b.reputationScore);
}

export function getMostSuspiciousDomains(inventory: DomainInventoryEntry[]): DomainInventoryEntry[] {
  return inventory
    .filter(e => e.isSuspicious || e.reputationScore < 40)
    .sort((a, b) => a.reputationScore - b.reputationScore);
}

export function getSafeDomains(inventory: DomainInventoryEntry[]): DomainInventoryEntry[] {
  return inventory.filter(e => e.isSafe || e.reputationScore >= 70);
}
