import { Finding } from '../types';

export type ChainLink =
  | 'external_payload_download'
  | 'payload_decode'
  | 'code_execution'
  | 'webshell_drop'
  | 'privilege_escalation'
  | 'persistence'
  | 'data_exfiltration'
  | 'obfuscation_layer'
  | 'database_injection'
  | 'file_inclusion';

export interface AttackChainLink {
  type: ChainLink;
  finding: Finding;
  file: string;
  line: number;
  description: string;
  mitreId?: string;
  mitreTactic?: string;
}

export interface AttackChain {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;
  chainType: string;
  links: AttackChainLink[];
  files: string[];
  riskScore: number;
  recommendation: string;
}

const LINK_PATTERNS: Array<{ type: ChainLink; patterns: RegExp[]; severity: Finding['details'] extends string ? 'critical' | 'high' | 'medium' | 'low' : never; mitreId: string; mitreTactic: string }> = [
  { type: 'external_payload_download', patterns: [/file_get_contents\s*\(\s*['"]https?:/i, /curl_exec/i, /wp_remote_(?:get|post)\s*\(/i, /fopen\s*\(\s*['"]https?:/i], severity: 'high', mitreId: 'T1105', mitreTactic: 'Command and Control' },
  { type: 'payload_decode', patterns: [/base64_decode\s*\(/i, /gzinflate\s*\(/i, /gzuncompress\s*\(/i, /str_rot13\s*\(/i], severity: 'medium', mitreId: 'T1027', mitreTactic: 'Defense Evasion' },
  { type: 'code_execution', patterns: [/\beval\s*\(/i, /\bexec\s*\(/i, /\bsystem\s*\(/i, /\bpassthru\s*\(/i, /\bshell_exec\s*\(/i, /\bproc_open\s*\(/i, /preg_replace\s*\(\s*['"]\/.*\/e/i], severity: 'critical', mitreId: 'T1059', mitreTactic: 'Execution' },
  { type: 'webshell_drop', patterns: [/file_put_contents\s*\(/i, /\bfwrite\s*\(\s*\$/i, /\bmove_uploaded_file\s*\(/i], severity: 'critical', mitreId: 'T1505.003', mitreTactic: 'Persistence' },
  { type: 'privilege_escalation', patterns: [/wp_create_user\s*\(/i, /\$wpdb.*UPDATE.*user/i, /add_option\s*\(/i, /update_option\s*\(/i, /wp_update_user\s*\(/i], severity: 'high', mitreId: 'T1078', mitreTactic: 'Privilege Escalation' },
  { type: 'persistence', patterns: [/wp_schedule_event\s*\(/i, /\bcron\s*\(/i, /\bschedule.*cron/i], severity: 'high', mitreId: 'T1053.005', mitreTactic: 'Persistence' },
  { type: 'data_exfiltration', patterns: [/mail\s*\(\s*['"][^'"]*@[a-z]/i, /wp_mail\s*\(/i, /file_get_contents\s*\(\s*['"]php:\/\/input/i, /\bcurl_setopt.*CURLOPT_POST/i], severity: 'high', mitreId: 'T1041', mitreTactic: 'Exfiltration' },
  { type: 'obfuscation_layer', patterns: [/eval\s*\(\s*base64_decode/i, /\beval\s*\(\s*gz/i, /\beval\s*\(\s*str_rot13/i], severity: 'medium', mitreId: 'T1027', mitreTactic: 'Defense Evasion' },
  { type: 'database_injection', patterns: [/\$wpdb\s*->\s*(?:query|get_results|get_var|get_row)\s*\(\s*['"].*\$/i, /SELECT.*\$_(?:GET|POST|REQUEST)/i], severity: 'critical', mitreId: 'T1190', mitreTactic: 'Initial Access' },
  { type: 'file_inclusion', patterns: [/include\s*\(\s*\$/i, /require\s*\(\s*\$/i, /include_once\s*\(\s*\$/i, /require_once\s*\(\s*\$/i, /\bfile_get_contents\s*\(\s*\$_/i], severity: 'critical', mitreId: 'T1190', mitreTactic: 'Initial Access' },
];

function classifyFinding(finding: Finding): ChainLink[] {
  const links: ChainLink[] = [];
  const text = `${finding.code} ${finding.message} ${finding.details}`.toLowerCase();
  for (const { type, patterns } of LINK_PATTERNS) {
    for (const p of patterns) {
      if (p.test(text)) {
        links.push(type);
        break;
      }
    }
  }
  return links;
}

function chainScore(links: ChainLink[]): number {
  const weights: Record<ChainLink, number> = {
    external_payload_download: 15,
    payload_decode: 10,
    code_execution: 25,
    webshell_drop: 25,
    privilege_escalation: 20,
    persistence: 15,
    data_exfiltration: 20,
    obfuscation_layer: 5,
    database_injection: 20,
    file_inclusion: 15,
  };
  let score = 0;
  for (const l of links) score += weights[l] || 0;
  return Math.min(score, 100);
}

const CHAIN_PATTERNS: Array<{ type: string; links: ChainLink[]; severity: 'critical' | 'high' | 'medium'; confidence: number; recommendation: string }> = [
  {
    type: 'remote_payload_to_webshell',
    links: ['external_payload_download', 'payload_decode', 'code_execution', 'webshell_drop'],
    severity: 'critical',
    confidence: 95,
    recommendation: 'Critical attack chain detected. Remote payload downloaded, decoded, executed, and used to drop a webshell. Immediately quarantine all affected files, change all credentials, and restore from clean backup.',
  },
  {
    type: 'obfuscated_backdoor',
    links: ['obfuscation_layer', 'code_execution'],
    severity: 'critical',
    confidence: 90,
    recommendation: 'Obfuscated backdoor detected. The code uses encoding to hide malicious execution. Deobfuscate and analyze the payload.',
  },
  {
    type: 'remote_file_inclusion',
    links: ['file_inclusion', 'external_payload_download'],
    severity: 'critical',
    confidence: 85,
    recommendation: 'Remote file inclusion attack chain. User-controlled input is used to include remote files. Patch the inclusion vulnerability and scan for injected content.',
  },
  {
    type: 'data_exfiltration_chain',
    links: ['code_execution', 'data_exfiltration'],
    severity: 'critical',
    confidence: 80,
    recommendation: 'Code execution combined with data exfiltration. Sensitive data may be leaving the server. Block outbound connections and investigate.',
  },
  {
    type: 'privilege_escalation_chain',
    links: ['code_execution', 'privilege_escalation'],
    severity: 'critical',
    confidence: 85,
    recommendation: 'Code execution leading to privilege escalation. An attacker may have created admin accounts. Check wp_users and remove unauthorized accounts.',
  },
  {
    type: 'persistence_chain',
    links: ['code_execution', 'persistence'],
    severity: 'high',
    confidence: 80,
    recommendation: 'Malicious code with persistence mechanism detected. Check wp-cron events and scheduled tasks for unauthorized entries.',
  },
  {
    type: 'sql_injection_chain',
    links: ['database_injection'],
    severity: 'critical',
    confidence: 85,
    recommendation: 'SQL injection vulnerability detected. User input is used directly in database queries. Use parameterized queries immediately.',
  },
  {
    type: 'simple_backdoor',
    links: ['code_execution'],
    severity: 'high',
    confidence: 70,
    recommendation: 'Dangerous code execution function detected. Review context to determine if this is a backdoor or legitimate functionality.',
  },
];

let chainIdCounter = 0;

export function detectAttackChains(findings: Finding[]): AttackChain[] {
  const chains: AttackChain[] = [];
  const classified: Array<{ finding: Finding; links: ChainLink[] }> = [];

  for (const finding of findings) {
    const links = classifyFinding(finding);
    if (links.length > 0) classified.push({ finding, links });
  }

  const fileGroups = new Map<string, Array<{ finding: Finding; links: ChainLink[] }>>();
  for (const c of classified) {
    const file = c.finding.file;
    if (!fileGroups.has(file)) fileGroups.set(file, []);
    fileGroups.get(file)!.push(c);
  }

  for (const [, group] of fileGroups) {
    group.sort((a, b) => a.finding.line - b.finding.line);

    for (const pattern of CHAIN_PATTERNS) {
      const chainLinks: AttackChainLink[] = [];
      let patternIdx = 0;

      for (const item of group) {
        if (patternIdx >= pattern.links.length) break;
        if (item.links.includes(pattern.links[patternIdx])) {
          const linkType = pattern.links[patternIdx];
          const linkMeta = LINK_PATTERNS.find(lp => lp.type === linkType);
          chainLinks.push({
            type: linkType,
            finding: item.finding,
            file: item.finding.file,
            line: item.finding.line,
            description: item.finding.message,
            mitreId: linkMeta?.mitreId,
            mitreTactic: linkMeta?.mitreTactic,
          });
          patternIdx++;
        }
      }

      if (chainLinks.length >= 2) {
        const allLinks = chainLinks.map(l => l.type);
        const score = chainScore(allLinks);
        const uniqueFiles = [...new Set(chainLinks.map(l => l.file))];

        chains.push({
          id: `chain-${Date.now()}-${++chainIdCounter}`,
          severity: pattern.severity,
          confidence: pattern.confidence,
          chainType: pattern.type,
          links: chainLinks,
          files: uniqueFiles,
          riskScore: score,
          recommendation: pattern.recommendation,
        });
      }
    }
  }

  for (const crossFile of classified) {
    for (const pattern of CHAIN_PATTERNS) {
      if (crossFile.links.includes(pattern.links[0])) {
        const firstLinkMeta = LINK_PATTERNS.find(lp => lp.type === pattern.links[0]);
        const chainLinks: AttackChainLink[] = [{
          type: pattern.links[0],
          finding: crossFile.finding,
          file: crossFile.finding.file,
          line: crossFile.finding.line,
          description: crossFile.finding.message,
          mitreId: firstLinkMeta?.mitreId,
          mitreTactic: firstLinkMeta?.mitreTactic,
        }];

        const relatedFindings = classified.filter(
          c => c.finding.file !== crossFile.finding.file && c.links.some(l => pattern.links.includes(l))
        );

        for (const related of relatedFindings.slice(0, 3)) {
          for (const linkType of pattern.links) {
            if (related.links.includes(linkType) && !chainLinks.some(l => l.type === linkType)) {
              const linkMeta = LINK_PATTERNS.find(lp => lp.type === linkType);
              chainLinks.push({
                type: linkType,
                finding: related.finding,
                file: related.finding.file,
                line: related.finding.line,
                description: related.finding.message,
                mitreId: linkMeta?.mitreId,
                mitreTactic: linkMeta?.mitreTactic,
              });
              break;
            }
          }
        }

        if (chainLinks.length >= 3) {
          const allLinks = chainLinks.map(l => l.type);
          const score = chainScore(allLinks);
          const uniqueFiles = [...new Set(chainLinks.map(l => l.file))];
          const hasDifferentFiles = uniqueFiles.length > 1;

          if (hasDifferentFiles) {
            chains.push({
              id: `chain-${Date.now()}-${++chainIdCounter}`,
              severity: pattern.severity,
              confidence: Math.max(60, pattern.confidence - 10),
              chainType: `cross_file_${pattern.type}`,
              links: chainLinks,
              files: uniqueFiles,
              riskScore: score,
              recommendation: pattern.recommendation,
            });
          }
        }
      }
    }
  }

  const seen = new Set<string>();
  return chains.filter(c => {
    const key = c.links.map(l => `${l.file}:${l.line}:${l.type}`).join('|');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort((a, b) => b.riskScore - a.riskScore);
}
