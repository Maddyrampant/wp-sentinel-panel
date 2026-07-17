import { CheckResult, Finding } from '../types';

export interface MitreMapping {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  findingCount: number;
  files: string[];
  severity: string;
  confidence: number;
}

export interface MitreResult {
  mappings: MitreMapping[];
  coverageScore: number;
  topTactics: Array<{ tactic: string; count: number }>;
  totalMappedFindings: number;
}

const MITRE_MAP: Record<string, { techniqueId: string; techniqueName: string; tactic: string }[]> = {
  'OBF': [{ techniqueId: 'T1027', techniqueName: 'Obfuscated Files or Information', tactic: 'Defense Evasion' }],

  'SEC-010': [{ techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter', tactic: 'Execution' }],
  'SEC-013': [{ techniqueId: 'T1059.004', techniqueName: 'Unix Shell', tactic: 'Execution' }],
  'SEC-036': [{ techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter', tactic: 'Execution' }],
  'SEC-035': [{ techniqueId: 'T1059.007', techniqueName: 'JavaScript', tactic: 'Execution' }],

  'SEC-001': [{ techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application', tactic: 'Initial Access' }],
  'SEC-024': [{ techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application', tactic: 'Initial Access' }],
  'SEC-025': [{ techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application', tactic: 'Initial Access' }],

  'SEC-002': [{ techniqueId: 'T1189', techniqueName: 'Drive-by Compromise', tactic: 'Initial Access' }],
  'SEC-021': [{ techniqueId: 'T1189', techniqueName: 'Drive-by Compromise', tactic: 'Initial Access' }],
  'SEC-022': [{ techniqueId: 'T1189', techniqueName: 'Drive-by Compromise', tactic: 'Initial Access' }],
  'SEC-023': [{ techniqueId: 'T1189', techniqueName: 'Drive-by Compromise', tactic: 'Initial Access' }],

  'SEC-007': [{ techniqueId: 'T1505.003', techniqueName: 'Web Shell', tactic: 'Persistence' }],
  'SEC-051': [{ techniqueId: 'T1505.003', techniqueName: 'Web Shell', tactic: 'Persistence' }],
  'SEC-052': [{ techniqueId: 'T1505.003', techniqueName: 'Web Shell', tactic: 'Persistence' }],
  'SEC-053': [{ techniqueId: 'T1505.003', techniqueName: 'Web Shell', tactic: 'Persistence' }],
  'SEC-054': [{ techniqueId: 'T1505.003', techniqueName: 'Web Shell', tactic: 'Persistence' }],
  'SEC-055': [{ techniqueId: 'T1505.003', techniqueName: 'Web Shell', tactic: 'Persistence' }],

  'SEC-004': [
    { techniqueId: 'T1505.003', techniqueName: 'Web Shell', tactic: 'Persistence' },
    { techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter', tactic: 'Execution' }
  ],
  'SEC-060': [{ techniqueId: 'T1505.003', techniqueName: 'Web Shell', tactic: 'Persistence' }],

  'SEC-011': [{ techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application', tactic: 'Initial Access' }],
  'SEC-050': [{ techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application', tactic: 'Initial Access' }],
  'SEC-066': [{ techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application', tactic: 'Initial Access' }],
  'SEC-067': [{ techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application', tactic: 'Initial Access' }],

  'SEC-027': [{ techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application', tactic: 'Initial Access' }],

  'SEC-012': [{ techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter', tactic: 'Execution' }],
  'SEC-028': [{ techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter', tactic: 'Execution' }],
  'SEC-040': [{ techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter', tactic: 'Execution' }],

  'SEC-008': [{ techniqueId: 'T1078', techniqueName: 'Valid Accounts', tactic: 'Privilege Escalation' }],
  'SEC-048': [{ techniqueId: 'T1078.001', techniqueName: 'Default Accounts', tactic: 'Privilege Escalation' }],

  'SEC-009': [{ techniqueId: 'T1048', techniqueName: 'Exfiltration Over Alternative Protocol', tactic: 'Exfiltration' }],
  'SEC-085': [{ techniqueId: 'T1048', techniqueName: 'Exfiltration Over Alternative Protocol', tactic: 'Exfiltration' }],

  'SEC-018': [{ techniqueId: 'T1552', techniqueName: 'Unsecured Credentials', tactic: 'Credential Access' }],
  'SEC-038': [{ techniqueId: 'T1552', techniqueName: 'Unsecured Credentials', tactic: 'Credential Access' }],
  'SEC-071': [{ techniqueId: 'T1552.004', techniqueName: 'Private Keys', tactic: 'Credential Access' }],
  'SEC-077': [{ techniqueId: 'T1552', techniqueName: 'Unsecured Credentials', tactic: 'Credential Access' }],

  'SEC-065': [{ techniqueId: 'T1021', techniqueName: 'Remote Services', tactic: 'Lateral Movement' }],
  'EXT-013': [{ techniqueId: 'T1071', techniqueName: 'Application Layer Protocol', tactic: 'Command and Control' }],

  'WP-012': [{ techniqueId: 'T1053.005', techniqueName: 'Scheduled Task/Job: Scheduled Task', tactic: 'Persistence' }],
  'WP-013': [{ techniqueId: 'T1053.005', techniqueName: 'Scheduled Task/Job: Scheduled Task', tactic: 'Persistence' }],
  'WP-009': [{ techniqueId: 'T1484', techniqueName: 'Domain Policy Modification', tactic: 'Defense Evasion' }],
  'WP-015': [{ techniqueId: 'T1078', techniqueName: 'Valid Accounts', tactic: 'Privilege Escalation' }],

  'EVD-001': [{ techniqueId: 'T1036', techniqueName: 'Masquerading', tactic: 'Defense Evasion' }],
  'EVD-002': [{ techniqueId: 'T1036', techniqueName: 'Masquerading', tactic: 'Defense Evasion' }],
  'EVD-003': [{ techniqueId: 'T1497', techniqueName: 'Virtualization/Sandbox Evasion', tactic: 'Defense Evasion' }],
  'EVD-004': [{ techniqueId: 'T1036', techniqueName: 'Masquerading', tactic: 'Defense Evasion' }],
  'EVD-005': [{ techniqueId: 'T1036', techniqueName: 'Masquerading', tactic: 'Defense Evasion' }],

  'SPM': [{ techniqueId: 'T1565.002', techniqueName: 'Transmitted Data Manipulation: Stored Data Manipulation', tactic: 'Impact' }],

  'JS-001': [{ techniqueId: 'T1189', techniqueName: 'Drive-by Compromise', tactic: 'Initial Access' }],
  'JS-002': [{ techniqueId: 'T1059.007', techniqueName: 'JavaScript', tactic: 'Execution' }],
  'JS-003': [{ techniqueId: 'T1496', techniqueName: 'Resource Hijacking', tactic: 'Impact' }],
  'JS-004': [{ techniqueId: 'T1056.001', techniqueName: 'Input Capture: Keylogging', tactic: 'Collection' }],
  'JS-005': [{ techniqueId: 'T1565', techniqueName: 'Transmitted Data Manipulation', tactic: 'Impact' }],

  'SUP': [{ techniqueId: 'T1195.002', techniqueName: 'Supply Chain Compromise: Compromise Software Supply Chain', tactic: 'Supply Chain Compromise' }],

  'INT': [{ techniqueId: 'T1565', techniqueName: 'Transmitted Data Manipulation', tactic: 'Impact' }],

  'SEC-086': [{ techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application', tactic: 'Initial Access' }],

  'HARD-015': [{ techniqueId: 'T1552.001', techniqueName: 'Credentials In Files', tactic: 'Credential Access' }],
  'HARD-022': [{ techniqueId: 'T1552.001', techniqueName: 'Credentials In Files', tactic: 'Credential Access' }],
  'HARD-023': [{ techniqueId: 'T1592', techniqueName: 'Gather Victim Host Information', tactic: 'Reconnaissance' }],
};

const SEVERITY_CONFIDENCE: Record<string, number> = {
  critical: 95,
  high: 80,
  medium: 60,
  low: 40,
  info: 20,
};

const TECHNIQUE_DESCRIPTIONS: Record<string, string> = {
  'T1027': 'Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit.',
  'T1059': 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.',
  'T1059.004': 'Adversaries may abuse Unix shell commands and scripts to execute commands, programs, or scripts.',
  'T1059.007': 'Adversaries may abuse JavaScript commands and scripts to execute commands, scripts, or binaries.',
  'T1189': 'Adversaries may gain access to a system through a user visiting a website over the normal course of browsing.',
  'T1190': 'Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.',
  'T1505.003': 'Adversaries may backdoor web servers with web shells to establish persistent access to systems.',
  'T1048': 'Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel.',
  'T1552': 'Adversaries may search compromised systems to find and obtain insecurely stored credentials.',
  'T1552.001': 'Adversaries may search local file systems and remote file shares for files containing passwords.',
  'T1552.004': 'Adversaries may search for private keys to use for credential access or data decryption.',
  'T1021': 'Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections, such as telnet, SSH, and VNC.',
  'T1071': 'Adversaries may communicate using application layer protocols to avoid detection and network filtering.',
  'T1053.005': 'Adversaries may abuse the Windows Task Scheduler to perform initial system execution, code execution, or persistence.',
  'T1484': 'Adversaries may modify the configuration settings of a domain to evade defenses and/or escalate privileges.',
  'T1078': 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.',
  'T1078.001': 'Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.',
  'T1036': 'Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools.',
  'T1497': 'Adversaries may employ means to detect and avoid virtualization and analysis environments.',
  'T1565.002': 'Adversaries may insert, delete, or alter data at rest within a storage system to prevent its intended use or to manipulate the results of forensic analysis.',
  'T1565': 'Adversaries may intercept data in transit from a compromised system to manipulate it before exfiltration.',
  'T1496': 'Adversaries may leverage the resources of co-opted systems to complete resource-intensive tasks, such as cryptocurrency mining.',
  'T1056.001': 'Adversaries may log user keystrokes to capture credentials as users type them.',
  'T1195.002': 'Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.',
  'T1592': 'Adversaries may gather information about the victim\'s hosts that can be used during targeting.',
};

function lookupTechniques(checkId: string): { techniqueId: string; techniqueName: string; tactic: string }[] {
  if (MITRE_MAP[checkId]) {
    return MITRE_MAP[checkId];
  }
  for (const prefix of Object.keys(MITRE_MAP)) {
    if (checkId.startsWith(prefix) && checkId.length > prefix.length) {
      return MITRE_MAP[prefix];
    }
  }
  return [];
}

export function mapFindingsToMitre(results: CheckResult[]): MitreResult {
  const techniqueMap = new Map<
    string,
    { techniqueId: string; techniqueName: string; tactic: string; findingCount: number; files: Set<string>; severity: string; confidenceSum: number; count: number }
  >();
  const tacticCounts = new Map<string, number>();
  let totalMappedFindings = 0;
  let totalFindings = 0;

  for (const result of results) {
    const techniques = lookupTechniques(result.checkId);
    if (techniques.length === 0) {
      totalFindings += result.findings.length;
      continue;
    }

    for (const finding of result.findings) {
      totalMappedFindings++;
      for (const tech of techniques) {
        const key = `${tech.techniqueId}:${tech.tactic}`;
        if (!techniqueMap.has(key)) {
          techniqueMap.set(key, {
            techniqueId: tech.techniqueId,
            techniqueName: tech.techniqueName,
            tactic: tech.tactic,
            findingCount: 0,
            files: new Set<string>(),
            severity: result.severity,
            confidenceSum: 0,
            count: 0,
          });
        }
        const entry = techniqueMap.get(key)!;
        entry.findingCount++;
        entry.files.add(finding.file);
        entry.confidenceSum += SEVERITY_CONFIDENCE[result.severity] || 50;
        entry.count++;
        if (severityRank(result.severity) > severityRank(entry.severity)) {
          entry.severity = result.severity;
        }
      }
      tacticCounts.set(result.severity, (tacticCounts.get(result.severity) || 0) + 1);
      totalFindings++;
    }
  }

  const tacticCountMap = new Map<string, number>();
  const mappings: MitreMapping[] = [];
  for (const entry of techniqueMap.values()) {
    const confidence = entry.count > 0 ? Math.round(entry.confidenceSum / entry.count) : 50;
    mappings.push({
      techniqueId: entry.techniqueId,
      techniqueName: entry.techniqueName,
      tactic: entry.tactic,
      findingCount: entry.findingCount,
      files: Array.from(entry.files),
      severity: entry.severity,
      confidence,
    });
    tacticCountMap.set(entry.tactic, (tacticCountMap.get(entry.tactic) || 0) + entry.findingCount);
  }

  const allPossibleTechniques = new Set<string>();
  for (const techs of Object.values(MITRE_MAP)) {
    for (const tech of techs) {
      allPossibleTechniques.add(tech.techniqueId);
    }
  }
  const uniqueFoundTechniques = new Set(mappings.map(m => m.techniqueId));
  const coverageScore = allPossibleTechniques.size > 0
    ? Math.round((uniqueFoundTechniques.size / allPossibleTechniques.size) * 100)
    : 0;

  const topTactics = Array.from(tacticCountMap.entries())
    .map(([tactic, count]) => ({ tactic, count }))
    .sort((a, b) => b.count - a.count);

  mappings.sort((a, b) => b.findingCount - a.findingCount);

  return {
    mappings,
    coverageScore,
    topTactics,
    totalMappedFindings,
  };
}

function severityRank(sev: string): number {
  switch (sev) {
    case 'critical': return 5;
    case 'high': return 4;
    case 'medium': return 3;
    case 'low': return 2;
    case 'info': return 1;
    default: return 0;
  }
}

export function getMitreDescription(techniqueId: string): string {
  return TECHNIQUE_DESCRIPTIONS[techniqueId] || `MITRE ATT&CK technique ${techniqueId}. No description available.`;
}
