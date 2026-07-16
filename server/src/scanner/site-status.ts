import { ScanSummary, Finding, Severity } from '../types';
import { AttackChain } from './attack-chain';

export type CompromiseStatus = 'clean' | 'suspicious' | 'likely_compromised' | 'confirmed_compromised';

export interface SiteStatus {
  status: CompromiseStatus;
  confidence: number;
  mainReasons: string[];
  details: {
    hasWebshell: boolean;
    hasBackdoor: boolean;
    hasMalware: boolean;
    hasNulled: boolean;
    hasSpam: boolean;
    hasRogueAdmin: boolean;
    hasCoreModification: boolean;
    hasSuspiciousExternalDomains: boolean;
    hasAttackChain: boolean;
    hasDatabaseInfection: boolean;
    hasObfuscation: boolean;
    hasEval: boolean;
    hasFileWrite: boolean;
    hasEvalBase64: boolean;
    hasRemoteCodeExecution: boolean;
  };
  score: number;
}

export function calculateSiteStatus(
  summary: ScanSummary,
  attackChains: AttackChain[] = []
): SiteStatus {
  const allFindings: Finding[] = [];
  for (const result of summary.results) {
    allFindings.push(...result.findings);
  }

  const details = {
    hasWebshell: allFindings.some(f => /webshell|shell\.php|cmd\.php/i.test(f.message + f.code + f.details)),
    hasBackdoor: allFindings.some(f => /backdoor|hidden.*admin|secret.*access/i.test(f.message + f.details)),
    hasMalware: allFindings.some(f => /malware|virus|trojan|ransomware/i.test(f.message)),
    hasNulled: allFindings.some(f => /nulled|cracked|warez|pirated|license bypass/i.test(f.message + f.details)),
    hasSpam: allFindings.some(f => /spam|seo.*inject|casino|viagra|hidden.*link|pharmacy/i.test(f.message + f.details)),
    hasRogueAdmin: allFindings.some(f => /admin.*creat|unknown.*admin|rogue.*admin|unauthorized.*account/i.test(f.message + f.details)),
    hasCoreModification: allFindings.some(f => /core.*modified|wp-admin.*modified|wp-includes.*modified|unexpected.*core/i.test(f.message + f.details)),
    hasSuspiciousExternalDomains: allFindings.some(f => /external.*domain|suspicious.*domain|remote.*request/i.test(f.message)),
    hasAttackChain: attackChains.length > 0,
    hasDatabaseInfection: allFindings.some(f => /database|wp_options|injection.*sql/i.test(f.message)),
    hasObfuscation: allFindings.some(f => /obfuscat|base64_decode.*eval|encoded.*string/i.test(f.message + f.code)),
    hasEval: allFindings.some(f => /\beval\s*\(/i.test(f.code)),
    hasFileWrite: allFindings.some(f => /file_put_contents|fwrite|move_uploaded/i.test(f.code)),
    hasEvalBase64: allFindings.some(f => /eval\s*\(\s*base64_decode/i.test(f.code)),
    hasRemoteCodeExecution: allFindings.some(f => /exec\s*\(|system\s*\(|passthru|shell_exec|proc_open/i.test(f.code)),
  };

  let score = 0;
  const reasons: string[] = [];

  if (details.hasWebshell) { score += 40; reasons.push('PHP webshell detected'); }
  if (details.hasBackdoor) { score += 30; reasons.push('Backdoor access mechanism found'); }
  if (details.hasRemoteCodeExecution) { score += 25; reasons.push('Remote code execution capability'); }
  if (details.hasAttackChain) { score += 25; reasons.push('Attack chain detected'); }
  if (details.hasEvalBase64) { score += 15; reasons.push('Obfuscated eval+base64 payload'); }
  if (details.hasCoreModification) { score += 20; reasons.push('WordPress core files modified'); }
  if (details.hasRogueAdmin) { score += 20; reasons.push('Unauthorized admin accounts'); }
  if (details.hasMalware) { score += 15; reasons.push('Malware signatures detected'); }
  if (details.hasDatabaseInfection) { score += 15; reasons.push('Database infection detected'); }
  if (details.hasFileWrite) { score += 10; reasons.push('File write operations detected'); }
  if (details.hasSuspiciousExternalDomains) { score += 10; reasons.push('Suspicious external connections'); }
  if (details.hasNulled) { score += 10; reasons.push('Nulled/pirated theme indicators'); }
  if (details.hasObfuscation) { score += 10; reasons.push('Obfuscated code detected'); }
  if (details.hasEval) { score += 8; reasons.push('eval() usage detected'); }
  if (details.hasSpam) { score += 8; reasons.push('SEO spam injection detected'); }

  score = Math.min(score, 100);

  let status: CompromiseStatus;
  let confidence: number;

  if (score >= 80) {
    status = 'confirmed_compromised';
    confidence = Math.min(95 + Math.floor(score / 20), 99);
  } else if (score >= 50) {
    status = 'likely_compromised';
    confidence = 70 + Math.floor(score / 10);
  } else if (score >= 20) {
    status = 'suspicious';
    confidence = 50 + Math.floor(score / 5);
  } else {
    status = 'clean';
    confidence = Math.max(90 - score, 60);
  }

  return {
    status,
    confidence,
    mainReasons: reasons.slice(0, 5),
    details,
    score,
  };
}
