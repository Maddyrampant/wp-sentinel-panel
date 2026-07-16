import { ScanSummary, Finding, Severity } from './types';

export type RemediationCategory = 'containment' | 'investigation' | 'remediation' | 'recovery' | 'hardening';
export type Urgency = 'immediate' | 'within_hours' | 'within_days' | 'when_convenient';
export type CompromiseStatus = 'clean' | 'suspicious' | 'likely_compromised' | 'confirmed_compromised';

export interface RemediationStep {
  order: number;
  category: RemediationCategory;
  severity: Severity;
  action: string;
  details: string;
  affectedFiles?: string[];
  affectedDbTables?: string[];
  estimatedTime: string;
}

export interface RemediationPlan {
  scanId: string;
  overallStatus: CompromiseStatus;
  confidence: number;
  urgency: Urgency;
  steps: RemediationStep[];
  summary: string;
}

let stepCounter = 0;

function addStep(
  steps: RemediationStep[],
  category: RemediationCategory,
  severity: Severity,
  action: string,
  details: string,
  affectedFiles?: string[],
  estimatedTime: string = '5 min'
): void {
  steps.push({
    order: ++stepCounter,
    category,
    severity,
    action,
    details,
    affectedFiles,
    estimatedTime,
  });
}

export function generateRemediationPlan(summary: ScanSummary): RemediationPlan {
  stepCounter = 0;
  const steps: RemediationStep[] = [];
  const allFindings: Finding[] = [];
  for (const result of summary.results) {
    allFindings.push(...result.findings);
  }

  const hasWebshell = allFindings.some(f => /webshell|shell/i.test(f.message) || /webshell/i.test(f.details));
  const hasBackdoor = allFindings.some(f => /backdoor/i.test(f.message) || /backdoor/i.test(f.details));
  const hasMalware = allFindings.some(f => /malware|virus|trojan/i.test(f.message));
  const hasSpam = allFindings.some(f => /spam|seo|casino|viagra/i.test(f.message));
  const hasRogueAdmin = allFindings.some(f => /admin.*creat|unknown.*admin|rogue.*admin/i.test(f.message));
  const hasCoreModified = allFindings.some(f => /core.*modified|wp-admin|wp-includes/i.test(f.message) && /modified|changed|unexpected/i.test(f.details));
  const hasExternalDomains = allFindings.some(f => /external.*domain|remote.*request/i.test(f.message));
  const hasEval = allFindings.some(f => /eval\s*\(/i.test(f.code));
  const hasFileWrite = allFindings.some(f => /file_put_contents|fwrite/i.test(f.code));
  const hasObfuscation = allFindings.some(f => /obfuscat|base64_decode.*eval|encoded/i.test(f.message));

  const criticalCount = allFindings.filter(f => f.message.includes('critical') || /webshell|backdoor|remote code/i.test(f.message)).length;
  const highCount = allFindings.filter(f => /high|eval|system|exec|file_put/i.test(f.message)).length;

  let status: CompromiseStatus = 'clean';
  let confidence = 95;
  let urgency: Urgency = 'when_convenient';

  if (hasWebshell) { status = 'confirmed_compromised'; confidence = 98; urgency = 'immediate'; }
  else if (hasBackdoor && hasExternalDomains) { status = 'confirmed_compromised'; confidence = 92; urgency = 'immediate'; }
  else if (hasEval && hasFileWrite) { status = 'confirmed_compromised'; confidence = 88; urgency = 'immediate'; }
  else if (hasMalware) { status = 'likely_compromised'; confidence = 80; urgency = 'within_hours'; }
  else if (hasRogueAdmin || hasCoreModified) { status = 'likely_compromised'; confidence = 75; urgency = 'within_hours'; }
  else if (hasObfuscation || highCount > 3) { status = 'suspicious'; confidence = 65; urgency = 'within_days'; }
  else if (allFindings.length > 0) { status = 'suspicious'; confidence = 50; urgency = 'within_days'; }

  if (status === 'confirmed_compromised' || status === 'likely_compromised') {
    addStep(steps, 'containment', 'critical', 'Set site to maintenance mode', 'Enable WordPress maintenance mode to prevent further damage and protect visitors. Add define("WP_MAINTENANCE_MODE", true); to wp-config.php or create .maintenance file.', undefined, '2 min');
  }

  const webshellFiles = allFindings.filter(f => /webshell|shell|backdoor/i.test(f.message)).map(f => f.file);
  if (webshellFiles.length > 0) {
    addStep(steps, 'containment', 'critical', 'Quarantine detected shells/backdoors', `Found ${webshellFiles.length} suspicious file(s). Move them to quarantine immediately.`, [...new Set(webshellFiles)], '5 min');
  }

  if (hasCoreModified) {
    addStep(steps, 'containment', 'critical', 'Restore WordPress core files', 'WordPress core files have been modified. Download clean copy from wordpress.org and replace wp-admin and wp-includes.', ['wp-admin/*', 'wp-includes/*'], '15 min');
  }

  if (hasRogueAdmin) {
    addStep(steps, 'containment', 'critical', 'Remove unauthorized admin accounts', 'Unknown administrator accounts detected. Review wp_users table and remove any unauthorized accounts.', undefined, '10 min');
  }

  addStep(steps, 'investigation', 'high', 'Change all passwords', 'Change WordPress admin password, database password, FTP/SFTP password, and hosting panel password. Use strong, unique passwords for each.', undefined, '15 min');

  addStep(steps, 'investigation', 'high', 'Review database for injection', 'Check wp_options for injected scripts, suspicious autoload values, and modified siteurl/home options.', ['wp_options', 'wp_posts', 'wp_users'], '20 min');

  if (hasExternalDomains) {
    addStep(steps, 'investigation', 'medium', 'Review external domain connections', 'Analyze all external domains contacted by the site. Block malicious domains in firewall/hosts file.', undefined, '10 min');
  }

  if (hasObfuscation) {
    addStep(steps, 'remediation', 'high', 'Deobfuscate and analyze payloads', 'Run safe deobfuscation on all encoded content to reveal hidden malicious code. Analyze extracted URLs and payloads.', undefined, '15 min');
  }

  if (hasSpam) {
    addStep(steps, 'remediation', 'high', 'Clean spam injections', 'Remove SEO spam, hidden links, and injected content from posts, pages, and theme files.', undefined, '20 min');
  }

  const evalFiles = allFindings.filter(f => /eval\s*\(/i.test(f.code)).map(f => f.file);
  if (evalFiles.length > 0) {
    addStep(steps, 'remediation', 'high', 'Remove eval-based code', `Found eval() usage in ${evalFiles.length} file(s). Remove or refactor all eval() calls.`, [...new Set(evalFiles)], '10 min');
  }

  addStep(steps, 'recovery', 'high', 'Update WordPress, themes, and plugins', 'Update WordPress core, all themes, and all plugins to latest versions. Remove any unused themes/plugins.', undefined, '30 min');

  addStep(steps, 'recovery', 'medium', 'Restore from clean backup', 'If available, restore from a known clean backup made before the suspected compromise date.', undefined, '20 min');

  addStep(steps, 'hardening', 'medium', 'Enable two-factor authentication', 'Install and enable 2FA for all admin accounts. Use a TOTP authenticator app.', undefined, '10 min');

  addStep(steps, 'hardening', 'medium', 'Install security plugin', 'Install Wordfence, Sucuri, or iThemes Security. Configure firewall and malware scanning.', undefined, '15 min');

  addStep(steps, 'hardening', 'low', 'Review file permissions', 'Ensure wp-config.php is 400/440, wp-content is 755, and all PHP files are 644. Remove write permissions where not needed.', undefined, '10 min');

  addStep(steps, 'hardening', 'low', 'Disable file editing in dashboard', 'Add define("DISALLOW_FILE_EDIT", true); to wp-config.php to prevent theme/plugin editing from dashboard.', undefined, '2 min');

  const summaryText = status === 'clean'
    ? 'No significant issues found. Site appears clean.'
    : `Site is ${status.replace(/_/g, ' ')}. ${steps.length} remediation steps generated. Estimated total time: ~${Math.round(steps.reduce((acc, s) => acc + parseInt(s.estimatedTime) || 5, 0))} minutes.`;

  return {
    scanId: summary.id,
    overallStatus: status,
    confidence,
    urgency,
    steps,
    summary: summaryText,
  };
}
