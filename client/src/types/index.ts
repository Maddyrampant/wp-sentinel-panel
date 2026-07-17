export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type CheckCategory =
  | 'obfuscation'
  | 'external-access'
  | 'security'
  | 'code-pattern'
  | 'file-analysis'
  | 'wordpress'
  | 'evasion'
  | 'supply-chain'
  | 'spam'
  | 'js-malware'
  | 'integrity'
  | 'plugin'
  | 'hardening'
  | 'database';

export interface Finding {
  file: string;
  line: number;
  column: number;
  code: string;
  message: string;
  details: string;
  context?: string;
  riskScore?: number;
  confidence?: string;
  recommendation?: string;
  tags?: string[];
  ruleId?: string;
}

export interface CheckResult {
  checkId: string;
  checkName: string;
  category: CheckCategory;
  severity: Severity;
  description: string;
  findings: Finding[];
}

export interface ScanSummary {
  id: string;
  targetName: string;
  scanDate: string;
  duration: number;
  totalFiles: number;
  phpFiles: number;
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<CheckCategory, number>;
  results: CheckResult[];
  status: string;
}

export interface ScanHistoryItem {
  id: string;
  target_name: string;
  scan_date: string;
  duration: number;
  total_files: number;
  php_files: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  status: string;
}

export interface DashboardStats {
  totalScans: number;
  totalFindings: number;
  totalFiles: number;
  totalPhpFiles: number;
  avgDuration: number;
  criticalTotal: number;
  highTotal: number;
  mediumTotal: number;
  lowTotal: number;
  infoTotal: number;
}

export interface CustomRule {
  id: string;
  name: string;
  description: string;
  pattern: string;
  patterns: string[];
  pathPatterns: string[];
  targetFiles: string[];
  isRegex: boolean;
  severity: string;
  category: string;
  confidence: string;
  recommendation: string;
  tags: string[];
  isBuiltin: boolean;
  checkType: string;
  scoringModifiers: Record<string, number>;
  filePattern: string;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface TrendDataPoint {
  date: string;
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

// Theme Intelligence types
export type ThemeFindingType =
  | 'malware'
  | 'backdoor'
  | 'nulled'
  | 'external_domain'
  | 'base64_payload'
  | 'suspicious_pattern';

export type ThemeRiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'clean';

export interface ThemeFinding {
  id: string;
  file: string;
  line: number;
  column?: number;
  type: ThemeFindingType;
  severity: ThemeRiskLevel;
  message: string;
  matchedText: string;
  confidence: number;
  recommendation?: string;
}

export interface ExternalDomain {
  domain: string;
  urls: string[];
  files: Array<{ file: string; line: number }>;
  isSuspicious: boolean;
}

export interface Base64Decoded {
  file: string;
  line: number;
  decoded: string;
  extractedUrls: string[];
  extractedDomains: string[];
}

export interface ThemeIntelResult {
  themeName: string;
  themePath: string;
  styleMetadata?: {
    name?: string;
    version?: string;
    author?: string;
    description?: string;
    textDomain?: string;
  };
  externalDomains: ExternalDomain[];
  nulledIndicators: ThemeFinding[];
  malwarePatterns: ThemeFinding[];
  base64Decoded: Base64Decoded[];
  riskScore: number;
  riskLevel: ThemeRiskLevel;
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface ThemeScanResult {
  id: string;
  themesPath: string;
  results: ThemeIntelResult[];
  duration: number;
  createdAt: string;
}

export interface ThemeScanHistoryItem {
  id: string;
  themes_path: string;
  duration: number;
  themes_count: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  created_at: string;
}

// Attack Chain types
export interface AttackChainLink {
  type: string;
  finding: Finding;
  file: string;
  line: number;
  description: string;
}

export interface AttackChain {
  id: string;
  severity: Severity;
  confidence: number;
  chainType: string;
  links: AttackChainLink[];
  files: string[];
  riskScore: number;
  recommendation: string;
}

// Timeline types
export interface TimelineEvent {
  id: string;
  timestamp: string;
  type: string;
  file?: string;
  severity: Severity;
  description: string;
  relatedFindingIds: string[];
}

// Database Scan types
export interface DatabaseFinding {
  id: string;
  check: string;
  table: string;
  column: string;
  rowId?: number;
  severity: Severity;
  message: string;
  matchedValue: string;
  recommendation: string;
}

export interface DatabaseScanResult {
  id: string;
  config: { host: string; database: string; tablePrefix: string };
  connected: boolean;
  findings: DatabaseFinding[];
  summary: { total: number; critical: number; high: number; medium: number; low: number };
  duration: number;
  createdAt: string;
}

// Quarantine types
export interface QuarantineRecord {
  id: string;
  originalPath: string;
  quarantinePath: string;
  sha256: string;
  fileSize: number;
  quarantinedAt: string;
  reason: string;
  scanId: string;
  findingId: string;
  restored: boolean;
  restoredAt?: string;
}

// Remediation types
export interface RemediationStep {
  order: number;
  category: string;
  severity: Severity;
  action: string;
  details: string;
  affectedFiles?: string[];
  affectedDbTables?: string[];
  estimatedTime: string;
}

export interface RemediationPlan {
  scanId: string;
  overallStatus: string;
  confidence: number;
  urgency: string;
  steps: RemediationStep[];
  summary: string;
}

// False Positive types
export interface FalsePositive {
  id: string;
  ruleId: string;
  scope: string;
  theme?: string;
  plugin?: string;
  filePath?: string;
  fileHash?: string;
  reason: string;
  createdBy: string;
  createdAt: string;
  active: boolean;
}

// Site Status types
export interface SiteStatus {
  status: string;
  confidence: number;
  mainReasons: string[];
  details: Record<string, boolean>;
  score: number;
}

// Domain Inventory types
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
}

// Hardening Check types
export interface HardeningCheckItem {
  id: string;
  name: string;
  category: string;
  status: 'pass' | 'fail' | 'warning' | 'info';
  severity: Severity;
  message: string;
  details: string;
  recommendation: string;
  reference?: string;
}

export interface HardeningResult {
  targetPath: string;
  totalChecks: number;
  passed: number;
  failed: number;
  warnings: number;
  score: number;
  checks: HardeningCheckItem[];
  scanDate: string;
  duration: number;
}

// Plugin Intel types
export interface PluginFinding {
  id: string;
  file: string;
  line: number;
  column?: number;
  type: string;
  severity: Severity;
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
  riskLevel: string;
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

// Checksum Verify types
export interface ChecksumFile {
  file: string;
  md5: string;
  status: 'match' | 'mismatch' | 'missing_local' | 'missing_remote' | 'extra_local';
  severity: Severity;
}

export interface ChecksumResult {
  id: string;
  targetPath: string;
  wpVersion?: string;
  totalFiles: number;
  matched: number;
  mismatched: number;
  extraLocal: number;
  missingLocal: number;
  files: ChecksumFile[];
  scanDate: string;
  duration: number;
}

// MITRE ATT&CK types
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
