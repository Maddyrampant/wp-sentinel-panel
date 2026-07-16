export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type CheckCategory =
  | 'obfuscation'
  | 'external-access'
  | 'security'
  | 'code-pattern'
  | 'file-analysis'
  | 'wordpress';

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
  status: 'running' | 'completed' | 'error';
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
  source_type: 'path' | 'upload';
  source_path: string;
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

export interface ThemeScanRecord {
  id: string;
  themes_path: string;
  results_json: string;
  created_at: string;
}
