const SEVERITY_BASE: Record<string, number> = {
  critical: 90,
  high: 70,
  medium: 45,
  low: 20,
  info: 5,
};

interface ScoreResult {
  score: number;
  appliedModifiers: string[];
}

export function calculateRiskScore(
  severity: string,
  filePath: string,
  matchedLine: string,
  fileMtime: Date,
  ruleModifiers: Record<string, number> = {}
): ScoreResult {
  let score = SEVERITY_BASE[severity] || 45;
  const appliedModifiers: string[] = [];

  // Context-based modifiers
  const lowerPath = filePath.toLowerCase();
  const lowerLine = matchedLine.toLowerCase();

  if (/\$_(GET|POST|REQUEST|COOKIE|SERVER)/.test(matchedLine)) {
    score += 20;
    appliedModifiers.push('request_input_used');
  }

  if (lowerPath.includes('wp-content/uploads/')) {
    score += 25;
    appliedModifiers.push('in_uploads_directory');
  }

  if (lowerPath.includes('wp-config.php')) {
    score += 25;
    appliedModifiers.push('in_wp_config');
  }

  if (/base64_decode|gzinflate|gzuncompress|str_rot13/.test(matchedLine)) {
    score += 20;
    appliedModifiers.push('obfuscated_payload');
  }

  if (lowerPath.startsWith('wp-admin/') || lowerPath.startsWith('wp-includes/')) {
    score += 30;
    appliedModifiers.push('known_core_file_modified');
  }

  const now = Date.now();
  const age = now - fileMtime.getTime();
  if (age < 604800000) { // 7 days
    score += 10;
    appliedModifiers.push('recent_file_change');
  }

  // Apply custom rule modifiers
  for (const [key, value] of Object.entries(ruleModifiers)) {
    if (typeof value === 'number') {
      score += value;
      appliedModifiers.push(key);
    }
  }

  return { score: Math.min(score, 100), appliedModifiers };
}

export function getSeverityFromScore(score: number): string {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 35) return 'medium';
  if (score >= 15) return 'low';
  return 'info';
}
