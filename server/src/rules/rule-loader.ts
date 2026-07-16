import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { type CustomRule } from '../db/database';

type RuleWithoutTimestamps = Omit<CustomRule, 'createdAt' | 'updatedAt'>;

interface RawRule {
  id: string;
  title: string;
  severity: string;
  category: string;
  confidence?: string;
  file_types?: string[];
  patterns?: string[];
  path_patterns?: string[];
  target_files?: string[];
  description?: string;
  recommendation?: string;
  tags?: string[];
  check_type?: string;
  scope?: string[];
}

interface RawRuleset {
  ruleset: { name: string; version: string; target: string; description: string };
  rules: RawRule[];
}

function mapRawToRule(rule: RawRule, isBuiltin: boolean): RuleWithoutTimestamps {
  const filePattern = rule.file_types
    ? rule.file_types.map(ft => ft.startsWith('.') ? ft : `.${ft}`).join(',')
    : '*';

  const patterns = rule.patterns || [];
  const pathPatterns = rule.path_patterns || [];
  const targetFiles = rule.target_files || [];
  const tags = rule.tags || [];

  return {
    id: rule.id,
    name: rule.title,
    description: rule.description || '',
    pattern: patterns[0] || '',
    patterns,
    pathPatterns,
    targetFiles,
    isRegex: true,
    severity: rule.severity || 'medium',
    category: rule.category || 'security',
    confidence: rule.confidence || 'medium',
    recommendation: rule.recommendation || '',
    tags,
    isBuiltin,
    checkType: rule.check_type || 'pattern',
    scoringModifiers: {},
    filePattern,
    enabled: true,
  };
}

export function loadBuiltinRules(): RuleWithoutTimestamps[] {
  const yamlPath = path.join(__dirname, 'wp-compromise-rules.yaml');
  try {
    const content = fs.readFileSync(yamlPath, 'utf-8');
    const parsed = yaml.load(content) as RawRuleset;
    if (!parsed?.rules) return [];
    return parsed.rules.map(rule => mapRawToRule(rule, true));
  } catch (err) {
    console.error('Failed to load builtin rules:', err);
    return [];
  }
}

export function parseYamlRules(yamlContent: string): RuleWithoutTimestamps[] {
  const parsed = yaml.load(yamlContent) as RawRuleset;
  if (!parsed?.rules) return [];
  return parsed.rules.map(rule => mapRawToRule(rule, false));
}

export function exportRulesToYaml(rules: CustomRule[]): string {
  const ruleset = {
    ruleset: {
      name: 'wp-sentinel-exported-rules',
      version: '1.0.0',
      target: 'wordpress',
      description: 'Exported custom rules from WP-Sentinel',
    },
    rules: rules.filter(r => !r.isBuiltin).map(rule => ({
      id: rule.id,
      title: rule.name,
      severity: rule.severity,
      category: rule.category,
      confidence: rule.confidence,
      file_types: rule.filePattern !== '*' ? rule.filePattern.split(',').map(f => f.replace('.', '')) : undefined,
      patterns: rule.patterns.length > 0 ? rule.patterns : [rule.pattern],
      path_patterns: rule.pathPatterns.length > 0 ? rule.pathPatterns : undefined,
      target_files: rule.targetFiles.length > 0 ? rule.targetFiles : undefined,
      description: rule.description,
      recommendation: rule.recommendation,
      tags: rule.tags.length > 0 ? rule.tags : undefined,
    })),
  };
  return yaml.dump(ruleset, { lineWidth: 120, noRefs: true });
}
