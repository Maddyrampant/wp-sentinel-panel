import Database from 'better-sqlite3';
import * as path from 'path';
import { ScanHistoryItem, ScanSummary } from '../types';

const DB_PATH = path.join(__dirname, '..', '..', 'data', 'wp-sentinel.db');

let db: Database.Database;

export function initDatabase(): void {
  const fs = require('fs');
  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');

  db.exec(`
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      target_name TEXT NOT NULL,
      scan_date TEXT NOT NULL,
      duration INTEGER DEFAULT 0,
      total_files INTEGER DEFAULT 0,
      php_files INTEGER DEFAULT 0,
      total_findings INTEGER DEFAULT 0,
      critical_count INTEGER DEFAULT 0,
      high_count INTEGER DEFAULT 0,
      medium_count INTEGER DEFAULT 0,
      low_count INTEGER DEFAULT 0,
      info_count INTEGER DEFAULT 0,
      status TEXT DEFAULT 'running',
      source_type TEXT DEFAULT 'path',
      source_path TEXT DEFAULT '',
      results_json TEXT DEFAULT '[]'
    );

    CREATE TABLE IF NOT EXISTS custom_rules (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      pattern TEXT NOT NULL DEFAULT '',
      patterns TEXT DEFAULT '[]',
      path_patterns TEXT DEFAULT '[]',
      target_files TEXT DEFAULT '[]',
      is_regex INTEGER DEFAULT 1,
      severity TEXT DEFAULT 'medium',
      category TEXT DEFAULT 'security',
      confidence TEXT DEFAULT 'medium',
      recommendation TEXT DEFAULT '',
      tags TEXT DEFAULT '[]',
      is_builtin INTEGER DEFAULT 0,
      check_type TEXT DEFAULT 'pattern',
      scoring_modifiers TEXT DEFAULT '{}',
      file_pattern TEXT DEFAULT '*',
      enabled INTEGER DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS theme_scans (
      id TEXT PRIMARY KEY,
      themes_path TEXT NOT NULL,
      duration INTEGER DEFAULT 0,
      themes_count INTEGER DEFAULT 0,
      total_findings INTEGER DEFAULT 0,
      critical_count INTEGER DEFAULT 0,
      high_count INTEGER DEFAULT 0,
      medium_count INTEGER DEFAULT 0,
      low_count INTEGER DEFAULT 0,
      results_json TEXT DEFAULT '[]',
      created_at TEXT NOT NULL
    );
  `);

  // Migration: add new columns if they don't exist (SQLite ignores duplicate ADD COLUMN)
  const migrateCols = [
    `ALTER TABLE custom_rules ADD COLUMN patterns TEXT DEFAULT '[]'`,
    `ALTER TABLE custom_rules ADD COLUMN path_patterns TEXT DEFAULT '[]'`,
    `ALTER TABLE custom_rules ADD COLUMN target_files TEXT DEFAULT '[]'`,
    `ALTER TABLE custom_rules ADD COLUMN confidence TEXT DEFAULT 'medium'`,
    `ALTER TABLE custom_rules ADD COLUMN recommendation TEXT DEFAULT ''`,
    `ALTER TABLE custom_rules ADD COLUMN tags TEXT DEFAULT '[]'`,
    `ALTER TABLE custom_rules ADD COLUMN is_builtin INTEGER DEFAULT 0`,
    `ALTER TABLE custom_rules ADD COLUMN check_type TEXT DEFAULT 'pattern'`,
    `ALTER TABLE custom_rules ADD COLUMN scoring_modifiers TEXT DEFAULT '{}'`,
  ];
  for (const sql of migrateCols) { try { db.exec(sql); } catch {} }
}

export function saveScan(summary: ScanSummary): void {
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO scans
    (id, target_name, scan_date, duration, total_files, php_files, total_findings,
     critical_count, high_count, medium_count, low_count, info_count, status,
     source_type, source_path, results_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    summary.id,
    summary.targetName,
    summary.scanDate,
    summary.duration,
    summary.totalFiles,
    summary.phpFiles,
    summary.totalFindings,
    summary.bySeverity.critical,
    summary.bySeverity.high,
    summary.bySeverity.medium,
    summary.bySeverity.low,
    summary.bySeverity.info,
    summary.status,
    'path',
    summary.targetName,
    JSON.stringify(summary.results)
  );
}

export function updateScan(summary: ScanSummary): void {
  const stmt = db.prepare(`
    UPDATE scans SET
      duration = ?, total_files = ?, php_files = ?, total_findings = ?,
      critical_count = ?, high_count = ?, medium_count = ?, low_count = ?, info_count = ?,
      status = ?, results_json = ?
    WHERE id = ?
  `);

  stmt.run(
    summary.duration,
    summary.totalFiles,
    summary.phpFiles,
    summary.totalFindings,
    summary.bySeverity.critical,
    summary.bySeverity.high,
    summary.bySeverity.medium,
    summary.bySeverity.low,
    summary.bySeverity.info,
    summary.status,
    JSON.stringify(summary.results),
    summary.id
  );
}

export function getScan(id: string): ScanSummary | null {
  const row = db.prepare('SELECT * FROM scans WHERE id = ?').get(id) as any;
  if (!row) return null;

  return {
    id: row.id,
    targetName: row.target_name,
    scanDate: row.scan_date,
    duration: row.duration,
    totalFiles: row.total_files,
    phpFiles: row.php_files,
    totalFindings: row.total_findings,
    bySeverity: {
      critical: row.critical_count,
      high: row.high_count,
      medium: row.medium_count,
      low: row.low_count,
      info: row.info_count,
    },
    byCategory: JSON.parse(row.results_json || '[]').reduce(
      (acc: any, r: any) => {
        acc[r.category] = (acc[r.category] || 0) + (r.findings?.length || 0);
        return acc;
      },
      {}
    ),
    results: JSON.parse(row.results_json || '[]'),
    status: row.status,
  };
}

export function getHistory(limit = 50, offset = 0): ScanHistoryItem[] {
  const rows = db
    .prepare('SELECT * FROM scans ORDER BY scan_date DESC LIMIT ? OFFSET ?')
    .all(limit, offset) as any[];

  return rows.map((r) => ({
    id: r.id,
    target_name: r.target_name,
    scan_date: r.scan_date,
    duration: r.duration,
    total_files: r.total_files,
    php_files: r.php_files,
    total_findings: r.total_findings,
    critical_count: r.critical_count,
    high_count: r.high_count,
    medium_count: r.medium_count,
    low_count: r.low_count,
    info_count: r.info_count,
    status: r.status,
    source_type: r.source_type,
    source_path: r.source_path,
  }));
}

export function deleteScan(id: string): boolean {
  const result = db.prepare('DELETE FROM scans WHERE id = ?').run(id);
  return result.changes > 0;
}

export function getStats(): {
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
} {
  const row = db
    .prepare(
      `SELECT
        COUNT(*) as totalScans,
        COALESCE(SUM(total_findings), 0) as totalFindings,
        COALESCE(SUM(total_files), 0) as totalFiles,
        COALESCE(SUM(php_files), 0) as totalPhpFiles,
        COALESCE(AVG(duration), 0) as avgDuration,
        COALESCE(SUM(critical_count), 0) as criticalTotal,
        COALESCE(SUM(high_count), 0) as highTotal,
        COALESCE(SUM(medium_count), 0) as mediumTotal,
        COALESCE(SUM(low_count), 0) as lowTotal,
        COALESCE(SUM(info_count), 0) as infoTotal
      FROM scans WHERE status = 'completed'`
    )
    .get() as any;

  return {
    totalScans: row.totalScans || 0,
    totalFindings: row.totalFindings || 0,
    totalFiles: row.totalFiles || 0,
    totalPhpFiles: row.totalPhpFiles || 0,
    avgDuration: Math.round(row.avgDuration || 0),
    criticalTotal: row.criticalTotal || 0,
    highTotal: row.highTotal || 0,
    mediumTotal: row.mediumTotal || 0,
    lowTotal: row.lowTotal || 0,
    infoTotal: row.infoTotal || 0,
  };
}

// Custom Rules CRUD
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

function mapRule(r: any): CustomRule {
  const patterns = (() => { try { return JSON.parse(r.patterns || '[]'); } catch { return []; } })();
  const pathPatterns = (() => { try { return JSON.parse(r.path_patterns || '[]'); } catch { return []; } })();
  const targetFiles = (() => { try { return JSON.parse(r.target_files || '[]'); } catch { return []; } })();
  const tags = (() => { try { return JSON.parse(r.tags || '[]'); } catch { return []; } })();
  const scoringModifiers = (() => { try { return JSON.parse(r.scoring_modifiers || '{}'); } catch { return {}; } })();
  // Backward compat: if patterns is empty but pattern exists, use [pattern]
  const effectivePatterns = patterns.length > 0 ? patterns : (r.pattern ? [r.pattern] : []);
  return {
    id: r.id,
    name: r.name,
    description: r.description,
    pattern: r.pattern,
    patterns: effectivePatterns,
    pathPatterns,
    targetFiles,
    isRegex: !!r.is_regex,
    severity: r.severity,
    category: r.category,
    confidence: r.confidence || 'medium',
    recommendation: r.recommendation || '',
    tags,
    isBuiltin: !!r.is_builtin,
    checkType: r.check_type || 'pattern',
    scoringModifiers,
    filePattern: r.file_pattern,
    enabled: !!r.enabled,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

export function getCustomRules(): CustomRule[] {
  const rows = db.prepare('SELECT * FROM custom_rules ORDER BY is_builtin DESC, created_at DESC').all() as any[];
  return rows.map(mapRule);
}

export function getEnabledCustomRules(): CustomRule[] {
  const rows = db.prepare('SELECT * FROM custom_rules WHERE enabled = 1').all() as any[];
  return rows.map(mapRule);
}

export function getBuiltinRules(): CustomRule[] {
  const rows = db.prepare('SELECT * FROM custom_rules WHERE is_builtin = 1 ORDER BY category, name').all() as any[];
  return rows.map(mapRule);
}

export function saveCustomRule(rule: Partial<CustomRule> & { id?: string }): CustomRule {
  const id = rule.id || `custom-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const now = new Date().toISOString();
  const patterns = rule.patterns || (rule.pattern ? [rule.pattern] : []);
  const pathPatterns = rule.pathPatterns || [];
  const targetFiles = rule.targetFiles || [];
  const tags = rule.tags || [];
  const scoringModifiers = rule.scoringModifiers || {};
  const existing = db.prepare('SELECT id FROM custom_rules WHERE id = ?').get(id);
  if (existing) {
    db.prepare(`UPDATE custom_rules SET name=?, description=?, pattern=?, patterns=?, path_patterns=?, target_files=?, is_regex=?, severity=?, category=?, confidence=?, recommendation=?, tags=?, is_builtin=?, check_type=?, scoring_modifiers=?, file_pattern=?, enabled=?, updated_at=? WHERE id=?`)
      .run(rule.name || '', rule.description || '', rule.pattern || '', JSON.stringify(patterns), JSON.stringify(pathPatterns), JSON.stringify(targetFiles), rule.isRegex !== false ? 1 : 0, rule.severity || 'medium', rule.category || 'security', rule.confidence || 'medium', rule.recommendation || '', JSON.stringify(tags), rule.isBuiltin ? 1 : 0, rule.checkType || 'pattern', JSON.stringify(scoringModifiers), rule.filePattern || '*', rule.enabled !== false ? 1 : 0, now, id);
  } else {
    db.prepare(`INSERT INTO custom_rules (id, name, description, pattern, patterns, path_patterns, target_files, is_regex, severity, category, confidence, recommendation, tags, is_builtin, check_type, scoring_modifiers, file_pattern, enabled, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .run(id, rule.name || '', rule.description || '', rule.pattern || '', JSON.stringify(patterns), JSON.stringify(pathPatterns), JSON.stringify(targetFiles), rule.isRegex !== false ? 1 : 0, rule.severity || 'medium', rule.category || 'security', rule.confidence || 'medium', rule.recommendation || '', JSON.stringify(tags), rule.isBuiltin ? 1 : 0, rule.checkType || 'pattern', JSON.stringify(scoringModifiers), rule.filePattern || '*', rule.enabled !== false ? 1 : 0, now, now);
  }
  return getCustomRules().find(r => r.id === id)!;
}

export function deleteCustomRule(id: string): boolean {
  const rule = db.prepare('SELECT * FROM custom_rules WHERE id = ?').get(id) as any;
  if (rule && rule.is_builtin) return false;
  const result = db.prepare('DELETE FROM custom_rules WHERE id = ? AND is_builtin = 0').run(id);
  return result.changes > 0;
}

export function seedBuiltinRules(rules: Array<Omit<CustomRule, 'createdAt' | 'updatedAt'>>): number {
  let seeded = 0;
  const now = new Date().toISOString();
  for (const rule of rules) {
    const existing = db.prepare('SELECT id FROM custom_rules WHERE id = ?').get(rule.id);
    if (!existing) {
      db.prepare(`INSERT INTO custom_rules (id, name, description, pattern, patterns, path_patterns, target_files, is_regex, severity, category, confidence, recommendation, tags, is_builtin, check_type, scoring_modifiers, file_pattern, enabled, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
        .run(rule.id, rule.name, rule.description, rule.pattern || '', JSON.stringify(rule.patterns || []), JSON.stringify(rule.pathPatterns || []), JSON.stringify(rule.targetFiles || []), rule.isRegex ? 1 : 0, rule.severity, rule.category, rule.confidence || 'medium', rule.recommendation || '', JSON.stringify(rule.tags || []), 1, rule.checkType || 'pattern', JSON.stringify(rule.scoringModifiers || {}), rule.filePattern || '*', rule.enabled !== false ? 1 : 0, now, now);
      seeded++;
    }
  }
  return seeded;
}

// Trend data for dashboard charts
export function getTrendData(): Array<{ date: string; findings: number; critical: number; high: number; medium: number; low: number; info: number }> {
  const rows = db.prepare(`
    SELECT
      DATE(scan_date) as date,
      SUM(total_findings) as findings,
      SUM(critical_count) as critical,
      SUM(high_count) as high,
      SUM(medium_count) as medium,
      SUM(low_count) as low,
      SUM(info_count) as info
    FROM scans WHERE status = 'completed'
    GROUP BY DATE(scan_date)
    ORDER BY date ASC
    LIMIT 30
  `).all() as any[];
  return rows.map(r => ({
    date: r.date,
    findings: r.findings || 0,
    critical: r.critical || 0,
    high: r.high || 0,
    medium: r.medium || 0,
    low: r.low || 0,
    info: r.info || 0,
  }));
}

// Theme Intel DB functions
export function saveThemeScan(record: {
  id: string;
  themesPath: string;
  results: any[];
  duration: number;
  createdAt: string;
}): void {
  let totalFindings = 0;
  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;
  for (const theme of record.results) {
    if (theme.summary) {
      totalFindings += theme.summary.totalFindings || 0;
      critical += theme.summary.critical || 0;
      high += theme.summary.high || 0;
      medium += theme.summary.medium || 0;
      low += theme.summary.low || 0;
    }
  }

  db.prepare(`
    INSERT INTO theme_scans (id, themes_path, duration, themes_count, total_findings, critical_count, high_count, medium_count, low_count, results_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    record.id,
    record.themesPath,
    record.duration,
    record.results.length,
    totalFindings,
    critical,
    high,
    medium,
    low,
    JSON.stringify(record.results),
    record.createdAt
  );
}

export function getThemeScanHistory(limit = 50, offset = 0): any[] {
  const rows = db.prepare(`
    SELECT id, themes_path, duration, themes_count, total_findings, critical_count, high_count, medium_count, low_count, created_at
    FROM theme_scans ORDER BY created_at DESC LIMIT ? OFFSET ?
  `).all(limit, offset) as any[];
  return rows.map(r => ({
    id: r.id,
    themes_path: r.themes_path,
    duration: r.duration,
    themes_count: r.themes_count,
    total_findings: r.total_findings,
    critical_count: r.critical_count,
    high_count: r.high_count,
    medium_count: r.medium_count,
    low_count: r.low_count,
    created_at: r.created_at,
  }));
}

export function getThemeScan(id: string): any | null {
  const row = db.prepare('SELECT * FROM theme_scans WHERE id = ?').get(id) as any;
  if (!row) return null;
  return {
    id: row.id,
    themesPath: row.themes_path,
    duration: row.duration,
    themesCount: row.themes_count,
    totalFindings: row.total_findings,
    criticalCount: row.critical_count,
    highCount: row.high_count,
    mediumCount: row.medium_count,
    lowCount: row.low_count,
    results: JSON.parse(row.results_json || '[]'),
    createdAt: row.created_at,
  };
}

export function deleteThemeScan(id: string): boolean {
  const result = db.prepare('DELETE FROM theme_scans WHERE id = ?').run(id);
  return result.changes > 0;
}
