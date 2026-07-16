import { v4 as uuidv4 } from 'uuid';
import { getDb } from './db/database';

export interface FalsePositive {
  id: string;
  ruleId: string;
  scope: 'global' | 'theme' | 'plugin' | 'file' | 'hash';
  theme?: string;
  plugin?: string;
  filePath?: string;
  fileHash?: string;
  reason: string;
  createdBy: string;
  createdAt: string;
  active: boolean;
}

export function createFalsePositive(data: {
  ruleId: string;
  scope: 'global' | 'theme' | 'plugin' | 'file' | 'hash';
  theme?: string;
  plugin?: string;
  filePath?: string;
  fileHash?: string;
  reason: string;
  createdBy?: string;
}): FalsePositive {
  const id = uuidv4();
  const now = new Date().toISOString();
  const fp: FalsePositive = {
    id,
    ruleId: data.ruleId,
    scope: data.scope,
    theme: data.theme,
    plugin: data.plugin,
    filePath: data.filePath,
    fileHash: data.fileHash,
    reason: data.reason,
    createdBy: data.createdBy || 'admin',
    createdAt: now,
    active: true,
  };

  try {
    const db = getDb();
    db.prepare(`
      INSERT INTO false_positives (id, rule_id, scope, theme, plugin, file_path, file_hash, reason, created_by, created_at, active)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
    `).run(id, data.ruleId, data.scope, data.theme || null, data.plugin || null, data.filePath || null, data.fileHash || null, data.reason, fp.createdBy, now);
  } catch {}

  return fp;
}

export function getFalsePositives(): FalsePositive[] {
  try {
    const db = getDb();
    const rows = db.prepare('SELECT * FROM false_positives WHERE active = 1 ORDER BY created_at DESC').all() as any[];
    return rows.map(r => ({
      id: r.id,
      ruleId: r.rule_id,
      scope: r.scope,
      theme: r.theme,
      plugin: r.plugin,
      filePath: r.file_path,
      fileHash: r.file_hash,
      reason: r.reason,
      createdBy: r.created_by,
      createdAt: r.created_at,
      active: !!r.active,
    }));
  } catch {
    return [];
  }
}

export function deleteFalsePositive(id: string): boolean {
  try {
    const db = getDb();
    const result = db.prepare('UPDATE false_positives SET active = 0 WHERE id = ?').run(id);
    return result.changes > 0;
  } catch {
    return false;
  }
}

export function isFindingFalsePositive(
  finding: { file: string; ruleId?: string; code?: string },
  fps: FalsePositive[]
): boolean {
  for (const fp of fps) {
    if (fp.ruleId !== finding.ruleId) continue;

    switch (fp.scope) {
      case 'global':
        return true;
      case 'file':
        if (fp.filePath && finding.file === fp.filePath) return true;
        break;
      case 'hash':
        if (fp.fileHash && finding.code) {
          const crypto = require('crypto');
          const hash = crypto.createHash('sha256').update(finding.code).digest('hex');
          if (hash === fp.fileHash) return true;
        }
        break;
    }
  }
  return false;
}
