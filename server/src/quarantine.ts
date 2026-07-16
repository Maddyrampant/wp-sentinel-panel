import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { getDb } from './db/database';

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

function getQuarantineDir(): string {
  const dir = path.join(__dirname, '..', '..', 'quarantine');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function computeSha256(filePath: string): string {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

export function quarantineFile(
  filePath: string,
  reason: string,
  scanId: string,
  findingId: string
): QuarantineRecord {
  if (!fs.existsSync(filePath)) throw new Error(`File not found: ${filePath}`);

  const sha256 = computeSha256(filePath);
  const stats = fs.statSync(filePath);
  const basename = path.basename(filePath);
  const quarantineDir = getQuarantineDir();
  const quarantineFileName = `${sha256.slice(0, 16)}-${basename}.bin`;
  const quarantinePath = path.join(quarantineDir, quarantineFileName);

  fs.copyFileSync(filePath, quarantinePath);
  fs.unlinkSync(filePath);

  const id = uuidv4();
  const record: QuarantineRecord = {
    id,
    originalPath: filePath,
    quarantinePath,
    sha256,
    fileSize: stats.size,
    quarantinedAt: new Date().toISOString(),
    reason,
    scanId,
    findingId,
    restored: false,
  };

  try {
    const db = getDb();
    db.prepare(`
      INSERT INTO quarantine_files (id, original_path, quarantine_path, sha256, file_size, quarantined_at, reason, scan_id, finding_id, restored)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
    `).run(id, filePath, quarantinePath, sha256, stats.size, record.quarantinedAt, reason, scanId, findingId);
  } catch {}

  return record;
}

export function restoreFile(quarantineId: string): boolean {
  try {
    const db = getDb();
    const row = db.prepare('SELECT * FROM quarantine_files WHERE id = ?').get(quarantineId) as any;
    if (!row) return false;

    if (!fs.existsSync(row.quarantine_path)) return false;

    const dir = path.dirname(row.original_path);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    fs.copyFileSync(row.quarantine_path, row.original_path);
    fs.unlinkSync(row.quarantine_path);

    db.prepare('UPDATE quarantine_files SET restored = 1, restored_at = ? WHERE id = ?')
      .run(new Date().toISOString(), quarantineId);

    return true;
  } catch {
    return false;
  }
}

export function getQuarantineList(): QuarantineRecord[] {
  try {
    const db = getDb();
    const rows = db.prepare('SELECT * FROM quarantine_files ORDER BY quarantined_at DESC').all() as any[];
    return rows.map(r => ({
      id: r.id,
      originalPath: r.original_path,
      quarantinePath: r.quarantine_path,
      sha256: r.sha256,
      fileSize: r.file_size,
      quarantinedAt: r.quarantined_at,
      reason: r.reason,
      scanId: r.scan_id,
      findingId: r.finding_id,
      restored: !!r.restored,
      restoredAt: r.restored_at,
    }));
  } catch {
    return [];
  }
}

export function deleteQuarantine(quarantineId: string): boolean {
  try {
    const db = getDb();
    const row = db.prepare('SELECT * FROM quarantine_files WHERE id = ?').get(quarantineId) as any;
    if (!row) return false;

    if (fs.existsSync(row.quarantine_path)) fs.unlinkSync(row.quarantine_path);
    db.prepare('DELETE FROM quarantine_files WHERE id = ?').run(quarantineId);
    return true;
  } catch {
    return false;
  }
}
