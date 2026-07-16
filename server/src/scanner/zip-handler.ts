import * as fs from 'fs';
import * as path from 'path';
import AdmZip from 'adm-zip';

const UPLOADS_DIR = path.join(__dirname, '..', '..', 'uploads');

export function extractZip(zipPath: string): string {
  if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

  const extractDir = path.join(UPLOADS_DIR, path.basename(zipPath, '.zip') + '_' + Date.now());
  fs.mkdirSync(extractDir, { recursive: true });

  const zip = new AdmZip(zipPath);
  zip.extractAllTo(extractDir, true);

  const entries = fs.readdirSync(extractDir);
  if (entries.length === 1) {
    const singleDir = path.join(extractDir, entries[0]);
    if (fs.statSync(singleDir).isDirectory()) return singleDir;
  }

  return extractDir;
}

export function cleanupTemp(dir: string): void {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
}
