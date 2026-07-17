import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as https from 'https';
import { v4 as uuidv4 } from 'uuid';
import { Severity } from '../types';

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

export function detectWpVersion(targetPath: string): string | null {
  const versionFile = path.join(targetPath, 'wp-includes', 'version.php');
  try {
    const content = fs.readFileSync(versionFile, 'utf8');
    const match = content.match(/\$wp_version\s*=\s*'([^']+)'/);
    if (match) {
      return match[1];
    }
    return null;
  } catch {
    return null;
  }
}

export function computeFileMd5(filePath: string): string | null {
  try {
    const content = fs.readFileSync(filePath);
    return crypto.createHash('md5').update(content).digest('hex');
  } catch {
    return null;
  }
}

export function walkPhpFiles(dir: string): string[] {
  const SKIP_DIRS = new Set(['node_modules', '.git', '__MACOSX']);
  const results: string[] = [];

  function walk(currentDir: string) {
    try {
      const entries = fs.readdirSync(currentDir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(currentDir, entry.name);
        if (entry.isDirectory()) {
          if (!SKIP_DIRS.has(entry.name)) {
            walk(fullPath);
          }
        } else if (entry.isFile() && entry.name.endsWith('.php')) {
          results.push(fullPath);
        }
      }
    } catch {
      // Skip directories we can't read
    }
  }

  walk(dir);
  return results;
}

export function fetchRemoteChecksums(version: string): Promise<Record<string, string>> {
  return new Promise((resolve) => {
    const url = `https://api.wordpress.org/core/checksums/1.0/?version=${version}&locale=en_US`;

    httpsGet(url)
      .then((data) => {
        try {
          const parsed = JSON.parse(data);
          if (parsed && parsed.checksums) {
            const checksums: Record<string, string> = {};
            for (const [filePath, md5] of Object.entries(parsed.checksums)) {
              if (typeof md5 === 'string') {
                checksums[filePath] = md5;
              }
            }
            resolve(checksums);
          } else {
            resolve({});
          }
        } catch {
          resolve({});
        }
      })
      .catch(() => {
        resolve({});
      });
  });
}

function httpsGet(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          httpsGet(res.headers.location).then(resolve).catch(reject);
          return;
        }
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          resolve(data);
        });
        res.on('error', (err) => {
          reject(err);
        });
      })
      .on('error', (err) => {
        reject(err);
      });
  });
}

export async function verifyCoreChecksums(targetPath: string): Promise<ChecksumResult> {
  const startTime = Date.now();
  const result: ChecksumResult = {
    id: uuidv4(),
    targetPath,
    totalFiles: 0,
    matched: 0,
    mismatched: 0,
    extraLocal: 0,
    missingLocal: 0,
    files: [],
    scanDate: new Date().toISOString(),
    duration: 0,
  };

  const wpVersion = detectWpVersion(targetPath);
  result.wpVersion = wpVersion ?? undefined;

  if (!wpVersion) {
    result.duration = Date.now() - startTime;
    return result;
  }

  const includesDir = path.join(targetPath, 'wp-includes');
  const adminDir = path.join(targetPath, 'wp-admin');

  const localFiles: string[] = [];
  if (fs.existsSync(includesDir)) {
    localFiles.push(...walkPhpFiles(includesDir));
  }
  if (fs.existsSync(adminDir)) {
    localFiles.push(...walkPhpFiles(adminDir));
  }

  const remoteChecksums = await fetchRemoteChecksums(wpVersion);

  const localChecksums: Record<string, string> = {};
  for (const filePath of localFiles) {
    const relativePath = path.relative(targetPath, filePath).replace(/\\/g, '/');
    const md5 = computeFileMd5(filePath);
    if (md5) {
      localChecksums[relativePath] = md5;
    }
  }

  const allFiles = new Set([...Object.keys(remoteChecksums), ...Object.keys(localChecksums)]);
  result.totalFiles = allFiles.size;

  for (const filePath of allFiles) {
    const localMd5 = localChecksums[filePath];
    const remoteMd5 = remoteChecksums[filePath];

    let status: ChecksumFile['status'];
    let severity: Severity;
    let md5: string;

    if (localMd5 && !remoteMd5) {
      status = 'extra_local';
      severity = 'critical';
      md5 = localMd5;
    } else if (!localMd5 && remoteMd5) {
      status = 'missing_local';
      severity = 'high';
      md5 = remoteMd5;
    } else if (localMd5 && remoteMd5) {
      if (localMd5 === remoteMd5) {
        status = 'match';
        severity = 'info';
        md5 = localMd5;
      } else {
        status = 'mismatch';
        severity = 'critical';
        md5 = localMd5;
      }
    } else {
      continue;
    }

    if (status === 'match') result.matched++;
    else if (status === 'mismatch') result.mismatched++;
    else if (status === 'extra_local') result.extraLocal++;
    else if (status === 'missing_local') result.missingLocal++;

    result.files.push({ file: filePath, md5, status, severity });
  }

  result.duration = Date.now() - startTime;
  return result;
}