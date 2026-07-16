import * as fs from 'fs';
import * as path from 'path';
import { Severity } from '../types';

export interface TimelineEvent {
  id: string;
  timestamp: string;
  type: 'file_created' | 'file_modified' | 'suspicious_file_created' |
        'external_domain_first_seen' | 'backdoor_first_seen' | 'obfuscation_first_seen' |
        'admin_account_created' | 'option_changed' | 'core_file_modified' |
        'php_in_uploads' | 'htaccess_modified' | 'functions_php_modified';
  file?: string;
  severity: Severity;
  description: string;
  relatedFindingIds: string[];
}

let eventCounter = 0;

function walkFiles(dir: string, base: string): Array<{ relativePath: string; fullPath: string; mtime: Date; birthtime: Date }> {
  const results: Array<{ relativePath: string; fullPath: string; mtime: Date; birthtime: Date }> = [];
  if (!fs.existsSync(dir)) return results;

  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const relativePath = path.relative(base, fullPath).replace(/\\/g, '/');

    if (entry.isDirectory()) {
      if (['node_modules', '.git', 'vendor', 'dist', 'build'].includes(entry.name)) continue;
      results.push(...walkFiles(fullPath, base));
    } else {
      try {
        const stats = fs.statSync(fullPath);
        results.push({
          relativePath,
          fullPath,
          mtime: stats.mtime,
          birthtime: stats.birthtime,
        });
      } catch {}
    }
  }
  return results;
}

export function generateTimeline(
  scanPath: string,
  findings: Array<{ file: string; line: number; message: string; details: string; code: string; ruleId?: string }>
): TimelineEvent[] {
  const events: TimelineEvent[] = [];
  const files = walkFiles(scanPath, scanPath);

  const now = new Date();
  const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const ninetyDaysAgo = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);

  for (const file of files) {
    const ext = path.extname(file.fullPath).toLowerCase();
    const basename = path.basename(file.fullPath).toLowerCase();

    if (ext === '.php' && file.relativePath.includes('uploads/')) {
      events.push({
        id: `ev-${++eventCounter}`,
        timestamp: file.birthtime.toISOString(),
        type: 'php_in_uploads',
        file: file.relativePath,
        severity: 'high',
        description: `PHP file created in uploads directory: ${file.relativePath}`,
        relatedFindingIds: [],
      });
    }

    if (basename === 'functions.php' && file.mtime > ninetyDaysAgo) {
      events.push({
        id: `ev-${++eventCounter}`,
        timestamp: file.mtime.toISOString(),
        type: 'functions_php_modified',
        file: file.relativePath,
        severity: 'medium',
        description: `functions.php modified: ${file.relativePath}`,
        relatedFindingIds: [],
      });
    }

    if (basename === '.htaccess' && file.mtime > ninetyDaysAgo) {
      events.push({
        id: `ev-${++eventCounter}`,
        timestamp: file.mtime.toISOString(),
        type: 'htaccess_modified',
        file: file.relativePath,
        severity: 'medium',
        description: `.htaccess modified: ${file.relativePath}`,
        relatedFindingIds: [],
      });
    }

    if (basename === 'wp-config.php' && file.mtime > ninetyDaysAgo) {
      events.push({
        id: `ev-${++eventCounter}`,
        timestamp: file.mtime.toISOString(),
        type: 'option_changed',
        file: file.relativePath,
        severity: 'critical',
        description: `wp-config.php modified: ${file.relativePath}`,
        relatedFindingIds: [],
      });
    }

    if (['wp-admin', 'wp-includes'].some(d => file.relativePath.startsWith(d + '/')) && ext === '.php' && file.mtime > ninetyDaysAgo) {
      events.push({
        id: `ev-${++eventCounter}`,
        timestamp: file.mtime.toISOString(),
        type: 'core_file_modified',
        file: file.relativePath,
        severity: 'critical',
        description: `WordPress core file modified: ${file.relativePath}`,
        relatedFindingIds: [],
      });
    }

    if (file.birthtime > sevenDaysAgo && ext === '.php') {
      events.push({
        id: `ev-${++eventCounter}`,
        timestamp: file.birthtime.toISOString(),
        type: 'suspicious_file_created',
        file: file.relativePath,
        severity: 'medium',
        description: `New PHP file created (last 7 days): ${file.relativePath}`,
        relatedFindingIds: [],
      });
    }
  }

  const findingFileMap = new Map<string, string[]>();
  for (const f of findings) {
    if (!findingFileMap.has(f.file)) findingFileMap.set(f.file, []);
    findingFileMap.get(f.file)!.push(f.ruleId || f.message);
  }

  const backdoorFindings = findings.filter(f => /backdoor|webshell|shell/i.test(f.message));
  if (backdoorFindings.length > 0) {
    const earliest = backdoorFindings[0];
    events.push({
      id: `ev-${++eventCounter}`,
      timestamp: new Date().toISOString(),
      type: 'backdoor_first_seen',
      file: earliest.file,
      severity: 'critical',
      description: `First backdoor/webshell detection: ${earliest.file}:${earliest.line} — ${earliest.message}`,
      relatedFindingIds: backdoorFindings.map(f => f.ruleId || ''),
    });
  }

  const obfuscationFindings = findings.filter(f => /obfuscat|base64_decode.*eval|encoded/i.test(f.message));
  if (obfuscationFindings.length > 0) {
    const earliest = obfuscationFindings[0];
    events.push({
      id: `ev-${++eventCounter}`,
      timestamp: new Date().toISOString(),
      type: 'obfuscation_first_seen',
      file: earliest.file,
      severity: 'high',
      description: `First obfuscation detection: ${earliest.file}:${earliest.line} — ${earliest.message}`,
      relatedFindingIds: obfuscationFindings.map(f => f.ruleId || ''),
    });
  }

  const externalFindings = findings.filter(f => /external.*domain|remote.*request|http.*request/i.test(f.message));
  if (externalFindings.length > 0) {
    events.push({
      id: `ev-${++eventCounter}`,
      timestamp: new Date().toISOString(),
      type: 'external_domain_first_seen',
      file: externalFindings[0].file,
      severity: 'medium',
      description: `External domain connections detected: ${externalFindings.length} finding(s)`,
      relatedFindingIds: externalFindings.map(f => f.ruleId || ''),
    });
  }

  return events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
}

export function getEarliestSuspiciousEvent(events: TimelineEvent[]): TimelineEvent | null {
  const suspicious = events.filter(e =>
    ['suspicious_file_created', 'backdoor_first_seen', 'obfuscation_first_seen', 'php_in_uploads', 'core_file_modified', 'htaccess_modified'].includes(e.type)
  );
  return suspicious.length > 0 ? suspicious[0] : null;
}
