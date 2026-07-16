import { v4 as uuidv4 } from 'uuid';
import { Severity } from '../types';

export interface DatabaseConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  tablePrefix: string;
}

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

let dbFindingCounter = 0;

function addFinding(
  findings: DatabaseFinding[],
  check: string,
  table: string,
  column: string,
  severity: Severity,
  message: string,
  matchedValue: string,
  recommendation: string,
  rowId?: number
): void {
  findings.push({
    id: `dbf-${Date.now()}-${++dbFindingCounter}`,
    check,
    table,
    column,
    rowId,
    severity,
    message,
    matchedValue: matchedValue.substring(0, 500),
    recommendation,
  });
}

export async function runDatabaseScan(config: DatabaseConfig): Promise<DatabaseScanResult> {
  const startTime = Date.now();
  const findings: DatabaseFinding[] = [];
  let connected = false;

  try {
    const mysql = require('mysql2/promise');
    const conn = await mysql.createConnection({
      host: config.host,
      port: config.port || 3306,
      user: config.user,
      password: config.password,
      database: config.database,
      connectTimeout: 10000,
    });

    connected = true;
    const p = config.tablePrefix || 'wp_';

    // Check wp_options for script injection
    try {
      const [rows] = await conn.execute(
        `SELECT option_name, option_value FROM ${p}options WHERE option_value LIKE '%<script%' OR option_value LIKE '%base64_decode%' OR option_value LIKE '%eval(%' OR option_value LIKE '%<iframe%'`
      );
      for (const row of rows as any[]) {
        addFinding(findings, 'script_injection_in_options', `${p}options`, 'option_value', 'high',
          `Suspicious content in option "${row.option_name}"`, row.option_value,
          'Review this option value. It may contain injected malicious scripts.');
      }
    } catch {}

    // Check for suspicious autoload options
    try {
      const [rows] = await conn.execute(
        `SELECT option_name, option_value FROM ${p}options WHERE autoload = 'yes' AND option_value LIKE '%eval(%' OR option_value LIKE '%base64_decode(%'`
      );
      for (const row of rows as any[]) {
        addFinding(findings, 'suspicious_autoload_option', `${p}options`, 'option_value', 'high',
          `Suspicious autoloaded option "${row.option_name}"`, row.option_value,
          'This autoloaded option contains suspicious code that executes on every page load.');
      }
    } catch {}

    // Check for rogue admin accounts
    try {
      const [rows] = await conn.execute(
        `SELECT u.ID, u.user_login, u.user_email, u.user_registered, m.meta_value FROM ${p}users u JOIN ${p}usermeta m ON u.ID = m.user_id WHERE m.meta_key = '${p}capabilities' AND m.meta_value LIKE '%administrator%'`
      );
      for (const row of rows as any[]) {
        addFinding(findings, 'admin_account', `${p}users`, 'user_login', 'medium',
          `Administrator account: ${row.user_login} (${row.user_email})`, row.user_login,
          'Verify this administrator account is legitimate.');
      }
    } catch {}

    // Check siteurl/home
    try {
      const [rows] = await conn.execute(
        `SELECT option_name, option_value FROM ${p}options WHERE option_name IN ('siteurl', 'home', 'admin_email')`
      );
      for (const row of rows as any[]) {
        if (/https?:\/\//.test(row.option_value) && !/localhost|127\.0\.0\.1/.test(row.option_value)) {
          addFinding(findings, 'site_url_check', `${p}options`, 'option_value', 'info',
            `${row.option_name}: ${row.option_value}`, row.option_value,
            'Verify this URL is correct and expected.');
        }
      }
    } catch {}

    // Check for suspicious cron events
    try {
      const [rows] = await conn.execute(
        `SELECT option_name, option_value FROM ${p}options WHERE option_name = '${p}cron' AND (option_value LIKE '%http%' OR option_value LIKE '%eval%' OR option_value LIKE '%file_get%')`
      );
      for (const row of rows as any[]) {
        addFinding(findings, 'suspicious_cron', `${p}options`, 'option_value', 'high',
          'Suspicious content in WordPress cron events', row.option_value,
          'Review wp-cron events for unauthorized scheduled tasks.');
      }
    } catch {}

    // Check for spam in post content
    try {
      const [rows] = await conn.execute(
        `SELECT ID, post_title, post_content FROM ${p}posts WHERE post_content LIKE '%<script%' OR post_content LIKE '%display:none%' OR post_content LIKE '%casino%' OR post_content LIKE '%viagra%' OR post_content LIKE '%<iframe%' LIMIT 50`
      );
      for (const row of rows as any[]) {
        addFinding(findings, 'spam_in_post', `${p}posts`, 'post_content', 'high',
          `Spam/injected content in post: ${row.post_title || row.ID}`, row.post_content?.substring(0, 300) || '',
          'Remove injected spam content and identify the injection vector.');
      }
    } catch {}

    // Check for hidden iframes
    try {
      const [rows] = await conn.execute(
        `SELECT option_name, option_value FROM ${p}options WHERE option_value LIKE '%<iframe%'`
      );
      for (const row of rows as any[]) {
        addFinding(findings, 'hidden_iframe', `${p}options`, 'option_value', 'critical',
          `Hidden iframe in option "${row.option_name}"`, row.option_value,
          'Iframes in WordPress options are almost always malicious. Remove immediately.');
      }
    } catch {}

    await conn.end();
  } catch (err: any) {
    if (!connected) {
      addFinding(findings, 'connection_failed', 'N/A', 'N/A', 'low',
        `Database connection failed: ${err.message}`, '',
        'Check database credentials and connectivity.');
    }
  }

  const summary = {
    total: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
  };

  return {
    id: uuidv4(),
    config: { host: config.host, database: config.database, tablePrefix: config.tablePrefix },
    connected,
    findings,
    summary,
    duration: Date.now() - startTime,
    createdAt: new Date().toISOString(),
  };
}
