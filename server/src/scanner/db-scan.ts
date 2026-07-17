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
        `SELECT option_name, option_value FROM ${p}options WHERE autoload = 'yes' AND (option_value LIKE '%eval(%' OR option_value LIKE '%base64_decode(%')`
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

    // DBDEEP-001: Post meta injection
    try {
      const postMetaResult = await conn.query(`SELECT pm.post_id, pm.meta_key, pm.meta_value FROM ${p}postmeta pm WHERE pm.meta_value LIKE '%eval(%' OR pm.meta_value LIKE '%base64_decode(%' OR pm.meta_value LIKE '%system(%' OR pm.meta_value LIKE '%exec(%' LIMIT 50`);
      for (const row of (postMetaResult as any)[0] || []) {
        addFinding(findings, 'post_meta_injection', `${p}postmeta`, 'meta_value', 'critical', `Suspicious code in post meta (key: ${row.meta_key})`, String(row.meta_value).substring(0, 200), 'Remove the malicious code from post_meta and check the post for backdoors.');
      }
    } catch {}

    // DBDEEP-002: Comment table XSS
    try {
      const commentResult = await conn.query(`SELECT comment_ID, comment_content, comment_author_url FROM ${p}comments WHERE comment_content LIKE '%<script%' OR comment_content LIKE '%onload=%' OR comment_content LIKE '%onclick=%' OR comment_content LIKE '%javascript:%' OR comment_author_url LIKE '%javascript:%' LIMIT 50`);
      for (const row of (commentResult as any)[0] || []) {
        addFinding(findings, 'comment_xss', `${p}comments`, 'comment_content', 'high', `XSS in comment (ID: ${row.comment_ID})`, String(row.comment_content).substring(0, 200), 'Remove the XSS payload from the comment and check for stored XSS vulnerabilities.');
      }
    } catch {}

    // DBDEEP-003: User meta escalation
    try {
      const userMetaResult = await conn.query(`SELECT um.user_id, um.meta_key, um.meta_value FROM ${p}usermeta um WHERE um.meta_key = '${p}capabilities' AND um.meta_value LIKE '%administrator%' LIMIT 20`);
      for (const row of (userMetaResult as any)[0] || []) {
        addFinding(findings, 'user_meta_escalation', `${p}usermeta`, 'meta_value', 'medium', `Administrator capability for user ID ${row.user_id}`, String(row.meta_value).substring(0, 200), 'Verify this user should have administrator privileges. Remove if unauthorized.');
      }
    } catch {}

    // DBDEEP-004: Option size anomalies
    try {
      const sizeResult = await conn.query(`SELECT option_name, LENGTH(option_value) as size FROM ${p}options WHERE LENGTH(option_value) > 102400 ORDER BY size DESC LIMIT 20`);
      for (const row of (sizeResult as any)[0] || []) {
        addFinding(findings, 'option_size_anomaly', `${p}options`, 'option_value', 'warning' as Severity, `Large option value: ${row.option_name} (${Math.round(row.size/1024)}KB)`, String(row.option_name), 'Investigate large option values - they may contain hidden malicious payloads. Consider clearing if unnecessary.');
      }
    } catch {}

    // DBDEEP-005: Transient injection
    try {
      const transientResult = await conn.query(`SELECT option_name, option_value FROM ${p}options WHERE option_name LIKE '%_transient_%' AND (option_value LIKE '%eval(%' OR option_value LIKE '%exec(%' OR option_value LIKE '%base64_decode(%') LIMIT 50`);
      for (const row of (transientResult as any)[0] || []) {
        addFinding(findings, 'transient_injection', `${p}options`, 'option_value', 'high', `Suspicious transient: ${row.option_name}`, String(row.option_value).substring(0, 200), 'Remove the malicious transient and check which plugin/theme created it.');
      }
    } catch {}

    // DBDEEP-006: Spam in post content
    try {
      const spamResult = await conn.query(`SELECT ID, post_title, post_content FROM ${p}posts WHERE post_content LIKE '%casino%' OR post_content LIKE '%viagra%' OR post_content LIKE '%cialis%' OR post_content LIKE '%gambling%' OR post_content LIKE '%pharmacy%' OR post_content LIKE '%<iframe%src=http%' LIMIT 50`);
      for (const row of (spamResult as any)[0] || []) {
        addFinding(findings, 'spam_in_post_content', `${p}posts`, 'post_content', 'high', `Spam content in post: ${row.post_title || row.ID}`, String(row.post_content).substring(0, 200), 'Remove the spam content and check for SEO spam injection vectors.');
      }
    } catch {}

    // DBDEEP-007: Suspicious user agents in options
    try {
      const uaResult = await conn.query(`SELECT option_name, option_value FROM ${p}options WHERE option_name LIKE '%user_agent%' OR option_name LIKE '%http_user_agent%' OR (option_value LIKE '%curl%' AND option_value LIKE '%user_agent%') LIMIT 20`);
      for (const row of (uaResult as any)[0] || []) {
        addFinding(findings, 'suspicious_user_agent', `${p}options`, 'option_value', 'medium', `Suspicious user agent option: ${row.option_name}`, String(row.option_value).substring(0, 200), 'Investigate user agent configuration - may indicate malware communication.');
      }
    } catch {}

    // DBDEEP-008: Hidden option obfuscation
    try {
      const obfResult = await conn.query(`SELECT option_name, option_value FROM ${p}options WHERE option_name LIKE '%\\_%' AND LENGTH(option_value) > 1000 AND option_value LIKE '%a:%' LIMIT 20`);
      for (const row of (obfResult as any)[0] || []) {
        addFinding(findings, 'obfuscated_option', `${p}options`, 'option_value', 'medium', `Large serialized option: ${row.option_name}`, String(row.option_value).substring(0, 200), 'Investigate large serialized options - they may contain hidden backdoor data.');
      }
    } catch {}

    // DBDEEP-009: Plugin option injection
    try {
      const pluginOptResult = await conn.query(`SELECT option_name, option_value FROM ${p}options WHERE option_name LIKE '%_plugins%' AND (option_value LIKE '%eval(%' OR option_value LIKE '%base64_decode(%' OR option_value LIKE '%<script%') LIMIT 10`);
      for (const row of (pluginOptResult as any)[0] || []) {
        addFinding(findings, 'plugin_option_injection', `${p}options`, 'option_value', 'critical', `Injected plugin option: ${row.option_name}`, String(row.option_value).substring(0, 200), 'This option contains malicious code. Remove immediately and identify the source.');
      }
    } catch {}

    // DBDEEP-010: Suspicious autoload total size
    try {
      const autoloadResult = await conn.query(`SELECT SUM(LENGTH(option_value)) as total_size FROM ${p}options WHERE autoload = 'yes'`) as any;
      const totalSize = (autoloadResult as any)[0]?.[0]?.total_size || 0;
      if (totalSize > 1048576) {
        addFinding(findings, 'autoload_size_anomaly', `${p}options`, 'option_value', 'warning' as Severity, `Excessive autoloaded options: ${Math.round(totalSize/1024/1024*100)/100}MB`, `${totalSize} bytes`, 'Large autoloaded options slow down every page load. Review and remove unnecessary autoloaded options.');
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
