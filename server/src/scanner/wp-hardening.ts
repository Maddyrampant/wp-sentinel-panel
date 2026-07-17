import * as fs from 'fs';
import * as path from 'path';
import { Severity } from '../types';

export interface HardeningCheck {
  id: string;
  name: string;
  category: 'config' | 'file-permissions' | 'network' | 'authentication' | 'database' | 'server' | 'wordpress';
  status: 'pass' | 'fail' | 'warning' | 'info';
  severity: Severity;
  message: string;
  details: string;
  recommendation: string;
  reference?: string;
}

export interface HardeningResult {
  targetPath: string;
  totalChecks: number;
  passed: number;
  failed: number;
  warnings: number;
  score: number;
  checks: HardeningCheck[];
  scanDate: string;
  duration: number;
}

function readFileSafe(filePath: string): string | null {
  try {
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
}

function fileExists(filePath: string): boolean {
  try {
    fs.accessSync(filePath, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function dirExists(dirPath: string): boolean {
  try {
    const stat = fs.statSync(dirPath);
    return stat.isDirectory();
  } catch {
    return false;
  }
}

function checkFilePermissions(filePath: string): number | null {
  try {
    const stat = fs.statSync(filePath);
    const mode = stat.mode;
    return mode & 0o777;
  } catch {
    return null;
  }
}

function findFilesRecursive(dir: string, extension: string, maxDepth: number = 5): string[] {
  const results: string[] = [];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'vendor') continue;
        if (maxDepth > 0) {
          results.push(...findFilesRecursive(fullPath, extension, maxDepth - 1));
        }
      } else if (entry.name.endsWith(extension)) {
        results.push(fullPath);
      }
    }
  } catch {
    // directory not readable
  }
  return results;
}

function findFilesByName(dir: string, fileName: string, maxDepth: number = 3): string[] {
  const results: string[] = [];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'vendor') continue;
        if (entry.name === fileName) {
          results.push(fullPath);
        }
        if (maxDepth > 0) {
          results.push(...findFilesByName(fullPath, fileName, maxDepth - 1));
        }
      } else if (entry.name === fileName) {
        results.push(fullPath);
      }
    }
  } catch {
    // directory not readable
  }
  return results;
}

function extractWpConfigDefines(wpConfigPath: string): Map<string, string> {
  const defines = new Map<string, string>();
  const content = readFileSafe(wpConfigPath);
  if (!content) return defines;

  const definePattern = /define\s*\(\s*['"]([A-Z_]+)['"]\s*,\s*(['"].*?['"]|true|false|null|\d+)\s*\)/gi;
  let match: RegExpExecArray | null;
  while ((match = definePattern.exec(content)) !== null) {
    defines.set(match[1], match[2]);
  }
  return defines;
}

function getWpConfigPath(targetPath: string): string | null {
  const candidates = [
    path.join(targetPath, 'wp-config.php'),
    path.join(targetPath, 'wordpress', 'wp-config.php'),
  ];
  for (const candidate of candidates) {
    if (fileExists(candidate)) return candidate;
  }
  return null;
}

function getWebRoot(targetPath: string): string {
  if (fileExists(path.join(targetPath, 'wp-config.php'))) {
    return targetPath;
  }
  if (fileExists(path.join(targetPath, 'wordpress', 'wp-config.php'))) {
    return path.join(targetPath, 'wordpress');
  }
  return targetPath;
}

// ─── CONFIG CHECKS ───────────────────────────────────────────────────────────

function checkHARD001(targetPath: string): HardeningCheck {
  const wpConfig = getWpConfigPath(targetPath);
  const defines = wpConfig ? extractWpConfigDefines(wpConfig) : new Map();
  const wpDebug = defines.get('WP_DEBUG');

  if (wpDebug && wpDebug.toLowerCase() === 'true') {
    return {
      id: 'HARD-001',
      name: 'WP_DEBUG Enabled',
      category: 'config',
      status: 'fail',
      severity: 'high',
      message: 'WP_DEBUG is set to true in wp-config.php',
      details: 'WP_DEBUG should be disabled in production. Leaving it enabled exposes PHP errors, warnings, and notices to visitors, which can reveal sensitive paths, database details, and other internal information.',
      recommendation: 'Set WP_DEBUG to false in wp-config.php: define("WP_DEBUG", false);',
      reference: 'https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/',
    };
  }

  return {
    id: 'HARD-001',
    name: 'WP_DEBUG Enabled',
    category: 'config',
    status: 'pass',
    severity: 'high',
    message: 'WP_DEBUG is not enabled or is set to false',
    details: 'WP_DEBUG is properly disabled, preventing PHP error output from being shown to visitors.',
    recommendation: 'Keep WP_DEBUG set to false in production environments.',
    reference: 'https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/',
  };
}

function checkHARD002(targetPath: string): HardeningCheck {
  const wpConfig = getWpConfigPath(targetPath);
  const defines = wpConfig ? extractWpConfigDefines(wpConfig) : new Map();
  const wpDebugLog = defines.get('WP_DEBUG_LOG');

  if (wpDebugLog && wpDebugLog.toLowerCase() === 'true') {
    return {
      id: 'HARD-002',
      name: 'WP_DEBUG_LOG Enabled',
      category: 'config',
      status: 'warning',
      severity: 'medium',
      message: 'WP_DEBUG_LOG is set to true in wp-config.php',
      details: 'WP_DEBUG_LOG writes PHP errors to a debug.log file in wp-content/. While useful for development, in production this file can be publicly accessible and expose sensitive information.',
      recommendation: 'Set WP_DEBUG_LOG to false in production, or ensure the debug.log file is protected from public access.',
      reference: 'https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/',
    };
  }

  return {
    id: 'HARD-002',
    name: 'WP_DEBUG_LOG Enabled',
    category: 'config',
    status: 'pass',
    severity: 'medium',
    message: 'WP_DEBUG_LOG is not enabled',
    details: 'Debug logging to file is disabled, preventing sensitive error information from being written to disk.',
    recommendation: 'Keep WP_DEBUG_LOG disabled in production environments.',
    reference: 'https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/',
  };
}

function checkHARD003(targetPath: string): HardeningCheck {
  const wpConfig = getWpConfigPath(targetPath);
  const defines = wpConfig ? extractWpConfigDefines(wpConfig) : new Map();
  const wpDebugDisplay = defines.get('WP_DEBUG_DISPLAY');

  if (wpDebugDisplay && wpDebugDisplay.toLowerCase() === 'true') {
    return {
      id: 'HARD-003',
      name: 'WP_DEBUG_DISPLAY Enabled',
      category: 'config',
      status: 'warning',
      severity: 'medium',
      message: 'WP_DEBUG_DISPLAY is set to true in wp-config.php',
      details: 'WP_DEBUG_DISPLAY controls whether debug messages are shown in the HTML output. When enabled, PHP errors are displayed directly on pages, potentially exposing sensitive paths and configuration details.',
      recommendation: 'Set WP_DEBUG_DISPLAY to false: define("WP_DEBUG_DISPLAY", false);',
      reference: 'https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/',
    };
  }

  return {
    id: 'HARD-003',
    name: 'WP_DEBUG_DISPLAY Enabled',
    category: 'config',
    status: 'pass',
    severity: 'medium',
    message: 'WP_DEBUG_DISPLAY is not enabled or is set to false',
    details: 'Debug display is properly disabled, preventing PHP errors from being shown in page output.',
    recommendation: 'Keep WP_DEBUG_DISPLAY set to false in production environments.',
    reference: 'https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/',
  };
}

function checkHARD004(targetPath: string): HardeningCheck {
  const wpConfig = getWpConfigPath(targetPath);
  const defines = wpConfig ? extractWpConfigDefines(wpConfig) : new Map();
  const disallowFileEdit = defines.get('DISALLOW_FILE_EDIT');

  if (!disallowFileEdit || disallowFileEdit.toLowerCase() === 'false') {
    return {
      id: 'HARD-004',
      name: 'DISALLOW_FILE_EDIT Not Set',
      category: 'config',
      status: 'fail',
      severity: 'high',
      message: 'DISALLOW_FILE_EDIT is not set or is false in wp-config.php',
      details: 'Without DISALLOW_FILE_EDIT set to true, administrators can edit theme and plugin files directly from the WordPress admin dashboard. If an attacker gains admin access, they can inject malicious code through the file editor.',
      recommendation: 'Add to wp-config.php: define("DISALLOW_FILE_EDIT", true);',
      reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
    };
  }

  return {
    id: 'HARD-004',
    name: 'DISALLOW_FILE_EDIT Not Set',
    category: 'config',
    status: 'pass',
    severity: 'high',
    message: 'DISALLOW_FILE_EDIT is properly set to true',
    details: 'The file editor in WordPress admin is disabled, preventing unauthorized code modifications through the dashboard.',
    recommendation: 'Keep DISALLOW_FILE_EDIT set to true for enhanced security.',
    reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
  };
}

function checkHARD005(targetPath: string): HardeningCheck {
  const wpConfig = getWpConfigPath(targetPath);
  const defines = wpConfig ? extractWpConfigDefines(wpConfig) : new Map();
  const wpCache = defines.get('WP_CACHE');

  if (wpCache && wpCache.toLowerCase() === 'true') {
    return {
      id: 'HARD-005',
      name: 'WP_CACHE Enabled',
      category: 'config',
      status: 'info',
      severity: 'info',
      message: 'WP_CACHE is set to true in wp-config.php',
      details: 'Object caching is enabled. This is generally a performance optimization and not a security concern, but should be verified that the caching plugin is from a trusted source.',
      recommendation: 'Ensure the caching plugin is from a reputable source and kept up to date.',
    };
  }

  return {
    id: 'HARD-005',
    name: 'WP_CACHE Enabled',
    category: 'config',
    status: 'info',
    severity: 'info',
    message: 'WP_CACHE is not enabled',
    details: 'Object caching is not enabled in wp-config.php. Consider enabling caching for performance improvements.',
    recommendation: 'Consider implementing object caching for better performance if not already handled by a plugin.',
  };
}

function checkHARD006(targetPath: string): HardeningCheck {
  const wpConfig = getWpConfigPath(targetPath);
  const defines = wpConfig ? extractWpConfigDefines(wpConfig) : new Map();
  const disableWpCron = defines.get('DISABLE_WP_CRON');

  if (disableWpCron && disableWpCron.toLowerCase() === 'true') {
    return {
      id: 'HARD-006',
      name: 'WP-Cron Disabled',
      category: 'config',
      status: 'info',
      severity: 'info',
      message: 'DISABLE_WP_CRON is set to true',
      details: 'The built-in WP-Cron system is disabled, which is recommended for production. Server-level cron jobs should be used instead for better reliability and performance.',
      recommendation: 'Ensure a server-level cron job is configured to run wp-cron.php.',
      reference: 'https://developer.wordpress.org/plugins/cron/',
    };
  }

  return {
    id: 'HARD-006',
    name: 'WP-Cron Disabled',
    category: 'config',
    status: 'info',
    severity: 'info',
    message: 'WP-Cron is using the default behavior',
    details: 'WP-Cron is enabled using the default WordPress behavior. Consider disabling it and using server-level cron for better performance.',
    recommendation: 'Set DISABLE_WP_CRON to true and configure a server cron job: */5 * * * * php /path/to/wp-cron.php',
    reference: 'https://developer.wordpress.org/plugins/cron/',
  };
}

// ─── FILE PERMISSIONS CHECKS ─────────────────────────────────────────────────

function checkHARD007(targetPath: string): HardeningCheck {
  const webRoot = getWebRoot(targetPath);
  const wpConfig = getWpConfigPath(targetPath);

  if (!wpConfig) {
    return {
      id: 'HARD-007',
      name: 'wp-config.php Permissions',
      category: 'file-permissions',
      status: 'info',
      severity: 'high',
      message: 'wp-config.php not found',
      details: 'Could not locate wp-config.php to check its permissions.',
      recommendation: 'Ensure wp-config.php exists and has restrictive permissions.',
    };
  }

  const perms = checkFilePermissions(wpConfig);
  if (perms === null) {
    return {
      id: 'HARD-007',
      name: 'wp-config.php Permissions',
      category: 'file-permissions',
      status: 'info',
      severity: 'high',
      message: 'Could not read wp-config.php permissions',
      details: 'Unable to determine file permissions for wp-config.php.',
      recommendation: 'Ensure wp-config.php exists and has permissions set to 640 or lower.',
    };
  }

  if (perms > 0o640) {
    const permOctal = '0' + perms.toString(8);
    return {
      id: 'HARD-007',
      name: 'wp-config.php Permissions',
      category: 'file-permissions',
      status: 'fail',
      severity: 'high',
      message: `wp-config.php has overly permissive permissions: ${permOctal}`,
      details: `wp-config.php permissions are ${permOctal} (should be 640 or lower). This file contains database credentials, authentication keys, and other sensitive configuration. Overly permissive access can expose these secrets.`,
      recommendation: 'Set permissions to 640 (owner read/write, group read): chmod 640 wp-config.php',
      reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
    };
  }

  const permOctal = '0' + perms.toString(8);
  return {
    id: 'HARD-007',
    name: 'wp-config.php Permissions',
    category: 'file-permissions',
    status: 'pass',
    severity: 'high',
    message: `wp-config.php has appropriate permissions: ${permOctal}`,
    details: `wp-config.php permissions are ${permOctal}, which is within the recommended range of 640 or lower.`,
    recommendation: 'Keep wp-config.php permissions restrictive.',
    reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
  };
}

function checkHARD008(targetPath: string): HardeningCheck {
  const webRoot = getWebRoot(targetPath);
  const htaccessPath = path.join(webRoot, '.htaccess');

  if (!fileExists(htaccessPath)) {
    return {
      id: 'HARD-008',
      name: '.htaccess Permissions',
      category: 'file-permissions',
      status: 'info',
      severity: 'medium',
      message: '.htaccess file not found',
      details: 'No .htaccess file found in the web root. This may indicate the server is using a different configuration method (e.g., Nginx, Apache in a different location).',
      recommendation: 'Ensure .htaccess exists if using Apache for proper access control.',
    };
  }

  const perms = checkFilePermissions(htaccessPath);
  if (perms === null) {
    return {
      id: 'HARD-008',
      name: '.htaccess Permissions',
      category: 'file-permissions',
      status: 'info',
      severity: 'medium',
      message: 'Could not read .htaccess permissions',
      details: 'Unable to determine file permissions for .htaccess.',
      recommendation: 'Ensure .htaccess has permissions set to 644 or lower.',
    };
  }

  if (perms > 0o644) {
    const permOctal = '0' + perms.toString(8);
    return {
      id: 'HARD-008',
      name: '.htaccess Permissions',
      category: 'file-permissions',
      status: 'fail',
      severity: 'medium',
      message: `.htaccess has overly permissive permissions: ${permOctal}`,
      details: `.htaccess permissions are ${permOctal} (should be 644 or lower). This file controls Apache access rules and can be exploited if world-writable.`,
      recommendation: 'Set permissions to 644: chmod 644 .htaccess',
      reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
    };
  }

  const permOctal = '0' + perms.toString(8);
  return {
    id: 'HARD-008',
    name: '.htaccess Permissions',
    category: 'file-permissions',
    status: 'pass',
    severity: 'medium',
    message: `.htaccess has appropriate permissions: ${permOctal}`,
    details: `.htaccess permissions are ${permOctal}, which is within the recommended range.`,
    recommendation: 'Keep .htaccess permissions at 644.',
    reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
  };
}

function checkHARD009(targetPath: string): HardeningCheck {
  const webRoot = getWebRoot(targetPath);
  const uploadsDir = path.join(webRoot, 'wp-content', 'uploads');

  if (!dirExists(uploadsDir)) {
    return {
      id: 'HARD-009',
      name: 'PHP Files in Uploads Directory',
      category: 'file-permissions',
      status: 'info',
      severity: 'critical',
      message: 'wp-content/uploads directory not found',
      details: 'Could not locate the uploads directory to check for PHP files.',
      recommendation: 'Ensure the wp-content/uploads directory exists.',
    };
  }

  const phpFiles = findFilesRecursive(uploadsDir, '.php', 3);
  if (phpFiles.length > 0) {
    const fileList = phpFiles.slice(0, 10).map(f => path.relative(webRoot, f)).join(', ');
    const suffix = phpFiles.length > 10 ? ` (and ${phpFiles.length - 10} more)` : '';
    return {
      id: 'HARD-009',
      name: 'PHP Files in Uploads Directory',
      category: 'file-permissions',
      status: 'fail',
      severity: 'critical',
      message: `Found ${phpFiles.length} PHP file(s) in wp-content/uploads`,
      details: `PHP files found in uploads: ${fileList}${suffix}. PHP files in the uploads directory are a strong indicator of a web shell or backdoor. WordPress uploads should only contain media files (images, documents, etc.).`,
      recommendation: 'Investigate and remove PHP files from wp-content/uploads. Add a rule to block PHP execution in uploads: .htaccess: <Files "*.php"> deny from all </Files>',
      reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
    };
  }

  return {
    id: 'HARD-009',
    name: 'PHP Files in Uploads Directory',
    category: 'file-permissions',
    status: 'pass',
    severity: 'critical',
    message: 'No PHP files found in wp-content/uploads',
    details: 'The uploads directory is clean of PHP files, which is the expected state for a secure WordPress installation.',
    recommendation: 'Consider adding a .htaccess rule to block PHP execution in the uploads directory as a preventive measure.',
    reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
  };
}

function checkHARD010(targetPath: string): HardeningCheck {
  const webRoot = getWebRoot(targetPath);
  const wpIncludesDir = path.join(webRoot, 'wp-includes');

  if (!dirExists(wpIncludesDir)) {
    return {
      id: 'HARD-010',
      name: 'wp-includes PHP Files Writable',
      category: 'file-permissions',
      status: 'info',
      severity: 'high',
      message: 'wp-includes directory not found',
      details: 'Could not locate the wp-includes directory.',
      recommendation: 'Ensure WordPress core files are properly installed.',
    };
  }

  let worldWritableCount = 0;
  let totalPhpFiles = 0;
  try {
    const entries = fs.readdirSync(wpIncludesDir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isFile() && entry.name.endsWith('.php')) {
        totalPhpFiles++;
        const filePath = path.join(wpIncludesDir, entry.name);
        const perms = checkFilePermissions(filePath);
        if (perms !== null && (perms & 0o002) !== 0) {
          worldWritableCount++;
        }
      }
    }
  } catch {
    return {
      id: 'HARD-010',
      name: 'wp-includes PHP Files Writable',
      category: 'file-permissions',
      status: 'info',
      severity: 'high',
      message: 'Could not read wp-includes directory',
      details: 'Unable to check file permissions in wp-includes.',
      recommendation: 'Ensure core PHP files are not world-writable.',
    };
  }

  if (worldWritableCount > 0) {
    return {
      id: 'HARD-010',
      name: 'wp-includes PHP Files Writable',
      category: 'file-permissions',
      status: 'fail',
      severity: 'high',
      message: `${worldWritableCount} of ${totalPhpFiles} PHP files in wp-includes are world-writable`,
      details: `${worldWritableCount} PHP files in wp-includes have world-writable permissions (other write bit set). Core WordPress files should never be world-writable as any process on the system could modify them.`,
      recommendation: 'Fix permissions: find wp-includes -name "*.php" -exec chmod o-w {} \\;',
      reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
    };
  }

  return {
    id: 'HARD-010',
    name: 'wp-includes PHP Files Writable',
    category: 'file-permissions',
    status: 'pass',
    severity: 'high',
    message: `All ${totalPhpFiles} PHP files in wp-includes have appropriate permissions`,
    details: 'No world-writable PHP files were found in wp-includes. Core WordPress files are properly secured.',
    recommendation: 'Maintain restrictive file permissions on core WordPress files.',
    reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
  };
}

// ─── NETWORK CHECKS ──────────────────────────────────────────────────────────

function checkHARD011(targetPath: string): HardeningCheck {
  const webRoot = getWebRoot(targetPath);
  const xmlrpcPath = path.join(webRoot, 'xmlrpc.php');

  if (fileExists(xmlrpcPath)) {
    return {
      id: 'HARD-011',
      name: 'XML-RPC Enabled',
      category: 'network',
      status: 'warning',
      severity: 'medium',
      message: 'xmlrpc.php exists and is accessible',
      details: 'The xmlrpc.php file is present. XML-RPC can be exploited for brute force attacks (using system.multicall), DDoS amplification, and pingback-based attacks. Unless specifically needed for remote publishing or Jetpack, it should be disabled.',
      recommendation: 'Disable XML-RPC via a plugin (e.g., Disable XML-RPC) or by adding a .htaccess rule to block access to xmlrpc.php.',
      reference: 'https://codex.wordpress.org/XML-RPC_Support',
    };
  }

  return {
    id: 'HARD-011',
    name: 'XML-RPC Enabled',
    category: 'network',
    status: 'pass',
    severity: 'medium',
    message: 'xmlrpc.php not found',
    details: 'The XML-RPC endpoint is not present, reducing the attack surface.',
    recommendation: 'Keep XML-RPC disabled unless required for specific functionality.',
    reference: 'https://codex.wordpress.org/XML-RPC_Support',
  };
}

function checkHARD012(targetPath: string): HardeningCheck {
  const webRoot = getWebRoot(targetPath);
  const directories = ['wp-content', 'wp-includes', 'wp-admin', 'uploads'];
  const missingIndex: string[] = [];

  for (const dir of directories) {
    const dirPath = path.join(webRoot, dir);
    if (dirExists(dirPath)) {
      const indexPhp = path.join(dirPath, 'index.php');
      const indexHtml = path.join(dirPath, 'index.html');
      if (!fileExists(indexPhp) && !fileExists(indexHtml)) {
        missingIndex.push(dir);
      }
    }
  }

  if (missingIndex.length > 0) {
    return {
      id: 'HARD-012',
      name: 'Directory Listing Exposed',
      category: 'network',
      status: 'warning',
      severity: 'medium',
      message: `Missing index files in directories: ${missingIndex.join(', ')}`,
      details: `The following directories lack an index.php or index.html file: ${missingIndex.join(', ')}. Without an index file, web servers may display a directory listing, exposing file names and structure to visitors.`,
      recommendation: 'Add an empty index.php file to each directory: echo "<?php // Silence is golden." > index.php',
      reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
    };
  }

  return {
    id: 'HARD-012',
    name: 'Directory Listing Exposed',
    category: 'network',
    status: 'pass',
    severity: 'medium',
    message: 'All key directories have index files',
    details: 'All checked directories contain index.php or index.html, preventing directory listing.',
    recommendation: 'Ensure all directories have index files to prevent directory exposure.',
    reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
  };
}

function checkHARD013(targetPath: string): HardeningCheck {
  const webRoot = getWebRoot(targetPath);
  const debugLogPath = path.join(webRoot, 'debug.log');
  const wpContentDebugLog = path.join(webRoot, 'wp-content', 'debug.log');

  const foundPaths: string[] = [];
  if (fileExists(debugLogPath)) foundPaths.push('debug.log');
  if (fileExists(wpContentDebugLog)) foundPaths.push('wp-content/debug.log');

  if (foundPaths.length > 0) {
    return {
      id: 'HARD-013',
      name: 'debug.log Exposed',
      category: 'network',
      status: 'fail',
      severity: 'high',
      message: `debug.log file(s) found: ${foundPaths.join(', ')}`,
      details: `WordPress debug log files found at ${foundPaths.join(' and ')}. These files can contain PHP errors, database queries, file paths, and other sensitive information that attackers can use to map the site\'s internals.`,
      recommendation: 'Remove debug.log files from the web root and disable WP_DEBUG_LOG. If logging is needed, ensure logs are stored outside the web root.',
      reference: 'https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/',
    };
  }

  return {
    id: 'HARD-013',
    name: 'debug.log Exposed',
    category: 'network',
    status: 'pass',
    severity: 'high',
    message: 'No debug.log files found in web root',
    details: 'No debug log files are exposed in the web root directory.',
    recommendation: 'Ensure debug logs are stored outside the web root if debug logging is enabled.',
    reference: 'https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/',
  };
}

function checkHARD014(targetPath: string): HardeningCheck {
  const webRoot = getWebRoot(targetPath);
  const readmeHtml = path.join(webRoot, 'readme.html');

  if (fileExists(readmeHtml)) {
    return {
      id: 'HARD-014',
      name: 'readme.html Exposed',
      category: 'network',
      status: 'info',
      severity: 'low',
      message: 'readme.html is present in the web root',
      details: 'The WordPress readme.html file is publicly accessible. This file reveals the exact WordPress version, which attackers can use to identify known vulnerabilities for that version.',
      recommendation: 'Remove readme.html: rm readme.html, or restrict access via .htaccess.',
      reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
    };
  }

  return {
    id: 'HARD-014',
    name: 'readme.html Exposed',
    category: 'network',
    status: 'pass',
    severity: 'low',
    message: 'readme.html not found',
    details: 'The WordPress readme.html file is not present, preventing version disclosure.',
    recommendation: 'Keep readme.html removed from the web root.',
    reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
  };
}

function checkHARD015(targetPath: string): HardeningCheck {
  const webRoot = getWebRoot(targetPath);
  const extensions = ['.bak', '.old', '.orig', '.save', '.swp'];
  const foundBackups: string[] = [];

  for (const ext of extensions) {
    const backupPath = path.join(webRoot, `wp-config${ext}`);
    if (fileExists(backupPath)) {
      foundBackups.push(`wp-config${ext}`);
    }
  }

  if (foundBackups.length > 0) {
    return {
      id: 'HARD-015',
      name: 'wp-config.php Backup Exposed',
      category: 'network',
      status: 'fail',
      severity: 'critical',
      message: `Backup copies of wp-config.php found: ${foundBackups.join(', ')}`,
      details: `Backup files of wp-config.php found: ${foundBackups.join(', ')}. These files contain database credentials, authentication keys and salts, and other sensitive configuration. They can be downloaded directly by attackers.`,
      recommendation: 'Immediately remove all backup copies of wp-config.php from the web root. Store backups outside the web-accessible directory.',
      reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
    };
  }

  return {
    id: 'HARD-015',
    name: 'wp-config.php Backup Exposed',
    category: 'network',
    status: 'pass',
    severity: 'critical',
    message: 'No backup copies of wp-config.php found',
    details: 'No .bak, .old, .orig, .save, or .swp copies of wp-config.php were found in the web root.',
    recommendation: 'Store backups of wp-config.php outside the web root.',
    reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
  };
}

// ─── AUTHENTICATION CHECKS ───────────────────────────────────────────────────

function checkHARD016(targetPath: string): HardeningCheck {
  const wpConfig = getWpConfigPath(targetPath);
  const webRoot = getWebRoot(targetPath);

  if (!wpConfig) {
    return {
      id: 'HARD-016',
      name: 'Default Admin Username',
      category: 'authentication',
      status: 'info',
      severity: 'high',
      message: 'wp-config.php not found — cannot verify database connection',
      details: 'Could not locate wp-config.php. Unable to determine if the default "admin" username is in use.',
      recommendation: 'Ensure WordPress is properly configured.',
    };
  }

  const wpConfigContent = readFileSafe(wpConfig);
  if (wpConfigContent) {
    const dbUserMatch = wpConfigContent.match(/define\s*\(\s*['"]DB_USER['"]\s*,\s*['"](.+?)['"]\s*\)/i);
    if (dbUserMatch && dbUserMatch[1] === 'admin') {
      return {
        id: 'HARD-016',
        name: 'Default Admin Username',
        category: 'authentication',
        status: 'fail',
        severity: 'high',
        message: 'Database user appears to be "admin"',
        details: 'The DB_USER in wp-config.php is set to "admin". While this is the database user and not the WordPress admin username, using "admin" as the DB user is a poor security practice.',
        recommendation: 'Use a non-obvious database username that is different from the WordPress admin account.',
        reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
      };
    }
  }

  return {
    id: 'HARD-016',
    name: 'Default Admin Username',
    category: 'authentication',
    status: 'pass',
    severity: 'high',
    message: 'No obvious default "admin" username detected',
    details: 'The database credentials in wp-config.php do not use the common "admin" username. Note: This check cannot verify WordPress user table entries directly without database access.',
    recommendation: 'Ensure no WordPress user accounts use the username "admin". Change it via the database if found.',
    reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
  };
}

function checkHARD017(targetPath: string): HardeningCheck {
  const webRoot = getWebRoot(targetPath);
  const wpLoginPath = path.join(webRoot, 'wp-login.php');

  if (fileExists(wpLoginPath)) {
    return {
      id: 'HARD-017',
      name: 'Login URL Exposed',
      category: 'authentication',
      status: 'info',
      severity: 'info',
      message: 'wp-login.php is present at the default location',
      details: 'The default WordPress login page (wp-login.php) exists. This is the standard login endpoint and is expected, but it can be targeted by brute force attacks.',
      recommendation: 'Consider using a login customizer plugin to change the login URL, or implement rate limiting and 2FA.',
      reference: 'https://developer.wordpress.org/advanced-administration/security/login-security/',
    };
  }

  return {
    id: 'HARD-017',
    name: 'Login URL Exposed',
    category: 'authentication',
    status: 'info',
    severity: 'info',
    message: 'wp-login.php not found at default location',
    details: 'The default login file is not present, which may indicate a custom login URL or WordPress installed in a subdirectory.',
    recommendation: 'Ensure the login URL is properly configured and accessible.',
    reference: 'https://developer.wordpress.org/advanced-administration/security/login-security/',
  };
}

function checkHARD018(targetPath: string): HardeningCheck {
  const webRoot = getWebRoot(targetPath);
  const pluginsDir = path.join(webRoot, 'wp-content', 'plugins');

  if (!dirExists(pluginsDir)) {
    return {
      id: 'HARD-018',
      name: 'Two-Factor Authentication Plugin',
      category: 'authentication',
      status: 'info',
      severity: 'info',
      message: 'wp-content/plugins directory not found',
      details: 'Could not check for two-factor authentication plugins.',
      recommendation: 'Install a 2FA plugin for enhanced login security.',
      reference: 'https://developer.wordpress.org/advanced-administration/security/login-security/',
    };
  }

  const twoFactorPlugins = [
    'wordfence',
    'google-authenticator',
    'two-factor',
    'wp-2fa',
    'clef',
    'duo-wordpress',
    'miniorange-2-factor',
    'rublon',
    'authy',
    'totp',
  ];

  const installedPlugins = twoFactorPlugins.filter(plugin => {
    const pluginDir = path.join(pluginsDir, plugin);
    if (dirExists(pluginDir)) return true;
    const pluginDirHyphen = path.join(pluginsDir, plugin.replace(/-/g, '_'));
    if (dirExists(pluginDirHyphen)) return true;
    const pluginDirCamel = path.join(pluginsDir, plugin.replace(/-./g, match => match[1].toUpperCase()));
    if (dirExists(pluginDirCamel)) return true;
    return false;
  });

  if (installedPlugins.length > 0) {
    return {
      id: 'HARD-018',
      name: 'Two-Factor Authentication Plugin',
      category: 'authentication',
      status: 'pass',
      severity: 'info',
      message: `Two-factor authentication plugin detected: ${installedPlugins.join(', ')}`,
      details: `A two-factor authentication plugin appears to be installed (${installedPlugins.join(', ')}). This significantly improves login security by requiring a second verification factor.`,
      recommendation: 'Ensure 2FA is enabled and configured for all administrator accounts.',
      reference: 'https://developer.wordpress.org/advanced-administration/security/login-security/',
    };
  }

  return {
    id: 'HARD-018',
    name: 'Two-Factor Authentication Plugin',
    category: 'authentication',
    status: 'info',
    severity: 'info',
    message: 'No two-factor authentication plugin detected',
    details: 'No popular two-factor authentication plugins were found in the plugins directory. While some themes may bundle 2FA functionality, this check looks for standalone plugins.',
    recommendation: 'Consider installing a two-factor authentication plugin such as "Two Factor" or "Wordfence Login Security".',
    reference: 'https://developer.wordpress.org/advanced-administration/security/login-security/',
  };
}

// ─── DATABASE CHECKS ─────────────────────────────────────────────────────────

function checkHARD019(targetPath: string): HardeningCheck {
  const wpConfig = getWpConfigPath(targetPath);
  const defines = wpConfig ? extractWpConfigDefines(wpConfig) : new Map();
  const tablePrefix = defines.get('table_prefix');

  if (tablePrefix) {
    const cleanPrefix = tablePrefix.replace(/['"]/g, '').trim();
    if (cleanPrefix === 'wp_') {
      return {
        id: 'HARD-019',
        name: 'Default Table Prefix',
        category: 'database',
        status: 'warning',
        severity: 'low',
        message: 'WordPress is using the default "wp_" table prefix',
        details: 'The database uses the default wp_ table prefix. While not a direct vulnerability, changing the default prefix can make certain SQL injection attacks more difficult.',
        recommendation: 'Change the table prefix in wp-config.php to a unique value (e.g., "wp_x7k2_") and update the database tables accordingly.',
        reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
      };
    }
    return {
      id: 'HARD-019',
      name: 'Default Table Prefix',
      category: 'database',
      status: 'pass',
      severity: 'low',
      message: `Custom table prefix is configured: "${cleanPrefix}"`,
      details: `A custom table prefix "${cleanPrefix}" is in use, which is a good security practice.`,
      recommendation: 'Maintain a non-default table prefix.',
      reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
    };
  }

  return {
    id: 'HARD-019',
    name: 'Default Table Prefix',
    category: 'database',
    status: 'info',
    severity: 'low',
    message: 'Could not determine table prefix from wp-config.php',
    details: 'The table_prefix variable was not found in wp-config.php. The default "wp_" prefix is likely in use.',
    recommendation: 'Set a custom table prefix: $table_prefix = "wp_custom_";',
    reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
  };
}

function checkHARD020(targetPath: string): HardeningCheck {
  const wpConfig = getWpConfigPath(targetPath);
  const defines = wpConfig ? extractWpConfigDefines(wpConfig) : new Map();
  const dbPassword = defines.get('DB_PASSWORD');

  if (dbPassword) {
    return {
      id: 'HARD-020',
      name: 'DB Credentials in wp-config',
      category: 'database',
      status: 'info',
      severity: 'info',
      message: 'DB_PASSWORD is defined in wp-config.php',
      details: 'Database password is configured in wp-config.php. This is the standard way to store WordPress database credentials. Verify the file permissions are restrictive (640 or lower).',
      recommendation: 'Ensure wp-config.php has restrictive permissions and is stored securely.',
      reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
    };
  }

  return {
    id: 'HARD-020',
    name: 'DB Credentials in wp-config',
    category: 'database',
    status: 'warning',
    severity: 'info',
    message: 'DB_PASSWORD not found in wp-config.php',
    details: 'No DB_PASSWORD definition was found in wp-config.php. The database password may be configured through environment variables or another method.',
    recommendation: 'Ensure database credentials are properly configured.',
    reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
  };
}

// ─── SERVER CHECKS ───────────────────────────────────────────────────────────

function checkHARD021(targetPath: string): HardeningCheck {
  const webRoot = getWebRoot(targetPath);
  const readmeHtml = path.join(webRoot, 'readme.html');
  const readmeMd = path.join(webRoot, 'readme.md');

  let content = readFileSafe(readmeHtml);
  if (!content) content = readFileSafe(readmeMd);

  if (content) {
    const php8Match = content.match(/PHP\s*(?:version\s*)?8\.\d+/i);
    const php7Match = content.match(/PHP\s*(?:version\s*)?7\.\d+/i);

    if (php8Match) {
      return {
        id: 'HARD-021',
        name: 'PHP Version Check',
        category: 'server',
        status: 'pass',
        severity: 'info',
        message: `PHP version reference found: ${php8Match[0]}`,
        details: `WordPress readme references PHP ${php8Match[0]}, which is a modern version. PHP 8.x provides better security features and performance.`,
        recommendation: 'Ensure the server is running a supported PHP version (8.0+).',
        reference: 'https://wordpress.org/about/requirements/',
      };
    }

    if (php7Match) {
      return {
        id: 'HARD-021',
        name: 'PHP Version Check',
        category: 'server',
        status: 'info',
        severity: 'info',
        message: `PHP version reference found: ${php7Match[0]}`,
        details: `WordPress readme references PHP ${php7Match[0]}. While PHP 7.x still receives some support, PHP 8.x is recommended for better security.`,
        recommendation: 'Consider upgrading to PHP 8.0 or later for improved security and performance.',
        reference: 'https://wordpress.org/about/requirements/',
      };
    }
  }

  return {
    id: 'HARD-021',
    name: 'PHP Version Check',
    category: 'server',
    status: 'info',
    severity: 'info',
    message: 'Could not determine PHP version from WordPress files',
    details: 'No PHP version references were found in WordPress readme files. The server PHP version cannot be determined from file analysis alone.',
    recommendation: 'Verify the server is running PHP 8.0 or later for optimal security.',
    reference: 'https://wordpress.org/about/requirements/',
  };
}

function checkHARD022(targetPath: string): HardeningCheck {
  const webRoot = getWebRoot(targetPath);
  const envFiles = ['.env', '.env.local', '.env.production', '.env.staging', '.env.development', '.env.backup', '.env.old'];
  const foundEnvFiles: string[] = [];

  for (const envFile of envFiles) {
    const envPath = path.join(webRoot, envFile);
    if (fileExists(envPath)) {
      foundEnvFiles.push(envFile);
    }
  }

  if (foundEnvFiles.length > 0) {
    return {
      id: 'HARD-022',
      name: 'Exposed .env Files',
      category: 'server',
      status: 'fail',
      severity: 'critical',
      message: `Sensitive .env files found in web root: ${foundEnvFiles.join(', ')}`,
      details: `.env files found: ${foundEnvFiles.join(', ')}. These files often contain database credentials, API keys, secret keys, and other sensitive configuration that can be downloaded directly by attackers.`,
      recommendation: 'Move .env files outside the web root or block access via .htaccess: <Files ".env"> deny from all </Files>',
      reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
    };
  }

  return {
    id: 'HARD-022',
    name: 'Exposed .env Files',
    category: 'server',
    status: 'pass',
    severity: 'critical',
    message: 'No .env files found in web root',
    details: 'No environment configuration files are exposed in the web root.',
    recommendation: 'Store .env files outside the web root if used.',
    reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
  };
}

function checkHARD023(targetPath: string): HardeningCheck {
  const webRoot = getWebRoot(targetPath);
  const gitDir = path.join(webRoot, '.git');
  const gitFile = path.join(webRoot, '.git');

  if (dirExists(gitDir)) {
    return {
      id: 'HARD-023',
      name: 'Exposed .git Directory',
      category: 'server',
      status: 'fail',
      severity: 'critical',
      message: '.git directory found in web root',
      details: 'A .git directory exists in the web root. This exposes the entire Git repository history, including source code, configuration files, credentials in commit history, and other sensitive data. Attackers can reconstruct the complete codebase and extract secrets.',
      recommendation: 'Remove the .git directory from the web root and add it to .gitignore. Block access: <Directory ".git"> deny from all </Directory>',
      reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
    };
  }

  return {
    id: 'HARD-023',
    name: 'Exposed .git Directory',
    category: 'server',
    status: 'pass',
    severity: 'critical',
    message: 'No .git directory found in web root',
    details: 'The Git repository directory is not exposed in the web root.',
    recommendation: 'Never deploy .git directories to production servers.',
    reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
  };
}

function checkHARD024(targetPath: string): HardeningCheck {
  const webRoot = getWebRoot(targetPath);
  const svnDir = path.join(webRoot, '.svn');

  if (dirExists(svnDir)) {
    return {
      id: 'HARD-024',
      name: 'Exposed .svn Directory',
      category: 'server',
      status: 'fail',
      severity: 'medium',
      message: '.svn directory found in web root',
      details: 'A .svn directory exists in the web root. This exposes the Subversion repository metadata, which can reveal source code, directory structure, and potentially sensitive information from version control.',
      recommendation: 'Remove the .svn directory from the web root. Use a proper deployment process that excludes version control directories.',
      reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
    };
  }

  return {
    id: 'HARD-024',
    name: 'Exposed .svn Directory',
    category: 'server',
    status: 'pass',
    severity: 'medium',
    message: 'No .svn directory found in web root',
    details: 'The Subversion directory is not exposed in the web root.',
    recommendation: 'Never deploy version control directories to production servers.',
    reference: 'https://developer.wordpress.org/advanced-administration/security/hardening/',
  };
}

function checkHARD025(targetPath: string): HardeningCheck {
  const webRoot = getWebRoot(targetPath);
  const composerJson = path.join(webRoot, 'composer.json');
  const composerLock = path.join(webRoot, 'composer.lock');
  const vendorDir = path.join(webRoot, 'vendor');

  const found: string[] = [];
  if (fileExists(composerJson)) found.push('composer.json');
  if (fileExists(composerLock)) found.push('composer.lock');
  if (dirExists(vendorDir)) found.push('vendor/');

  if (found.length > 0) {
    return {
      id: 'HARD-025',
      name: 'Exposed Composer/Vendor',
      category: 'server',
      status: 'warning',
      severity: 'low',
      message: `Composer files found in web root: ${found.join(', ')}`,
      details: `Composer files found: ${found.join(', ')}. While these are common in WordPress with Composer, exposing composer.json in the web root can reveal project dependencies and their versions, which attackers can use to identify known vulnerabilities.`,
      recommendation: 'Move composer files outside the web root, or add them to .htaccess deny rules. Use "composer install --no-dev" for production.',
      reference: 'https://getcomposer.org/doc/03-cli.md#install',
    };
  }

  return {
    id: 'HARD-025',
    name: 'Exposed Composer/Vendor',
    category: 'server',
    status: 'pass',
    severity: 'low',
    message: 'No Composer files found in web root',
    details: 'No composer.json, composer.lock, or vendor directory found in the web root.',
    recommendation: 'Keep Composer files outside the web root in production.',
    reference: 'https://getcomposer.org/doc/03-cli.md#install',
  };
}

// ─── SCORE CALCULATION ───────────────────────────────────────────────────────

export function calculateScore(checks: HardeningCheck[]): number {
  if (checks.length === 0) return 0;
  const passed = checks.filter(c => c.status === 'pass').length;
  return Math.round((passed / checks.length) * 100);
}

// ─── MAIN FUNCTION ───────────────────────────────────────────────────────────

export function runHardeningChecks(targetPath: string): HardeningResult {
  const startTime = Date.now();
  const checks: HardeningCheck[] = [
    checkHARD001(targetPath),
    checkHARD002(targetPath),
    checkHARD003(targetPath),
    checkHARD004(targetPath),
    checkHARD005(targetPath),
    checkHARD006(targetPath),
    checkHARD007(targetPath),
    checkHARD008(targetPath),
    checkHARD009(targetPath),
    checkHARD010(targetPath),
    checkHARD011(targetPath),
    checkHARD012(targetPath),
    checkHARD013(targetPath),
    checkHARD014(targetPath),
    checkHARD015(targetPath),
    checkHARD016(targetPath),
    checkHARD017(targetPath),
    checkHARD018(targetPath),
    checkHARD019(targetPath),
    checkHARD020(targetPath),
    checkHARD021(targetPath),
    checkHARD022(targetPath),
    checkHARD023(targetPath),
    checkHARD024(targetPath),
    checkHARD025(targetPath),
  ];

  const duration = Date.now() - startTime;
  const passed = checks.filter(c => c.status === 'pass').length;
  const failed = checks.filter(c => c.status === 'fail').length;
  const warnings = checks.filter(c => c.status === 'warning').length;

  return {
    targetPath,
    totalChecks: checks.length,
    passed,
    failed,
    warnings,
    score: calculateScore(checks),
    checks,
    scanDate: new Date().toISOString(),
    duration,
  };
}
