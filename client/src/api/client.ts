import axios from 'axios';
import type { ScanSummary, ScanHistoryItem, DashboardStats, CustomRule, TrendDataPoint, ThemeScanResult, ThemeScanHistoryItem, DatabaseScanResult, QuarantineRecord, RemediationPlan, FalsePositive, AttackChain, TimelineEvent, SiteStatus } from '../types';

const api = axios.create({ baseURL: '/api' });

export async function scanByPath(path: string): Promise<ScanSummary> {
  const { data } = await api.post('/scan', { path });
  return data;
}

export async function uploadAndScan(file: File): Promise<ScanSummary> {
  const formData = new FormData();
  formData.append('file', file);
  const { data } = await api.post('/upload', formData);
  return data;
}

export async function getScan(id: string): Promise<ScanSummary> {
  const { data } = await api.get(`/scan/${id}`);
  return data;
}

export async function getHistory(limit = 50, offset = 0): Promise<ScanHistoryItem[]> {
  const { data } = await api.get('/history', { params: { limit, offset } });
  return data;
}

export async function deleteScan(id: string): Promise<void> {
  await api.delete(`/scan/${id}`);
}

export async function getStats(): Promise<DashboardStats> {
  const { data } = await api.get('/stats');
  return data;
}

export async function compareScans(id1: string, id2: string): Promise<any> {
  const { data } = await api.post('/compare', { scanId1: id1, scanId2: id2 });
  return data;
}

export function getReportUrl(id: string, format: string): string {
  return `/api/report/${id}/${format}`;
}

export async function getTrend(): Promise<TrendDataPoint[]> {
  const { data } = await api.get('/trend');
  return data;
}

export async function getCustomRules(): Promise<CustomRule[]> {
  const { data } = await api.get('/rules');
  return data;
}

export async function saveCustomRule(rule: Partial<CustomRule>): Promise<CustomRule> {
  const { data } = await api.post('/rules', rule);
  return data;
}

export async function deleteCustomRule(id: string): Promise<void> {
  await api.delete(`/rules/${id}`);
}

export async function getBuiltinRules(): Promise<CustomRule[]> {
  const { data } = await api.get('/rules/builtin');
  return data;
}

export async function importRules(yamlContent: string): Promise<{ imported: number; total: number }> {
  const { data } = await api.post('/rules/import', { yamlContent });
  return data;
}

export async function exportRules(): Promise<string> {
  const { data } = await api.get('/rules/export', { responseType: 'text' });
  return data;
}

// Theme Intelligence API
export async function themeScan(themesPath: string, themeName?: string): Promise<ThemeScanResult> {
  const { data } = await api.post('/theme-scan', { themesPath, themeName });
  return data;
}

export async function uploadThemeScan(file: File, themeName?: string): Promise<ThemeScanResult> {
  const formData = new FormData();
  formData.append('file', file);
  if (themeName) formData.append('themeName', themeName);
  const { data } = await api.post('/theme-scan/upload', formData);
  return data;
}

export async function getThemeScanHistory(limit = 50, offset = 0): Promise<ThemeScanHistoryItem[]> {
  const { data } = await api.get('/theme-scan/history', { params: { limit, offset } });
  return data;
}

export async function getThemeScan(id: string): Promise<ThemeScanResult> {
  const { data } = await api.get(`/theme-scan/${id}`);
  return data;
}

export async function deleteThemeScan(id: string): Promise<void> {
  await api.delete(`/theme-scan/${id}`);
}

// Database Scan API
export async function dbScan(config: { host: string; port?: number; database: string; user: string; password: string; tablePrefix?: string }): Promise<DatabaseScanResult> {
  const { data } = await api.post('/db-scan', config);
  return data;
}

export async function getDbScanHistory(limit = 50, offset = 0): Promise<any[]> {
  const { data } = await api.get('/db-scan/history', { params: { limit, offset } });
  return data;
}

// Quarantine API
export async function quarantineFile(filePath: string, reason: string, scanId: string, findingId: string): Promise<QuarantineRecord> {
  const { data } = await api.post('/quarantine', { filePath, reason, scanId, findingId });
  return data;
}

export async function restoreQuarantine(id: string): Promise<void> {
  await api.post(`/quarantine/${id}/restore`);
}

export async function getQuarantineList(): Promise<QuarantineRecord[]> {
  const { data } = await api.get('/quarantine');
  return data;
}

export async function deleteQuarantineFile(id: string): Promise<void> {
  await api.delete(`/quarantine/${id}`);
}

// Remediation API
export async function getRemediationPlan(scanId: string): Promise<RemediationPlan> {
  const { data } = await api.get(`/remediation/${scanId}`);
  return data;
}

// False Positive API
export async function createFalsePositive(fp: { ruleId: string; scope: string; theme?: string; plugin?: string; filePath?: string; fileHash?: string; reason: string }): Promise<FalsePositive> {
  const { data } = await api.post('/false-positives', fp);
  return data;
}

export async function getFalsePositives(): Promise<FalsePositive[]> {
  const { data } = await api.get('/false-positives');
  return data;
}

export async function deleteFalsePositive(id: string): Promise<void> {
  await api.delete(`/false-positives/${id}`);
}

// Timeline API
export async function getTimeline(scanId: string): Promise<TimelineEvent[]> {
  const { data } = await api.get(`/timeline/${scanId}`);
  return data;
}

// Attack Chain API
export async function getAttackChains(scanId: string): Promise<AttackChain[]> {
  const { data } = await api.get(`/attack-chains/${scanId}`);
  return data;
}

// Site Status API
export async function getSiteStatus(scanId: string): Promise<SiteStatus> {
  const { data } = await api.get(`/site-status/${scanId}`);
  return data;
}

// Plugin Intel API
export async function pluginScan(pluginsPath: string, pluginName?: string): Promise<any> {
  const { data } = await api.post('/plugin-scan', { pluginsPath, pluginName });
  return data;
}

export async function uploadPluginScan(file: File): Promise<any> {
  const formData = new FormData();
  formData.append('file', file);
  const { data } = await api.post('/plugin-scan/upload', formData);
  return data;
}

export async function getPluginScanHistory(): Promise<any[]> {
  // Placeholder for future plugin scan history
  return [];
}

// Hardening Check API
export async function hardeningScan(targetPath: string): Promise<any> {
  const { data } = await api.post('/hardening-scan', { targetPath });
  return data;
}

export async function uploadHardeningScan(file: File): Promise<any> {
  const formData = new FormData();
  formData.append('file', file);
  const { data } = await api.post('/hardening-scan/upload', formData);
  return data;
}

// Checksum Verify API
export async function checksumVerify(targetPath: string): Promise<any> {
  const { data } = await api.post('/checksum-verify', { targetPath });
  return data;
}

// MITRE ATT&CK API
export async function getMitreMapping(scanId: string): Promise<any> {
  const { data } = await api.get(`/mitre/${scanId}`);
  return data;
}

// SSE Scan Stream
export function streamScan(targetPath: string, onEvent: (event: { type: string; message?: string; percent?: number; scanId?: string; summary?: any }) => void): EventSource {
  const reqId = crypto.randomUUID();
  const es = new EventSource(`/api/scan-stream/${reqId}?path=${encodeURIComponent(targetPath)}`);

  es.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      onEvent(data);
      if (data.type === 'complete' || data.type === 'error') {
        es.close();
      }
    } catch {}
  };

  es.onerror = () => {
    onEvent({ type: 'error', message: 'Connection lost' });
    es.close();
  };

  return es;
}
