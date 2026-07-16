import axios from 'axios';
import type { ScanSummary, ScanHistoryItem, DashboardStats, CustomRule, TrendDataPoint, ThemeScanResult, ThemeScanHistoryItem } from '../types';

const api = axios.create({ baseURL: '/api' });

export async function scanByPath(path: string): Promise<ScanSummary> {
  const { data } = await api.post('/scan', { path });
  return data;
}

export async function uploadAndScan(file: File): Promise<ScanSummary> {
  const formData = new FormData();
  formData.append('file', file);
  const { data } = await api.post('/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
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
