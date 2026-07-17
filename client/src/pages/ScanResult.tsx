import { useEffect, useState, useMemo } from 'react';
import { useParams } from 'react-router-dom';
import { getScan, getReportUrl } from '../api/client';
import type { ScanSummary, Severity, CheckCategory, CheckResult, Finding } from '../types';
import LoadingSpinner from '../components/LoadingSpinner';
import { useTranslation } from '../i18n';
import { IconDashboard, IconEyeOff, IconGlobe, IconSecurity, IconCode, IconFileSearch, IconServer, IconFileText, IconDownload, IconLightbulb } from '../components/Icons';

const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const sevColors: Record<Severity, string> = { critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-cyan-400', info: 'text-gray-400' };
const sevBg: Record<Severity, string> = { critical: 'bg-red-500/20 text-red-400 border-red-500/30', high: 'bg-orange-500/20 text-orange-400 border-orange-500/30', medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30', low: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30', info: 'bg-gray-500/20 text-gray-400 border-gray-500/30' };
const sevDot: Record<Severity, string> = { critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-cyan-500', info: 'bg-gray-500' };
const confBg: Record<string, string> = { high: 'bg-green-500/20 text-green-400', medium: 'bg-yellow-500/20 text-yellow-400', low: 'bg-gray-500/20 text-gray-400' };
const riskBg = (score: number) => score >= 80 ? 'text-red-400' : score >= 60 ? 'text-orange-400' : score >= 35 ? 'text-yellow-400' : 'text-cyan-400';

interface TabDef {
  id: string;
  labelKey: string;
  icon: React.ReactNode;
  categories: CheckCategory[];
}

export default function ScanResult() {
  const { t, tc } = useTranslation();
  const { id } = useParams();
  const [scan, setScan] = useState<ScanSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const [expandedFile, setExpandedFile] = useState<string | null>(null);
  const [expandedCheck, setExpandedCheck] = useState<string | null>(null);
  const [expandedContext, setExpandedContext] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState<Severity | 'all'>('all');
  const [threatFilter, setThreatFilter] = useState<string>('all');

  const threatTypes = [
    { id: 'all', label: 'All Threats' },
    { id: 'webshell', label: 'Webshell', checkPrefixes: ['SEC-051', 'SEC-052', 'SEC-053', 'SEC-054', 'SEC-055', 'SEC-056', 'SEC-057', 'SEC-058', 'SEC-060', 'SEC-061', 'SEC-065'] },
    { id: 'injection', label: 'Injection', checkPrefixes: ['SEC-066', 'SEC-067', 'SEC-068', 'SEC-069', 'SEC-070', 'SEC-035', 'SEC-036', 'SEC-029', 'SEC-030', 'SEC-024', 'SEC-025', 'WP-018', 'SEC-001', 'SEC-002', 'SEC-021', 'SEC-022', 'SEC-023', 'SEC-026', 'SEC-027'] },
    { id: 'backdoor', label: 'Backdoor', checkPrefixes: ['SEC-006', 'SEC-007', 'SEC-008', 'SEC-009', 'SEC-010', 'SEC-046', 'SEC-047', 'SEC-048', 'SEC-059', 'SEC-062', 'SEC-063', 'SEC-064', 'WP-012', 'WP-015'] },
    { id: 'redirect', label: 'Redirect/Inject', checkPrefixes: ['SEC-026', 'WP-014', 'SEC-031'] },
    { id: 'secrets', label: 'Secrets/Creds', checkPrefixes: ['SEC-071', 'SEC-072', 'SEC-073', 'SEC-074', 'SEC-075', 'SEC-076', 'SEC-077', 'SEC-078', 'SEC-079', 'SEC-080', 'SEC-081', 'SEC-082', 'SEC-083', 'SEC-084', 'SEC-085', 'SEC-018', 'SEC-038'] },
  ];

  const TABS: TabDef[] = [
    { id: 'overview', labelKey: t.scanResult.overview, icon: <IconDashboard size={16} />, categories: [] },
    { id: 'obfuscation', labelKey: t.scanResult.obfuscatedFiles, icon: <IconEyeOff size={16} />, categories: ['obfuscation'] },
    { id: 'external', labelKey: t.scanResult.externalAccess, icon: <IconGlobe size={16} />, categories: ['external-access'] },
    { id: 'security', labelKey: t.scanResult.securityIssues, icon: <IconSecurity size={16} />, categories: ['security'] },
    { id: 'code', labelKey: t.scanResult.codePatterns, icon: <IconCode size={16} />, categories: ['code-pattern'] },
    { id: 'files', labelKey: t.scanResult.fileAnalysis, icon: <IconFileSearch size={16} />, categories: ['file-analysis'] },
    { id: 'wordpress', labelKey: t.scanResult.wordpress, icon: <IconServer size={16} />, categories: ['wordpress'] },
  ];

  useEffect(() => {
    if (!id) return;
    getScan(id).then(setScan).finally(() => setLoading(false));
  }, [id]);

  const activeTabDef = TABS.find(t => t.id === activeTab)!;

  const tabResults = useMemo(() => {
    if (!scan) return [];
    let results = scan.results.filter(r => r.findings.length > 0);
    if (activeTabDef.categories.length > 0) {
      results = results.filter(r => activeTabDef.categories.includes(r.category));
    }
    if (sevFilter !== 'all') results = results.filter(r => r.severity === sevFilter);
    if (threatFilter !== 'all') {
      const threatDef = threatTypes.find(t => t.id === threatFilter);
      if (threatDef?.checkPrefixes) {
        results = results.filter(r => threatDef.checkPrefixes.some(p => r.checkId.startsWith(p)));
      }
    }
    if (search) {
      const q = search.toLowerCase();
      results = results.filter(r =>
        r.checkName.toLowerCase().includes(q) ||
        r.checkId.toLowerCase().includes(q) ||
        r.findings.some(f => f.message.toLowerCase().includes(q) || f.file.toLowerCase().includes(q))
      );
    }
    return results;
  }, [scan, activeTab, sevFilter, threatFilter, search]);

  const fileGrouped = useMemo(() => {
    const map = new Map<string, { findings: Finding[]; checks: CheckResult[] }>();
    for (const result of tabResults) {
      for (const f of result.findings) {
        if (!map.has(f.file)) map.set(f.file, { findings: [], checks: [] });
        map.get(f.file)!.findings.push(f);
        if (!map.get(f.file)!.checks.includes(result)) map.get(f.file)!.checks.push(result);
      }
    }
    return Array.from(map.entries()).sort((a, b) => b[1].findings.length - a[1].findings.length);
  }, [tabResults]);

  const tabTotalFindings = tabResults.reduce((sum, r) => sum + r.findings.length, 0);
  const tabSeverityCounts = useMemo(() => {
    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const r of tabResults) counts[r.severity] += r.findings.length;
    return counts;
  }, [tabResults]);

  const riskScore = useMemo(() => {
    if (!scan) return 0;
    const s = scan.bySeverity;
    return s.critical * 10 + s.high * 5 + s.medium * 2 + s.low * 1;
  }, [scan]);

  const riskLevel = riskScore >= 50 ? t.severity.critical : riskScore >= 20 ? t.severity.high : riskScore >= 5 ? t.severity.medium : t.severity.low;
  const riskColor = riskScore >= 50 ? 'text-red-400' : riskScore >= 20 ? 'text-orange-400' : riskScore >= 5 ? 'text-yellow-400' : 'text-green-400';

  if (loading) return <LoadingSpinner text={t.scanResult.loadingResults} />;
  if (!scan) return <div className="text-center py-20 text-dark-500">{t.scanResult.scanNotFound}</div>;

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold text-white">{scan.targetName}</h1>
          <p className="text-dark-500 mt-1">{new Date(scan.scanDate).toLocaleString()} | {scan.duration}ms | {scan.totalFiles} {t.scanResult.files} | {scan.phpFiles} PHP</p>
        </div>
        <div className="flex gap-2">
          <a href={getReportUrl(scan.id, 'pdf')} className="bg-red-600 hover:bg-red-500 text-white px-4 py-2 rounded-lg text-sm transition-colors font-medium flex items-center gap-1.5"><IconFileText size={14} /> PDF</a>
          <a href={getReportUrl(scan.id, 'html')} className="bg-dark-700 hover:bg-dark-600 text-white px-4 py-2 rounded-lg text-sm transition-colors flex items-center gap-1.5"><IconDownload size={14} /> HTML</a>
          <a href={getReportUrl(scan.id, 'json')} className="bg-dark-700 hover:bg-dark-600 text-white px-4 py-2 rounded-lg text-sm transition-colors flex items-center gap-1.5"><IconDownload size={14} /> JSON</a>
          <a href={getReportUrl(scan.id, 'csv')} className="bg-dark-700 hover:bg-dark-600 text-white px-4 py-2 rounded-lg text-sm transition-colors flex items-center gap-1.5"><IconDownload size={14} /> CSV</a>
        </div>
      </div>

      {/* Risk Score + Severity Cards */}
      <div className="grid grid-cols-8 gap-3 mb-6">
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-4 text-center col-span-1">
          <div className={`text-3xl font-bold ${riskColor}`}>{riskScore}</div>
          <div className="text-xs text-dark-500 mt-1">{t.scanResult.riskScore}</div>
          <div className={`text-xs font-bold mt-1 ${riskColor}`}>{riskLevel}</div>
        </div>
        {severityOrder.map(s => (
          <div key={s} className={`bg-dark-800 border border-dark-700 rounded-xl p-4 text-center cursor-pointer hover:border-dark-500 transition-all ${sevFilter === s ? 'ring-2 ring-blue-500 border-blue-500' : ''}`}
            onClick={() => setSevFilter(sevFilter === s ? 'all' : s)}>
            <div className={`text-2xl font-bold ${sevColors[s]}`}>{scan.bySeverity[s]}</div>
            <div className="text-xs text-dark-500 mt-1">{t.severity[s]}</div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-dark-800 border border-dark-700 rounded-xl p-1 mb-6 overflow-x-auto">
        {TABS.map(tab => {
          const count = tab.categories.length > 0
            ? scan.results.filter(r => tab.categories.includes(r.category)).reduce((s, r) => s + r.findings.length, 0)
            : scan.totalFindings;
          return (
            <button key={tab.id} onClick={() => { setActiveTab(tab.id); setExpandedFile(null); setExpandedCheck(null); }}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all whitespace-nowrap ${activeTab === tab.id ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/20' : 'text-dark-500 hover:text-gray-300 hover:bg-dark-700'}`}>
              <span className="flex-shrink-0">{tab.icon}</span>
              <span>{tab.labelKey}</span>
              {count > 0 && <span className={`text-xs px-1.5 py-0.5 rounded-full ${activeTab === tab.id ? 'bg-blue-500/30' : 'bg-dark-700'}`}>{count}</span>}
            </button>
          );
        })}
      </div>

      {/* Search + Threat Filter */}
      <div className="flex gap-3 mb-6">
        <input type="text" value={search} onChange={e => setSearch(e.target.value)}
          placeholder={t.scanResult.searchPlaceholder}
          className="flex-1 bg-dark-800 border border-dark-700 rounded-lg px-4 py-2.5 text-white placeholder:text-dark-600 focus:border-blue-500 focus:outline-none text-sm" />
        {search && <button onClick={() => setSearch('')} className="bg-dark-700 hover:bg-dark-600 text-white px-3 py-2 rounded-lg text-sm">✕</button>}
        <div className="relative">
          <select value={threatFilter} onChange={e => setThreatFilter(e.target.value)}
            className="bg-dark-800 border border-dark-700 rounded-lg px-4 py-2.5 text-white text-sm appearance-none cursor-pointer pr-8 focus:border-blue-500 focus:outline-none">
            {threatTypes.map(tt => <option key={tt.id} value={tt.id}>{tt.label}</option>)}
          </select>
          <span className="absolute right-2 top-1/2 -translate-y-1/2 text-dark-500 pointer-events-none text-xs">▼</span>
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' ? (
        <OverviewTab scan={scan} riskScore={riskScore} />
      ) : (
        <FileGroupedTab
          fileGrouped={fileGrouped}
          tabResults={tabResults}
          tabTotalFindings={tabTotalFindings}
          tabSeverityCounts={tabSeverityCounts}
          expandedFile={expandedFile}
          setExpandedFile={setExpandedFile}
          expandedCheck={expandedCheck}
          setExpandedCheck={setExpandedCheck}
          expandedContext={expandedContext}
          setExpandedContext={setExpandedContext}
          tab={activeTabDef}
        />
      )}
    </div>
  );
}

/* ===================== OVERVIEW TAB ===================== */
function OverviewTab({ scan, riskScore }: { scan: ScanSummary; riskScore: number }) {
  const { t, tc } = useTranslation();
  const catEntries = Object.entries(scan.byCategory).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]);
  const maxCat = Math.max(...catEntries.map(([, v]) => v), 1);

  const catLabels: Record<string, string> = {
    'obfuscation': t.scanResult.catObfuscation,
    'external-access': t.scanResult.catExternalAccess,
    'security': t.scanResult.catSecurity,
    'code-pattern': t.scanResult.catCodePattern,
    'file-analysis': t.scanResult.catFileAnalysis,
    'wordpress': t.scanResult.catWordPress,
  };

  return (
    <div className="space-y-6">
      {/* Risk meter */}
      <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
        <h3 className="text-sm font-semibold text-dark-500 mb-4">{t.scanResult.riskAssessment}</h3>
        <div className="flex items-center gap-6">
          <div className="flex-1">
            <div className="h-4 bg-dark-700 rounded-full overflow-hidden">
              <div className="h-full rounded-full transition-all duration-500"
                style={{ width: `${Math.min(riskScore, 100)}%`, background: riskScore >= 50 ? '#ef4444' : riskScore >= 20 ? '#f97316' : riskScore >= 5 ? '#eab308' : '#22c55e' }} />
            </div>
            <div className="flex justify-between mt-2 text-xs text-dark-500">
              <span>{t.scanResult.safe}</span><span>{t.scanResult.low}</span><span>{t.scanResult.medium}</span><span>{t.scanResult.high}</span><span>{t.scanResult.critical}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Category breakdown */}
      <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
        <h3 className="text-sm font-semibold text-dark-500 mb-4">{t.scanResult.findingsByCategory}</h3>
        <div className="space-y-3">
          {catEntries.map(([cat, count]) => {
            const pct = (count / maxCat) * 100;
            const catColors: Record<string, string> = { security: 'bg-red-500', obfuscation: 'bg-purple-500', 'external-access': 'bg-cyan-500', 'code-pattern': 'bg-yellow-500', 'file-analysis': 'bg-green-500', wordpress: 'bg-blue-500' };
            const catIcons: Record<string, React.ReactNode> = { security: <IconSecurity size={18} />, obfuscation: <IconEyeOff size={18} />, 'external-access': <IconGlobe size={18} />, 'code-pattern': <IconCode size={18} />, 'file-analysis': <IconFileSearch size={18} />, wordpress: <IconServer size={18} /> };
            return (
              <div key={cat} className="flex items-center gap-4">
                <span className="w-8 text-center flex-shrink-0 text-dark-500">{catIcons[cat] || <IconFileSearch size={18} />}</span>
                <span className="text-sm text-gray-300 w-40">{catLabels[cat] || cat}</span>
                <div className="flex-1 bg-dark-700 rounded-full h-3">
                  <div className={`h-3 rounded-full ${catColors[cat] || 'bg-gray-500'}`} style={{ width: `${pct}%` }} />
                </div>
                <span className="text-sm text-white font-medium w-10 text-right">{count}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Top findings */}
      <div className="bg-dark-800 border border-dark-700 rounded-xl">
        <div className="px-6 py-4 border-b border-dark-700">
          <h3 className="font-semibold text-white">{t.scanResult.topFindings}</h3>
        </div>
        <div className="divide-y divide-dark-700">
          {scan.results
            .filter(r => (r.severity === 'critical' || r.severity === 'high') && r.findings.length > 0)
            .slice(0, 10)
            .map(result => (
              <div key={result.checkId} className="px-6 py-3 flex items-center gap-3">
                <span className={`w-2 h-2 rounded-full ${sevDot[result.severity]}`} />
                <span className="text-xs font-mono text-dark-500 w-20">{result.checkId}</span>
                <span className="text-white text-sm flex-1">{tc(result.checkId).name || result.checkName}</span>
                <span className="text-xs text-dark-500">{catLabels[result.category]}</span>
                <span className="bg-dark-700 text-gray-300 px-2 py-0.5 rounded text-xs">{result.findings.length}</span>
              </div>
            ))}
        </div>
      </div>
    </div>
  );
}

/* ===================== FILE GROUPED TAB ===================== */
function FileGroupedTab({
  fileGrouped, tabResults, tabTotalFindings, tabSeverityCounts,
  expandedFile, setExpandedFile, expandedCheck, setExpandedCheck,
  expandedContext, setExpandedContext, tab
}: {
  fileGrouped: [string, { findings: Finding[]; checks: CheckResult[] }][];
  tabResults: CheckResult[];
  tabTotalFindings: number;
  tabSeverityCounts: Record<Severity, number>;
  expandedFile: string | null;
  setExpandedFile: (f: string | null) => void;
  expandedCheck: string | null;
  setExpandedCheck: (c: string | null) => void;
  expandedContext: string | null;
  setExpandedContext: (c: string | null) => void;
  tab: TabDef;
}) {
  const { t, tc } = useTranslation();
  const [viewMode, setViewMode] = useState<'files' | 'checks'>('files');

  return (
    <div>
      {/* Tab Summary Bar */}
      <div className="flex items-center gap-4 mb-4">
        <div className="flex items-center gap-2 bg-dark-800 border border-dark-700 rounded-lg px-4 py-2">
          <span className="flex-shrink-0">{tab.icon}</span>
          <span className="text-white font-medium">{tab.labelKey}</span>
          <span className="text-dark-500 text-sm">|</span>
          <span className="text-white font-bold">{tabTotalFindings}</span>
          <span className="text-dark-500 text-sm">{t.scanResult.findings}</span>
          <span className="text-dark-500 text-sm">|</span>
          <span className="text-white">{fileGrouped.length}</span>
          <span className="text-dark-500 text-sm">{t.scanResult.files}</span>
        </div>
        <div className="flex gap-1 bg-dark-800 border border-dark-700 rounded-lg p-1">
          <button onClick={() => setViewMode('files')} className={`px-3 py-1.5 rounded text-xs font-medium ${viewMode === 'files' ? 'bg-blue-600 text-white' : 'text-dark-500 hover:text-white'}`}>{t.scanResult.byFile}</button>
          <button onClick={() => setViewMode('checks')} className={`px-3 py-1.5 rounded text-xs font-medium ${viewMode === 'checks' ? 'bg-blue-600 text-white' : 'text-dark-500 hover:text-white'}`}>{t.scanResult.byCheck}</button>
        </div>
        <div className="flex gap-1 ml-auto">
          {severityOrder.map(s => tabSeverityCounts[s] > 0 && (
            <span key={s} className={`text-xs px-2 py-1 rounded border ${sevBg[s]}`}>{tabSeverityCounts[s]} {t.severity[s]}</span>
          ))}
        </div>
      </div>

      {/* File Grouped View */}
      {viewMode === 'files' && (
        <div className="space-y-3">
          {fileGrouped.map(([file, { findings, checks }]) => {
            const isExpanded = expandedFile === file;
            const fileSevCounts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
            for (const f of findings) {
              const check = checks.find(c => c.findings.includes(f));
              if (check) fileSevCounts[check.severity]++;
            }
            const worstSeverity = severityOrder.find(s => fileSevCounts[s] > 0) || 'info';

            return (
              <div key={file} className="bg-dark-800 border border-dark-700 rounded-xl overflow-hidden">
                <div className="px-5 py-4 flex items-center gap-3 cursor-pointer hover:bg-dark-700/50 transition-colors"
                  onClick={() => setExpandedFile(isExpanded ? null : file)}>
                  <span className={`w-2.5 h-2.5 rounded-full ${sevDot[worstSeverity]}`} />
                  <span className="text-blue-400 font-mono text-sm flex-1">{file || t.scanResult.root}</span>
                  <div className="flex gap-1.5">
                    {severityOrder.map(s => fileSevCounts[s] > 0 && (
                      <span key={s} className={`text-xs px-1.5 py-0.5 rounded ${sevBg[s]}`}>{fileSevCounts[s]}</span>
                    ))}
                  </div>
                  <span className="text-dark-500 text-xs">{findings.length} {t.scanResult.issues}</span>
                  <span className="text-dark-500 text-sm">{isExpanded ? '▲' : '▼'}</span>
                </div>

                {isExpanded && (
                  <div className="border-t border-dark-700">
                    {/* File Summary */}
                    <div className="px-5 py-3 bg-dark-900/50 grid grid-cols-4 gap-4 text-xs">
                      <div><span className="text-dark-500">{t.scanResult.checksTriggered} </span><span className="text-white">{checks.length}</span></div>
                      <div><span className="text-dark-500">{t.scanResult.totalIssues} </span><span className="text-white">{findings.length}</span></div>
                      <div><span className="text-dark-500">{t.scanResult.worstSeverity} </span><span className={sevColors[worstSeverity]}>{t.severity[worstSeverity]}</span></div>
                      <div><span className="text-dark-500">{t.scanResult.riskScoreLabel} </span><span className="text-white">{fileSevCounts.critical * 10 + fileSevCounts.high * 5 + fileSevCounts.medium * 2 + fileSevCounts.low}</span></div>
                    </div>

                    {/* Checks for this file */}
                    {checks.map(check => {
                      const fileFindings = findings.filter(f => check.findings.includes(f));
                      return (
                        <div key={check.checkId} className="border-t border-dark-700/50">
                          <div className="px-5 py-3 flex items-center gap-2 bg-dark-900/30 cursor-pointer hover:bg-dark-700/30"
                            onClick={() => setExpandedCheck(expandedCheck === `${file}-${check.checkId}` ? null : `${file}-${check.checkId}`)}>
                            <span className={`w-2 h-2 rounded-full ${sevDot[check.severity]}`} />
                            <span className="text-xs font-mono text-dark-500">{check.checkId}</span>
                            <span className="text-white text-sm font-medium">{tc(check.checkId).name || check.checkName}</span>
                            <span className="text-dark-500 text-xs flex-1">{tc(check.checkId).desc || check.description}</span>
                            <span className="bg-dark-700 text-gray-300 px-2 py-0.5 rounded text-xs">{fileFindings.length}</span>
                            <span className="text-dark-500 text-xs">{expandedCheck === `${file}-${check.checkId}` ? '▲' : '▼'}</span>
                          </div>

                              {expandedCheck === `${file}-${check.checkId}` && (
                            <div className="border-t border-dark-700/50">
                              {fileFindings.map((f, i) => (
                                <div key={i} className="px-5 py-3 border-b border-dark-700/30 last:border-0 hover:bg-dark-700/20">
                                  <div className="flex items-center gap-3 mb-2">
                                    <span className="text-dark-500 text-xs">{t.scanResult.line} {f.line}</span>
                                    <span className="text-white text-sm flex-1">{f.message}</span>
                                    {f.riskScore != null && (
                                      <span className={`text-xs font-mono font-bold px-1.5 py-0.5 rounded ${riskBg(f.riskScore)} bg-dark-900`}>score: {f.riskScore}</span>
                                    )}
                                    {f.confidence && (
                                      <span className={`text-[10px] px-1.5 py-0.5 rounded ${confBg[f.confidence] || confBg.medium}`}>{f.confidence}</span>
                                    )}
                                    {f.context && (
                                      <button onClick={() => setExpandedContext(expandedContext === `${file}-${check.checkId}-${i}` ? null : `${file}-${check.checkId}-${i}`)}
                                        className="text-xs px-2 py-0.5 rounded bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 transition-colors">
                                        {t.scanResult.whyFlagged || 'Why Flagged?'}
                                      </button>
                                    )}
                                  </div>
                                  {f.code && (
                                    <div className="bg-dark-900 rounded-lg px-4 py-2 font-mono text-xs text-blue-300 overflow-x-auto">{f.code}</div>
                                  )}
                                  {f.details && (
                                    <div className="mt-2 text-xs text-dark-500">{f.details}</div>
                                  )}
                                  {expandedContext === `${file}-${check.checkId}-${i}` && (
                                    <div className="mt-3 space-y-2">
                                      {f.recommendation && (
                                        <div className="bg-green-500/5 border border-green-500/20 rounded-lg px-4 py-2 text-xs text-green-300">
                                          <span className="font-semibold">Recommendation:</span> {f.recommendation}
                                        </div>
                                      )}
                                      {f.context && (
                                        <div className="bg-dark-950 border border-dark-700 rounded-lg p-4 font-mono text-xs overflow-x-auto">
                                          <div className="text-dark-500 text-[10px] mb-2 uppercase tracking-wider">{t.scanResult.contextLines || 'Context (±3 lines)'}</div>
                                          <pre className="text-gray-300 whitespace-pre">{f.context}</pre>
                                        </div>
                                      )}
                                    </div>
                                  )}
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}

          {fileGrouped.length === 0 && <div className="text-center py-16 text-dark-500">{t.scanResult.noFindings}</div>}
        </div>
      )}

      {/* Check Grouped View */}
      {viewMode === 'checks' && (
        <div className="space-y-3">
          {tabResults.map(result => (
            <div key={result.checkId} className="bg-dark-800 border border-dark-700 rounded-xl overflow-hidden">
              <div className="px-5 py-4 flex items-center gap-3 cursor-pointer hover:bg-dark-700/50 transition-colors"
                onClick={() => setExpandedCheck(expandedCheck === result.checkId ? null : result.checkId)}>
                <span className={`w-2.5 h-2.5 rounded-full ${sevDot[result.severity]}`} />
                <span className="text-xs font-mono text-dark-500 w-20">{result.checkId}</span>
                <span className="text-white font-medium flex-1">{tc(result.checkId).name || result.checkName}</span>
                <span className="text-dark-500 text-xs">{tc(result.checkId).desc || result.description}</span>
                <span className="bg-dark-700 text-gray-300 px-2 py-0.5 rounded text-xs">{result.findings.length}</span>
                <span className="text-dark-500 text-sm">{expandedCheck === result.checkId ? '▲' : '▼'}</span>
              </div>

                  {expandedCheck === result.checkId && (
                <div className="border-t border-dark-700">
                  <div className="px-5 py-2 bg-dark-900/50 text-xs text-dark-500">{tc(result.checkId).desc || result.description}</div>
                  <table className="w-full text-sm">
                    <thead><tr className="text-dark-500 text-xs uppercase border-t border-dark-700">
                      <th className="px-5 py-2 text-left">{t.scanResult.file}</th><th className="px-5 py-2 text-left">{t.scanResult.line}</th><th className="px-5 py-2 text-left">{t.scanResult.message}</th><th className="px-5 py-2 text-left">{t.scanResult.code}</th><th className="px-5 py-2 text-left"></th>
                    </tr></thead>
                    <tbody>
                      {result.findings.map((f, i) => (
                        <tr key={i} className="border-t border-dark-700/50 hover:bg-dark-700/30">
                          <td className="px-5 py-2 font-mono text-xs text-blue-300">{f.file}</td>
                          <td className="px-5 py-2 text-dark-500 text-xs">{f.line}</td>
                          <td className="px-5 py-2 text-gray-300">{f.message}</td>
                          <td className="px-5 py-2 font-mono text-xs text-dark-500 max-w-xs truncate">{f.code}</td>
                          <td className="px-5 py-2">
                            {f.context && (
                              <button onClick={() => setExpandedContext(expandedContext === `check-${result.checkId}-${i}` ? null : `check-${result.checkId}-${i}`)}
                                className="text-xs px-2 py-0.5 rounded bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 transition-colors">
                                {t.scanResult.whyFlagged || 'Why Flagged?'}
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {result.findings.map((f, i) => expandedContext === `check-${result.checkId}-${i}` && f.context && (
                    <div key={`ctx-${i}`} className="mx-5 mb-3 bg-dark-950 border border-dark-700 rounded-lg p-4 font-mono text-xs overflow-x-auto">
                      <div className="text-dark-500 text-[10px] mb-2 uppercase tracking-wider">{f.file}:{f.line} — {t.scanResult.contextLines || 'Context (±3 lines)'}</div>
                      <pre className="text-gray-300 whitespace-pre">{f.context}</pre>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
          {tabResults.length === 0 && <div className="text-center py-16 text-dark-500">{t.scanResult.noFindings}</div>}
        </div>
      )}
    </div>
  );
}
