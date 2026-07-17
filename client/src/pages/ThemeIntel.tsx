import { useState, useRef } from 'react';
import { useTranslation } from '../i18n';
import { themeScan, uploadThemeScan, getThemeScanHistory, deleteThemeScan } from '../api/client';
import type { ThemeScanResult, ThemeIntelResult, ThemeFinding } from '../types';
import { IconCheckCircle, IconLightbulb, IconPackage, IconUpload } from '../components/Icons';

export default function ThemeIntel() {
  const { t, dir } = useTranslation();
  const [themesPath, setThemesPath] = useState('');
  const [themeName, setThemeName] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ThemeScanResult | null>(null);
  const [error, setError] = useState('');
  const [expandedThemes, setExpandedThemes] = useState<Set<string>>(new Set());
  const [activeTab, setActiveTab] = useState<'results' | 'history'>('results');
  const [history, setHistory] = useState<any[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [inputMode, setInputMode] = useState<'path' | 'upload'>('path');
  const fileRef = useRef<HTMLInputElement>(null);

  const handleScan = async () => {
    if (!themesPath.trim()) return;
    setScanning(true);
    setError('');
    setResult(null);
    try {
      const res = await themeScan(themesPath.trim(), themeName.trim() || undefined);
      setResult(res);
      setActiveTab('results');
    } catch (err: any) {
      setError(err.response?.data?.error || err.message || 'Scan failed');
    } finally {
      setScanning(false);
    }
  };

  const handleFileScan = async () => {
    if (!file) return;
    setScanning(true);
    setError('');
    setResult(null);
    try {
      const res = await uploadThemeScan(file, themeName.trim() || undefined);
      setResult(res);
      setActiveTab('results');
    } catch (err: any) {
      setError(err.response?.data?.error || err.message || 'Upload scan failed');
    } finally {
      setScanning(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f?.name.endsWith('.zip')) setFile(f);
  };

  const loadHistory = async () => {
    setHistoryLoading(true);
    try {
      const h = await getThemeScanHistory();
      setHistory(Array.isArray(h) ? h : []);
    } catch {
      setHistory([]);
    } finally {
      setHistoryLoading(false);
    }
  };

  const handleDeleteHistory = async (id: string) => {
    if (!confirm(t.themeIntel.deleteScan + '?')) return;
    try {
      await deleteThemeScan(id);
      setHistory(h => h.filter(i => i.id !== id));
    } catch {}
  };

  const toggleTheme = (name: string) => {
    setExpandedThemes(prev => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  const riskColor = (level: string) => {
    switch (level) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'low': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      default: return 'bg-green-500/20 text-green-400 border-green-500/30';
    }
  };

  const riskLabel = (level: string) => {
    switch (level) {
      case 'critical': return t.themeIntel.critical;
      case 'high': return t.themeIntel.high;
      case 'medium': return t.themeIntel.medium;
      case 'low': return t.themeIntel.low;
      default: return t.themeIntel.clean;
    }
  };

  const severityColor = (sev: string) => {
    switch (sev) {
      case 'critical': return 'text-red-400';
      case 'high': return 'text-orange-400';
      case 'medium': return 'text-yellow-400';
      case 'low': return 'text-blue-400';
      default: return 'text-gray-400';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-100">{t.themeIntel.title}</h1>
        <p className="text-dark-500 mt-1">{t.themeIntel.subtitle}</p>
      </div>

      {/* Scan Form */}
      <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
        {/* Mode Toggle */}
        <div className="flex gap-2 mb-4">
          <button onClick={() => setInputMode('path')} className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${inputMode === 'path' ? 'bg-blue-600 text-white' : 'bg-dark-700 text-dark-500 hover:text-gray-300'}`}>
            {t.themeIntel.themesPath}
          </button>
          <button onClick={() => setInputMode('upload')} className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${inputMode === 'upload' ? 'bg-blue-600 text-white' : 'bg-dark-700 text-dark-500 hover:text-gray-300'}`}>
            {t.newScan?.uploadZip || 'Upload ZIP'}
          </button>
        </div>

        <div className="space-y-4">
          {inputMode === 'path' ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">{t.themeIntel.themesPath}</label>
                <input
                  type="text"
                  value={themesPath}
                  onChange={(e) => setThemesPath(e.target.value)}
                  placeholder={t.themeIntel.pathPlaceholder}
                  className="w-full bg-dark-900 border border-dark-600 rounded-lg px-4 py-2.5 text-gray-200 placeholder-dark-500 focus:outline-none focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">{t.themeIntel.singleTheme}</label>
                <input
                  type="text"
                  value={themeName}
                  onChange={(e) => setThemeName(e.target.value)}
                  placeholder={t.themeIntel.singleThemePlaceholder}
                  className="w-full bg-dark-900 border border-dark-600 rounded-lg px-4 py-2.5 text-gray-200 placeholder-dark-500 focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">{t.themeIntel.singleTheme}</label>
                <input
                  type="text"
                  value={themeName}
                  onChange={(e) => setThemeName(e.target.value)}
                  placeholder={t.themeIntel.singleThemePlaceholder}
                  className="w-full bg-dark-900 border border-dark-600 rounded-lg px-4 py-2.5 text-gray-200 placeholder-dark-500 focus:outline-none focus:border-blue-500"
                />
              </div>
              <div
                className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-colors ${dragOver ? 'border-blue-500 bg-blue-500/10' : 'border-dark-600 hover:border-dark-500'}`}
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleDrop}
                onClick={() => fileRef.current?.click()}
              >
                <input ref={fileRef} type="file" accept=".zip" className="hidden" onChange={(e) => setFile(e.target.files?.[0] || null)} />
                {file ? (
                  <div>
                    <div className="mb-2 flex justify-center text-blue-400"><IconPackage size={32} /></div>
                    <div className="text-white font-medium text-sm">{file.name}</div>
                    <div className="text-dark-500 text-xs mt-1">{(file.size / 1024).toFixed(1)} KB</div>
                  </div>
                ) : (
                  <div>
                    <div className="mb-2 flex justify-center text-dark-500"><IconUpload size={32} /></div>
                    <div className="text-gray-400 text-sm">{t.newScan?.dropzone || 'Drag & drop .zip file'}</div>
                    <div className="text-dark-500 text-xs mt-1">{t.newScan?.maxSize || 'Max 200MB'}</div>
                  </div>
                )}
              </div>
            </div>
          )}

          <button
            onClick={inputMode === 'path' ? handleScan : handleFileScan}
            disabled={scanning || (inputMode === 'path' ? !themesPath.trim() : !file)}
            className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white px-6 py-2.5 rounded-lg font-medium transition-colors"
          >
            {scanning ? t.themeIntel.scanning : (inputMode === 'upload' ? (t.newScan?.uploadAndScan || 'Upload & Scan') : t.themeIntel.scanButton)}
          </button>
        </div>
        {error && (
          <div className="mt-4 bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-red-400 text-sm">{error}</div>
        )}
      </div>

      {/* Tab Bar */}
      {(result || history.length > 0) && (
        <div className="flex gap-4 border-b border-dark-700">
          <button
            onClick={() => { setActiveTab('results'); }}
            className={`pb-3 px-1 text-sm font-medium border-b-2 transition-colors ${activeTab === 'results' ? 'border-blue-500 text-blue-400' : 'border-transparent text-dark-500 hover:text-gray-300'}`}
          >
            {t.themeIntel.title}
          </button>
          <button
            onClick={() => { setActiveTab('history'); loadHistory(); }}
            className={`pb-3 px-1 text-sm font-medium border-b-2 transition-colors ${activeTab === 'history' ? 'border-blue-500 text-blue-400' : 'border-transparent text-dark-500 hover:text-gray-300'}`}
          >
            {t.themeIntel.scanHistory}
          </button>
        </div>
      )}

      {/* History Tab */}
      {activeTab === 'history' && (
        <div className="bg-dark-800 border border-dark-700 rounded-xl overflow-hidden">
          {historyLoading ? (
            <div className="p-8 text-center text-dark-500">{t.dashboard.loading}</div>
          ) : history.length === 0 ? (
            <div className="p-8 text-center text-dark-500">{t.themeIntel.noHistory}</div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-dark-700 text-left text-xs text-dark-500 uppercase">
                  <th className="px-4 py-3">{t.themeIntel.themesPath}</th>
                  <th className="px-4 py-3">{t.themeIntel.themesScanned}</th>
                  <th className="px-4 py-3">{t.themeIntel.totalFindings}</th>
                  <th className="px-4 py-3">{t.themeIntel.riskBadge}</th>
                  <th className="px-4 py-3">Actions</th>
                </tr>
              </thead>
              <tbody>
                {(history || []).map((h) => (
                  <tr key={h.id} className="border-b border-dark-700/50 hover:bg-dark-700/30">
                    <td className="px-4 py-3 text-sm text-gray-300 max-w-[200px] truncate">{h.themes_path}</td>
                    <td className="px-4 py-3 text-sm text-gray-400">{h.themes_count}</td>
                    <td className="px-4 py-3 text-sm text-gray-400">{h.total_findings}</td>
                    <td className="px-4 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded-full ${riskColor(h.critical_count > 0 ? 'critical' : h.high_count > 0 ? 'high' : h.medium_count > 0 ? 'medium' : h.low_count > 0 ? 'low' : 'clean')}`}>
                        {riskLabel(h.critical_count > 0 ? 'critical' : h.high_count > 0 ? 'high' : h.medium_count > 0 ? 'medium' : h.low_count > 0 ? 'low' : 'clean')}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => handleDeleteHistory(h.id)}
                        className="text-red-400 hover:text-red-300 text-xs"
                      >
                        {t.themeIntel.deleteScan}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Results Tab */}
      {activeTab === 'results' && result && (
        <div className="space-y-4">
          <div className="bg-dark-800 border border-dark-700 rounded-xl p-4 flex items-center justify-between">
            <div className="text-sm text-gray-400">
              {(result?.results || []).length} {t.themeIntel.themesScanned} — {t.themeIntel.scanComplete}
               <span className="ml-2 text-dark-500">({(result.duration / 1000).toFixed(1)}s)</span>
            </div>
          </div>

          {(result?.results || []).length === 0 ? (
            <div className="bg-dark-800 border border-dark-700 rounded-xl p-8 text-center text-dark-500">
              {t.themeIntel.noThemesFound}
            </div>
          ) : (
            (result?.results || []).map((theme) => (
              <ThemeCard
                key={theme.themeName}
                theme={theme}
                expanded={expandedThemes.has(theme.themeName)}
                onToggle={() => toggleTheme(theme.themeName)}
                t={t}
                riskColor={riskColor}
                riskLabel={riskLabel}
                severityColor={severityColor}
              />
            ))
          )}
        </div>
      )}
    </div>
  );
}

function ThemeCard({
  theme,
  expanded,
  onToggle,
  t,
  riskColor,
  riskLabel,
  severityColor,
}: {
  theme: ThemeIntelResult;
  expanded: boolean;
  onToggle: () => void;
  t: any;
  riskColor: (level: string) => string;
  riskLabel: (level: string) => string;
  severityColor: (sev: string) => string;
}) {
  return (
    <div className="bg-dark-800 border border-dark-700 rounded-xl overflow-hidden">
      {/* Theme Header */}
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between p-5 hover:bg-dark-700/30 transition-colors text-left"
      >
        <div className="flex items-center gap-4">
          <div>
            <div className="flex items-center gap-3">
              <h3 className="text-lg font-semibold text-gray-100">
                {theme.styleMetadata?.name || theme.themeName}
              </h3>
              <span className={`text-xs px-2.5 py-0.5 rounded-full border font-medium ${riskColor(theme.riskLevel)}`}>
                {t.themeIntel.riskBadge}: {theme.riskScore} — {riskLabel(theme.riskLevel)}
              </span>
            </div>
            {theme.styleMetadata && (
              <div className="text-xs text-dark-500 mt-1">
                {theme.styleMetadata.author && <span>{theme.styleMetadata.author}</span>}
                {theme.styleMetadata.version && <span className="ml-2">v{theme.styleMetadata.version}</span>}
              </div>
            )}
          </div>
        </div>
        <div className="flex items-center gap-6 text-sm">
          <div className="text-center">
            <div className="text-lg font-bold text-gray-200">{theme.summary.totalFindings}</div>
            <div className="text-xs text-dark-500">{t.themeIntel.totalFindings}</div>
          </div>
          {theme.summary.critical > 0 && (
            <div className="text-center">
              <div className="text-lg font-bold text-red-400">{theme.summary.critical}</div>
              <div className="text-xs text-dark-500">{t.themeIntel.criticalFindings}</div>
            </div>
          )}
          {theme.summary.high > 0 && (
            <div className="text-center">
              <div className="text-lg font-bold text-orange-400">{theme.summary.high}</div>
              <div className="text-xs text-dark-500">{t.themeIntel.highFindings}</div>
            </div>
          )}
          <svg className={`w-5 h-5 text-dark-500 transition-transform ${expanded ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>

      {/* Expanded Content */}
      {expanded && (
        <div className="border-t border-dark-700 p-5 space-y-6">
          {/* Style Metadata */}
          {theme.styleMetadata && (
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              {theme.styleMetadata.name && (
                <div>
                  <div className="text-xs text-dark-500">{t.themeIntel.themeName}</div>
                  <div className="text-sm text-gray-300">{theme.styleMetadata.name}</div>
                </div>
              )}
              {theme.styleMetadata.version && (
                <div>
                  <div className="text-xs text-dark-500">{t.themeIntel.themeVersion}</div>
                  <div className="text-sm text-gray-300">{theme.styleMetadata.version}</div>
                </div>
              )}
              {theme.styleMetadata.author && (
                <div>
                  <div className="text-xs text-dark-500">{t.themeIntel.themeAuthor}</div>
                  <div className="text-sm text-gray-300">{theme.styleMetadata.author}</div>
                </div>
              )}
              {theme.styleMetadata.textDomain && (
                <div>
                  <div className="text-xs text-dark-500">{t.themeIntel.themeTextDomain}</div>
                  <div className="text-sm text-gray-300">{theme.styleMetadata.textDomain}</div>
                </div>
              )}
            </div>
          )}

          {/* Malware Patterns */}
          {theme.malwarePatterns.length > 0 && (
            <Section title={t.themeIntel.malwarePatterns} count={theme.malwarePatterns.length} color="text-red-400">
              <div className="space-y-2">
                {theme.malwarePatterns.map((f) => (
                  <FindingRow key={f.id} finding={f} t={t} severityColor={severityColor} />
                ))}
              </div>
            </Section>
          )}

          {/* Nulled Indicators */}
          {theme.nulledIndicators.length > 0 && (
            <Section title={t.themeIntel.nulledIndicators} count={theme.nulledIndicators.length} color="text-orange-400">
              <div className="space-y-2">
                {theme.nulledIndicators.map((f) => (
                  <FindingRow key={f.id} finding={f} t={t} severityColor={severityColor} />
                ))}
              </div>
            </Section>
          )}

          {/* Nulled - No findings */}
          {theme.nulledIndicators.length === 0 && theme.malwarePatterns.length === 0 && (
            <div className="text-sm text-green-400/80 bg-green-500/5 border border-green-500/20 rounded-lg p-3 flex items-center gap-2">
              <IconCheckCircle size={16} className="text-green-400 shrink-0" /> {t.themeIntel.noMalware}
            </div>
          )}

          {/* External Domains */}
          {theme.externalDomains.length > 0 && (
            <Section title={t.themeIntel.externalDomains} count={theme.externalDomains.length} color="text-blue-400">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-xs text-dark-500 uppercase border-b border-dark-700">
                      <th className="text-left py-2 px-3">{t.themeIntel.domain}</th>
                      <th className="text-left py-2 px-3">{t.themeIntel.suspicious}</th>
                      <th className="text-left py-2 px-3">{t.themeIntel.files}</th>
                      <th className="text-left py-2 px-3">{t.themeIntel.urls}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {theme.externalDomains.map((d, i) => (
                      <tr key={i} className="border-b border-dark-700/50 hover:bg-dark-700/20">
                        <td className="py-2 px-3 font-mono text-xs text-gray-300">{d.domain}</td>
                        <td className="py-2 px-3">
                          {d.isSuspicious ? (
                            <span className="text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded-full">{t.themeIntel.suspicious}</span>
                          ) : (
                            <span className="text-xs bg-green-500/20 text-green-400 px-2 py-0.5 rounded-full">{t.themeIntel.safe}</span>
                          )}
                        </td>
                        <td className="py-2 px-3 text-xs text-gray-400">
                          {d.files.map((f, j) => (
                            <div key={j}>{f.file}:{f.line}</div>
                          ))}
                        </td>
                        <td className="py-2 px-3 text-xs text-gray-400 max-w-[300px] truncate">
                          {d.urls.slice(0, 2).join(', ')}
                          {d.urls.length > 2 && <span className="text-dark-500"> +{d.urls.length - 2}</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>
          )}

          {/* Base64 Decoded */}
          {theme.base64Decoded.length > 0 && (
            <Section title={t.themeIntel.base64Decoded} count={theme.base64Decoded.length} color="text-yellow-400">
              <div className="space-y-3">
                {theme.base64Decoded.map((b, i) => (
                  <div key={i} className="bg-dark-900 border border-dark-600 rounded-lg p-4">
                    <div className="flex items-center gap-2 text-xs text-dark-500 mb-2">
                      <span className="font-mono">{b.file}</span>
                      <span>{t.themeIntel.line} {b.line}</span>
                    </div>
                    <pre className="text-xs text-gray-400 bg-dark-950 rounded p-3 overflow-x-auto max-h-32 mb-2">
                      {b.decoded}
                    </pre>
                    {b.extractedUrls.length > 0 && (
                      <div className="text-xs">
                        <span className="text-dark-500">{t.themeIntel.extractedUrls}:</span>
                        <div className="text-red-400 font-mono mt-1">{b.extractedUrls.join('\n')}</div>
                      </div>
                    )}
                    {b.extractedDomains.length > 0 && (
                      <div className="text-xs mt-1">
                        <span className="text-dark-500">{t.themeIntel.extractedDomains}:</span>
                        <div className="text-orange-400 font-mono mt-1">{b.extractedDomains.join(', ')}</div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </Section>
          )}
        </div>
      )}
    </div>
  );
}

function Section({ title, count, color, children }: { title: string; count: number; color: string; children: React.ReactNode }) {
  return (
    <div>
      <h4 className={`text-sm font-semibold ${color} mb-3`}>{title} ({count})</h4>
      {children}
    </div>
  );
}

function FindingRow({ finding, t, severityColor }: { finding: ThemeFinding; t: any; severityColor: (s: string) => string }) {
  return (
    <div className="bg-dark-900 border border-dark-600 rounded-lg p-3">
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className={`text-xs font-medium ${severityColor(finding.severity)}`}>{finding.severity.toUpperCase()}</span>
            <span className="text-xs text-dark-500">{finding.type}</span>
            <span className="text-xs text-dark-600">•</span>
            <span className="text-xs font-mono text-dark-500">{finding.file}:{finding.line}</span>
          </div>
          <p className="text-sm text-gray-300">{finding.message}</p>
          {finding.matchedText && (
            <pre className="text-xs text-gray-500 mt-2 bg-dark-950 rounded p-2 overflow-x-auto max-h-16">
              {finding.matchedText}
            </pre>
          )}
          {finding.recommendation && (
            <p className="text-xs text-blue-400/80 mt-2 flex items-center gap-1"><IconLightbulb size={12} /> {finding.recommendation}</p>
          )}
        </div>
        <div className="text-right shrink-0">
          <div className="text-xs text-dark-500">{t.themeIntel.confidence}</div>
          <div className="text-sm font-medium text-gray-300">{finding.confidence}%</div>
        </div>
      </div>
    </div>
  );
}
