import { useState, useRef } from 'react';
import { pluginScan, uploadPluginScan } from '../api/client';
import type { PluginIntelResult } from '../types';
import { useTranslation } from '../i18n';
import { IconPackage, IconSearch, IconAlertTriangle, IconShieldCheck, IconUpload } from '../components/Icons';

export default function PluginIntel() {
  const { t } = useTranslation();
  const [pluginsPath, setPluginsPath] = useState('');
  const [pluginName, setPluginName] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<PluginIntelResult | null>(null);
  const [error, setError] = useState('');
  const [results, setResults] = useState<PluginIntelResult[]>([]);
  const [file, setFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [inputMode, setInputMode] = useState<'path' | 'upload'>('path');
  const fileRef = useRef<HTMLInputElement>(null);

  const handleScan = async () => {
    if (!pluginsPath.trim()) return;
    setScanning(true);
    setError('');
    try {
      if (pluginName.trim()) {
        const res = await pluginScan(pluginsPath, pluginName);
        setResult(res);
      } else {
        const res = await pluginScan(pluginsPath);
        setResults(res.results || []);
      }
    } catch (err: any) {
      setError(err.message || 'Scan failed');
    } finally {
      setScanning(false);
    }
  };

  const handleFileScan = async () => {
    if (!file) return;
    setScanning(true);
    setError('');
    try {
      const res = await uploadPluginScan(file);
      setResults(res.results || []);
    } catch (err: any) {
      setError(err.message || 'Upload scan failed');
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

  const riskColor = (level: string) => {
    switch (level) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'low': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      default: return 'bg-green-500/20 text-green-400 border-green-500/30';
    }
  };

  return (
    <div>
      <div className="flex items-center gap-3 mb-8">
        <IconPackage size={28} className="text-blue-400" />
        <div>
          <h1 className="text-2xl font-bold text-white">{t.pluginIntel?.title || 'Plugin Security Intelligence'}</h1>
          <p className="text-sm text-dark-500">{t.pluginIntel?.subtitle || 'Analyze WordPress plugins for malware, backdoors, and vulnerabilities'}</p>
        </div>
      </div>

      <div className="bg-dark-800 border border-dark-700 rounded-xl p-6 mb-8">
        {/* Mode Toggle */}
        <div className="flex gap-2 mb-4">
          <button onClick={() => setInputMode('path')} className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${inputMode === 'path' ? 'bg-blue-600 text-white' : 'bg-dark-700 text-dark-500 hover:text-gray-300'}`}>
            {t.pluginIntel?.pluginsPath || 'Directory Path'}
          </button>
          <button onClick={() => setInputMode('upload')} className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${inputMode === 'upload' ? 'bg-blue-600 text-white' : 'bg-dark-700 text-dark-500 hover:text-gray-300'}`}>
            {t.newScan?.uploadZip || 'Upload ZIP'}
          </button>
        </div>

        {inputMode === 'path' ? (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs text-dark-500 mb-1">{t.pluginIntel?.pluginsPath || 'Plugins Directory Path'}</label>
              <input
                type="text"
                value={pluginsPath}
                onChange={e => setPluginsPath(e.target.value)}
                placeholder="/var/www/html/wp-content/plugins"
                className="w-full bg-dark-900 border border-dark-600 rounded-lg px-4 py-2.5 text-sm text-white placeholder-dark-500 focus:border-blue-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs text-dark-500 mb-1">{t.pluginIntel?.singlePlugin || 'Single Plugin Name (optional)'}</label>
              <input
                type="text"
                value={pluginName}
                onChange={e => setPluginName(e.target.value)}
                placeholder="e.g., contact-form-7"
                className="w-full bg-dark-900 border border-dark-600 rounded-lg px-4 py-2.5 text-sm text-white placeholder-dark-500 focus:border-blue-500 focus:outline-none"
              />
            </div>
            <div className="flex items-end">
              <button
                onClick={handleScan}
                disabled={scanning || !pluginsPath.trim()}
                className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white px-6 py-2.5 rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2"
              >
                <IconSearch size={16} />
                {scanning ? (t.pluginIntel?.scanning || 'Scanning...') : (t.pluginIntel?.scanButton || 'Scan Plugins')}
              </button>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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
            <div className="flex items-center">
              <button
                onClick={handleFileScan}
                disabled={scanning || !file}
                className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white px-6 py-2.5 rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2"
              >
                <IconSearch size={16} />
                {scanning ? (t.pluginIntel?.scanning || 'Scanning...') : (t.newScan?.uploadAndScan || 'Upload & Scan')}
              </button>
            </div>
          </div>
        )}

        {error && <p className="text-red-400 text-sm mt-3">{error}</p>}
      </div>

      {/* Single plugin result */}
      {result && (
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-6 mb-8">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">{result.pluginName}</h3>
            <span className={`px-3 py-1 rounded-lg text-xs font-medium border ${riskColor(result.riskLevel)}`}>
              Risk Score: {result.riskScore}/100 ({result.riskLevel})
            </span>
          </div>
          {result.metadata && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4 text-xs">
              {result.metadata.version && <div className="bg-dark-900 rounded-lg p-2"><span className="text-dark-500">Version:</span> <span className="text-white">{result.metadata.version}</span></div>}
              {result.metadata.author && <div className="bg-dark-900 rounded-lg p-2"><span className="text-dark-500">Author:</span> <span className="text-white">{result.metadata.author}</span></div>}
              {result.metadata.requiresPhp && <div className="bg-dark-900 rounded-lg p-2"><span className="text-dark-500">PHP:</span> <span className="text-white">{result.metadata.requiresPhp}</span></div>}
              {result.metadata.license && <div className="bg-dark-900 rounded-lg p-2"><span className="text-dark-500">License:</span> <span className="text-white">{result.metadata.license}</span></div>}
            </div>
          )}
          <div className="grid grid-cols-5 gap-2 mb-4">
            {[
              { label: 'Critical', count: result.summary.critical, color: 'text-red-400' },
              { label: 'High', count: result.summary.high, color: 'text-orange-400' },
              { label: 'Medium', count: result.summary.medium, color: 'text-yellow-400' },
              { label: 'Low', count: result.summary.low, color: 'text-blue-400' },
              { label: 'Total', count: result.summary.totalFindings, color: 'text-white' },
            ].map(s => (
              <div key={s.label} className="bg-dark-900 rounded-lg p-3 text-center">
                <div className={`text-xl font-bold ${s.color}`}>{s.count}</div>
                <div className="text-xs text-dark-500">{s.label}</div>
              </div>
            ))}
          </div>
          {/* Findings */}
          {result.malwarePatterns.length > 0 && (
            <div className="mb-4">
              <h4 className="text-sm font-semibold text-red-400 mb-2 flex items-center gap-2"><IconAlertTriangle size={14} /> Malware Patterns</h4>
              <div className="space-y-1">
                {result.malwarePatterns.slice(0, 10).map(f => (
                  <div key={f.id} className="bg-dark-900 rounded-lg px-4 py-2 text-xs flex gap-3">
                    <span className="text-blue-400 font-mono whitespace-nowrap">{f.file}:{f.line}</span>
                    <span className="text-gray-300">{f.message}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {result.vulnerabilityPatterns.length > 0 && (
            <div className="mb-4">
              <h4 className="text-sm font-semibold text-orange-400 mb-2 flex items-center gap-2"><IconAlertTriangle size={14} /> Vulnerability Patterns</h4>
              <div className="space-y-1">
                {result.vulnerabilityPatterns.slice(0, 10).map(f => (
                  <div key={f.id} className="bg-dark-900 rounded-lg px-4 py-2 text-xs flex gap-3">
                    <span className="text-blue-400 font-mono whitespace-nowrap">{f.file}:{f.line}</span>
                    <span className="text-gray-300">{f.message}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {result.nulledIndicators.length > 0 && (
            <div>
              <h4 className="text-sm font-semibold text-yellow-400 mb-2">Nulled Indicators</h4>
              <div className="space-y-1">
                {result.nulledIndicators.slice(0, 5).map(f => (
                  <div key={f.id} className="bg-dark-900 rounded-lg px-4 py-2 text-xs flex gap-3">
                    <span className="text-blue-400 font-mono whitespace-nowrap">{f.file}:{f.line}</span>
                    <span className="text-gray-300">{f.message}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* All plugins results */}
      {results.length > 0 && (
        <div className="bg-dark-800 border border-dark-700 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-dark-700">
            <h3 className="font-semibold text-white">{results.length} plugins scanned</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-dark-500 text-xs uppercase border-b border-dark-700">
                  <th className="px-6 py-3 text-left">Plugin</th>
                  <th className="px-6 py-3 text-left">Risk</th>
                  <th className="px-6 py-3 text-left">Score</th>
                  <th className="px-6 py-3 text-left">Critical</th>
                  <th className="px-6 py-3 text-left">High</th>
                  <th className="px-6 py-3 text-left">Total</th>
                </tr>
              </thead>
              <tbody>
                {results.sort((a, b) => b.riskScore - a.riskScore).map(p => (
                  <tr key={p.pluginName} className="border-t border-dark-700/50 hover:bg-dark-700/30">
                    <td className="px-6 py-3 text-white font-medium">{p.pluginName}</td>
                    <td className="px-6 py-3"><span className={`px-2 py-0.5 rounded text-xs border ${riskColor(p.riskLevel)}`}>{p.riskLevel}</span></td>
                    <td className="px-6 py-3 text-gray-300">{p.riskScore}</td>
                    <td className="px-6 py-3 text-red-400">{p.summary.critical}</td>
                    <td className="px-6 py-3 text-orange-400">{p.summary.high}</td>
                    <td className="px-6 py-3 text-gray-300">{p.summary.totalFindings}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
