import { useState, useRef } from 'react';
import { hardeningScan, uploadHardeningScan } from '../api/client';
import { useTranslation } from '../i18n';
import { IconShieldCheck, IconSearch, IconCheck, IconX, IconAlertTriangle, IconInfo, IconPackage, IconUpload } from '../components/Icons';

interface HardeningCheckItem {
  id: string;
  name: string;
  category: string;
  status: 'pass' | 'fail' | 'warning' | 'info';
  severity: string;
  message: string;
  details: string;
  recommendation: string;
  reference?: string;
}

interface HardeningResult {
  totalChecks: number;
  passed: number;
  failed: number;
  warnings: number;
  score: number;
  checks: HardeningCheckItem[];
  duration: number;
}

export default function HardeningCheck() {
  const { t } = useTranslation();
  const [targetPath, setTargetPath] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<HardeningResult | null>(null);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState<string>('all');
  const [file, setFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [inputMode, setInputMode] = useState<'path' | 'upload'>('path');
  const fileRef = useRef<HTMLInputElement>(null);

  const handleScan = async () => {
    if (!targetPath.trim()) return;
    setScanning(true);
    setError('');
    try {
      const res = await hardeningScan(targetPath);
      setResult(res);
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
      const res = await uploadHardeningScan(file);
      setResult(res);
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

  const statusIcon = (status: string) => {
    switch (status) {
      case 'pass': return <IconCheck size={16} className="text-green-400" />;
      case 'fail': return <IconX size={16} className="text-red-400" />;
      case 'warning': return <IconAlertTriangle size={16} className="text-yellow-400" />;
      default: return <IconInfo size={16} className="text-blue-400" />;
    }
  };

  const statusColor = (status: string) => {
    switch (status) {
      case 'pass': return 'bg-green-500/10 border-green-500/20';
      case 'fail': return 'bg-red-500/10 border-red-500/20';
      case 'warning': return 'bg-yellow-500/10 border-yellow-500/20';
      default: return 'bg-blue-500/10 border-blue-500/20';
    }
  };

  const categories = result ? [...new Set(result.checks.map(c => c.category))] : [];
  const filteredChecks = result ? (filter === 'all' ? result.checks : result.checks.filter(c => c.category === filter)) : [];

  return (
    <div>
      <div className="flex items-center gap-3 mb-8">
        <IconShieldCheck size={28} className="text-blue-400" />
        <div>
          <h1 className="text-2xl font-bold text-white">{t.hardening?.title || 'WordPress Hardening Check'}</h1>
          <p className="text-sm text-dark-500">{t.hardening?.subtitle || 'Verify your WordPress installation against security best practices'}</p>
        </div>
      </div>

      <div className="bg-dark-800 border border-dark-700 rounded-xl p-6 mb-8">
        {/* Mode Toggle */}
        <div className="flex gap-2 mb-4">
          <button onClick={() => setInputMode('path')} className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${inputMode === 'path' ? 'bg-blue-600 text-white' : 'bg-dark-700 text-dark-500 hover:text-gray-300'}`}>
            Directory Path
          </button>
          <button onClick={() => setInputMode('upload')} className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${inputMode === 'upload' ? 'bg-blue-600 text-white' : 'bg-dark-700 text-dark-500 hover:text-gray-300'}`}>
            {t.newScan?.uploadZip || 'Upload ZIP'}
          </button>
        </div>

        {inputMode === 'path' ? (
          <div className="flex gap-4">
            <input
              type="text"
              value={targetPath}
              onChange={e => setTargetPath(e.target.value)}
              placeholder="/var/www/html"
              className="flex-1 bg-dark-900 border border-dark-600 rounded-lg px-4 py-2.5 text-sm text-white placeholder-dark-500 focus:border-blue-500 focus:outline-none"
            />
            <button
              onClick={handleScan}
              disabled={scanning || !targetPath.trim()}
              className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white px-6 py-2.5 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
            >
              <IconSearch size={16} />
              {scanning ? 'Checking...' : 'Run Checks'}
            </button>
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
                {scanning ? 'Checking...' : (t.newScan?.uploadAndScan || 'Upload & Scan')}
              </button>
            </div>
          </div>
        )}
        {error && <p className="text-red-400 text-sm mt-3">{error}</p>}
      </div>

      {result && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
            <div className="bg-dark-800 border border-dark-700 rounded-xl p-5 text-center">
              <div className="text-3xl font-bold text-white">{result.score}%</div>
              <div className="text-xs text-dark-500 mt-1">Security Score</div>
              <div className="mt-2 h-2 bg-dark-700 rounded-full">
                <div className={`h-2 rounded-full ${result.score >= 80 ? 'bg-green-500' : result.score >= 50 ? 'bg-yellow-500' : 'bg-red-500'}`} style={{ width: `${result.score}%` }}></div>
              </div>
            </div>
            <div className="bg-dark-800 border border-dark-700 rounded-xl p-5 text-center">
              <div className="text-2xl font-bold text-green-400">{result.passed}</div>
              <div className="text-xs text-dark-500 mt-1">Passed</div>
            </div>
            <div className="bg-dark-800 border border-dark-700 rounded-xl p-5 text-center">
              <div className="text-2xl font-bold text-red-400">{result.failed}</div>
              <div className="text-xs text-dark-500 mt-1">Failed</div>
            </div>
            <div className="bg-dark-800 border border-dark-700 rounded-xl p-5 text-center">
              <div className="text-2xl font-bold text-yellow-400">{result.warnings}</div>
              <div className="text-xs text-dark-500 mt-1">Warnings</div>
            </div>
            <div className="bg-dark-800 border border-dark-700 rounded-xl p-5 text-center">
              <div className="text-2xl font-bold text-dark-500">{result.totalChecks}</div>
              <div className="text-xs text-dark-500 mt-1">Total Checks</div>
            </div>
          </div>

          <div className="flex gap-2 mb-6 flex-wrap">
            <button onClick={() => setFilter('all')} className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${filter === 'all' ? 'bg-blue-600 text-white' : 'bg-dark-700 text-dark-500 hover:text-gray-300'}`}>All ({result.totalChecks})</button>
            {categories.map(cat => (
              <button key={cat} onClick={() => setFilter(cat)} className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${filter === cat ? 'bg-blue-600 text-white' : 'bg-dark-700 text-dark-500 hover:text-gray-300'}`}>{cat} ({result.checks.filter(c => c.category === cat).length})</button>
            ))}
          </div>

          <div className="space-y-2">
            {filteredChecks.map(check => (
              <div key={check.id} className={`border rounded-xl p-4 ${statusColor(check.status)}`}>
                <div className="flex items-center gap-3">
                  {statusIcon(check.status)}
                  <span className="font-mono text-xs text-dark-500">{check.id}</span>
                  <span className="text-white font-medium text-sm">{check.name}</span>
                  <span className="text-xs text-dark-500 ml-auto">{check.category}</span>
                </div>
                <p className="text-xs text-gray-400 mt-2 ml-7">{check.message}</p>
                {check.status !== 'pass' && check.recommendation && (
                  <p className="text-xs text-blue-400 mt-1 ml-7">Fix: {check.recommendation}</p>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
