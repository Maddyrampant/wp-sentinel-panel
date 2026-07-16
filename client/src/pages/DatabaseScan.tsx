import { useState } from 'react';
import { useTranslation } from '../i18n';
import { dbScan, getDbScanHistory } from '../api/client';
import type { DatabaseScanResult } from '../types';

export default function DatabaseScan() {
  const { t } = useTranslation();
  const [host, setHost] = useState('localhost');
  const [port, setPort] = useState('3306');
  const [database, setDatabase] = useState('');
  const [user, setUser] = useState('');
  const [password, setPassword] = useState('');
  const [tablePrefix, setTablePrefix] = useState('wp_');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<DatabaseScanResult | null>(null);
  const [error, setError] = useState('');

  const handleScan = async () => {
    if (!database || !user || !password) return;
    setScanning(true);
    setError('');
    try {
      const res = await dbScan({ host, port: parseInt(port), database, user, password, tablePrefix });
      setResult(res);
    } catch (err: any) {
      setError(err.response?.data?.error || err.message);
    } finally {
      setScanning(false);
    }
  };

  const sevColor = (s: string) => {
    switch (s) {
      case 'critical': return 'text-red-400 bg-red-500/10 border-red-500/20';
      case 'high': return 'text-orange-400 bg-orange-500/10 border-orange-500/20';
      case 'medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20';
      default: return 'text-blue-400 bg-blue-500/10 border-blue-500/20';
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-100">Database Malware Scan</h1>
        <p className="text-dark-500 mt-1">Connect to a WordPress database and scan for injected malware</p>
      </div>

      <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Host</label>
            <input value={host} onChange={e => setHost(e.target.value)} className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-gray-200 text-sm" />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Port</label>
            <input value={port} onChange={e => setPort(e.target.value)} className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-gray-200 text-sm" />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Table Prefix</label>
            <input value={tablePrefix} onChange={e => setTablePrefix(e.target.value)} className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-gray-200 text-sm" />
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Database Name</label>
            <input value={database} onChange={e => setDatabase(e.target.value)} className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-gray-200 text-sm" placeholder="wordpress_db" />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Username</label>
            <input value={user} onChange={e => setUser(e.target.value)} className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-gray-200 text-sm" />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Password</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)} className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-gray-200 text-sm" />
          </div>
        </div>
        <button onClick={handleScan} disabled={scanning || !database || !user} className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-5 py-2 rounded-lg text-sm font-medium">
          {scanning ? 'Scanning...' : 'Scan Database'}
        </button>
        {error && <div className="mt-3 text-red-400 text-sm bg-red-500/10 border border-red-500/20 rounded-lg p-3">{error}</div>}
      </div>

      {result && (
        <div className="space-y-4">
          <div className="bg-dark-800 border border-dark-700 rounded-xl p-4 flex gap-6 items-center">
            <div className="text-sm text-gray-400">
              {result.connected ? '✅ Connected' : '❌ Connection failed'}
              <span className="ml-3 text-dark-500">({(result.duration / 1000).toFixed(1)}s)</span>
            </div>
            <div className="flex gap-4 text-sm">
              <span className="text-red-400">{result.summary.critical} critical</span>
              <span className="text-orange-400">{result.summary.high} high</span>
              <span className="text-yellow-400">{result.summary.medium} medium</span>
              <span className="text-blue-400">{result.summary.low} low</span>
            </div>
          </div>

          {result.findings.length === 0 ? (
            <div className="bg-dark-800 border border-dark-700 rounded-xl p-8 text-center text-green-400">
              ✅ No malware or suspicious content found in database
            </div>
          ) : (
            <div className="space-y-3">
              {result.findings.map(f => (
                <div key={f.id} className={`border rounded-lg p-4 ${sevColor(f.severity)}`}>
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs font-bold uppercase">{f.severity}</span>
                        <span className="text-xs text-dark-500">{f.check}</span>
                        <span className="text-xs text-dark-600">•</span>
                        <span className="text-xs font-mono text-dark-500">{f.table}.{f.column}</span>
                      </div>
                      <p className="text-sm">{f.message}</p>
                      {f.matchedValue && (
                        <pre className="text-xs mt-2 bg-dark-950/50 rounded p-2 overflow-x-auto max-h-20 opacity-70">{f.matchedValue}</pre>
                      )}
                      <p className="text-xs mt-2 opacity-80">💡 {f.recommendation}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
