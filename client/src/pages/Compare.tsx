import { useEffect, useState } from 'react';
import { getHistory, compareScans } from '../api/client';
import type { ScanHistoryItem } from '../types';
import LoadingSpinner from '../components/LoadingSpinner';
import { useTranslation } from '../i18n';

export default function Compare() {
  const { t } = useTranslation();
  const [items, setItems] = useState<ScanHistoryItem[]>([]);
  const [id1, setId1] = useState('');
  const [id2, setId2] = useState('');
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [comparing, setComparing] = useState(false);

  useEffect(() => {
    getHistory(100).then(setItems).finally(() => setLoading(false));
  }, []);

  const handleCompare = async () => {
    if (!id1 || !id2) return;
    setComparing(true);
    try {
      const r = await compareScans(id1, id2);
      setResult(r);
    } catch { alert(t.compare.failedToCompare); }
    setComparing(false);
  };

  if (loading) return <LoadingSpinner />;
  if (comparing) return <LoadingSpinner text={t.compare.comparing} />;

  return (
    <div>
      <h1 className="text-3xl font-bold text-white mb-2">{t.compare.title}</h1>
      <p className="text-dark-500 mb-6">{t.compare.subtitle}</p>

      <div className="grid grid-cols-2 gap-6 mb-8">
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-5">
          <label className="text-sm text-dark-500 mb-2 block">{t.compare.scan1}</label>
          <select value={id1} onChange={(e) => setId1(e.target.value)} className="w-full bg-dark-900 border border-dark-700 rounded-lg px-4 py-3 text-white text-sm focus:border-blue-500 focus:outline-none">
            <option value="">{t.compare.selectScan}</option>
            {(items || []).map(s => <option key={s.id} value={s.id}>{s.target_name} - {new Date(s.scan_date).toLocaleDateString()} ({s.total_findings} {t.compare.findings})</option>)}
          </select>
        </div>
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-5">
          <label className="text-sm text-dark-500 mb-2 block">{t.compare.scan2}</label>
          <select value={id2} onChange={(e) => setId2(e.target.value)} className="w-full bg-dark-900 border border-dark-700 rounded-lg px-4 py-3 text-white text-sm focus:border-blue-500 focus:outline-none">
            <option value="">{t.compare.selectScan}</option>
            {(items || []).map(s => <option key={s.id} value={s.id}>{s.target_name} - {new Date(s.scan_date).toLocaleDateString()} ({s.total_findings} {t.compare.findings})</option>)}
          </select>
        </div>
      </div>

      <button onClick={handleCompare} disabled={!id1 || !id2} className="bg-blue-600 hover:bg-blue-500 disabled:bg-dark-700 disabled:text-dark-500 text-white px-8 py-3 rounded-lg font-medium transition-colors mb-8">
        {t.compare.compareScans}
      </button>

      {result && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-6">
            <div className="bg-dark-800 border border-dark-700 rounded-xl p-5">
              <h3 className="font-semibold text-white mb-3">{result.scan1.name}</h3>
              <p className="text-dark-500 text-sm">{result.scan1.date}</p>
              <p className="text-2xl font-bold text-white mt-2">{result.scan1.findings} {t.compare.findings}</p>
            </div>
            <div className="bg-dark-800 border border-dark-700 rounded-xl p-5">
              <h3 className="font-semibold text-white mb-3">{result.scan2.name}</h3>
              <p className="text-dark-500 text-sm">{result.scan2.date}</p>
              <p className="text-2xl font-bold text-white mt-2">{result.scan2.findings} {t.compare.findings}</p>
            </div>
          </div>

          <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
            <h3 className="font-semibold text-white mb-4">{t.compare.changes}</h3>
            <div className="grid grid-cols-5 gap-4">
              <DiffCard label={t.compare.critical} delta={result.diff.criticalDelta} color="text-red-400" increased={t.compare.increased} decreased={t.compare.decreased} unchanged={t.compare.unchanged} />
              <DiffCard label={t.compare.high} delta={result.diff.highDelta} color="text-orange-400" increased={t.compare.increased} decreased={t.compare.decreased} unchanged={t.compare.unchanged} />
              <DiffCard label={t.compare.medium} delta={result.diff.mediumDelta} color="text-yellow-400" increased={t.compare.increased} decreased={t.compare.decreased} unchanged={t.compare.unchanged} />
              <DiffCard label={t.compare.low} delta={result.diff.lowDelta} color="text-cyan-400" increased={t.compare.increased} decreased={t.compare.decreased} unchanged={t.compare.unchanged} />
              <DiffCard label={t.compare.total} delta={result.diff.findingsDelta} color="text-white" increased={t.compare.increased} decreased={t.compare.decreased} unchanged={t.compare.unchanged} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function DiffCard({ label, delta, color, increased, decreased, unchanged }: { label: string; delta: number; color: string; increased: string; decreased: string; unchanged: string }) {
  const isUp = delta > 0;
  const isDown = delta < 0;
  return (
    <div className="text-center">
      <div className={`text-xl font-bold ${color}`}>{delta > 0 ? '+' : ''}{delta}</div>
      <div className="text-xs text-dark-500">{label}</div>
      <div className={`text-xs mt-1 ${isUp ? 'text-red-400' : isDown ? 'text-green-400' : 'text-dark-500'}`}>
        {isUp ? increased : isDown ? decreased : unchanged}
      </div>
    </div>
  );
}
