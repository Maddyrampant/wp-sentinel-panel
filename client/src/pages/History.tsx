import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { getHistory, deleteScan } from '../api/client';
import type { ScanHistoryItem } from '../types';
import LoadingSpinner from '../components/LoadingSpinner';
import { useTranslation } from '../i18n';

export default function History() {
  const { t } = useTranslation();
  const [items, setItems] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    getHistory(100).then(setItems).finally(() => setLoading(false));
  };

  useEffect(load, []);

  const handleDelete = async (id: string) => {
    if (!confirm(t.history.deleteConfirm)) return;
    await deleteScan(id);
    setItems(items.filter(i => i.id !== id));
  };

  if (loading) return <LoadingSpinner />;

  return (
    <div>
      <h1 className="text-3xl font-bold text-white mb-2">{t.history.title}</h1>
      <p className="text-dark-500 mb-6">{items.length} {t.history.scansRecorded}</p>

      <div className="bg-dark-800 border border-dark-700 rounded-xl">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-dark-500 text-xs uppercase border-b border-dark-700">
              <th className="px-5 py-3 text-left">{t.history.name}</th>
              <th className="px-5 py-3 text-left">{t.history.date}</th>
              <th className="px-5 py-3 text-left">{t.history.files}</th>
              <th className="px-5 py-3 text-left">{t.history.php}</th>
              <th className="px-5 py-3 text-left">{t.history.findings}</th>
              <th className="px-5 py-3 text-left">{t.history.severity}</th>
              <th className="px-5 py-3 text-left">{t.history.actions}</th>
            </tr>
          </thead>
          <tbody>
            {(items || []).map((s) => (
              <tr key={s.id} className="border-t border-dark-700 hover:bg-dark-700/50 transition-colors">
                <td className="px-5 py-3">
                  <Link to={`/scan/${s.id}`} className="text-white font-medium hover:text-blue-400 transition-colors">{s.target_name}</Link>
                </td>
                <td className="px-5 py-3 text-dark-500">{new Date(s.scan_date).toLocaleString()}</td>
                <td className="px-5 py-3 text-gray-400">{s.total_files}</td>
                <td className="px-5 py-3 text-gray-400">{s.php_files}</td>
                <td className="px-5 py-3 text-white font-medium">{s.total_findings}</td>
                <td className="px-5 py-3">
                  <div className="flex gap-1">
                    {s.critical_count > 0 && <span className="text-red-400 text-xs">{t.severity.critical[0]}:{s.critical_count}</span>}
                    {s.high_count > 0 && <span className="text-orange-400 text-xs">{t.severity.high[0]}:{s.high_count}</span>}
                    {s.medium_count > 0 && <span className="text-yellow-400 text-xs">{t.severity.medium[0]}:{s.medium_count}</span>}
                    {s.low_count > 0 && <span className="text-cyan-400 text-xs">{t.severity.low[0]}:{s.low_count}</span>}
                  </div>
                </td>
                <td className="px-5 py-3">
                  <Link to={`/scan/${s.id}`} className="text-blue-400 hover:underline text-xs mr-3">{t.history.view}</Link>
                  <button onClick={() => handleDelete(s.id)} className="text-red-400 hover:underline text-xs">{t.history.delete}</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {items.length === 0 && <div className="p-8 text-center text-dark-500">{t.history.noScansYet}</div>}
      </div>
    </div>
  );
}
