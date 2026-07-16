import { useState, useEffect } from 'react';
import { useTranslation } from '../i18n';
import { getQuarantineList, restoreQuarantine, deleteQuarantineFile } from '../api/client';
import type { QuarantineRecord } from '../types';

export default function Quarantine() {
  const { t } = useTranslation();
  const [records, setRecords] = useState<QuarantineRecord[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadRecords();
  }, []);

  const loadRecords = async () => {
    setLoading(true);
    try {
      const data = await getQuarantineList();
      setRecords(data);
    } catch { setRecords([]); }
    finally { setLoading(false); }
  };

  const handleRestore = async (id: string) => {
    if (!confirm('Restore this file to its original location?')) return;
    try {
      await restoreQuarantine(id);
      loadRecords();
    } catch {}
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Permanently delete this quarantined file?')) return;
    try {
      await deleteQuarantineFile(id);
      loadRecords();
    } catch {}
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-100">Quarantine</h1>
        <p className="text-dark-500 mt-1">Manage quarantined files removed during security scans</p>
      </div>

      <div className="bg-dark-800 border border-dark-700 rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-dark-500">{t.dashboard.loading}</div>
        ) : records.length === 0 ? (
          <div className="p-8 text-center text-dark-500">No quarantined files</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-dark-700 text-xs text-dark-500 uppercase">
                <th className="text-left px-4 py-3">Original Path</th>
                <th className="text-left px-4 py-3">SHA-256</th>
                <th className="text-left px-4 py-3">Reason</th>
                <th className="text-left px-4 py-3">Quarantined</th>
                <th className="text-left px-4 py-3">Status</th>
                <th className="text-left px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {records.map(r => (
                <tr key={r.id} className="border-b border-dark-700/50 hover:bg-dark-700/30">
                  <td className="px-4 py-3 font-mono text-xs text-gray-300 max-w-[250px] truncate">{r.originalPath}</td>
                  <td className="px-4 py-3 font-mono text-xs text-dark-500">{r.sha256.slice(0, 16)}...</td>
                  <td className="px-4 py-3 text-xs text-gray-400 max-w-[200px] truncate">{r.reason}</td>
                  <td className="px-4 py-3 text-xs text-dark-500">{new Date(r.quarantinedAt).toLocaleDateString()}</td>
                  <td className="px-4 py-3">
                    {r.restored ? (
                      <span className="text-xs bg-green-500/20 text-green-400 px-2 py-0.5 rounded-full">Restored</span>
                    ) : (
                      <span className="text-xs bg-yellow-500/20 text-yellow-400 px-2 py-0.5 rounded-full">Quarantined</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-2">
                      {!r.restored && (
                        <button onClick={() => handleRestore(r.id)} className="text-xs text-green-400 hover:text-green-300">Restore</button>
                      )}
                      <button onClick={() => handleDelete(r.id)} className="text-xs text-red-400 hover:text-red-300">Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
