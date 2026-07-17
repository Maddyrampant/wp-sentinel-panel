import { useEffect, useState } from 'react';
import { getFalsePositives, deleteFalsePositive } from '../api/client';
import type { FalsePositive } from '../types';
import { useTranslation } from '../i18n';
import { IconTrash, IconShieldCheck } from '../components/Icons';

export default function FalsePositives() {
  const { t } = useTranslation();
  const [fps, setFps] = useState<FalsePositive[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getFalsePositives()
      .then(d => setFps(Array.isArray(d) ? d : []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const handleDelete = async (id: string) => {
    if (!window.confirm(t.falsePositives?.deleteConfirm || 'Remove this false positive?')) return;
    await deleteFalsePositive(id);
    setFps(prev => prev.filter(fp => fp.id !== id));
  };

  if (loading) return <div className="text-center py-20 text-dark-500">{t.common?.loading || 'Loading...'}</div>;

  return (
    <div>
      <div className="flex items-center gap-3 mb-8">
        <IconShieldCheck size={28} className="text-blue-400" />
        <div>
          <h1 className="text-2xl font-bold text-white">{t.falsePositives?.title || 'False Positives'}</h1>
          <p className="text-sm text-dark-500">{t.falsePositives?.subtitle || 'Manage learned false positive exclusions'}</p>
        </div>
      </div>

      {fps.length === 0 ? (
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-12 text-center">
          <IconShieldCheck size={48} className="text-dark-600 mx-auto mb-4" />
          <p className="text-dark-500">{t.falsePositives?.noFps || 'No false positives recorded yet.'}</p>
        </div>
      ) : (
        <div className="bg-dark-800 border border-dark-700 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-dark-500 text-xs uppercase border-b border-dark-700">
                <th className="px-6 py-3 text-left">Rule ID</th>
                <th className="px-6 py-3 text-left">Scope</th>
                <th className="px-6 py-3 text-left">Reason</th>
                <th className="px-6 py-3 text-left">Created</th>
                <th className="px-6 py-3 text-left">Actions</th>
              </tr>
            </thead>
            <tbody>
              {fps.map(fp => (
                <tr key={fp.id} className="border-t border-dark-700/50 hover:bg-dark-700/30">
                  <td className="px-6 py-3 font-mono text-blue-400 text-xs">{fp.ruleId}</td>
                  <td className="px-6 py-3">
                    <span className="px-2 py-0.5 rounded text-xs bg-dark-600 text-gray-300">{fp.scope}</span>
                  </td>
                  <td className="px-6 py-3 text-gray-300 max-w-xs truncate">{fp.reason}</td>
                  <td className="px-6 py-3 text-dark-500 text-xs">{new Date(fp.createdAt).toLocaleDateString()}</td>
                  <td className="px-6 py-3">
                    <button onClick={() => handleDelete(fp.id)} className="text-red-400 hover:text-red-300 transition-colors">
                      <IconTrash size={16} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
