import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { getMitreMapping } from '../api/client';
import { useTranslation } from '../i18n';
import { IconTarget, IconShield } from '../components/Icons';

interface MitreMapping {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  findingCount: number;
  files: string[];
  severity: string;
  confidence: number;
}

interface MitreResult {
  mappings: MitreMapping[];
  coverageScore: number;
  topTactics: Array<{ tactic: string; count: number }>;
  totalMappedFindings: number;
}

const TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact', 'Supply Chain Compromise'
];

const TACTIC_COLORS: Record<string, string> = {
  'Reconnaissance': 'bg-cyan-500', 'Resource Development': 'bg-purple-500', 'Initial Access': 'bg-red-500',
  'Execution': 'bg-orange-500', 'Persistence': 'bg-yellow-600', 'Privilege Escalation': 'bg-pink-500',
  'Defense Evasion': 'bg-gray-500', 'Credential Access': 'bg-rose-500', 'Discovery': 'bg-teal-500',
  'Lateral Movement': 'bg-indigo-500', 'Collection': 'bg-violet-500', 'Command and Control': 'bg-amber-500',
  'Exfiltration': 'bg-lime-500', 'Impact': 'bg-red-700', 'Supply Chain Compromise': 'bg-emerald-600',
};

export default function MitreMatrix() {
  const { id } = useParams();
  const { t } = useTranslation();
  const [result, setResult] = useState<MitreResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!id) { setLoading(false); return; }
    getMitreMapping(id)
      .then(setResult)
      .catch(err => setError(err.message || 'Failed to load'))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) return <div className="text-center py-20 text-dark-500">Loading MITRE ATT&CK mapping...</div>;
  if (error) return <div className="text-center py-20 text-red-400">{error}</div>;
  if (!result || !result.mappings || result.mappings.length === 0) {
    return (
      <div className="text-center py-20">
        <IconTarget size={48} className="text-dark-600 mx-auto mb-4" />
        <p className="text-dark-500">No ATT&CK techniques mapped for this scan.</p>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center gap-3 mb-8">
        <IconTarget size={28} className="text-blue-400" />
        <div>
          <h1 className="text-2xl font-bold text-white">MITRE ATT&CK Matrix</h1>
          <p className="text-sm text-dark-500">Security findings mapped to ATT&CK techniques</p>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-5 text-center">
          <div className="text-3xl font-bold text-blue-400">{result.mappings.length}</div>
          <div className="text-xs text-dark-500 mt-1">Techniques Detected</div>
        </div>
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-5 text-center">
          <div className="text-3xl font-bold text-white">{result.totalMappedFindings}</div>
          <div className="text-xs text-dark-500 mt-1">Mapped Findings</div>
        </div>
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-5 text-center">
          <div className="text-3xl font-bold text-orange-400">{result.coverageScore.toFixed(0)}%</div>
          <div className="text-xs text-dark-500 mt-1">ATT&CK Coverage</div>
        </div>
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-5 text-center">
          <div className="text-3xl font-bold text-dark-500">{result.topTactics?.length || 0}</div>
          <div className="text-xs text-dark-500 mt-1">Tactics Impacted</div>
        </div>
      </div>

      <div className="bg-dark-800 border border-dark-700 rounded-xl p-6 mb-8">
        <h3 className="text-sm font-semibold text-dark-500 mb-4">Top Tactics</h3>
        <div className="flex flex-wrap gap-3">
          {(result.topTactics || []).map(t => (
            <div key={t.tactic} className="flex items-center gap-2 bg-dark-900 rounded-lg px-4 py-2">
              <div className={`w-3 h-3 rounded-full ${TACTIC_COLORS[t.tactic] || 'bg-gray-500'}`}></div>
              <span className="text-sm text-white">{t.tactic}</span>
              <span className="text-xs text-dark-500">({t.count})</span>
            </div>
          ))}
        </div>
      </div>

      <div className="space-y-3">
        {(result.mappings || []).sort((a, b) => b.findingCount - a.findingCount).map(m => (
          <div key={m.techniqueId} className="bg-dark-800 border border-dark-700 rounded-xl p-5">
            <div className="flex items-center gap-3 mb-2">
              <div className={`w-3 h-3 rounded-full ${TACTIC_COLORS[m.tactic] || 'bg-gray-500'}`}></div>
              <span className="font-mono text-sm text-blue-400">{m.techniqueId}</span>
              <span className="text-white font-medium">{m.techniqueName}</span>
              <span className="text-xs text-dark-500 ml-auto">{m.tactic}</span>
            </div>
            <div className="flex items-center gap-4 text-xs text-gray-400 ml-6">
              <span>{m.findingCount} findings</span>
              <span>Confidence: {m.confidence}%</span>
              <span>{m.files.length} files</span>
            </div>
            {m.files.length > 0 && (
              <div className="mt-2 ml-6 flex flex-wrap gap-1">
                {m.files.slice(0, 5).map(f => (
                  <span key={f} className="bg-dark-900 text-xs text-gray-400 px-2 py-0.5 rounded font-mono">{f}</span>
                ))}
                {m.files.length > 5 && <span className="text-xs text-dark-500">+{m.files.length - 5} more</span>}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
