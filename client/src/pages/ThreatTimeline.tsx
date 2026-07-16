import { useState, useEffect } from 'react';
import { useTranslation } from '../i18n';
import { getTimeline, getAttackChains, getRemediationPlan, getSiteStatus } from '../api/client';
import type { TimelineEvent, AttackChain, RemediationPlan, SiteStatus } from '../types';

export default function ThreatTimeline() {
  const { t } = useTranslation();
  const [scanId, setScanId] = useState('');
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [chains, setChains] = useState<AttackChain[]>([]);
  const [remediation, setRemediation] = useState<RemediationPlan | null>(null);
  const [siteStatus, setSiteStatus] = useState<SiteStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'timeline' | 'chains' | 'remediation' | 'status'>('status');

  const load = async () => {
    if (!scanId.trim()) return;
    setLoading(true);
    try {
      const [tl, ch, rem, st] = await Promise.all([
        getTimeline(scanId).catch(() => []),
        getAttackChains(scanId).catch(() => []),
        getRemediationPlan(scanId).catch(() => null),
        getSiteStatus(scanId).catch(() => null),
      ]);
      setTimeline(Array.isArray(tl) ? tl : []);
      setChains(Array.isArray(ch) ? ch : []);
      setRemediation(rem);
      setSiteStatus(st);
    } finally { setLoading(false); }
  };

  const statusColor = (s: string) => {
    switch (s) {
      case 'confirmed_compromised': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'likely_compromised': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'suspicious': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      default: return 'bg-green-500/20 text-green-400 border-green-500/30';
    }
  };

  const sevDot = (s: string) => {
    switch (s) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      default: return 'bg-blue-500';
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-100">Threat Intelligence</h1>
        <p className="text-dark-500 mt-1">Timeline, attack chains, remediation plan, and site compromise status</p>
      </div>

      <div className="bg-dark-800 border border-dark-700 rounded-xl p-4 flex gap-3 items-end">
        <div className="flex-1">
          <label className="block text-xs text-dark-500 mb-1">Scan ID</label>
          <input value={scanId} onChange={e => setScanId(e.target.value)} placeholder="Enter scan ID..." className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-gray-200" />
        </div>
        <button onClick={load} disabled={loading || !scanId} className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-5 py-2 rounded-lg text-sm font-medium">
          {loading ? 'Loading...' : 'Analyze'}
        </button>
      </div>

      {siteStatus && (
        <div className={`border rounded-xl p-6 ${statusColor(siteStatus.status)}`}>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-bold uppercase">{siteStatus.status.replace(/_/g, ' ')}</h2>
            <div className="text-right">
              <div className="text-2xl font-bold">{siteStatus.confidence}%</div>
              <div className="text-xs opacity-70">confidence</div>
            </div>
          </div>
          {siteStatus.mainReasons.length > 0 && (
            <div className="space-y-1">
              {siteStatus.mainReasons.map((r, i) => (
                <div key={i} className="text-sm flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-current shrink-0" />
                  {r}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="flex gap-4 border-b border-dark-700">
        {(['status', 'timeline', 'chains', 'remediation'] as const).map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            className={`pb-3 px-1 text-sm font-medium border-b-2 transition-colors ${activeTab === tab ? 'border-blue-500 text-blue-400' : 'border-transparent text-dark-500 hover:text-gray-300'}`}>
            {tab === 'status' ? 'Site Status' : tab === 'timeline' ? 'Timeline' : tab === 'chains' ? `Attack Chains (${chains.length})` : 'Remediation'}
          </button>
        ))}
      </div>

      {activeTab === 'timeline' && (
        <div className="space-y-0">
          {timeline.length === 0 ? (
            <div className="bg-dark-800 border border-dark-700 rounded-xl p-8 text-center text-dark-500">No timeline events</div>
          ) : (
            <div className="relative pl-8">
              <div className="absolute left-3 top-0 bottom-0 w-0.5 bg-dark-700" />
              {timeline.map(ev => (
                <div key={ev.id} className="relative mb-6">
                  <div className={`absolute -left-5 top-1 w-3 h-3 rounded-full ${sevDot(ev.severity)} ring-2 ring-dark-800`} />
                  <div className="bg-dark-800 border border-dark-700 rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-mono text-dark-500">{new Date(ev.timestamp).toLocaleString()}</span>
                      <span className={`text-xs px-1.5 py-0.5 rounded ${sevDot(ev.severity)} bg-opacity-20 text-${ev.severity === 'critical' ? 'red' : ev.severity === 'high' ? 'orange' : ev.severity === 'medium' ? 'yellow' : 'blue'}-400`}>
                        {ev.severity}
                      </span>
                      <span className="text-xs text-dark-500">{ev.type.replace(/_/g, ' ')}</span>
                    </div>
                    <p className="text-sm text-gray-300">{ev.description}</p>
                    {ev.file && <p className="text-xs font-mono text-dark-500 mt-1">{ev.file}</p>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'chains' && (
        <div className="space-y-4">
          {chains.length === 0 ? (
            <div className="bg-dark-800 border border-dark-700 rounded-xl p-8 text-center text-dark-500">No attack chains detected</div>
          ) : (
            chains.map(chain => (
              <div key={chain.id} className="bg-dark-800 border border-dark-700 rounded-xl p-5">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${chain.severity === 'critical' ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'}`}>
                      {chain.severity.toUpperCase()}
                    </span>
                    <span className="text-sm font-semibold text-gray-200">{chain.chainType.replace(/_/g, ' ')}</span>
                  </div>
                  <span className="text-xs text-dark-500">Score: {chain.riskScore}</span>
                </div>
                <div className="flex items-center gap-2 mb-3">
                  {chain.links.map((link, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <span className="text-xs bg-dark-900 border border-dark-600 rounded px-2 py-1 text-gray-400">{link.type.replace(/_/g, ' ')}</span>
                      {i < chain.links.length - 1 && <span className="text-dark-500">→</span>}
                    </div>
                  ))}
                </div>
                <div className="text-xs text-dark-500 mb-2">Files: {chain.files.join(', ')}</div>
                <p className="text-xs text-blue-400/80">💡 {chain.recommendation}</p>
              </div>
            ))
          )}
        </div>
      )}

      {activeTab === 'remediation' && remediation && (
        <div className="space-y-4">
          <div className={`border rounded-xl p-4 ${statusColor(remediation.overallStatus)}`}>
            <div className="flex items-center justify-between">
              <span className="font-bold uppercase">{remediation.overallStatus.replace(/_/g, ' ')}</span>
              <span className="text-xs">Urgency: {remediation.urgency}</span>
            </div>
            <p className="text-sm mt-2 opacity-80">{remediation.summary}</p>
          </div>
          <div className="space-y-3">
            {remediation.steps.map(step => (
              <div key={step.order} className="bg-dark-800 border border-dark-700 rounded-lg p-4">
                <div className="flex items-center gap-3 mb-2">
                  <span className="w-6 h-6 rounded-full bg-blue-600 text-white text-xs flex items-center justify-center font-bold">{step.order}</span>
                  <span className={`text-xs px-2 py-0.5 rounded ${step.severity === 'critical' ? 'bg-red-500/20 text-red-400' : step.severity === 'high' ? 'bg-orange-500/20 text-orange-400' : 'bg-dark-700 text-dark-500'}`}>{step.severity}</span>
                  <span className="text-xs text-dark-500">{step.category}</span>
                  <span className="text-xs text-dark-600 ml-auto">~{step.estimatedTime}</span>
                </div>
                <p className="text-sm font-medium text-gray-200">{step.action}</p>
                <p className="text-xs text-gray-400 mt-1">{step.details}</p>
                {step.affectedFiles && step.affectedFiles.length > 0 && (
                  <div className="mt-2 text-xs text-dark-500 font-mono">{step.affectedFiles.join(', ')}</div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
