import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { getStats, getHistory, getTrend } from '../api/client';
import type { DashboardStats, ScanHistoryItem, TrendDataPoint } from '../types';
import { useTranslation } from '../i18n';
import { Line } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend } from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend);

export default function Dashboard() {
  const { t } = useTranslation();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recent, setRecent] = useState<ScanHistoryItem[]>([]);
  const [trend, setTrend] = useState<TrendDataPoint[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getStats().then(setStats).catch(() => {});
    getHistory(5).then(setRecent).catch(() => {});
    getTrend().then(setTrend).catch(() => {});
    setLoading(false);
  }, []);

  if (loading) return <div className="text-center py-20 text-dark-500">{t.dashboard.loading}</div>;

  const trendChartData = Array.isArray(trend) && trend.length > 1 ? {
    labels: trend.map(d => d.date),
    datasets: [
      { label: t.severity.critical, data: trend.map(d => d.critical), borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.1)', tension: 0.3 },
      { label: t.severity.high, data: trend.map(d => d.high), borderColor: '#f97316', backgroundColor: 'rgba(249,115,22,0.1)', tension: 0.3 },
      { label: t.severity.medium, data: trend.map(d => d.medium), borderColor: '#eab308', backgroundColor: 'rgba(234,179,8,0.1)', tension: 0.3 },
      { label: t.severity.low, data: trend.map(d => d.low), borderColor: '#06b6d4', backgroundColor: 'rgba(6,182,212,0.1)', tension: 0.3 },
    ],
  } : null;

  const trendChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } },
    scales: {
      x: { ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: '#1e293b' } },
      y: { ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: '#1e293b' } },
    },
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white">{t.dashboard.title}</h1>
          <p className="text-dark-500 mt-1">{t.dashboard.subtitle}</p>
        </div>
        <Link to="/scan/new" className="bg-blue-600 hover:bg-blue-500 text-white px-6 py-3 rounded-lg font-medium transition-colors">
          + {t.nav.newScan}
        </Link>
      </div>

      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 mb-8">
          <StatCard label={t.dashboard.totalScans} value={stats.totalScans} color="text-blue-400" />
          <StatCard label={t.dashboard.totalFindings} value={stats.totalFindings} color="text-white" />
          <StatCard label={t.dashboard.critical} value={stats.criticalTotal} color="text-red-400" />
          <StatCard label={t.dashboard.high} value={stats.highTotal} color="text-orange-400" />
          <StatCard label={t.dashboard.avgDuration} value={`${stats.avgDuration}ms`} color="text-dark-500" />
        </div>
      )}

      {trendChartData && (
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-6 mb-8">
          <h3 className="text-sm font-semibold text-dark-500 mb-4">{t.trend.title}</h3>
          <div className="h-64">
            <Line data={trendChartData} options={trendChartOptions} />
          </div>
        </div>
      )}

      {stats && stats.totalFindings > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
            <h3 className="text-sm font-semibold text-dark-500 mb-4">{t.dashboard.findingsBySeverity}</h3>
            <div className="space-y-3">
              {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
                const count = stats[`${sev}Total` as keyof DashboardStats] as number;
                const max = Math.max(stats.criticalTotal, stats.highTotal, stats.mediumTotal, stats.lowTotal, stats.infoTotal, 1);
                const pct = (count / max) * 100;
                const barColors: Record<string, string> = { critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-cyan-500', info: 'bg-gray-500' };
                return (
                  <div key={sev} className="flex items-center gap-3">
                    <span className="text-xs text-dark-500 w-16">{t.severity[sev]}</span>
                    <div className="flex-1 bg-dark-700 rounded-full h-2">
                      <div className={`h-2 rounded-full ${barColors[sev]}`} style={{ width: `${pct}%` }}></div>
                    </div>
                    <span className="text-xs text-dark-500 w-8 text-right">{count}</span>
                  </div>
                );
              })}
            </div>
          </div>
          <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
            <h3 className="text-sm font-semibold text-dark-500 mb-4">{t.dashboard.quickStats}</h3>
            <div className="space-y-3 text-sm">
              <div className="flex justify-between"><span className="text-gray-400">{t.dashboard.totalPhpFiles}</span><span className="text-white font-medium">{stats.totalPhpFiles}</span></div>
              <div className="flex justify-between"><span className="text-gray-400">{t.dashboard.totalFilesScanned}</span><span className="text-white font-medium">{stats.totalFiles}</span></div>
              <div className="flex justify-between"><span className="text-gray-400">{t.dashboard.criticalIssues}</span><span className="text-red-400 font-medium">{stats.criticalTotal}</span></div>
              <div className="flex justify-between"><span className="text-gray-400">{t.dashboard.highIssues}</span><span className="text-orange-400 font-medium">{stats.highTotal}</span></div>
            </div>
          </div>
        </div>
      )}

      <div className="bg-dark-800 border border-dark-700 rounded-xl">
        <div className="px-6 py-4 border-b border-dark-700 flex items-center justify-between">
          <h3 className="font-semibold text-white">{t.dashboard.recentScans}</h3>
          <Link to="/history" className="text-blue-400 text-sm hover:underline">{t.dashboard.viewAll}</Link>
        </div>
        {recent.length === 0 ? (
          <div className="p-8 text-center text-dark-500">{t.dashboard.noScansYet}</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="text-dark-500 text-xs uppercase"><th className="px-6 py-3 text-left">{t.dashboard.name}</th><th className="px-6 py-3 text-left">{t.dashboard.date}</th><th className="px-6 py-3 text-left hidden sm:table-cell">{t.dashboard.files}</th><th className="px-6 py-3 text-left">{t.dashboard.findings}</th><th className="px-6 py-3 text-left">{t.dashboard.actions}</th></tr></thead>
              <tbody>
                {(recent || []).map((s) => (
                  <tr key={s.id} className="border-t border-dark-700 hover:bg-dark-700/50">
                    <td className="px-6 py-3 text-white font-medium">{s.target_name}</td>
                    <td className="px-6 py-3 text-dark-500">{new Date(s.scan_date).toLocaleDateString()}</td>
                    <td className="px-6 py-3 text-gray-400 hidden sm:table-cell">{s.total_files}</td>
                    <td className="px-6 py-3">
                      <span className="text-white">{s.total_findings}</span>
                      {s.critical_count > 0 && <span className="ml-2 text-red-400 text-xs">({s.critical_count} {t.dashboard.criticalCount})</span>}
                    </td>
                    <td className="px-6 py-3"><Link to={`/scan/${s.id}`} className="text-blue-400 hover:underline">{t.dashboard.view}</Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: number | string; color: string }) {
  return (
    <div className="bg-dark-800 border border-dark-700 rounded-xl p-5">
      <div className={`text-2xl lg:text-3xl font-bold ${color}`}>{value}</div>
      <div className="text-xs text-dark-500 mt-1">{label}</div>
    </div>
  );
}
