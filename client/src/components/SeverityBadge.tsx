import { Severity } from '../types';
import { useTranslation } from '../i18n';

const colors: Record<Severity, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  info: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

export default function SeverityBadge({ severity, count }: { severity: Severity; count: number }) {
  const { t } = useTranslation();
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-semibold border ${colors[severity]}`}>
      {t.severity[severity]}
      {count > 0 && <span className="ml-1 opacity-75">({count})</span>}
    </span>
  );
}
