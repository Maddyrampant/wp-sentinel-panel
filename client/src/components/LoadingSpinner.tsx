import { useTranslation } from '../i18n';

export default function LoadingSpinner({ text }: { text?: string }) {
  const { t } = useTranslation();
  return (
    <div className="flex flex-col items-center justify-center py-20">
      <div className="w-12 h-12 border-4 border-dark-700 border-t-blue-500 rounded-full animate-spin mb-4"></div>
      <p className="text-dark-500 text-sm">{text || t.dashboard.loading}</p>
    </div>
  );
}
