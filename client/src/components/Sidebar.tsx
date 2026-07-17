import { NavLink } from 'react-router-dom';
import { useTranslation } from '../i18n';
import { IconDashboard, IconSearch, IconHistory, IconCompare, IconTarget, IconPalette, IconDatabase, IconRadar, IconLock, IconSecurity, IconLangEn, IconLangFa, IconShieldCheck } from './Icons';

export default function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const { t, lang, setLang, dir } = useTranslation();

  const links = [
    { to: '/', icon: <IconDashboard size={18} />, label: t.nav.dashboard },
    { to: '/scan/new', icon: <IconSearch size={18} />, label: t.nav.newScan },
    { to: '/history', icon: <IconHistory size={18} />, label: t.nav.history },
    { to: '/compare', icon: <IconCompare size={18} />, label: t.nav.compare },
    { to: '/rules', icon: <IconTarget size={18} />, label: t.nav.customRules },
    { to: '/theme-intel', icon: <IconPalette size={18} />, label: t.nav.themeIntel },
    { to: '/db-scan', icon: <IconDatabase size={18} />, label: t.nav.dbScan },
    { to: '/threat-intel', icon: <IconRadar size={18} />, label: t.nav.threatIntel },
    { to: '/quarantine', icon: <IconLock size={18} />, label: t.nav.quarantine },
    { to: '/false-positives', icon: <IconShieldCheck size={18} />, label: t.nav.falsePositives },
  ];

  return (
    <aside className={`fixed top-0 bottom-0 w-64 bg-dark-800 border-dark-700 flex flex-col z-50 ${dir === 'rtl' ? 'right-0 border-l' : 'left-0 border-r'}`}>
      <div className="p-6 border-b border-dark-700">
        <h1 className="text-xl font-bold text-blue-400 flex items-center gap-2"><IconSecurity size={22} /> {t.appName}</h1>
        <p className="text-xs text-dark-500 mt-1">{t.appSubtitle}</p>
      </div>
      <nav className="flex-1 p-4 space-y-1">
        {links.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            end={link.to === '/'}
            onClick={onNavigate}
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-3 rounded-lg text-sm transition-colors ${
                isActive
                  ? 'bg-blue-500/20 text-blue-400 font-medium'
                  : 'text-gray-400 hover:bg-dark-700 hover:text-gray-200'
              }`
            }
          >
            <span className="text-lg flex-shrink-0">{link.icon}</span>
            {link.label}
          </NavLink>
        ))}
      </nav>
      {/* Language Switcher */}
      <div className="p-4 border-t border-dark-700">
        <div className="flex items-center justify-center gap-2 mb-3">
          <button
            onClick={() => setLang('en')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 ${
              lang === 'en' ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/20' : 'bg-dark-700 text-dark-500 hover:text-gray-300'
            }`}
          >
            <IconLangEn size={14} /> English
          </button>
          <button
            onClick={() => setLang('fa')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 ${
              lang === 'fa' ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/20' : 'bg-dark-700 text-dark-500 hover:text-gray-300'
            }`}
          >
            <IconLangFa size={14} /> فارسی
          </button>
        </div>
        <p className="text-xs text-dark-500 text-center">{t.version}</p>
      </div>
    </aside>
  );
}
