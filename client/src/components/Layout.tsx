import { ReactNode, useEffect, useState } from 'react';
import Sidebar from './Sidebar';
import { useTranslation } from '../i18n';

export default function Layout({ children }: { children: ReactNode }) {
  const { dir } = useTranslation();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEffect(() => {
    document.documentElement.dir = dir;
  }, [dir]);

  return (
    <div className={`flex min-h-screen ${dir === 'rtl' ? 'flex-row-reverse' : ''}`}>
      {/* Mobile hamburger */}
      <button
        onClick={() => setSidebarOpen(!sidebarOpen)}
        className="fixed top-4 left-4 z-[60] lg:hidden bg-dark-800 border border-dark-700 rounded-lg p-2 text-gray-400 hover:text-white"
      >
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          {sidebarOpen
            ? <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            : <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
          }
        </svg>
      </button>

      {/* Mobile overlay */}
      {sidebarOpen && (
        <div className="fixed inset-0 bg-black/50 z-[49] lg:hidden" onClick={() => setSidebarOpen(false)} />
      )}

      {/* Sidebar */}
      <div className={`${dir === 'rtl' ? 'right-0' : 'left-0'} fixed top-0 bottom-0 z-50 transition-transform duration-200 lg:translate-x-0 ${
        sidebarOpen ? 'translate-x-0' : dir === 'rtl' ? 'translate-x-full' : '-translate-x-full'
      }`}>
        <Sidebar onNavigate={() => setSidebarOpen(false)} />
      </div>

      <main className={`flex-1 ${dir === 'rtl' ? 'lg:mr-64' : 'lg:ml-64'} p-4 lg:p-8 pt-16 lg:pt-8`}>{children}</main>
    </div>
  );
}
