import { createContext, useContext, useState, ReactNode } from 'react';
import en from './en';
import fa from './fa';
import { checkTranslations } from './checks';

export type Lang = 'en' | 'fa';
export type Translations = typeof en;

const translations: Record<Lang, Translations> = { en, fa };

export interface CheckTranslation {
  name: string;
  desc: string;
}

interface I18nContextType {
  lang: Lang;
  t: Translations;
  dir: 'ltr' | 'rtl';
  setLang: (lang: Lang) => void;
  tc: (checkId: string) => CheckTranslation;
}

const I18nContext = createContext<I18nContextType>({
  lang: 'en',
  t: en,
  dir: 'ltr',
  setLang: () => {},
  tc: () => ({ name: '', desc: '' }),
});

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(() => {
    const saved = localStorage.getItem('wp-sentinel-lang');
    return (saved === 'en' || saved === 'fa') ? saved : 'en';
  });

  const setLang = (newLang: Lang) => {
    setLangState(newLang);
    localStorage.setItem('wp-sentinel-lang', newLang);
    document.documentElement.dir = newLang === 'fa' ? 'rtl' : 'ltr';
    document.documentElement.lang = newLang;
  };

  const dir = lang === 'fa' ? 'rtl' : 'ltr';

  const tc = (checkId: string): CheckTranslation => {
    const translations = checkTranslations[lang] || checkTranslations.en;
    return translations[checkId as keyof typeof translations] || { name: checkId, desc: '' };
  };

  return (
    <I18nContext.Provider value={{ lang, t: translations[lang], dir, setLang, tc }}>
      {children}
    </I18nContext.Provider>
  );
}

export function useTranslation() {
  return useContext(I18nContext);
}
