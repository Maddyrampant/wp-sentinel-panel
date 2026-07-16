export const SAFE_DOMAINS: string[] = [
  'wordpress.org',
  'wordpress.com',
  'wp.com',
  'developer.wordpress.org',
  'codex.wordpress.org',
  'developer.wordpress.org',
  'make.wordpress.org',
  'global.wordpress.org',
  'w.org',
  'cdn.jsdelivr.net',
  'unpkg.com',
  'cdnjs.cloudflare.com',
  'cdn.jsdelivr.net',
  'ajax.googleapis.com',
  'fonts.googleapis.com',
  'fonts.gstatic.com',
  'www.google-analytics.com',
  'googletagmanager.com',
  'www.googletagmanager.com',
  'platform.twitter.com',
  'connect.facebook.net',
  'cdn.shopify.com',
  'stackpath.bootstrapcdn.com',
  'maxcdn.bootstrapcdn.com',
  'use.fontawesome.com',
  'cdnjs.cloudflare.com',
  'cdn.datatables.net',
  'cdn.ckeditor.com',
  'js.stripe.com',
  'player.vimeo.com',
  'www.youtube.com',
  'i.ytimg.com',
  'i0.wp.com',
  'i1.wp.com',
  'i2.wp.com',
  's.w.org',
  's0.wp.com',
  's1.wp.com',
  's2.wp.com',
  'secure.gravatar.com',
  'www.gravatar.com',
  'api.wordpress.org',
  'downloads.wordpress.org',
  'themes.svn.wordpress.org',
  'plugins.svn.wordpress.org',
];

export function isDomainSafe(domain: string): boolean {
  const normalized = domain.toLowerCase().replace(/^www\./, '');
  return SAFE_DOMAINS.some(
    (safe) => normalized === safe || normalized.endsWith('.' + safe)
  );
}

export function isDomainSuspicious(domain: string): boolean {
  if (isDomainSafe(domain)) return false;
  const tld = domain.split('.').pop()?.toLowerCase() || '';
  const suspiciousTlds = ['xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'cc', 'pw', 'top', 'club', 'work', 'buzz', 'icu', 'monster', 'cfd', 'sbs', 'rest'];
  if (suspiciousTlds.includes(tld)) return true;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) return true;
  if (domain.split('.').length === 1) return true;
  return false;
}
