interface IconProps {
  className?: string;
  size?: number;
}

function Svg({ className = '', size = 20, children }: IconProps & { children?: React.ReactNode }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      {children}
    </svg>
  );
}

export function IconDashboard({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="4" rx="1" />
      <rect x="14" y="10" width="7" height="11" rx="1" />
      <rect x="3" y="13" width="7" height="8" rx="1" />
    </Svg>
  );
}

export function IconSearch({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <circle cx="11" cy="11" r="7" />
      <path d="M21 21l-4.35-4.35" />
    </Svg>
  );
}

export function IconHistory({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <circle cx="12" cy="12" r="9" />
      <polyline points="12,7 12,12 15,15" />
    </Svg>
  );
}

export function IconCompare({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path d="M8 3H5a2 2 0 00-2 2v14a2 2 0 002 2h3" />
      <path d="M16 3h3a2 2 0 012 2v14a2 2 0 01-2 2h-3" />
      <path d="M12 20V4" />
      <polyline points="9,8 12,4 15,8" />
    </Svg>
  );
}

export function IconTarget({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <circle cx="12" cy="12" r="9" />
      <circle cx="12" cy="12" r="5" />
      <circle cx="12" cy="12" r="1" />
    </Svg>
  );
}

export function IconPalette({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <circle cx="13.5" cy="6.5" r="2.5" />
      <circle cx="17.5" cy="10.5" r="2.5" />
      <circle cx="8.5" cy="7.5" r="2.5" />
      <circle cx="6.5" cy="12" r="2.5" />
      <path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c1.5 0 3-1 3-3 0-.7-.3-1.4-.7-1.9-.4-.5-.7-1.1-.7-1.8 0-1.4 1.1-2.5 2.5-2.5H18c3.3 0 6-2.7 6-6 0-5.5-4.5-9.8-12-9.8z" />
    </Svg>
  );
}

export function IconDatabase({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <ellipse cx="12" cy="5" rx="8" ry="3" />
      <path d="M4 5v6c0 1.66 3.58 3 8 3s8-1.34 8-3V5" />
      <path d="M4 11v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6" />
    </Svg>
  );
}

export function IconRadar({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <circle cx="12" cy="12" r="9" />
      <circle cx="12" cy="12" r="5" />
      <circle cx="12" cy="12" r="1" fill="currentColor" />
      <path d="M12 3v3" />
      <path d="M19.07 4.93l-2.12 2.12" />
    </Svg>
  );
}

export function IconShield({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path d="M12 2l7 4v5c0 5.25-3.5 8.75-7 10-3.5-1.25-7-4.75-7-10V6l7-4z" />
      <polyline points="9,12 11,14 15,10" />
    </Svg>
  );
}

export function IconLock({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <rect x="5" y="11" width="14" height="10" rx="2" />
      <path d="M8 11V7a4 4 0 018 0v4" />
    </Svg>
  );
}

export function IconEyeOff({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94" />
      <path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19" />
      <path d="M14.12 14.12a3 3 0 11-4.24-4.24" />
      <line x1="1" y1="1" x2="23" y2="23" />
    </Svg>
  );
}

export function IconGlobe({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <circle cx="12" cy="12" r="9" />
      <ellipse cx="12" cy="12" rx="4" ry="9" />
      <path d="M3 12h18" />
      <path d="M4.5 7.5h15" />
      <path d="M4.5 16.5h15" />
    </Svg>
  );
}

export function IconCode({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <polyline points="16,18 22,12 16,6" />
      <polyline points="8,6 2,12 8,18" />
      <line x1="14" y1="4" x2="10" y2="20" />
    </Svg>
  );
}

export function IconFileSearch({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
      <polyline points="14,2 14,8 20,8" />
      <circle cx="11" cy="14" r="3" />
      <path d="M13.5 13.5L16 16" />
    </Svg>
  );
}

export function IconServer({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <rect x="3" y="3" width="18" height="6" rx="2" />
      <rect x="3" y="15" width="18" height="6" rx="2" />
      <circle cx="7" cy="6" r="1" fill="currentColor" />
      <circle cx="7" cy="18" r="1" fill="currentColor" />
      <path d="M15 6h3" />
      <path d="M15 18h3" />
    </Svg>
  );
}

export function IconFileText({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
      <polyline points="14,2 14,8 20,8" />
      <line x1="8" y1="13" x2="16" y2="13" />
      <line x1="8" y1="17" x2="13" y2="17" />
    </Svg>
  );
}

export function IconDownload({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
      <polyline points="7,10 12,15 17,10" />
      <line x1="12" y1="15" x2="12" y2="3" />
    </Svg>
  );
}

export function IconUpload({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
      <polyline points="17,8 12,3 7,8" />
      <line x1="12" y1="3" x2="12" y2="15" />
    </Svg>
  );
}

export function IconUploadCloud({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path d="M16 16l-4-4-4 4" />
      <path d="M12 12v9" />
      <path d="M20.39 18.39A5 5 0 0018 9h-1.26A8 8 0 103 16.3" />
      <polyline points="16,16 12,12 8,16" />
    </Svg>
  );
}

export function IconDoor({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path d="M18 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V4a2 2 0 00-2-2z" />
      <path d="M14 2v4H6" />
      <circle cx="12" cy="14" r="1.5" fill="currentColor" />
    </Svg>
  );
}

export function IconSpider({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <circle cx="12" cy="12" r="3" />
      <path d="M12 2v4" />
      <path d="M12 18v4" />
      <path d="M4.93 4.93l2.83 2.83" />
      <path d="M16.24 16.24l2.83 2.83" />
      <path d="M2 12h4" />
      <path d="M18 12h4" />
      <path d="M4.93 19.07l2.83-2.83" />
      <path d="M16.24 7.76l2.83-2.83" />
    </Svg>
  );
}

export function IconRefresh({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <polyline points="23,4 23,10 17,10" />
      <polyline points="1,20 1,14 7,14" />
      <path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15" />
    </Svg>
  );
}

export function IconArrowUpRight({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <line x1="7" y1="17" x2="17" y2="7" />
      <polyline points="7,7 17,7 17,17" />
    </Svg>
  );
}

export function IconKey({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.78 7.78 5.5 5.5 0 017.78-7.78zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
    </Svg>
  );
}

export function IconZap({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <polygon points="13,2 3,14 12,14 11,22 21,10 12,10" />
    </Svg>
  );
}

export function IconBug({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <rect x="8" y="6" width="8" height="14" rx="4" />
      <path d="M2 10h2" />
      <path d="M20 10h2" />
      <path d="M2 14h2" />
      <path d="M20 14h2" />
      <path d="M8 6V4" />
      <path d="M16 6V4" />
      <path d="M8 6c0 2-2 4-5 4" />
      <path d="M16 6c0 2 2 4 5 4" />
    </Svg>
  );
}

export function IconCheckCircle({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <circle cx="12" cy="12" r="9" />
      <polyline points="9,12 11,14 15,10" />
    </Svg>
  );
}

export function IconXCircle({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <circle cx="12" cy="12" r="9" />
      <line x1="9" y1="9" x2="15" y2="15" />
      <line x1="15" y1="9" x2="9" y2="15" />
    </Svg>
  );
}

export function IconLightbulb({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path d="M9 18h6" />
      <path d="M10 22h4" />
      <path d="M15.09 14c.18-.98.65-1.74 1.41-2.5A4.65 4.65 0 0018 8 6 6 0 006 8c0 1 .23 2.23 1.5 3.5A4.61 4.61 0 018.91 14" />
    </Svg>
  );
}

export function IconPackage({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path d="M16.5 9.4l-9-5.19M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z" />
      <polyline points="3.27,6.96 12,12.01 20.73,6.96" />
      <line x1="12" y1="22.08" x2="12" y2="12" />
    </Svg>
  );
}

export function IconFolderOpen({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path d="M5 19a2 2 0 01-2-2V7a2 2 0 012-2h4l2 2h4a2 2 0 012 2v1" />
      <path d="M20.27 9H8.18a1 1 0 00-.95.68L4.23 19a1 1 0 00.95 1.32h15.09" />
    </Svg>
  );
}

export function IconShieldAlert({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path d="M12 2l7 4v5c0 5.25-3.5 8.75-7 10-3.5-1.25-7-4.75-7-10V6l7-4z" />
      <line x1="12" y1="8" x2="12" y2="12" />
      <line x1="12" y1="16" x2="12.01" y2="16" />
    </Svg>
  );
}

export function IconImport({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path d="M12 3v12" />
      <polyline points="8,11 12,15 16,11" />
      <path d="M20 21H4" />
    </Svg>
  );
}

export function IconExport({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path d="M12 21V9" />
      <polyline points="16,5 12,1 8,5" />
      <path d="M20 3H4" />
    </Svg>
  );
}

export function IconLangEn({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <circle cx="12" cy="12" r="9" strokeWidth={1.2} />
      <path d="M3 12h18" strokeWidth={1.2} />
      <path d="M12 3c3 3 4.5 5.5 4.5 9s-1.5 6-4.5 9" strokeWidth={1.2} />
      <path d="M12 3c-3 3-4.5 5.5-4.5 9s1.5 6 4.5 9" strokeWidth={1.2} />
    </Svg>
  );
}

export function IconLangFa({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <circle cx="12" cy="12" r="9" strokeWidth={1.2} />
      <path d="M8 8h8M8 12h8M8 16h5" strokeWidth={1.2} />
    </Svg>
  );
}

export function IconSecurity({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path d="M12 2l7 4v5c0 5.25-3.5 8.75-7 10-3.5-1.25-7-4.75-7-10V6l7-4z" />
    </Svg>
  );
}

export function IconCategory({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" />
    </Svg>
  );
}
