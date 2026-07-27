/** Iconos SVG inline (sin dependencias, sin emojis). */
import React from 'react';

type P = { size?: number; className?: string };
const base = (size: number): React.SVGProps<SVGSVGElement> => ({
  width: size,
  height: size,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 2,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
});

export const Shield = ({ size = 18, className }: P) => (
  <svg {...base(size)} className={className}>
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);

export const Bug = ({ size = 18, className }: P) => (
  <svg {...base(size)} className={className}>
    <rect x="8" y="6" width="8" height="14" rx="4" />
    <path d="M19 7l-3 2M5 7l3 2M12 2v4M4 13H2m20 0h-2M5 19l3-1m8 1l-3-1M4.5 10.5L3 9m18 1.5L19.5 9" />
  </svg>
);

export const Wrench = ({ size = 18, className }: P) => (
  <svg {...base(size)} className={className}>
    <path d="M14.7 6.3a4 4 0 0 0-5.4 5.2L3 18l3 3 6.5-6.3a4 4 0 0 0 5.2-5.4l-2.6 2.6-2.3-.3-.3-2.3z" />
  </svg>
);

export const Check = ({ size = 18, className }: P) => (
  <svg {...base(size)} className={className}>
    <path d="M20 6L9 17l-5-5" />
  </svg>
);

export const Alert = ({ size = 18, className }: P) => (
  <svg {...base(size)} className={className}>
    <path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" />
    <path d="M12 9v4m0 4h.01" />
  </svg>
);

export const Play = ({ size = 18, className }: P) => (
  <svg {...base(size)} className={className}>
    <path d="M6 4l14 8-14 8V4z" fill="currentColor" stroke="none" />
  </svg>
);

export const Spinner = ({ size = 18, className }: P) => (
  <svg {...base(size)} className={className}>
    <path d="M21 12a9 9 0 1 1-6.2-8.6" />
  </svg>
);

export const Search = ({ size = 18, className }: P) => (
  <svg {...base(size)} className={className}>
    <circle cx="11" cy="11" r="7" />
    <path d="M21 21l-4.3-4.3" />
  </svg>
);

export const Github = ({ size = 18, className }: P) => (
  <svg {...base(size)} className={className}>
    <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.9a3.4 3.4 0 0 0-1-2.6c3-.3 6-1.5 6-6.6a5.1 5.1 0 0 0-1.4-3.6 4.8 4.8 0 0 0-.1-3.6s-1.1-.3-3.7 1.4a12.6 12.6 0 0 0-6.6 0C6.1 1.3 5 1.6 5 1.6a4.8 4.8 0 0 0-.1 3.6A5.1 5.1 0 0 0 3.5 8.8c0 5 3 6.3 6 6.6a3.4 3.4 0 0 0-1 2.6V22" />
  </svg>
);
