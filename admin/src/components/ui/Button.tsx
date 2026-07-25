import { clsx } from 'clsx'
import type { ButtonHTMLAttributes } from 'react'

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger'
  size?: 'sm' | 'md'
  loading?: boolean
}

export function Button({ variant = 'primary', size = 'md', loading, className, children, disabled, ...rest }: Props) {
  return (
    <button
      disabled={disabled || loading}
      className={clsx(
        'inline-flex items-center justify-center gap-2 font-medium rounded-md border transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gold-300 focus-visible:ring-offset-2 focus-visible:ring-offset-canvas disabled:opacity-50 disabled:pointer-events-none',
        size === 'sm' && 'px-3 py-1.5 text-xs',
        size === 'md' && 'px-4 py-2 text-sm',
        variant === 'primary' && 'bg-axiom-900 text-white border-gold-400/50 hover:bg-axiom-800 active:bg-axiom-950 shadow-sm',
        variant === 'secondary' && 'bg-panel text-axiom-900 border-line hover:bg-slate-50 active:bg-slate-100',
        variant === 'ghost' && 'border-transparent text-ink-700 hover:bg-axiom-50 hover:text-axiom-900',
        variant === 'danger' && 'bg-red-700 text-white border-red-700 hover:bg-red-800 active:bg-red-900',
        className,
      )}
      {...rest}
    >
      {loading ? (
        <>
          <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          <span>Working</span>
        </>
      ) : children}
    </button>
  )
}
