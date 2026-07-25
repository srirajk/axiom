import { clsx } from 'clsx'
import { useId } from 'react'
import type { InputHTMLAttributes, SelectHTMLAttributes, TextareaHTMLAttributes } from 'react'

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string
  error?: string
  hint?: string
}

export function Input({ label, error, hint, className, id, ...rest }: InputProps) {
  const generatedId = useId()
  const inputId = id ?? (label ? `${label.toLowerCase().replace(/\s+/g, '-')}-${generatedId}` : generatedId)
  const describedBy = error ? `${inputId}-error` : hint ? `${inputId}-hint` : undefined
  return (
    <div className="flex flex-col gap-1">
      {label && <label htmlFor={inputId} className="text-sm font-medium text-ink-700">{label}</label>}
      <input
        id={inputId}
        aria-invalid={!!error}
        aria-describedby={describedBy}
        className={clsx(
          'px-3 py-2 text-sm border rounded-md bg-white/95 text-ink-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-gold-300 focus:border-axiom-700 transition-colors shadow-sm',
          error ? 'border-red-400 focus:ring-red-300 focus:border-red-500' : 'border-line',
          rest.disabled && 'bg-slate-50 text-slate-500 cursor-not-allowed',
          className,
        )}
        {...rest}
      />
      {error && <p id={`${inputId}-error`} className="text-xs text-red-600">{error}</p>}
      {hint && !error && <p id={`${inputId}-hint`} className="text-xs text-ink-500">{hint}</p>}
    </div>
  )
}

interface TextareaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string
  error?: string
  hint?: string
}

export function Textarea({ label, error, hint, className, id, ...rest }: TextareaProps) {
  const generatedId = useId()
  const textareaId = id ?? (label ? `${label.toLowerCase().replace(/\s+/g, '-')}-${generatedId}` : generatedId)
  const describedBy = error ? `${textareaId}-error` : hint ? `${textareaId}-hint` : undefined
  return (
    <div className="flex flex-col gap-1">
      {label && <label htmlFor={textareaId} className="text-sm font-medium text-ink-700">{label}</label>}
      <textarea
        id={textareaId}
        aria-invalid={!!error}
        aria-describedby={describedBy}
        className={clsx(
          'px-3 py-2 text-sm border rounded-md bg-white/95 text-ink-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-gold-300 focus:border-axiom-700 transition-colors resize-none shadow-sm',
          error ? 'border-red-400 focus:ring-red-300 focus:border-red-500' : 'border-line',
          className,
        )}
        {...rest}
      />
      {error && <p id={`${textareaId}-error`} className="text-xs text-red-600">{error}</p>}
      {hint && !error && <p id={`${textareaId}-hint`} className="text-xs text-ink-500">{hint}</p>}
    </div>
  )
}

interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: string
  error?: string
  children: React.ReactNode
}

export function Select({ label, error, className, children, id, ...rest }: SelectProps) {
  const generatedId = useId()
  const selectId = id ?? (label ? `${label.toLowerCase().replace(/\s+/g, '-')}-${generatedId}` : generatedId)
  return (
    <div className="flex flex-col gap-1">
      {label && <label htmlFor={selectId} className="text-sm font-medium text-ink-700">{label}</label>}
      <select
        id={selectId}
        aria-invalid={!!error}
        aria-describedby={error ? `${selectId}-error` : undefined}
        className={clsx(
          'px-3 py-2 text-sm border rounded-md bg-white/95 text-ink-900 focus:outline-none focus:ring-2 focus:ring-gold-300 focus:border-axiom-700 transition-colors shadow-sm',
          error ? 'border-red-400' : 'border-line',
          className,
        )}
        {...(rest as React.SelectHTMLAttributes<HTMLSelectElement>)}
      >
        {children}
      </select>
      {error && <p id={`${selectId}-error`} className="text-xs text-red-600">{error}</p>}
    </div>
  )
}
