import { createContext, useContext, useState, useCallback, useRef } from 'react'
import { CheckCircle, XCircle, X } from 'lucide-react'
import { clsx } from 'clsx'

type ToastType = 'success' | 'error'
interface ToastMsg { id: number; type: ToastType; message: string }

interface ToastCtx { toast: (type: ToastType, message: string) => void }

const Ctx = createContext<ToastCtx>({ toast: () => {} })

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<ToastMsg[]>([])
  const seq = useRef(0)

  const toast = useCallback((type: ToastType, message: string) => {
    const id = ++seq.current
    setToasts(prev => [...prev, { id, type, message }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000)
  }, [])

  return (
    <Ctx.Provider value={{ toast }}>
      {children}
      <div
        className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2"
        role="status"
        aria-live="polite"
        aria-atomic="true"
      >
        {toasts.map(t => (
          <div
            key={t.id}
            className={clsx(
              'flex items-start gap-3 px-4 py-3 rounded-lg shadow-lg text-sm font-medium min-w-[300px] max-w-sm',
              t.type === 'success' ? 'bg-white border border-green-200 text-green-800' : 'bg-white border border-red-200 text-red-800',
            )}
          >
            {t.type === 'success'
              ? <CheckCircle size={16} className="text-green-500 mt-0.5 shrink-0" />
              : <XCircle size={16} className="text-red-500 mt-0.5 shrink-0" />}
            <span className="flex-1">{t.message}</span>
            <button
              type="button"
              aria-label="Dismiss notification"
              onClick={() => setToasts(p => p.filter(x => x.id !== t.id))}
            >
              <X size={14} className="text-slate-400 hover:text-slate-600" />
            </button>
          </div>
        ))}
      </div>
    </Ctx.Provider>
  )
}

export function useToast() { return useContext(Ctx) }
