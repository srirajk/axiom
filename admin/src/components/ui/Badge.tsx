import { clsx } from 'clsx'

type Color = 'blue' | 'green' | 'yellow' | 'red' | 'slate' | 'purple' | 'indigo' | 'gold' | 'navy'

interface Props {
  children: React.ReactNode
  color?: Color
  className?: string
}

const colors: Record<Color, string> = {
  blue:   'bg-sky-50 text-sky-800 ring-1 ring-sky-600/20',
  green:  'bg-emerald-50 text-emerald-800 ring-1 ring-emerald-600/20',
  yellow: 'bg-gold-50 text-gold-800 ring-1 ring-gold-600/25',
  red:    'bg-red-50 text-red-800 ring-1 ring-red-600/20',
  slate:  'bg-slate-100 text-ink-700 ring-1 ring-slate-500/20',
  purple: 'bg-violet-50 text-violet-800 ring-1 ring-violet-600/20',
  indigo: 'bg-axiom-50 text-axiom-800 ring-1 ring-axiom-600/20',
  gold:   'bg-gold-50 text-gold-800 ring-1 ring-gold-600/25',
  navy:   'bg-axiom-50 text-axiom-800 ring-1 ring-axiom-600/20',
}

export function Badge({ children, color = 'slate', className }: Props) {
  return (
    <span className={clsx('inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium', colors[color], className)}>
      {children}
    </span>
  )
}

export function RoleBadge({ role }: { role: string }) {
  const color: Color =
    role === 'platform_admin' ? 'purple' :
    role === 'domain_admin'   ? 'indigo' :
    role === 'relationship_manager' ? 'blue' : 'slate'
  return <Badge color={color}>{role}</Badge>
}
