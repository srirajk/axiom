import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Users, Shield, UsersRound, GitCompare, LogOut, Clock, Boxes, Globe2, Link2, KeyRound, History, ClipboardCheck, UserRoundCheck } from 'lucide-react'
import { clsx } from 'clsx'
import { useAuth } from '../hooks/useAuth'

const nav = [
  { to: '/',        label: 'Dashboard', icon: LayoutDashboard },
  { to: '/users',   label: 'Users',     icon: Users },
  { to: '/teams',   label: 'Teams',     icon: UsersRound },
  { to: '/applications', label: 'Applications', icon: Boxes },
  { to: '/identity-sources', label: 'Customer IdP', icon: Globe2 },
  { to: '/scim-sources', label: 'SCIM Sources', icon: Link2 },
  { to: '/signing-keys', label: 'Signing Keys', icon: KeyRound },
  { to: '/sessions', label: 'Sessions', icon: History },
  { to: '/identity-controls', label: 'Identity Controls', icon: ClipboardCheck },
  { to: '/recovery-operators', label: 'Recovery Operators', icon: UserRoundCheck },
  { to: '/recovery-operators/self', label: 'My recovery access', icon: UserRoundCheck },
  { to: '/roles',   label: 'Roles',     icon: Shield },
  { to: '/studio',  label: 'Policy Studio', icon: GitCompare },
  { to: '/audit',   label: 'Audit Log', icon: Clock },
]

export function Sidebar() {
  const { user, logout } = useAuth()

  return (
    <aside className="w-64 shrink-0 bg-axiom-950 border-r border-axiom-800 flex flex-col h-screen sticky top-0 text-white">
      {/* Logo */}
      <div className="px-4 py-4 border-b border-white/10">
        <div className="flex items-center gap-2.5">
          <div className="axiom-mark w-8 h-8">
            <span className="font-bold text-sm">A</span>
          </div>
          <div>
            <p className="text-sm font-semibold text-white">Axiom</p>
            <p className="text-[11px] text-slate-400 -mt-0.5">Identity & platform policy</p>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {nav.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              clsx(
                'sidebar-link',
                isActive && 'active',
              )
            }
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* User footer */}
      <div className="px-3 py-4 border-t border-white/10">
        <div className="flex items-center gap-3 px-2 py-2 rounded-md bg-white/5">
          <div className="w-7 h-7 rounded-md bg-gold-100 flex items-center justify-center">
            <span className="text-gold-800 text-xs font-semibold">
              {user?.username?.charAt(0).toUpperCase() ?? '?'}
            </span>
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium text-white truncate">{user?.username}</p>
            <p className="text-[11px] text-slate-400 truncate">{user?.id}</p>
          </div>
          <button
            type="button"
            onClick={logout}
            aria-label="Sign out"
            className="p-1.5 text-slate-400 hover:text-white hover:bg-white/10 rounded-md transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gold-300"
            title="Sign out"
          >
            <LogOut size={14} />
          </button>
        </div>
      </div>
    </aside>
  )
}
