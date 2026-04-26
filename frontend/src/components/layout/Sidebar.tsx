import { NavLink } from 'react-router-dom'
import { LayoutDashboard, History, Settings, PanelLeftClose, PanelLeft } from 'lucide-react'
import { clsx } from 'clsx'
import { useUiStore } from '@/store/uiStore'
import logoMark from '@/assets/logo.svg'

const navItems = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/history', label: 'History', icon: History },
  { to: '/settings', label: 'Settings', icon: Settings },
] as const

export function Sidebar() {
  const collapsed = useUiStore((s) => s.sidebarCollapsed)
  const toggleSidebar = useUiStore((s) => s.toggleSidebar)

  return (
    <aside
      className={clsx(
        'fixed left-0 top-0 z-40 flex h-screen flex-col border-r border-border bg-surface-raised transition-[width] duration-200',
        collapsed ? 'w-16' : 'w-64',
      )}
    >
      {/* Logo */}
      <div className="flex h-[60px] items-center gap-3 border-b border-border px-4">
        <img src={logoMark} alt="Smart Home Guard" className="h-14 w-14 shrink-0" />
        {!collapsed && (
          <span className="whitespace-nowrap font-serif text-lg font-semibold text-content-primary">
            Smart Home Guard
          </span>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 px-2 py-4">
        {navItems.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                isActive
                  ? 'bg-accent/10 text-accent'
                  : 'text-content-secondary hover:bg-surface-base hover:text-content-primary',
                collapsed && 'justify-center',
              )
            }
          >
            <Icon className="h-5 w-5 shrink-0" />
            {!collapsed && <span>{label}</span>}
          </NavLink>
        ))}
      </nav>

      {/* Collapse toggle */}
      <button
        onClick={toggleSidebar}
        className="flex items-center justify-center border-t border-border p-4 text-content-secondary hover:text-content-primary"
      >
        {collapsed ? <PanelLeft className="h-5 w-5" /> : <PanelLeftClose className="h-5 w-5" />}
      </button>
    </aside>
  )
}
