import { useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Bell, Sun, Moon, LogOut, ChevronDown } from 'lucide-react'
import { clsx } from 'clsx'
import { useQuery } from '@tanstack/react-query'
import { useThemeStore } from '@/store/themeStore'
import { useAlertStore } from '@/store/alertStore'
import { useAuth } from '@/hooks/useAuth'
import { getUserPreferences } from '@/services/supabaseService'

const routeTitles: Record<string, string> = {
  '/dashboard': 'Dashboard',
  '/history': 'History',
  '/settings': 'Settings',
}

export function TopBar() {
  const location = useLocation()
  const navigate = useNavigate()
  const { theme, toggleTheme } = useThemeStore()
  const unreadCount = useAlertStore((s) => s.unreadCount)
  const { user, logout } = useAuth()
  const [menuOpen, setMenuOpen] = useState(false)

  const { data: prefs } = useQuery({
    queryKey: ['user-preferences', user?.id ?? ''],
    queryFn: () => getUserPreferences(user!.id),
    enabled: !!user?.id,
  })
  const username = prefs?.username ?? null

  const title = routeTitles[location.pathname] ?? 'SmartHomeGuard'

  async function handleLogout() {
    await logout()
    navigate('/login')
  }

  return (
    <header className="sticky top-0 z-30 flex h-[60px] items-center justify-between border-b border-border bg-surface-raised px-6">
      <h1 className="text-lg font-semibold text-content-primary">{title}</h1>

      <div className="flex items-center gap-3">
        {/* Alert bell */}
        <button className="relative rounded-md p-2 text-content-secondary hover:bg-surface-base">
          <Bell className="h-5 w-5" />
          {unreadCount > 0 && (
            <span className="absolute -right-0.5 -top-0.5 flex h-5 min-w-[20px] items-center justify-center rounded-full bg-severity-critical px-1 text-[10px] font-bold text-white">
              {unreadCount > 99 ? '99+' : unreadCount}
            </span>
          )}
        </button>

        {/* Theme toggle */}
        <button
          onClick={toggleTheme}
          className="rounded-md p-2 text-content-secondary hover:bg-surface-base"
        >
          {theme === 'light' ? <Moon className="h-5 w-5" /> : <Sun className="h-5 w-5" />}
        </button>

        {/* User menu */}
        <div className="relative">
          <button
            onClick={() => setMenuOpen(!menuOpen)}
            className="flex items-center gap-2 rounded-md px-3 py-2 text-sm text-content-secondary hover:bg-surface-base"
          >
            <span className="max-w-[160px] truncate">{username ?? user?.email ?? 'User'}</span>
            <ChevronDown className={clsx('h-4 w-4 transition-transform', menuOpen && 'rotate-180')} />
          </button>

          {menuOpen && (
            <>
              <div className="fixed inset-0 z-40" onClick={() => setMenuOpen(false)} />
              <div className="absolute right-0 top-full z-50 mt-1 w-48 rounded-lg border border-border bg-surface-raised py-1 shadow-lg">
                <div className="border-b border-border px-4 py-2 text-xs text-content-secondary">
                  {username && <p className="font-medium text-content-primary">{username}</p>}
                  <p>{user?.email}</p>
                </div>
                <button
                  onClick={handleLogout}
                  className="flex w-full items-center gap-2 px-4 py-2 text-sm text-severity-critical hover:bg-surface-base"
                >
                  <LogOut className="h-4 w-4" />
                  Sign Out
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </header>
  )
}
