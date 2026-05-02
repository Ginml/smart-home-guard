import { Outlet } from 'react-router-dom'
import { clsx } from 'clsx'
import { useUiStore } from '@/store/uiStore'
import { useRealtimeFlows } from '@/hooks/useRealtimeFlows'
import { useSessionStatus } from '@/hooks/useSessionStatus'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'
import { ToastContainer } from '@/components/ui/Toast'

export function AppShell() {
  const collapsed = useUiStore((s) => s.sidebarCollapsed)
  useRealtimeFlows()
  useSessionStatus()

  return (
    <div className="min-h-screen bg-surface-base">
      <Sidebar />
      <div
        className={clsx(
          'transition-[margin-left] duration-200',
          collapsed ? 'ml-16' : 'ml-60',
        )}
      >
        <TopBar />
        <main className="p-6">
          <Outlet />
        </main>
      </div>
      <ToastContainer />
    </div>
  )
}
