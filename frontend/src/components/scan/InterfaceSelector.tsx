import { useEffect } from 'react'
import { useInterfaces } from '@/hooks/useInterfaces'

interface InterfaceSelectorProps {
  value: string | null
  onChange: (iface: string) => void
  disabled?: boolean
}

export function InterfaceSelector({ value, onChange, disabled = false }: InterfaceSelectorProps) {
  const { data: interfaces, isLoading, isError } = useInterfaces()

  useEffect(() => {
    if (!value && interfaces && interfaces.length > 0) {
      onChange(interfaces[0].name)
    }
  }, [value, interfaces, onChange])

  return (
    <div className="flex flex-col gap-1.5">
      <label className="text-sm font-medium text-content-primary">Network Interface</label>
      <select
        className="w-full rounded-lg border border-border bg-surface-base px-3 py-2 text-sm text-content-primary disabled:opacity-50"
        value={value ?? ''}
        disabled={disabled || isLoading || isError}
        onChange={(e) => onChange(e.target.value)}
      >
        {isLoading && <option>Loading interfaces...</option>}
        {isError && <option>Could not load interfaces</option>}
        {interfaces?.map((iface) => (
          <option key={iface.name} value={iface.name}>
            {iface.name} — {iface.description}
          </option>
        ))}
      </select>
    </div>
  )
}
