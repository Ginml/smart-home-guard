import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import logoMark from '@/assets/logo.svg'
import { clsx } from 'clsx'
import { useAuth } from '@/hooks/useAuth'
import { Button } from '@/components/ui/Button'

type AuthMode = 'signIn' | 'signUp'

export function LoginPage() {
  const navigate = useNavigate()
  const { login, register } = useAuth()

  const [mode, setMode] = useState<AuthMode>('signIn')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const isEmailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  const isFormValid =
    isEmailValid &&
    password.length >= 6 &&
    (mode === 'signIn' || username.trim().length > 0)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    try {
      setError(null)
      setLoading(true)

      if (mode === 'signIn') {
        await login(email, password)
      } else {
        await register(email, password, username.trim())
      }

      navigate('/dashboard')
    } catch (err) {
      console.error('Authentication error:', err)
      setError(
        err instanceof Error
          ? err.message
          : 'An unexpected error occurred. Please try again.',
      )
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-surface-base px-4">
      <div className="w-full max-w-sm">
        {/* Header */}
        <div className="mb-8 flex flex-col items-center justify-center gap-3">
          <img src={logoMark} alt="Smart Home Guard" className="h-32 w-auto" />
          <span className="font-serif text-3xl font-semibold text-content-primary">
            Smart Home Guard
          </span>
        </div>

        {/* Tabs */}
        <div className="mb-6 flex rounded-lg border border-border bg-surface-base p-1">
          {(['signIn', 'signUp'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => { setMode(tab); setError(null) }}
              className={clsx(
                'flex-1 rounded-md py-2 text-sm font-medium transition-colors',
                mode === tab
                  ? 'bg-surface-raised text-content-primary shadow-sm'
                  : 'text-content-secondary hover:text-content-primary',
              )}
            >
              {tab === 'signIn' ? 'Sign In' : 'Create Account'}
            </button>
          ))}
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4 rounded-xl border border-border bg-surface-raised p-6">
          {mode === 'signUp' && (
            <div>
              <label className="mb-1.5 block text-sm font-medium text-content-primary">
                Username
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Your display name"
                required
                className="w-full rounded-lg border border-border bg-surface-base px-3 py-2 text-sm text-content-primary placeholder:text-content-secondary/50 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent"
              />
            </div>
          )}

          <div>
            <label className="mb-1.5 block text-sm font-medium text-content-primary">
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              required
              className="w-full rounded-lg border border-border bg-surface-base px-3 py-2 text-sm text-content-primary placeholder:text-content-secondary/50 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent"
            />
          </div>

          <div>
            <label className="mb-1.5 block text-sm font-medium text-content-primary">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={mode === 'signUp' ? 'At least 6 characters' : 'Your password'}
              required
              minLength={6}
              className="w-full rounded-lg border border-border bg-surface-base px-3 py-2 text-sm text-content-primary placeholder:text-content-secondary/50 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent"
            />
          </div>

          {error && (
            <p className="rounded-md bg-severity-critical/10 px-3 py-2 text-sm text-severity-critical">
              {error}
            </p>
          )}

          <Button
            type="submit"
            className="w-full"
            loading={loading}
            disabled={!isFormValid}
          >
            {mode === 'signIn' ? 'Sign In' : 'Create Account'}
          </Button>
        </form>
      </div>
    </div>
  )
}
