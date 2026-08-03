import { useEffect, useState } from 'react'

import { BrandMark } from './components/BrandMark'
import { WindowChrome } from './components/WindowChrome'
import { SetupApp } from './SetupApp'
import { StudioApp } from './StudioApp'
import type { AppMode, LuxuryBridge } from './types'

type ModeState =
  | { kind: 'boot' }
  | { kind: 'ready'; mode: AppMode }
  | { kind: 'error'; message: string }

export default function App({ bridge }: { bridge: LuxuryBridge }) {
  const [attempt, setAttempt] = useState(0)
  const [state, setState] = useState<ModeState>({ kind: 'boot' })

  useEffect(() => {
    let active = true
    setState({ kind: 'boot' })
    void bridge
      .getAppMode()
      .then((mode) => {
        if (active) setState({ kind: 'ready', mode })
      })
      .catch((error: unknown) => {
        if (active) setState({ kind: 'error', message: errorMessage(error) })
      })
    return () => {
      active = false
    }
  }, [attempt, bridge])

  if (state.kind === 'boot') return <ModeGate bridge={bridge} />
  if (state.kind === 'error') {
    return <ModeGate bridge={bridge} message={state.message} onRetry={() => setAttempt((value) => value + 1)} />
  }
  return state.mode === 'setup' ? <SetupApp bridge={bridge} /> : <StudioApp bridge={bridge} />
}

function ModeGate({ bridge, message, onRetry }: { bridge: LuxuryBridge; message?: string; onRetry?(): void }) {
  return (
    <div className="mode-gate">
      <WindowChrome bridge={bridge} />
      <BrandMark />
      {message ? (
        <>
          <h1>Не удалось запустить Luxury Installer</h1>
          <p className="error-message" role="alert">{message}</p>
          <button className="primary-button" type="button" onClick={onRetry}>
            Повторить
          </button>
        </>
      ) : (
        <p role="status">Запускаем приложение…</p>
      )}
    </div>
  )
}

function errorMessage(error: unknown): string {
  return error instanceof Error && error.message.trim()
    ? error.message
    : 'Неизвестная ошибка запуска.'
}
