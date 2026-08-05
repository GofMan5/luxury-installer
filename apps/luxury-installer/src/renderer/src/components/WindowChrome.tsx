import { Minus, X } from 'lucide-react'
import { useRef, useState } from 'react'

import type { LuxuryBridge } from '../types'

export function WindowChrome({ bridge }: { bridge: LuxuryBridge }) {
  const closingRef = useRef(false)
  const [closing, setClosing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const run = async (operation: () => Promise<void>) => {
    setError(null)
    try {
      await operation()
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Системное действие не выполнено.')
    }
  }

  const close = async () => {
    if (closingRef.current) return
    closingRef.current = true
    setClosing(true)
    setError(null)
    try {
      await bridge.closeWindow()
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Не удалось закрыть окно.')
    } finally {
      closingRef.current = false
      setClosing(false)
    }
  }

  return (
    <div className="titlebar" data-tauri-drag-region>
      {error ? <span className="window-controls__error" role="alert">{error}</span> : null}
      <div className="window-controls" role="group" aria-label="Управление окном">
        <button type="button" title="Свернуть" aria-label="Свернуть" onClick={() => void run(bridge.minimizeWindow)}>
          <Minus size={16} aria-hidden="true" />
        </button>
        <button className="window-controls__close" type="button" title="Закрыть" aria-label="Закрыть" disabled={closing} onClick={() => void close()}>
          <X size={16} aria-hidden="true" />
        </button>
      </div>
    </div>
  )
}
