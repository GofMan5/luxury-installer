import { Check } from 'lucide-react'

import type { InstallResultAction, SetupAction } from '../types'
import { BrandMark } from './BrandMark'

interface InstallRailProps {
  currentStep: number
  action: InstallResultAction | SetupAction | null
  operation: 'install' | 'uninstall' | null
}

export function InstallRail({ currentStep, action, operation }: InstallRailProps) {
  const steps = ['Параметры', operationLabel(action, operation), 'Готово']
  return (
    <aside className="rail">
      <BrandMark />

      <nav className="steps" aria-label="Этапы операции">
        {steps.map((label, index) => {
          const number = index + 1
          const complete = number < currentStep
          const active = number === currentStep
          return (
            <div
              className={`step${active ? ' step--active' : ''}${complete ? ' step--complete' : ''}`}
              aria-current={active ? 'step' : undefined}
              key={label}
            >
              <span className="step__marker" aria-hidden="true">
                {complete ? <Check size={14} strokeWidth={2.5} /> : number}
              </span>
              <span>{label}</span>
            </div>
          )
        })}
      </nav>

    </aside>
  )
}

function operationLabel(
  action: InstallResultAction | SetupAction | null,
  operation: 'install' | 'uninstall' | null,
): string {
  if (operation === 'uninstall') return 'Удаление'
  if (action === null) return 'Подготовка'
  if (action === 'update') return 'Обновление'
  if (action === 'repair' || action === 'recover') return 'Восстановление'
  return 'Установка'
}
