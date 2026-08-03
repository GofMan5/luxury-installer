import { Check, ExternalLink, Play, RotateCcw, SquareDashed, SquareX } from 'lucide-react'

import type { FinishLink, InstallResultAction } from '../../types'

export function CompleteView({
  name,
  action,
  canLaunch,
  canReveal,
  launchPending,
  actionPending,
  actionError,
  finishLinks,
  onLaunch,
  onReveal,
  onOpenLink,
  onClose,
}: {
  name: string
  action: InstallResultAction
  canLaunch: boolean
  canReveal: boolean
  launchPending: boolean
  actionPending: 'reveal' | 'close' | number | null
  actionError: string | null
  finishLinks: FinishLink[]
  onLaunch(): void
  onReveal(): void
  onOpenLink(index: number): void
  onClose(): void
}) {
  return (
    <section className="screen result-screen" aria-labelledby="complete-title">
      <div className="result-mark result-mark--success" aria-hidden="true">
        <Check size={38} strokeWidth={2.2} />
      </div>
      <h1 id="complete-title" data-view-heading tabIndex={-1}>
        {completeTitle(action, name)}
      </h1>
      <p>{completeDescription(action)}</p>

      {actionError ? <div className="error-message result-action-error" role="alert">{actionError}</div> : null}
      <div className="result-actions">
        {canReveal ? (
          <button className="secondary-button" type="button" disabled={launchPending || actionPending !== null} onClick={onReveal}>
            {actionPending === 'reveal' ? <SquareDashed className="spin" size={16} /> : <ExternalLink size={16} />}
            {actionPending === 'reveal' ? 'Открываем…' : 'Показать в папке'}
          </button>
        ) : null}
        {finishLinks.map((link, index) => (
          <button
            className="secondary-button"
            type="button"
            key={`${index}-${link.url}`}
            disabled={launchPending || actionPending !== null}
            onClick={() => onOpenLink(index)}
          >
            {actionPending === index ? <SquareDashed className="spin" size={16} /> : <ExternalLink size={16} />}
            {actionPending === index ? 'Открываем…' : link.label}
          </button>
        ))}
        {canLaunch ? (
          <button className="primary-button" type="button" disabled={launchPending || actionPending !== null} onClick={onLaunch}>
            {launchPending ? <SquareDashed className="spin" size={16} /> : <Play size={16} />}
            {launchPending ? 'Запускаем…' : 'Запустить'}
          </button>
        ) : null}
        <button
          className={canLaunch || canReveal || finishLinks.length > 0 ? 'secondary-button' : 'primary-button'}
          type="button"
          disabled={launchPending || actionPending !== null}
          onClick={onClose}
        >
          Готово
        </button>
      </div>
    </section>
  )
}

export function ErrorView({
  message,
  canRetry,
  retryLabel,
  onRetry,
}: {
  message: string
  canRetry: boolean
  retryLabel: string
  onRetry(): void
}) {
  return (
    <section className="screen result-screen" aria-labelledby="error-title">
      <div className="result-mark result-mark--error" aria-hidden="true">
        <SquareX size={38} strokeWidth={1.9} />
      </div>
      <h1 id="error-title" data-view-heading tabIndex={-1}>Операция не завершена</h1>
      <p>Проверьте сообщение ниже и повторите действие, если это доступно.</p>
      <div className="error-message" role="alert">
        {message}
      </div>
      {canRetry ? (
        <button className="primary-button" type="button" onClick={onRetry}>
          <RotateCcw size={16} />
          {retryLabel}
        </button>
      ) : null}
    </section>
  )
}

export function CancelledView({ onBack }: { onBack(): void }) {
  return (
    <section className="screen result-screen" aria-labelledby="cancelled-title">
      <div className="result-mark result-mark--neutral" aria-hidden="true">
        <RotateCcw size={38} strokeWidth={1.9} />
      </div>
      <h1 id="cancelled-title" data-view-heading tabIndex={-1}>Операция отменена</h1>
      <p>Незавершённые изменения убраны. Можно проверить параметры и повторить действие.</p>
      <div className="result-actions">
        <button className="primary-button" type="button" onClick={onBack}>
          Вернуться к проверке
        </button>
      </div>
    </section>
  )
}

export function UninstallCompleteView({
  name,
  removedFiles,
  missingFiles,
  preservedModifiedFiles,
  closePending,
  actionError,
  onClose,
}: {
  name: string
  removedFiles: number
  missingFiles: number
  preservedModifiedFiles: number
  closePending: boolean
  actionError: string | null
  onClose(): void
}) {
  const alreadyRemoved = removedFiles + missingFiles + preservedModifiedFiles === 0
  return (
    <section className="screen result-screen" aria-labelledby="uninstall-complete-title">
      <div className="result-mark result-mark--success" aria-hidden="true">
        <Check size={38} strokeWidth={2.2} />
      </div>
      <h1 id="uninstall-complete-title" data-view-heading tabIndex={-1}>
        {alreadyRemoved ? `${name} уже удалён` : `${name} удалён`}
      </h1>
      <p>{uninstallDescription(alreadyRemoved, preservedModifiedFiles)}</p>

      {!alreadyRemoved ? (
        <dl className="uninstall-summary">
          <div><dt>Удалено</dt><dd>{removedFiles.toLocaleString('ru-RU')}</dd></div>
          <div><dt>Уже отсутствовало</dt><dd>{missingFiles.toLocaleString('ru-RU')}</dd></div>
          <div><dt>Сохранено изменённых</dt><dd>{preservedModifiedFiles.toLocaleString('ru-RU')}</dd></div>
        </dl>
      ) : null}

      {actionError ? <div className="error-message result-action-error" role="alert">{actionError}</div> : null}
      <div className="result-actions">
        <button className="primary-button" type="button" disabled={closePending} onClick={onClose}>
          {closePending ? <SquareDashed className="spin" size={16} /> : null}
          {closePending ? 'Закрываем…' : 'Готово'}
        </button>
      </div>
    </section>
  )
}

function completeTitle(action: InstallResultAction, name: string): string {
  return {
    install: `${name} установлен`,
    update: `${name} обновлён`,
    repair: `${name} восстановлен`,
  }[action]
}

function completeDescription(action: InstallResultAction): string {
  return action === 'repair'
    ? 'Файлы приложения проверены и восстановлены.'
    : 'Приложение готово к работе.'
}

function uninstallDescription(alreadyRemoved: boolean, preservedModifiedFiles: number): string {
  if (alreadyRemoved) return 'Установленные файлы уже отсутствуют.'
  if (preservedModifiedFiles > 0) {
    return 'Файлы, изменённые после установки, оставлены на месте.'
  }
  return 'Удаление приложения завершено.'
}
