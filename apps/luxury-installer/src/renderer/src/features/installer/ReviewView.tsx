import {
  Check,
  ChevronRight,
  FolderOpen,
  KeyRound,
  PackageCheck,
  ShieldAlert,
  Trash2,
} from 'lucide-react'
import { useRef, useState } from 'react'

import type { InstallerDestination, PackageSummary, SetupAction } from '../../types'
import { formatBytes, shortenPath } from './format'

interface ReviewViewProps {
  summary: PackageSummary
  destination: InstallerDestination | null
  action: SetupAction
  installedVersion: string | null
  spaceAvailable: boolean
  unsignedAccepted: boolean
  publisherMigrationRequired: boolean
  publisherMigrationAccepted: boolean
  destinationPending: boolean
  destinationError: string | null
  canUninstall: boolean
  onChooseDestination(): void
  onUnsignedAccepted(value: boolean): void
  onPublisherMigrationAccepted(value: boolean): void
  onInstall(): void
  onUninstall(): void
}

export function ReviewView({
  summary,
  destination,
  action,
  installedVersion,
  spaceAvailable,
  unsignedAccepted,
  publisherMigrationRequired,
  publisherMigrationAccepted,
  destinationPending,
  destinationError,
  canUninstall,
  onChooseDestination,
  onUnsignedAccepted,
  onPublisherMigrationAccepted,
  onInstall,
  onUninstall,
}: ReviewViewProps) {
  const [confirmingUninstall, setConfirmingUninstall] = useState(false)
  const removeButton = useRef<HTMLButtonElement>(null)

  const cancelUninstall = () => {
    setConfirmingUninstall(false)
    requestAnimationFrame(() => removeButton.current?.focus())
  }

  return (
    <section className="screen screen--review" aria-labelledby="review-title">
      <header className="screen__header">
        <div>
          <h1 id="review-title" data-view-heading tabIndex={-1}>
            {reviewTitle(action, summary.name)}
          </h1>
          <p>{reviewDescription(action, summary.version, installedVersion)}</p>
        </div>
        <div className="integrity-badge">
          <Check size={14} strokeWidth={2.5} aria-hidden="true" />
          {summary.trust.kind === 'trustedPublisher'
            ? 'Подпись издателя проверена'
            : 'Файлы проверены'}
        </div>
      </header>

      <div className="package-hero">
        <div className="package-hero__icon" aria-hidden="true">
          <PackageCheck size={24} strokeWidth={1.7} />
        </div>
        <div className="package-hero__identity">
          <strong>{summary.name}</strong>
          <span>
            {summary.publisher} · {summary.version}
          </span>
        </div>
        <div className="package-hero__facts">
          <span>{formatBytes(summary.bytes)}</span>
        </div>
      </div>

      <div className="review-grid">
        {destination ? (
          <button
            className="destination"
            type="button"
            disabled={destinationPending}
            aria-busy={destinationPending}
            aria-label={`Выбрать папку установки. Базовая папка: ${destination.installBase}. Полный путь: ${destination.installPath}`}
            onClick={() => {
              setConfirmingUninstall(false)
              onChooseDestination()
            }}
          >
            <span className="destination__icon" aria-hidden="true">
              <FolderOpen size={20} />
            </span>
            <span className="destination__copy">
              <span className="field-label">Папка установки</span>
              <strong title={destination.installBase}>{shortenPath(destination.installBase)}</strong>
              <small title={destination.installPath}>{shortenPath(destination.installPath)}</small>
            </span>
            <ChevronRight size={18} aria-hidden="true" />
          </button>
        ) : (
          <div className="destination destination--fixed" aria-label="Защищённая системная папка установки">
            <span className="destination__icon" aria-hidden="true">
              <FolderOpen size={20} />
            </span>
            <span className="destination__copy">
              <span className="field-label">Папка установки</span>
              <strong>Системная папка приложений</strong>
              <small>Путь определит защищённый компонент ОС</small>
            </span>
          </div>
        )}

        {summary.publisherRotation ? (
          <div className="publisher-rotation">
            <span className="publisher-rotation__icon" aria-hidden="true">
              <KeyRound size={19} />
            </span>
            <span className="publisher-rotation__copy">
              <span className="field-label">Подтверждённая смена ключа</span>
              <code
                title={`${summary.publisherRotation.signerKeyId} → ${summary.publisherRotation.nextKeyId}`}
              >
                {shortKeyId(summary.publisherRotation.signerKeyId)} →{' '}
                {shortKeyId(summary.publisherRotation.nextKeyId)}
              </code>
              <small>Текущий и следующий ключи подтвердили переход.</small>
            </span>
          </div>
        ) : null}
      </div>

      {destinationError ? (
        <div className="destination-error" role="alert">
          <ShieldAlert size={18} aria-hidden="true" />
          <span>
            <strong>Папка не изменена.</strong>
            <small>{destinationError} Текущая рабочая папка сохранена.</small>
          </span>
        </div>
      ) : null}

      {!spaceAvailable ? (
        <div className="trust-consent capacity-warning" role="alert">
          <ShieldAlert size={19} aria-hidden="true" />
          <span>
            <strong>Недостаточно свободного места.</strong>
            <small>Освободите место и заново выберите эту папку либо укажите другую.</small>
          </span>
        </div>
      ) : null}

      {summary.trust.kind === 'unsigned' ? (
        <label className="trust-consent">
          <input
            type="checkbox"
            checked={unsignedAccepted}
            onChange={(event) => onUnsignedAccepted(event.currentTarget.checked)}
          />
          <span className="trust-consent__check" aria-hidden="true">
            <Check size={14} strokeWidth={3} />
          </span>
          <ShieldAlert size={19} aria-hidden="true" />
          <span>
            <strong>Издатель не подтверждён.</strong>
            <small>Продолжайте, только если доверяете источнику установщика.</small>
          </span>
        </label>
      ) : null}

      {publisherMigrationRequired ? (
        <label className="trust-consent">
          <input
            type="checkbox"
            checked={publisherMigrationAccepted}
            onChange={(event) =>
              onPublisherMigrationAccepted(event.currentTarget.checked)
            }
          />
          <span className="trust-consent__check" aria-hidden="true">
            <Check size={14} strokeWidth={3} />
          </span>
          <ShieldAlert size={19} aria-hidden="true" />
          <span>
            <strong>Обновить привязку издателя.</strong>
            <small>
              Разрешить запись текущего уровня доверия пакета в старое состояние установки. Смена
              уже закреплённого ключа останется запрещена.
            </small>
          </span>
        </label>
      ) : null}

      {confirmingUninstall && canUninstall ? (
        <footer
          className="screen__actions maintenance-confirmation"
          role="group"
          aria-labelledby="remove-title"
        >
          <div>
            <strong id="remove-title">Удалить {summary.name}?</strong>
            <small>Изменённые пользователем файлы будут сохранены.</small>
          </div>
          <span className="maintenance-confirmation__actions">
            <button
              className="secondary-button"
              type="button"
              disabled={destinationPending}
              autoFocus
              onClick={cancelUninstall}
            >
              Отмена
            </button>
            <button className="secondary-button danger-button" type="button" disabled={destinationPending} onClick={onUninstall}>
              <Trash2 size={16} aria-hidden="true" />
              Удалить
            </button>
          </span>
        </footer>
      ) : (
        <footer className="screen__actions screen__actions--end">
          {canUninstall ? (
            <button
              className="secondary-button"
              type="button"
              ref={removeButton}
              disabled={destinationPending}
              onClick={() => setConfirmingUninstall(true)}
            >
              <Trash2 size={16} aria-hidden="true" />
              Удалить
            </button>
          ) : null}
          <button
            className="primary-button"
            type="button"
            disabled={
              !spaceAvailable ||
              destinationPending ||
              (summary.trust.kind === 'unsigned' && !unsignedAccepted) ||
              (publisherMigrationRequired && !publisherMigrationAccepted)
            }
            onClick={onInstall}
          >
            {summary.license ? 'Далее' : actionLabel(action)}
            <ChevronRight size={17} />
          </button>
        </footer>
      )}
    </section>
  )
}

function actionLabel(action: SetupAction): string {
  return {
    install: 'Установить',
    update: 'Обновить',
    repair: 'Восстановить файлы',
    recover: 'Продолжить восстановление',
  }[action]
}

function reviewTitle(action: SetupAction, name: string): string {
  return {
    install: `Установить ${name}`,
    update: `Обновить ${name}`,
    repair: `Восстановить ${name}`,
    recover: `Восстановить установку ${name}`,
  }[action]
}

function reviewDescription(
  action: SetupAction,
  version: string,
  installedVersion: string | null,
): string {
  if (action === 'update' && installedVersion) {
    return `Установлена версия ${installedVersion}. Будет установлена версия ${version}.`
  }
  if (action === 'repair') {
    return `Версия ${installedVersion ?? version} уже установлена. Повреждённые файлы будут восстановлены.`
  }
  if (action === 'recover') {
    return 'Найдена незавершённая операция. Установщик безопасно продолжит восстановление.'
  }
  return 'Проверьте папку установки и продолжите.'
}

function shortKeyId(value: string): string {
  return `${value.slice(0, 8)}…${value.slice(-8)}`
}
