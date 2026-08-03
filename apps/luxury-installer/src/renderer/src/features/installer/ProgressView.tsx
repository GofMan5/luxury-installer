import { Check, ChevronRight, RotateCcw, Square, SquareDashed, X } from 'lucide-react'

import type {
  InstallerDestination,
  InstallLog,
  InstallPhase,
  InstallResultAction,
  UninstallPhase,
} from '../../types'
import { formatBytes, formatFileCount } from './format'

type ProgressViewProps =
  | {
      name: string
      operation: 'install'
      action: InstallResultAction | null
      phase: InstallPhase
      completedFiles: number
      totalFiles: number
      completedBytes: number
      totalBytes: number
      cancellationRequested: boolean
      installLog?: InstallLog | null
      destination?: InstallerDestination | null
      onCancel?(): void
      onContinue?(): void
    }
  | {
      name: string
      operation: 'uninstall'
      phase: UninstallPhase
      processedFiles: number
      totalFiles: number
      cancellationRequested: boolean
      onCancel(): void
    }

const installPhaseOrder: InstallPhase[] = [
  'validating',
  'verifying',
  'recovering',
  'planning',
  'applying',
  'committing',
  'completed',
]

const uninstallPhaseOrder: UninstallPhase[] = [
  'recovering',
  'loadingReceipt',
  'removing',
  'committing',
  'completed',
]

export function ProgressView(props: ProgressViewProps) {
  const completedFiles = props.operation === 'install' ? props.completedFiles : props.processedFiles
  const totalFiles = props.totalFiles
  const completedBytes = props.operation === 'install' ? props.completedBytes : 0
  const totalBytes = props.operation === 'install' ? props.totalBytes : 0
  const hasProgress = props.operation === 'install' ? totalBytes > 0 : totalFiles > 0
  const progress =
    props.operation === 'install'
      ? totalBytes > 0 ? Math.min(completedBytes / totalBytes, 1) : 0
      : totalFiles > 0 ? Math.min(completedFiles / totalFiles, 1) : 0
  const percent = Math.round(progress * 100)
  const rollingBack = props.phase === 'rollingBack' || props.cancellationRequested
  const installLog = props.operation === 'install' ? props.installLog : null
  const destination = props.operation === 'install' ? props.destination : null
  const onContinue = props.operation === 'install' ? props.onContinue : undefined
  const finished = props.phase === 'completed' && onContinue !== undefined
  const cancellationDisabled =
    rollingBack || ['committing', 'completed', 'cancelled', 'failed'].includes(props.phase)
  const items = operationItems(props)

  return (
    <section className="screen screen--progress" aria-labelledby="progress-title">
      <header className="screen__header">
        <div>
          <h1 id="progress-title" data-view-heading tabIndex={-1}>
            {progressTitle(props, rollingBack, finished)}
          </h1>
          <p>
            {finished
              ? 'Все файлы применены. При необходимости проверьте детали и нажмите «Далее».'
              : rollingBack
              ? 'Дождитесь завершения отмены. Уже внесённые изменения будут убраны.'
              : 'Окно можно свернуть — операция продолжится в фоне.'}
          </p>
        </div>
        <span className={finished ? 'live-indicator live-indicator--done' : 'live-indicator'}>
          <span /> {finished ? 'готово' : rollingBack ? 'отмена' : 'выполняется'}
        </span>
      </header>

      <div className="progress-overview">
        <div className="progress-overview__number" aria-hidden="true">
          {rollingBack ? (
            <RotateCcw size={45} />
          ) : !hasProgress ? (
            <SquareDashed className="spin" size={45} />
          ) : (
            <><strong>{percent}</strong><span>%</span></>
          )}
        </div>
        <div className="progress-overview__track">
          <div className="progress-overview__labels">
            <strong role="status" aria-live="polite" aria-atomic="true">
              {phaseLabel(props)}
            </strong>
            <span>
              {totalFiles > 0
                ? `${completedFiles.toLocaleString('ru-RU')} / ${formatFileCount(totalFiles)}`
                : 'Подготовка'}
            </span>
          </div>
          <progress
            className="progress-bar"
            aria-label="Ход операции"
            max={100}
            value={percent}
          />
          {props.operation === 'install' ? (
            <div className="progress-overview__bytes">
              <span>{formatBytes(completedBytes)}</span>
              <span>{formatBytes(totalBytes)}</span>
            </div>
          ) : null}
        </div>
      </div>

      <div className="operation-list" aria-label="Ход операции">
        {items.map((item) => {
          const state = phaseState(item.key, props, rollingBack)
          return (
            <div className={`operation operation--${state}`} key={item.key}>
              <span className="operation__marker" aria-hidden="true">
                {state === 'done' ? (
                  <Check size={15} strokeWidth={2.8} />
                ) : state === 'active' ? (
                  <SquareDashed className="spin" size={17} />
                ) : (
                  <Square size={15} />
                )}
              </span>
              <span>
                <strong>{item.label}</strong>
                <small>{item.detail}</small>
              </span>
              <em>{state === 'done' ? 'Готово' : state === 'active' ? 'Сейчас' : 'Ожидание'}</em>
            </div>
          )
        })}
      </div>

      {finished && installLog ? (
        <InstallDetails
          log={installLog}
          destination={destination ?? null}
          installedFiles={completedFiles}
          installedBytes={completedBytes}
        />
      ) : null}

      <footer className="screen__actions screen__actions--end">
        {finished ? (
          <button className="primary-button" type="button" onClick={onContinue}>
            Далее
            <ChevronRight size={17} />
          </button>
        ) : (
          <button
            className="secondary-button"
            type="button"
            disabled={cancellationDisabled}
            onClick={props.onCancel}
          >
            <X size={16} />
            Отменить
          </button>
        )}
      </footer>
    </section>
  )
}

function InstallDetails({
  log,
  destination,
  installedFiles,
  installedBytes,
}: {
  log: InstallLog
  destination: InstallerDestination | null
  installedFiles: number
  installedBytes: number
}) {
  return (
    <details className="install-details">
      <summary>
        <span>
          <strong>Детали установки</strong>
          <small>{formatFileCount(installedFiles)} · {formatBytes(installedBytes)}</small>
        </span>
      </summary>
      <dl className="install-details__summary">
        <div>
          <dt>Папка</dt>
          <dd title={destination?.installPath}>{destination?.installPath ?? 'Системная папка приложений'}</dd>
        </div>
        <div>
          <dt>Результат</dt>
          <dd>{formatFileCount(installedFiles)}, {formatBytes(installedBytes)}</dd>
        </div>
      </dl>
      <div className="install-details__files" aria-label="Файлы пакета">
        {log.files.map((file) => <code key={file} title={file}>{file}</code>)}
        {log.omittedFiles > 0 ? (
          <small>Ещё {formatFileCount(log.omittedFiles)} скрыто для компактного отображения.</small>
        ) : null}
      </div>
    </details>
  )
}

function operationItems(
  props: ProgressViewProps,
): Array<{ key: string; label: string; detail: string }> {
  if (props.operation === 'uninstall') {
    return [
      { key: 'loadingReceipt', label: 'Проверка установки', detail: 'Состояние и список файлов' },
      { key: 'removing', label: 'Удаление файлов', detail: 'Только неизменённые файлы приложения' },
      { key: 'committing', label: 'Завершение', detail: 'Сохранение результата' },
    ]
  }
  return [
    {
      key: 'recovering',
      label: 'Проверка состояния',
      detail: 'Целостность и незавершённые операции',
    },
    {
      key: 'planning',
      label: 'Подготовка',
      detail: 'Папка назначения, состояние и конфликты',
    },
    { key: 'applying', label: applyingLabel(props.action), detail: actionDetail(props.action) },
    { key: 'committing', label: 'Завершение', detail: 'Сохранение настроек' },
  ]
}

function phaseState(
  item: string,
  props: ProgressViewProps,
  rollingBack: boolean,
): 'done' | 'active' | 'waiting' {
  if (rollingBack) {
    return item === (props.operation === 'install' ? 'applying' : 'removing') ? 'active' : 'waiting'
  }
  const order: readonly string[] =
    props.operation === 'install' ? installPhaseOrder : uninstallPhaseOrder
  const currentIndex = order.indexOf(props.phase)
  const itemIndex = order.indexOf(item)
  if (itemIndex < currentIndex) return 'done'
  const firstItem = props.operation === 'install' ? 'recovering' : 'loadingReceipt'
  if (itemIndex === currentIndex || (item === firstItem && currentIndex < itemIndex)) return 'active'
  return 'waiting'
}

function phaseLabel(props: ProgressViewProps): string {
  if (props.operation === 'uninstall') {
    const labels: Record<UninstallPhase, string> = {
      recovering: 'Проверяем незавершённые операции',
      loadingReceipt: 'Проверяем установленное приложение',
      removing: 'Удаляем файлы',
      committing: 'Завершаем удаление',
      rollingBack: 'Отменяем изменения',
      completed: 'Готово',
      cancelled: 'Отменено',
      failed: 'Ошибка',
    }
    return labels[props.phase]
  }
  const labels: Record<InstallPhase, string> = {
    validating: 'Проверяем установщик',
    recovering: 'Восстанавливаем предыдущую установку',
    verifying: 'Проверяем файлы',
    planning: 'Готовим папку',
    applying: applyingLabel(props.action),
    committing: 'Завершаем операцию',
    rollingBack: 'Отменяем изменения',
    completed: 'Готово',
    cancelled: 'Отменено',
    failed: 'Ошибка',
  }
  return labels[props.phase]
}

function progressTitle(
  props: ProgressViewProps,
  rollingBack: boolean,
  finished: boolean,
): string {
  if (rollingBack) return 'Отменяем изменения'
  if (props.operation === 'uninstall') return `Удаляем ${props.name}`
  if (finished) {
    return {
      install: 'Установка завершена',
      update: 'Обновление завершено',
      repair: 'Восстановление завершено',
    }[props.action ?? 'install']
  }
  if (props.action === null) return `Подготавливаем ${props.name}`
  return {
    install: `Устанавливаем ${props.name}`,
    update: `Обновляем ${props.name}`,
    repair: `Восстанавливаем ${props.name}`,
  }[props.action]
}

function applyingLabel(action: InstallResultAction | null): string {
  if (action === null) return 'Подготавливаем файлы'
  return {
    install: 'Копируем файлы',
    update: 'Обновляем файлы',
    repair: 'Восстанавливаем файлы',
  }[action]
}

function actionDetail(action: InstallResultAction | null): string {
  if (action === null) return 'Определение состояния установки'
  return {
    install: 'Установка приложения',
    update: 'Обновление приложения',
    repair: 'Проверка и восстановление',
  }[action]
}
