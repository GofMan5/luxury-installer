import {
  Check,
  FileCode2,
  FilePlus2,
  Folder,
  FolderOpen,
  Hammer,
  RefreshCw,
  SquareDashed,
  Terminal,
  TriangleAlert,
} from 'lucide-react'
import { useEffect, useRef } from 'react'

import { BrandMark } from './components/BrandMark'
import { WindowChrome } from './components/WindowChrome'
import { formatBytes, formatFileCount } from './features/installer/format'
import type { LuxuryBridge, StudioBuildResult, StudioProject } from './types'
import { projectFrom, useStudio, type StudioView as StudioState } from './use-studio'

export function StudioApp({ bridge }: { bridge: LuxuryBridge }) {
  const studio = useStudio(bridge)
  return (
    <StudioView
      bridge={bridge}
      state={studio.view}
      onCreate={() => void studio.createProject()}
      onOpen={() => void studio.openProject()}
      onReload={() => void studio.reloadProject()}
      onReveal={() => void studio.revealProject()}
      onBuild={() => void studio.buildProject()}
      folderPending={studio.folderPending}
      onDismissError={studio.dismissError}
    />
  )
}

interface StudioViewProps {
  bridge: LuxuryBridge
  state: StudioState
  onCreate(): void
  onOpen(): void
  onReload(): void
  onReveal(): void
  onBuild(): void
  folderPending: boolean
  onDismissError(): void
}

export function StudioView({
  bridge,
  state,
  onCreate,
  onOpen,
  onReload,
  onReveal,
  onBuild,
  folderPending,
  onDismissError,
}: StudioViewProps) {
  const project = projectFrom(state)
  const busy =
    state.kind === 'loading' ||
    state.kind === 'refreshing' ||
    state.kind === 'building' ||
    folderPending
  const workspace = useRef<HTMLElement>(null)

  useEffect(() => {
    workspace.current
      ?.querySelector<HTMLElement>('[data-view-heading]')
      ?.focus({ preventScroll: true })
  }, [state.kind])

  return (
    <div className="app-shell studio-shell">
      <WindowChrome bridge={bridge} />
      <aside className="rail studio-rail">
        <BrandMark />
        <nav className="studio-rail__actions" aria-label="Действия с проектом">
          <span className="rail-label">Проект</span>
          <button type="button" disabled={busy} onClick={onCreate}>
            <FilePlus2 size={17} aria-hidden="true" />
            Новый проект
          </button>
          <button type="button" disabled={busy} onClick={onOpen}>
            <FolderOpen size={17} aria-hidden="true" />
            Открыть проект
          </button>
          {project ? (
            <>
              <button type="button" disabled={busy} onClick={onReveal}>
                {folderPending ? (
                  <SquareDashed className="spin" size={17} aria-hidden="true" />
                ) : (
                  <Folder size={17} aria-hidden="true" />
                )}
                {folderPending ? 'Открываем…' : 'Папка проекта'}
              </button>
              <button type="button" disabled={busy} onClick={onReload}>
                <RefreshCw
                  className={state.kind === 'refreshing' ? 'spin' : undefined}
                  size={17}
                  aria-hidden="true"
                />
                {state.kind === 'refreshing' ? 'Проверяем…' : 'Перепроверить'}
              </button>
            </>
          ) : null}
        </nav>
        <div className="studio-rail__current">
          <span className="rail-label">Текущий проект</span>
          <strong>{project?.name ?? 'Не открыт'}</strong>
          {project ? <small title={project.packageId}>{project.packageId}</small> : null}
        </div>
      </aside>

      <main className="workspace studio-workspace" ref={workspace}>
        {state.kind === 'loading' ? (
          <BusyView
            title={state.action === 'create' ? 'Создаём проект' : 'Открываем проект'}
          />
        ) : state.kind === 'empty' ? (
          <EmptyStudioView onCreate={onCreate} onOpen={onOpen} />
        ) : state.kind === 'error' && !state.project ? (
          <EmptyErrorView message={state.message} onDismiss={onDismissError} />
        ) : project ? (
          <ProjectView
            project={project}
            state={state}
            busy={busy}
            onBuild={onBuild}
            onDismissError={onDismissError}
          />
        ) : null}
      </main>
    </div>
  )
}

function EmptyStudioView({ onCreate, onOpen }: { onCreate(): void; onOpen(): void }) {
  return (
    <section className="studio-empty" aria-labelledby="studio-empty-title">
      <FileCode2 size={28} strokeWidth={1.6} aria-hidden="true" />
      <h1 id="studio-empty-title" data-view-heading tabIndex={-1}>Новый установщик</h1>
      <p>Создайте проект или откройте существующий. Настройки и файлы остаются в обычной папке.</p>
      <div className="studio-empty__actions">
        <button className="primary-button" type="button" onClick={onCreate}>
          <FilePlus2 size={17} aria-hidden="true" />
          Новый проект
        </button>
        <button className="secondary-button" type="button" onClick={onOpen}>
          <FolderOpen size={17} aria-hidden="true" />
          Открыть проект
        </button>
      </div>
    </section>
  )
}

function BusyView({ title }: { title: string }) {
  return (
    <section className="studio-busy" role="status" aria-live="polite">
      <SquareDashed className="spin" size={26} aria-hidden="true" />
      <h1 data-view-heading tabIndex={-1}>{title}</h1>
      <p>Проверяем настройки и файлы…</p>
    </section>
  )
}

function EmptyErrorView({ message, onDismiss }: { message: string; onDismiss(): void }) {
  return (
    <section className="studio-empty" aria-labelledby="studio-error-title">
      <TriangleAlert className="studio-error-icon" size={28} aria-hidden="true" />
      <h1 id="studio-error-title" data-view-heading tabIndex={-1}>Не удалось открыть проект</h1>
      <p className="studio-error-message" role="alert">{message}</p>
      <button className="secondary-button" type="button" onClick={onDismiss}>
        Вернуться
      </button>
    </section>
  )
}

function ProjectView({
  project,
  state,
  busy,
  onBuild,
  onDismissError,
}: {
  project: StudioProject
  state: StudioState
  busy: boolean
  onBuild(): void
  onDismissError(): void
}) {
  const building = state.kind === 'building'
  const buildable = project.formatVersion === 1
  const result = state.kind === 'built' ? state.result : null
  const error = state.kind === 'error' ? state.message : null

  return (
    <section className="studio-project" aria-labelledby="studio-project-title">
      <header className="studio-project__header">
        <div>
          <h1 id="studio-project-title" data-view-heading tabIndex={-1}>{project.name}</h1>
          <p>{project.publisher} · {project.version}</p>
          <code tabIndex={0} title={project.projectPath}>{project.projectPath}</code>
        </div>
        <button
          className="primary-button"
          type="button"
          disabled={busy || !buildable}
          aria-describedby={buildable ? undefined : 'studio-signed-build-note'}
          onClick={onBuild}
        >
          {building ? <SquareDashed className="spin" size={17} aria-hidden="true" /> : <Hammer size={17} aria-hidden="true" />}
          {building ? 'Собираем…' : 'Собрать'}
        </button>
      </header>

      {error ? (
        <div className="studio-error" role="alert">
          <TriangleAlert size={19} aria-hidden="true" />
          <div>
            <strong>Операция не завершена</strong>
            <span>{error}</span>
          </div>
          <button className="secondary-button" type="button" onClick={onDismissError}>
            Закрыть
          </button>
        </div>
      ) : null}

      {!buildable ? (
        <p className="studio-build-note" id="studio-signed-build-note">
          <Terminal size={17} aria-hidden="true" />
          Подписанные пакеты v2/v3 собираются в командной строке; закрытый ключ передаётся только через stdin.
        </p>
      ) : null}

      {building ? (
        <div className="studio-build-progress" role="status" aria-live="polite">
          <SquareDashed className="spin" size={19} aria-hidden="true" />
          Rust проверяет проект и собирает пакет…
        </div>
      ) : null}

      {state.kind === 'refreshing' ? (
        <div className="studio-build-progress" role="status" aria-live="polite">
          <SquareDashed className="spin" size={19} aria-hidden="true" />
          Перепроверяем настройки и файлы…
        </div>
      ) : null}

      {result ? <BuildResult result={result} /> : null}

      <div className="studio-sections">
        <section aria-labelledby="manifest-title">
          <h2 id="manifest-title">Манифест</h2>
          <dl className="studio-facts">
            <Fact label="ID пакета" value={project.packageId} mono />
            <Fact label="Формат пакета" value={`luxpkg v${project.formatVersion}`} />
            <Fact label="Лицензия" value={project.hasLicense ? 'Требует принятия' : 'Не задана'} />
            {project.formatVersion === 3 ? (
              <Fact
                label="Ротация ключа"
                value="Секция настроена; PoP проверяется при CLI build текущим ключом"
              />
            ) : null}
            <Fact label="Папка установки" value={project.installDirectory} mono />
            <Fact label="Область" value={project.scope === 'user' ? 'Текущий пользователь' : 'Вся система'} />
            <Fact label="Запуск после установки" value={project.hasEntrypoint ? 'Настроен' : 'Не настроен'} />
          </dl>
        </section>

        <section aria-labelledby="payload-title">
          <h2 id="payload-title">Файлы</h2>
          <dl className="studio-facts">
            <Fact label="Файлы" value={formatFileCount(project.files)} />
            <Fact label="Размер" value={formatBytes(project.bytes)} />
            <Fact label="Система" value={targetLabel(project)} />
            <Fact label="Архитектура" value={project.targetArch} mono />
          </dl>
        </section>
      </div>
    </section>
  )
}

function BuildResult({ result }: { result: StudioBuildResult }) {
  return (
    <section className="studio-build-result" aria-labelledby="studio-build-result-title" aria-live="polite">
      <Check size={21} strokeWidth={2.5} aria-hidden="true" />
      <div>
        <h2 id="studio-build-result-title">Пакет собран</h2>
        <code tabIndex={0} title={result.outputPath}>{result.outputPath}</code>
      </div>
    </section>
  )
}

function Fact({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd className={mono ? 'mono' : undefined} title={value}>{value}</dd>
    </div>
  )
}

function targetLabel(project: StudioProject): string {
  const os = { windows: 'Windows', linux: 'Linux', macos: 'macOS' }[project.targetOs]
  return `${os} · ${project.targetArch}`
}
