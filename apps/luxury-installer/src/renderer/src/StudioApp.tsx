import {
  Check,
  FileCode2,
  FilePlus2,
  Folder,
  FolderOpen,
  Hammer,
  Plus,
  RefreshCw,
  Save,
  SquareDashed,
  Terminal,
  Trash2,
  TriangleAlert,
  X,
} from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { BrandMark } from './components/BrandMark'
import { WindowChrome } from './components/WindowChrome'
import { formatBytes, formatElapsedTime, formatFileCount } from './features/installer/format'
import type {
  LuxuryBridge,
  RecentProject,
  StudioBuildResult,
  StudioProject,
  StudioProjectUpdate,
} from './types'
import { projectFrom, useStudio, type StudioView as StudioState } from './use-studio'

export function StudioApp({ bridge }: { bridge: LuxuryBridge }) {
  const studio = useStudio(bridge)
  return (
    <StudioView
      bridge={bridge}
      state={studio.view}
      onCreate={() => void studio.createProject()}
      onOpen={() => void studio.openProject()}
      recentProjects={studio.recentProjects}
      onOpenRecent={(index) => void studio.openRecentProject(index)}
      onReload={() => void studio.reloadProject()}
      onReveal={() => void studio.revealProject()}
      onSave={(input) => void studio.updateProject(input)}
      onImportFiles={() => void studio.importProject('files')}
      onImportDirectory={() => void studio.importProject('directory')}
      onReplacePayload={() => void studio.importProject('replace')}
      onChooseEntrypoint={studio.chooseProjectEntrypoint}
      onBuild={(input) => void studio.buildProject(input)}
      onCancelBuild={() => void studio.cancelProjectBuild()}
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
  recentProjects: RecentProject[]
  onOpenRecent(index: number): void
  onReload(): void
  onReveal(): void
  onSave(input: StudioProjectUpdate): void
  onImportFiles(): void
  onImportDirectory(): void
  onReplacePayload(): void
  onChooseEntrypoint(): Promise<string | null>
  onBuild(input?: StudioProjectUpdate): void
  onCancelBuild(): void
  folderPending: boolean
  onDismissError(): void
}

export function StudioView({
  bridge,
  state,
  onCreate,
  onOpen,
  recentProjects,
  onOpenRecent,
  onReload,
  onReveal,
  onSave,
  onImportFiles,
  onImportDirectory,
  onReplacePayload,
  onChooseEntrypoint,
  onBuild,
  onCancelBuild,
  folderPending,
  onDismissError,
}: StudioViewProps) {
  const project = projectFrom(state)
  const busy =
    state.kind === 'loading' ||
    state.kind === 'refreshing' ||
    state.kind === 'saving' ||
    state.kind === 'importing' ||
    state.kind === 'choosingEntrypoint' ||
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
          <EmptyStudioView
            recentProjects={recentProjects}
            onCreate={onCreate}
            onOpen={onOpen}
            onOpenRecent={onOpenRecent}
          />
        ) : state.kind === 'error' && !state.project ? (
          <EmptyErrorView message={state.message} onDismiss={onDismissError} />
        ) : project ? (
          <ProjectView
            project={project}
            state={state}
            busy={busy}
            onSave={onSave}
            onImportFiles={onImportFiles}
            onImportDirectory={onImportDirectory}
            onReplacePayload={onReplacePayload}
            onChooseEntrypoint={onChooseEntrypoint}
            onBuild={onBuild}
            onCancelBuild={onCancelBuild}
            onRevealBuildOutput={bridge.revealBuildOutput}
            onDismissError={onDismissError}
          />
        ) : null}
      </main>
    </div>
  )
}

function EmptyStudioView({
  recentProjects,
  onCreate,
  onOpen,
  onOpenRecent,
}: {
  recentProjects: RecentProject[]
  onCreate(): void
  onOpen(): void
  onOpenRecent(index: number): void
}) {
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
      {recentProjects.length ? (
        <section className="studio-recent" aria-labelledby="studio-recent-title">
          <h2 id="studio-recent-title">Недавние проекты</h2>
          <div className="studio-recent__list">
            {recentProjects.map((project, index) => (
              <button
                key={project.projectPath}
                type="button"
                title={project.projectPath}
                onClick={() => onOpenRecent(index)}
              >
                <FolderOpen size={18} aria-hidden="true" />
                <span>
                  <strong>{project.name}</strong>
                  <small>{project.publisher} · {project.version}</small>
                  <code>{project.projectPath}</code>
                </span>
                <small>{targetLabel(project)}</small>
              </button>
            ))}
          </div>
        </section>
      ) : null}
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

function projectUpdateFrom(project: StudioProject): StudioProjectUpdate {
  return {
    packageId: project.packageId,
    name: project.name,
    publisher: project.publisher,
    version: project.version,
    description: project.description,
    license: project.license,
    targetOs: project.targetOs,
    targetArch: project.targetArch,
    installDirectory: project.installDirectory,
    scope: project.scope,
    allowDowngrade: project.allowDowngrade,
    entrypoint: project.entrypoint,
    showInstallLog: project.showInstallLog,
    finishLinks: project.finishLinks.map((link) => ({ ...link })),
  }
}

function ProjectView({
  project,
  state,
  busy,
  onSave,
  onImportFiles,
  onImportDirectory,
  onReplacePayload,
  onChooseEntrypoint,
  onBuild,
  onCancelBuild,
  onRevealBuildOutput,
  onDismissError,
}: {
  project: StudioProject
  state: StudioState
  busy: boolean
  onSave(input: StudioProjectUpdate): void
  onImportFiles(): void
  onImportDirectory(): void
  onReplacePayload(): void
  onChooseEntrypoint(): Promise<string | null>
  onBuild(input?: StudioProjectUpdate): void
  onCancelBuild(): void
  onRevealBuildOutput(): Promise<void>
  onDismissError(): void
}) {
  const building = state.kind === 'building'
  const buildElapsed = useBuildElapsed(building)
  const saving = state.kind === 'saving'
  const importing = state.kind === 'importing'
  const choosingEntrypoint = state.kind === 'choosingEntrypoint'
  const buildable = project.formatVersion === 1
  const result = state.kind === 'built' ? state.result : null
  const error = state.kind === 'error' ? state.message : null
  const baseline = useMemo(() => projectUpdateFrom(project), [project])
  const [draft, setDraft] = useState(baseline)
  const dirty = JSON.stringify(draft) !== JSON.stringify(baseline)

  useEffect(() => setDraft(baseline), [baseline])

  const updateLink = (index: number, field: 'label' | 'url', value: string) => {
    setDraft((current) => ({
      ...current,
      finishLinks: current.finishLinks.map((link, linkIndex) =>
        linkIndex === index ? { ...link, [field]: value } : link,
      ),
    }))
  }

  return (
    <form
      className="studio-project"
      aria-labelledby="studio-project-title"
      onSubmit={(event) => {
        event.preventDefault()
        if (buildable && dirty && !busy) onSave(draft)
      }}
    >
      <header className="studio-project__header">
        <div>
          <h1 id="studio-project-title" data-view-heading tabIndex={-1}>{project.name}</h1>
          <p>{project.publisher} · {project.version}</p>
          <code tabIndex={0} title={project.projectPath}>{project.projectPath}</code>
        </div>
        <div className="studio-project__header-actions">
          {building ? (
            <button
              className="secondary-button"
              type="button"
              disabled={state.cancellationRequested}
              onClick={onCancelBuild}
            >
              {state.cancellationRequested ? (
                <SquareDashed className="spin" size={17} aria-hidden="true" />
              ) : (
                <X size={17} aria-hidden="true" />
              )}
              {state.cancellationRequested ? 'Отменяем…' : 'Отменить'}
            </button>
          ) : null}
          {buildable && !building ? (
            <button className="secondary-button" type="submit" disabled={busy || !dirty}>
              {saving ? <SquareDashed className="spin" size={17} aria-hidden="true" /> : <Save size={17} aria-hidden="true" />}
              {saving ? 'Сохраняем…' : 'Сохранить'}
            </button>
          ) : null}
          <button
            className="primary-button"
            type="button"
            disabled={busy || !buildable}
            aria-describedby={buildable ? undefined : 'studio-signed-build-note'}
            onClick={(event) => {
              if (!event.currentTarget.form?.reportValidity()) return
              onBuild(dirty ? draft : undefined)
            }}
          >
            {saving || building ? <SquareDashed className="spin" size={17} aria-hidden="true" /> : <Hammer size={17} aria-hidden="true" />}
            {saving
              ? 'Сохраняем…'
              : building
                ? 'Собираем…'
                : dirty
                  ? `Сохранить и ${nativeBuildLabel(draft.targetOs).toLowerCase()}`
                  : nativeBuildLabel(draft.targetOs)}
          </button>
        </div>
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
          Подписанные проекты собираются в командной строке; закрытый ключ передаётся только через stdin.
        </p>
      ) : null}

      {building ? (
        <div className="studio-build-progress" role="status" aria-live="polite">
          <SquareDashed className="spin" size={19} aria-hidden="true" />
          <div>
            <span>
              {state.cancellationRequested
                ? 'Останавливаем native-сборку и очищаем временные файлы…'
                : 'Rust проверяет проект и собирает готовый установщик…'}
            </span>
            <time
              className="studio-build-progress__elapsed"
              dateTime={`PT${buildElapsed}S`}
              aria-hidden="true"
            >
              Прошло {formatElapsedTime(buildElapsed)}
            </time>
            {state.cancellationError ? <small role="alert">{state.cancellationError}</small> : null}
          </div>
        </div>
      ) : null}

      {state.kind === 'refreshing' ? (
        <div className="studio-build-progress" role="status" aria-live="polite">
          <SquareDashed className="spin" size={19} aria-hidden="true" />
          Перепроверяем настройки и файлы…
        </div>
      ) : null}

      {importing ? (
        <div className="studio-build-progress" role="status" aria-live="polite">
          <SquareDashed className="spin" size={19} aria-hidden="true" />
          Rust проверяет файлы приложения…
        </div>
      ) : null}

      {result ? (
        <BuildResult key={result.outputPath} result={result} onReveal={onRevealBuildOutput} />
      ) : null}

      {buildable ? (
        <div className="studio-editor">
          <fieldset>
            <legend>Приложение</legend>
            <div className="studio-form-grid">
              <StudioField label="Название">
                <input required maxLength={128} value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} />
              </StudioField>
              <StudioField label="Версия">
                <input required maxLength={1024} value={draft.version} onChange={(event) => setDraft({ ...draft, version: event.target.value })} placeholder="1.0.0" />
              </StudioField>
              <StudioField label="ID приложения" wide>
                <input required maxLength={128} value={draft.packageId} onChange={(event) => setDraft({ ...draft, packageId: event.target.value })} placeholder="com.company.app" />
              </StudioField>
              <StudioField label="Издатель" wide>
                <input required maxLength={128} value={draft.publisher} onChange={(event) => setDraft({ ...draft, publisher: event.target.value })} />
              </StudioField>
              <StudioField label="Описание" wide>
                <input maxLength={1024} value={draft.description ?? ''} onChange={(event) => setDraft({ ...draft, description: event.target.value || null })} placeholder="Короткое описание приложения" />
              </StudioField>
            </div>
          </fieldset>

          <fieldset>
            <legend>Установка</legend>
            <div className="studio-form-grid">
              <StudioField label="Система">
                <select value={draft.targetOs} onChange={(event) => setDraft({ ...draft, targetOs: event.target.value as StudioProjectUpdate['targetOs'] })}>
                  <option value="windows">Windows</option>
                  <option value="linux">Linux</option>
                  <option value="macos">macOS</option>
                </select>
              </StudioField>
              <StudioField label="Архитектура">
                <select value={draft.targetArch} onChange={(event) => setDraft({ ...draft, targetArch: event.target.value as StudioProjectUpdate['targetArch'] })}>
                  <option value="x86_64">x86_64</option>
                  <option value="aarch64">aarch64</option>
                </select>
              </StudioField>
              <StudioField label="Папка приложения">
                <input required maxLength={255} value={draft.installDirectory} onChange={(event) => setDraft({ ...draft, installDirectory: event.target.value })} />
              </StudioField>
              <StudioField label="Область установки">
                <select value={draft.scope} onChange={(event) => setDraft({ ...draft, scope: event.target.value as StudioProjectUpdate['scope'] })}>
                  <option value="user">Текущий пользователь</option>
                  <option value="system">Вся система</option>
                </select>
              </StudioField>
              <div className="studio-field studio-field--wide">
                <label htmlFor="studio-entrypoint">Точка запуска</label>
                <div className="studio-entrypoint">
                  <input id="studio-entrypoint" aria-describedby="studio-entrypoint-hint" maxLength={4096} value={draft.entrypoint ?? ''} onChange={(event) => setDraft({ ...draft, entrypoint: event.target.value || null })} placeholder="bin/app.exe" />
                  <button
                    className="secondary-button"
                    type="button"
                    disabled={busy}
                    onClick={() => {
                      void onChooseEntrypoint().then((path) => {
                        if (path) setDraft((current) => ({ ...current, entrypoint: path }))
                      })
                    }}
                  >
                    {choosingEntrypoint ? <SquareDashed className="spin" size={15} aria-hidden="true" /> : <FolderOpen size={15} aria-hidden="true" />}
                    {choosingEntrypoint ? 'Выбираем…' : 'Выбрать'}
                  </button>
                </div>
                <small id="studio-entrypoint-hint">Путь внутри payload, например bin/app.exe</small>
              </div>
            </div>
            <div className="studio-toggles">
              <label><input type="checkbox" checked={draft.showInstallLog} onChange={(event) => setDraft({ ...draft, showInstallLog: event.target.checked })} />Показывать пользователю детали установки</label>
              <label><input type="checkbox" checked={draft.allowDowngrade} onChange={(event) => setDraft({ ...draft, allowDowngrade: event.target.checked })} />Разрешить установку более старой версии</label>
            </div>
          </fieldset>

          <fieldset>
            <legend>Лицензия</legend>
            <StudioField label="Текст соглашения" hint="Оставьте пустым, если соглашение не требуется">
              <textarea rows={6} maxLength={16384} value={draft.license ?? ''} onChange={(event) => setDraft({ ...draft, license: event.target.value || null })} />
            </StudioField>
          </fieldset>

          <fieldset>
            <legend>Ссылки после установки</legend>
            <div className="studio-fieldset-heading">
              <p>До четырёх безопасных HTTPS-ссылок на финальном экране.</p>
              <button className="secondary-button" type="button" disabled={draft.finishLinks.length >= 4} onClick={() => setDraft({ ...draft, finishLinks: [...draft.finishLinks, { label: '', url: 'https://' }] })}>
                <Plus size={15} aria-hidden="true" />Добавить
              </button>
            </div>
            {draft.finishLinks.length ? (
              <div className="studio-link-list">
                {draft.finishLinks.map((link, index) => (
                  <div className="studio-link-row" key={index}>
                    <input aria-label={`Название ссылки ${index + 1}`} required maxLength={48} value={link.label} onChange={(event) => updateLink(index, 'label', event.target.value)} placeholder="Документация" />
                    <input aria-label={`HTTPS адрес ${index + 1}`} required type="url" pattern="https://.*" maxLength={2048} value={link.url} onChange={(event) => updateLink(index, 'url', event.target.value)} placeholder="https://example.com" />
                    <button type="button" aria-label={`Удалить ссылку ${index + 1}`} onClick={() => setDraft({ ...draft, finishLinks: draft.finishLinks.filter((_, linkIndex) => linkIndex !== index) })}>
                      <Trash2 size={16} aria-hidden="true" />
                    </button>
                  </div>
                ))}
              </div>
            ) : <p className="studio-empty-copy">Ссылки не добавлены.</p>}
          </fieldset>

          <section className="studio-payload-summary" aria-labelledby="payload-title">
            <div>
              <h2 id="payload-title">Файлы приложения</h2>
              <p>{formatFileCount(project.files)} · {formatBytes(project.bytes)}</p>
            </div>
            <div>
              <span>{targetLabel(project)}</span>
              <span>{project.executableFiles ? `Исполняемых: ${project.executableFiles}` : 'Исполняемые файлы не отмечены'}</span>
            </div>
            <div className="studio-payload-actions">
              <button className="secondary-button" type="button" disabled={busy || dirty} onClick={onImportFiles}>
                <FilePlus2 size={15} aria-hidden="true" />Файлы
              </button>
              <button className="secondary-button" type="button" disabled={busy || dirty} onClick={onImportDirectory}>
                <Folder size={15} aria-hidden="true" />Папка
              </button>
              <button
                className="secondary-button"
                type="button"
                title="Текущие файлы приложения будут полностью заменены содержимым выбранной папки"
                disabled={busy || dirty}
                onClick={onReplacePayload}
              >
                <RefreshCw size={15} aria-hidden="true" />Заменить всё
              </button>
            </div>
          </section>
        </div>
      ) : <ReadOnlyProject project={project} />}
    </form>
  )
}

function useBuildElapsed(active: boolean): number {
  const [seconds, setSeconds] = useState(0)

  useEffect(() => {
    if (!active) {
      setSeconds(0)
      return
    }
    const started = performance.now()
    setSeconds(0)
    const timer = window.setInterval(() => {
      setSeconds(Math.max(0, Math.floor((performance.now() - started) / 1000)))
    }, 1000)
    return () => window.clearInterval(timer)
  }, [active])

  return seconds
}

function ReadOnlyProject({ project }: { project: StudioProject }) {
  return (
    <div className="studio-sections">
      <section aria-labelledby="manifest-title">
        <h2 id="manifest-title">Манифест</h2>
        <dl className="studio-facts">
          <Fact label="ID приложения" value={project.packageId} mono />
          <Fact label="Подпись" value={project.formatVersion === 1 ? 'Не подписан' : 'Подписанный проект'} />
          <Fact label="Лицензия" value={project.hasLicense ? 'Требует принятия' : 'Не задана'} />
          {project.formatVersion === 3 ? <Fact label="Ротация ключа" value="Проверяется при CLI build текущим ключом" /> : null}
          <Fact label="Папка установки" value={project.installDirectory} mono />
          <Fact label="Область" value={project.scope === 'user' ? 'Текущий пользователь' : 'Вся система'} />
          <Fact label="Запуск" value={project.hasEntrypoint ? project.entrypoint ?? 'Настроен' : 'Не настроен'} />
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
  )
}

function StudioField({ label, hint, wide = false, children }: { label: string; hint?: string; wide?: boolean; children: React.ReactNode }) {
  return (
    <label className={wide ? 'studio-field studio-field--wide' : 'studio-field'}>
      <span>{label}</span>
      {children}
      {hint ? <small>{hint}</small> : null}
    </label>
  )
}

function BuildResult({ result, onReveal }: { result: StudioBuildResult; onReveal(): Promise<void> }) {
  const pendingRef = useRef(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const reveal = async () => {
    if (pendingRef.current) return
    pendingRef.current = true
    setPending(true)
    setError(null)
    try {
      await onReveal()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Не удалось показать установщик.')
    } finally {
      pendingRef.current = false
      setPending(false)
    }
  }

  return (
    <section className="studio-build-result" aria-labelledby="studio-build-result-title" aria-live="polite">
      <Check size={21} strokeWidth={2.5} aria-hidden="true" />
      <div>
        <h2 id="studio-build-result-title">Установщик готов</h2>
        <code tabIndex={0} title={result.outputPath}>{result.outputPath}</code>
        {error ? <small role="alert">{error}</small> : null}
      </div>
      <button className="secondary-button" type="button" disabled={pending} onClick={() => void reveal()}>
        {pending ? <SquareDashed className="spin" size={15} aria-hidden="true" /> : <FolderOpen size={15} aria-hidden="true" />}
        {pending ? 'Открываем…' : 'Показать результат'}
      </button>
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

function targetLabel(project: Pick<StudioProject, 'targetOs' | 'targetArch'>): string {
  const os = { windows: 'Windows', linux: 'Linux', macos: 'macOS' }[project.targetOs]
  return `${os} · ${project.targetArch}`
}

function nativeBuildLabel(target: StudioProject['targetOs']): string {
  return {
    windows: 'Собрать .exe',
    linux: 'Собрать .deb / .rpm',
    macos: 'Собрать .dmg',
  }[target]
}
