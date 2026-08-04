import { useEffect, useRef, useState } from 'react'

import type {
  LuxuryBridge,
  RecentProject,
  StudioBuildResult,
  StudioProject,
  StudioProjectUpdate,
} from './types'

export type StudioView =
  | { kind: 'empty' }
  | { kind: 'loading'; action: 'create' | 'open' }
  | { kind: 'ready'; project: StudioProject }
  | { kind: 'refreshing'; project: StudioProject }
  | { kind: 'saving'; project: StudioProject }
  | { kind: 'importing'; project: StudioProject }
  | { kind: 'choosingEntrypoint'; project: StudioProject }
  | { kind: 'building'; project: StudioProject }
  | { kind: 'built'; result: StudioBuildResult }
  | { kind: 'error'; message: string; project: StudioProject | null }

export interface StudioController {
  view: StudioView
  recentProjects: RecentProject[]
  folderPending: boolean
  createProject(): Promise<void>
  openProject(): Promise<void>
  openRecentProject(index: number): Promise<void>
  reloadProject(): Promise<void>
  updateProject(input: StudioProjectUpdate): Promise<void>
  importProject(kind: 'files' | 'directory' | 'replace'): Promise<void>
  chooseProjectEntrypoint(): Promise<string | null>
  revealProject(): Promise<void>
  buildProject(): Promise<void>
  dismissError(): void
}

export function useStudio(bridge: LuxuryBridge): StudioController {
  const [view, setView] = useState<StudioView>({ kind: 'empty' })
  const [folderPending, setFolderPending] = useState(false)
  const [recentProjects, setRecentProjects] = useState<RecentProject[]>([])
  const busy = useRef(false)
  const recentRequest = useRef(0)

  async function refreshRecentProjects() {
    const request = ++recentRequest.current
    try {
      const projects = await bridge.getRecentProjects()
      if (request === recentRequest.current) setRecentProjects(projects)
    } catch {
      if (request === recentRequest.current) setRecentProjects([])
    }
  }

  useEffect(() => {
    void refreshRecentProjects()
  }, [bridge])

  async function loadProject(action: 'create' | 'open') {
    if (busy.current) return
    const previous = view
    busy.current = true
    setView({ kind: 'loading', action })
    try {
      const project = await (action === 'create'
        ? bridge.createProject()
        : bridge.openProject())
      setView(project ? { kind: 'ready', project } : previous)
      if (project) void refreshRecentProjects()
    } catch (error) {
      setView({ kind: 'error', message: errorMessage(error), project: projectFrom(previous) })
    } finally {
      busy.current = false
    }
  }

  async function openRecentProject(index: number) {
    if (busy.current) return
    const previous = view
    busy.current = true
    setView({ kind: 'loading', action: 'open' })
    try {
      const project = await bridge.openRecentProject(index)
      setView({ kind: 'ready', project })
      void refreshRecentProjects()
    } catch (error) {
      setView({ kind: 'error', message: errorMessage(error), project: projectFrom(previous) })
      void refreshRecentProjects()
    } finally {
      busy.current = false
    }
  }

  async function reloadProject() {
    if (busy.current) return
    const project = projectFrom(view)
    if (!project) return
    busy.current = true
    setView({ kind: 'refreshing', project })
    try {
      setView({ kind: 'ready', project: await bridge.reloadProject() })
      void refreshRecentProjects()
    } catch (error) {
      setView({ kind: 'error', message: errorMessage(error), project })
    } finally {
      busy.current = false
    }
  }

  async function revealProject() {
    if (busy.current) return
    const project = projectFrom(view)
    if (!project) return
    busy.current = true
    setFolderPending(true)
    try {
      await bridge.revealProject()
    } catch (error) {
      setView({ kind: 'error', message: errorMessage(error), project })
    } finally {
      setFolderPending(false)
      busy.current = false
    }
  }

  async function updateProject(input: StudioProjectUpdate) {
    if (busy.current) return
    const project = projectFrom(view)
    if (!project || project.formatVersion !== 1) return
    busy.current = true
    setView({ kind: 'saving', project })
    try {
      setView({ kind: 'ready', project: await bridge.updateProject(input) })
      void refreshRecentProjects()
    } catch (error) {
      setView({ kind: 'error', message: errorMessage(error), project })
    } finally {
      busy.current = false
    }
  }

  async function buildProject() {
    if (busy.current) return
    const project = projectFrom(view)
    if (!project || project.formatVersion !== 1) return
    const previous = view
    busy.current = true
    setView({ kind: 'building', project })
    try {
      const result = await bridge.buildProject()
      setView(result ? { kind: 'built', result } : previous)
      if (result) void refreshRecentProjects()
    } catch (error) {
      setView({ kind: 'error', message: errorMessage(error), project })
    } finally {
      busy.current = false
    }
  }

  async function importProject(kind: 'files' | 'directory' | 'replace') {
    if (busy.current) return
    const project = projectFrom(view)
    if (!project || project.formatVersion !== 1) return
    busy.current = true
    setView({ kind: 'importing', project })
    try {
      const imported = await (kind === 'files'
        ? bridge.importProjectFiles()
        : kind === 'directory'
          ? bridge.importProjectDirectory()
          : bridge.replaceProjectPayload())
      setView({ kind: 'ready', project: imported ?? project })
    } catch (error) {
      setView({ kind: 'error', message: errorMessage(error), project })
    } finally {
      busy.current = false
    }
  }

  async function chooseProjectEntrypoint(): Promise<string | null> {
    if (busy.current) return null
    const project = projectFrom(view)
    if (!project || project.formatVersion !== 1) return null
    busy.current = true
    setView({ kind: 'choosingEntrypoint', project })
    try {
      const selected = await bridge.chooseProjectEntrypoint()
      setView({ kind: 'ready', project })
      return selected
    } catch (error) {
      setView({ kind: 'error', message: errorMessage(error), project })
      return null
    } finally {
      busy.current = false
    }
  }

  function dismissError() {
    setView((current) =>
      current.kind === 'error' && current.project
        ? { kind: 'ready', project: current.project }
        : { kind: 'empty' },
    )
  }

  return {
    view,
    recentProjects,
    folderPending,
    createProject: () => loadProject('create'),
    openProject: () => loadProject('open'),
    openRecentProject,
    reloadProject,
    updateProject,
    importProject,
    chooseProjectEntrypoint,
    revealProject,
    buildProject,
    dismissError,
  }
}

export function projectFrom(view: StudioView): StudioProject | null {
  if (
    view.kind === 'ready' ||
    view.kind === 'refreshing' ||
    view.kind === 'saving' ||
    view.kind === 'importing' ||
    view.kind === 'choosingEntrypoint' ||
    view.kind === 'building'
  ) {
    return view.project
  }
  if (view.kind === 'built') return view.result.project
  if (view.kind === 'error') return view.project
  return null
}

function errorMessage(error: unknown): string {
  return error instanceof Error && error.message.trim()
    ? error.message
    : 'Неизвестная ошибка Studio.'
}
