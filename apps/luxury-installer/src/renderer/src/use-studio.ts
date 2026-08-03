import { useRef, useState } from 'react'

import type { LuxuryBridge, StudioBuildResult, StudioProject } from './types'

export type StudioView =
  | { kind: 'empty' }
  | { kind: 'loading'; action: 'create' | 'open' }
  | { kind: 'ready'; project: StudioProject }
  | { kind: 'refreshing'; project: StudioProject }
  | { kind: 'building'; project: StudioProject }
  | { kind: 'built'; result: StudioBuildResult }
  | { kind: 'error'; message: string; project: StudioProject | null }

export interface StudioController {
  view: StudioView
  folderPending: boolean
  createProject(): Promise<void>
  openProject(): Promise<void>
  reloadProject(): Promise<void>
  revealProject(): Promise<void>
  buildProject(): Promise<void>
  dismissError(): void
}

export function useStudio(bridge: LuxuryBridge): StudioController {
  const [view, setView] = useState<StudioView>({ kind: 'empty' })
  const [folderPending, setFolderPending] = useState(false)
  const busy = useRef(false)

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
    } catch (error) {
      setView({ kind: 'error', message: errorMessage(error), project: projectFrom(previous) })
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
    } catch (error) {
      setView({ kind: 'error', message: errorMessage(error), project })
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
    folderPending,
    createProject: () => loadProject('create'),
    openProject: () => loadProject('open'),
    reloadProject,
    revealProject,
    buildProject,
    dismissError,
  }
}

export function projectFrom(view: StudioView): StudioProject | null {
  if (view.kind === 'ready' || view.kind === 'refreshing' || view.kind === 'building') {
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
