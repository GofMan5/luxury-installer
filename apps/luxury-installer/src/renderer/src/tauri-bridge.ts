import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import type { ZodType } from 'zod'

import {
  appModeSchema,
  eventEnvelopeSchema,
  installRequestSchema,
  installerReviewSchema,
  operationStartedSchema,
  publicErrorSchema,
  setupEventSchema,
  studioBuildResultSchema,
  studioProjectSchema,
} from './bridge-contracts'
import type { LuxuryBridge, SetupEvent } from './types'

const OPERATION_EVENT = 'luxury://operation-event'

export function createTauriBridge(): LuxuryBridge {
  const subscribers = new Set<(event: SetupEvent) => void>()
  let unlisten: UnlistenFn | undefined
  let disposed = false
  let eventFailure: Error | undefined
  const eventReady = listen<unknown>(OPERATION_EVENT, ({ payload }) => {
    const parsed = setupEventSchema.safeParse(payload)
    if (parsed.success) {
      for (const subscriber of subscribers) subscriber(parsed.data)
      return
    }
    const operationId = eventEnvelopeSchema.safeParse(payload)
    if (!operationId.success) return
    const failure: SetupEvent = {
      kind: 'error',
      operationId: operationId.data.operationId,
      code: 'internal_error',
      message: 'Компоненты установщика вернули несовместимое событие.',
    }
    for (const subscriber of subscribers) subscriber(failure)
  }).then((dispose) => {
    if (disposed) dispose()
    else unlisten = dispose
  }).catch(() => {
    eventFailure = new Error('Не удалось запустить защищённый канал событий установщика.')
  })

  window.addEventListener(
    'beforeunload',
    () => {
      disposed = true
      unlisten?.()
    },
    { once: true },
  )

  const bridge: LuxuryBridge = {
    getAppMode: () => parsedInvoke('get_app_mode', appModeSchema),
    getBootstrap: () => parsedInvoke('get_bootstrap', installerReviewSchema),
    createProject: () => parsedInvoke('create_project', studioProjectSchema.nullable()),
    openProject: () => parsedInvoke('open_project', studioProjectSchema.nullable()),
    reloadProject: () => parsedInvoke('reload_project', studioProjectSchema),
    revealProject: () => invokeCommand('reveal_project'),
    buildProject: () => parsedInvoke('build_project', studioBuildResultSchema.nullable()),
    chooseDirectory: () => parsedInvoke('choose_directory', installerReviewSchema.nullable()),
    startInstall: async (input) => {
      await ensureEventReady()
      return parsedInvoke('start_install', operationStartedSchema, {
        input: installRequestSchema.parse(input),
      })
    },
    startUninstall: async () => {
      await ensureEventReady()
      return parsedInvoke('start_uninstall', operationStartedSchema)
    },
    cancelOperation: () => invokeCommand('cancel_operation'),
    onOperationEvent: (listener) => {
      subscribers.add(listener)
      return () => subscribers.delete(listener)
    },
    launchInstalled: () => invokeCommand('launch_installed'),
    revealInstalled: () => invokeCommand('reveal_installed'),
    openFinishLink: (index) => invokeCommand('open_finish_link', { index }),
    minimizeWindow: () => invokeCommand('minimize_window'),
    toggleMaximizeWindow: () => invokeCommand('toggle_maximize_window'),
    closeWindow: () => invokeCommand('close_window'),
  }
  return Object.freeze(bridge)

  async function ensureEventReady(): Promise<void> {
    await eventReady
    if (eventFailure) throw eventFailure
  }
}

async function parsedInvoke<T>(
  command: string,
  schema: ZodType<T>,
  args?: Record<string, unknown>,
): Promise<T> {
  try {
    return schema.parse(await invoke<unknown>(command, args))
  } catch (error) {
    throw publicError(error)
  }
}

async function invokeCommand(command: string, args?: Record<string, unknown>): Promise<void> {
  try {
    await invoke(command, args)
  } catch (error) {
    throw publicError(error)
  }
}

function publicError(error: unknown): Error {
  const parsed = publicErrorSchema.safeParse(error)
  return new Error(
    parsed.success ? parsed.data.message : 'Компоненты Luxury Installer несовместимы или недоступны.',
  )
}
