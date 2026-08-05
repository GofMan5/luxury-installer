import { useCallback, useEffect, useRef, useState } from 'react'
import type {
  InstallPhase,
  InstallerDestination,
  InstallerReview,
  InstallResultAction,
  LuxuryBridge,
  PackageSummary,
  SetupAction,
  SetupEvent,
  UninstallPhase,
} from './types'

type RunningInstall = {
  kind: 'running'
  operation: 'install'
  phase: InstallPhase
  completedFiles: number
  totalFiles: number
  completedBytes: number
  totalBytes: number
  cancellationRequested: boolean
  cancellationError: string | null
  action: InstallResultAction | null
}

type RunningUninstall = {
  kind: 'running'
  operation: 'uninstall'
  phase: UninstallPhase
  processedFiles: number
  totalFiles: number
  cancellationRequested: boolean
  cancellationError: string | null
}

export type InstallerView =
  | { kind: 'booting' }
  | { kind: 'review' }
  | { kind: 'license' }
  | RunningInstall
  | RunningUninstall
  | {
      kind: 'installFinished'
      action: InstallResultAction
      installedFiles: number
      installedBytes: number
    }
  | { kind: 'installComplete'; action: InstallResultAction }
  | { kind: 'cancelled' }
  | {
      kind: 'uninstallComplete'
      removedFiles: number
      missingFiles: number
      preservedModifiedFiles: number
    }
  | {
      kind: 'error'
      message: string
      canRetry: boolean
      publisherMigrationRequired: boolean
    }

export interface InstallerController {
  bridge: LuxuryBridge
  summary: PackageSummary | null
  destination: InstallerDestination | null
  action: SetupAction | null
  installedVersion: string | null
  spaceAvailable: boolean
  canUninstall: boolean
  unsignedAccepted: boolean
  licenseAccepted: boolean
  publisherMigrationRequired: boolean
  publisherMigrationAccepted: boolean
  destinationPending: boolean
  destinationError: string | null
  view: InstallerView
  selectDestination(): Promise<void>
  setUnsignedAccepted(value: boolean): void
  setLicenseAccepted(value: boolean): void
  setPublisherMigrationAccepted(value: boolean): void
  showLicense(): void
  backToReview(): void
  startInstall(): Promise<void>
  startUninstall(): Promise<void>
  cancelOperation(): Promise<void>
  continueAfterInstall(): void
  retry(): void
}

export function useInstaller(bridge: LuxuryBridge): InstallerController {
  const [review, setReview] = useState<InstallerReview | null>(null)
  const [unsignedAccepted, setUnsignedAccepted] = useState(false)
  const [licenseAccepted, setLicenseAccepted] = useState(false)
  const [publisherMigrationAccepted, setPublisherMigrationAccepted] = useState(false)
  const operationId = useRef<string | null>(null)
  const operationPending = useRef(false)
  const cancelPending = useRef(false)
  const destinationPendingRef = useRef(false)
  const [destinationPending, setDestinationPending] = useState(false)
  const [destinationError, setDestinationError] = useState<string | null>(null)
  const [bootstrapAttempt, setBootstrapAttempt] = useState(0)
  const [view, setView] = useState<InstallerView>({ kind: 'booting' })

  useEffect(() => {
    let active = true
    void bridge
      .getBootstrap()
      .then((nextReview) => {
        if (!active) return
        setReview(nextReview)
        setUnsignedAccepted(false)
        setLicenseAccepted(false)
        setPublisherMigrationAccepted(false)
        setDestinationError(null)
        setView({ kind: 'review' })
      })
      .catch((error: unknown) => {
        if (!active) return
        setView({
          kind: 'error',
          message: errorMessage(error),
          canRetry: true,
          publisherMigrationRequired: false,
        })
      })
    return () => {
      active = false
    }
  }, [bootstrapAttempt, bridge])

  useEffect(
    () =>
      bridge.onOperationEvent((event: SetupEvent) => {
        if (!operationPending.current) return
        if (operationId.current && event.operationId !== operationId.current) return
        operationId.current = event.operationId
        if (event.kind === 'action') {
          setView((current) =>
            current.kind === 'running' && current.operation === 'install'
              ? { ...current, action: event.action }
              : current,
          )
        } else if (event.kind === 'phase') {
          setView((current) =>
            current.kind === 'running' && current.operation === 'install'
              ? { ...current, phase: event.phase }
              : current,
          )
        } else if (event.kind === 'progress') {
          setView((current) =>
            current.kind === 'running' && current.operation === 'install'
              ? {
                  ...current,
                  completedFiles: event.completedFiles,
                  totalFiles: event.totalFiles,
                  completedBytes: event.completedBytes,
                  totalBytes: event.totalBytes,
                }
              : current,
          )
        } else if (event.kind === 'complete') {
          if (event.review) setReview(event.review)
          setPublisherMigrationAccepted(false)
          setView({
            kind: 'installFinished',
            action: event.action,
            installedFiles: event.installedFiles,
            installedBytes: event.installedBytes,
          })
          operationPending.current = false
          operationId.current = null
        } else if (event.kind === 'uninstallPhase') {
          setView((current) =>
            current.kind === 'running' && current.operation === 'uninstall'
              ? { ...current, phase: event.phase }
              : current,
          )
        } else if (event.kind === 'uninstallProgress') {
          setView((current) =>
            current.kind === 'running' && current.operation === 'uninstall'
              ? {
                  ...current,
                  processedFiles: event.processedFiles,
                  totalFiles: event.totalFiles,
                }
              : current,
          )
        } else if (event.kind === 'uninstallComplete') {
          setReview((current) =>
            current ? { ...current, canUninstall: false } : current,
          )
          setView({
            kind: 'uninstallComplete',
            removedFiles: event.removedFiles,
            missingFiles: event.missingFiles,
            preservedModifiedFiles: event.preservedModifiedFiles,
          })
          operationPending.current = false
          operationId.current = null
        } else {
          if (event.review) setReview(event.review)
          if (event.code === 'cancelled') {
            setPublisherMigrationAccepted(false)
            setView({ kind: 'cancelled' })
            operationPending.current = false
            operationId.current = null
            return
          }
          const publisherMigrationRequired =
            event.code === 'publisher_migration_required' &&
            event.review?.publisherMigrationRequired === true
          if (!publisherMigrationRequired) setPublisherMigrationAccepted(false)
          setView({
            kind: 'error',
            message: event.message,
            canRetry:
              event.code === 'publisher_migration_required'
                ? publisherMigrationRequired
                : ![
                    'state_conflict',
                    'downgrade_denied',
                    'reinstall_mismatch',
                    'publisher_mismatch',
                    'publisher_rotation_denied',
                  ].includes(event.code),
            publisherMigrationRequired,
          })
          operationPending.current = false
          operationId.current = null
        }
      }),
    [bridge],
  )

  const selectDestination = useCallback(async () => {
    if (destinationPendingRef.current) return
    destinationPendingRef.current = true
    setDestinationPending(true)
    setDestinationError(null)
    try {
      const nextReview = await bridge.chooseDirectory()
      if (!nextReview) return
      setReview(nextReview)
      setPublisherMigrationAccepted(false)
    } catch (error) {
      setDestinationError(errorMessage(error))
    } finally {
      destinationPendingRef.current = false
      setDestinationPending(false)
    }
  }, [bridge])

  const sendCancellation = useCallback(async () => {
    try {
      await bridge.cancelOperation()
    } catch (error) {
      cancelPending.current = false
      setView((current) =>
        current.kind === 'running'
          ? {
              ...current,
              cancellationRequested: false,
              cancellationError: errorMessage(error),
            }
          : current,
      )
    }
  }, [bridge])

  const startInstall = useCallback(async () => {
    if (
      operationPending.current ||
      !review ||
      !review.spaceAvailable ||
      (review.package.trust.kind === 'unsigned' && !unsignedAccepted) ||
      (review.package.license !== null && !licenseAccepted) ||
      (review.publisherMigrationRequired && !publisherMigrationAccepted)
    ) return
    setDestinationError(null)
    setView({
      kind: 'running',
      operation: 'install',
      phase: 'validating',
      completedFiles: 0,
      totalFiles: review.package.files,
      completedBytes: 0,
      totalBytes: review.package.bytes,
      cancellationRequested: false,
      cancellationError: null,
      action: null,
    })
    operationId.current = null
    operationPending.current = true
    cancelPending.current = false
    try {
      const operation = await bridge.startInstall({
        allowUnsigned:
          review.package.trust.kind === 'unsigned' ? unsignedAccepted : false,
        acceptLicense: review.package.license !== null && licenseAccepted,
        allowPublisherMigration: review.publisherMigrationRequired && publisherMigrationAccepted,
      })
      if (!operationPending.current) return
      operationId.current = operation.operationId
      if (cancelPending.current) await sendCancellation()
    } catch (error) {
      if (!operationPending.current) return
      operationPending.current = false
      operationId.current = null
      setPublisherMigrationAccepted(false)
      setView({
        kind: 'error',
        message: errorMessage(error),
        canRetry: true,
        publisherMigrationRequired: false,
      })
    }
  }, [
    bridge,
    licenseAccepted,
    publisherMigrationAccepted,
    review,
    sendCancellation,
    unsignedAccepted,
  ])

  const showLicense = useCallback(() => {
    if (view.kind === 'review' && review?.package.license) {
      setView({ kind: 'license' })
    }
  }, [review, view.kind])

  const continueAfterInstall = useCallback(() => {
    if (view.kind === 'installFinished') {
      setView({ kind: 'installComplete', action: view.action })
    }
  }, [view])

  const backToReview = useCallback(() => {
    if (view.kind === 'license') setView({ kind: 'review' })
  }, [view.kind])

  const startUninstall = useCallback(async () => {
    if (operationPending.current || !review?.canUninstall) return
    setView({
      kind: 'running',
      operation: 'uninstall',
      phase: 'recovering',
      processedFiles: 0,
      totalFiles: 0,
      cancellationRequested: false,
      cancellationError: null,
    })
    operationId.current = null
    operationPending.current = true
    cancelPending.current = false
    try {
      const operation = await bridge.startUninstall()
      if (!operationPending.current) return
      operationId.current = operation.operationId
      if (cancelPending.current) await sendCancellation()
    } catch (error) {
      if (!operationPending.current) return
      operationPending.current = false
      operationId.current = null
      setView({
        kind: 'error',
        message: errorMessage(error),
        canRetry: true,
        publisherMigrationRequired: false,
      })
    }
  }, [bridge, review, sendCancellation])

  const cancelOperation = useCallback(async () => {
    if (cancelPending.current) return
    cancelPending.current = true
    setView((current) =>
      current.kind === 'running'
        ? { ...current, cancellationRequested: true, cancellationError: null }
        : current,
    )
    if (!operationId.current) return
    await sendCancellation()
  }, [sendCancellation])

  const retry = useCallback(() => {
    if (view.kind === 'error') setPublisherMigrationAccepted(false)
    setView({ kind: 'booting' })
    setBootstrapAttempt((attempt) => attempt + 1)
  }, [view.kind])

  return {
    bridge,
    summary: review?.package ?? null,
    destination: review?.destination ?? null,
    action: review?.action ?? null,
    installedVersion: review?.installedVersion ?? null,
    spaceAvailable: review?.spaceAvailable ?? false,
    canUninstall: review?.canUninstall ?? false,
    unsignedAccepted,
    licenseAccepted,
    publisherMigrationRequired: review?.publisherMigrationRequired ?? false,
    publisherMigrationAccepted,
    destinationPending,
    destinationError,
    view,
    selectDestination,
    setUnsignedAccepted,
    setLicenseAccepted,
    setPublisherMigrationAccepted,
    showLicense,
    backToReview,
    startInstall,
    startUninstall,
    cancelOperation,
    continueAfterInstall,
    retry,
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Неизвестная ошибка установщика.'
}
