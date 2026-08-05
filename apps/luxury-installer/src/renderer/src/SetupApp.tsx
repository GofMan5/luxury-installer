import { useEffect, useRef, useState } from 'react'

import { InstallRail } from './components/InstallRail'
import { WindowChrome } from './components/WindowChrome'
import { EmptyView } from './features/installer/EmptyView'
import { LicenseView } from './features/installer/LicenseView'
import { ProgressView } from './features/installer/ProgressView'
import {
  CancelledView,
  CompleteView,
  ErrorView,
  UninstallCompleteView,
} from './features/installer/ResultView'
import { ReviewView } from './features/installer/ReviewView'
import type { InstallResultAction, LuxuryBridge, SetupAction } from './types'
import { useInstaller, type InstallerView } from './use-installer'

export function SetupApp({ bridge }: { bridge: LuxuryBridge }) {
  const installer = useInstaller(bridge)
  const { action, destination, view, summary } = installer
  const workspace = useRef<HTMLElement>(null)
  const resultPendingRef = useRef(false)
  const [resultPending, setResultPending] = useState<'reveal' | 'close' | number | null>(null)
  const [resultError, setResultError] = useState<string | null>(null)

  useEffect(() => {
    setResultError(null)
    const container = workspace.current
    if (!container) return
    container.scrollTop = 0
    container.scrollLeft = 0
    container.querySelector<HTMLElement>('[data-view-heading]')?.focus({ preventScroll: true })
  }, [view.kind])

  const runResultAction = async (
    action: 'reveal' | 'close' | number,
    operation: () => Promise<void>,
  ) => {
    if (resultPendingRef.current) return
    resultPendingRef.current = true
    setResultPending(action)
    setResultError(null)
    try {
      await operation()
    } catch (error) {
      setResultError(actionError(error))
    } finally {
      resultPendingRef.current = false
      setResultPending(null)
    }
  }

  return (
    <div className="app-shell">
      <WindowChrome bridge={bridge} />
      <InstallRail currentStep={currentStep(view.kind)} {...railState(view, action)} />
      <main className="workspace" ref={workspace}>
        {view.kind === 'booting' ? (
          <EmptyView />
        ) : view.kind === 'review' && summary && action ? (
          <ReviewView
            summary={summary}
            destination={destination}
            action={action}
            installedVersion={installer.installedVersion}
            spaceAvailable={installer.spaceAvailable}
            canUninstall={installer.canUninstall}
            unsignedAccepted={installer.unsignedAccepted}
            publisherMigrationRequired={installer.publisherMigrationRequired}
            publisherMigrationAccepted={installer.publisherMigrationAccepted}
            destinationPending={installer.destinationPending}
            destinationError={installer.destinationError}
            onChooseDestination={() => void installer.selectDestination()}
            onUnsignedAccepted={installer.setUnsignedAccepted}
            onPublisherMigrationAccepted={installer.setPublisherMigrationAccepted}
            onInstall={() => {
              if (summary.license) installer.showLicense()
              else void installer.startInstall()
            }}
            onUninstall={() => void installer.startUninstall()}
          />
        ) : view.kind === 'license' && summary?.license ? (
          <LicenseView
            name={summary.name}
            publisher={summary.publisher}
            license={summary.license}
            accepted={installer.licenseAccepted}
            onAccepted={installer.setLicenseAccepted}
            onBack={installer.backToReview}
            onInstall={() => void installer.startInstall()}
          />
        ) : view.kind === 'running' && view.operation === 'install' && summary ? (
          <ProgressView
            name={summary.name}
            operation="install"
            action={view.action}
            phase={view.phase}
            completedFiles={view.completedFiles}
            totalFiles={view.totalFiles}
            completedBytes={view.completedBytes}
            totalBytes={view.totalBytes}
            cancellationRequested={view.cancellationRequested}
            cancellationError={view.cancellationError}
            installLog={summary.installLog}
            destination={destination}
            onCancel={() => void installer.cancelOperation()}
          />
        ) : view.kind === 'running' && view.operation === 'uninstall' && summary ? (
          <ProgressView
            name={summary.name}
            operation="uninstall"
            phase={view.phase}
            processedFiles={view.processedFiles}
            totalFiles={view.totalFiles}
            cancellationRequested={view.cancellationRequested}
            cancellationError={view.cancellationError}
            onCancel={() => void installer.cancelOperation()}
          />
        ) : view.kind === 'installFinished' && summary ? (
          <ProgressView
            name={summary.name}
            operation="install"
            action={view.action}
            phase="completed"
            completedFiles={view.installedFiles}
            totalFiles={summary.files}
            completedBytes={view.installedBytes}
            totalBytes={summary.bytes}
            cancellationRequested={false}
            installLog={summary.installLog}
            destination={destination}
            onContinue={installer.continueAfterInstall}
          />
        ) : view.kind === 'installComplete' && summary ? (
          <CompleteView
            name={summary.name}
            action={view.action}
            canLaunch={summary.hasEntrypoint}
            canReveal
            launchPending={installer.launchPending}
            actionPending={resultPending}
            actionError={resultError}
            finishLinks={summary.finishLinks}
            onLaunch={() => void installer.launchInstalled()}
            onReveal={() => void runResultAction('reveal', installer.bridge.revealInstalled)}
            onOpenLink={(index) =>
              void runResultAction(index, () => installer.bridge.openFinishLink(index))
            }
            onClose={() => void runResultAction('close', installer.bridge.closeWindow)}
          />
        ) : view.kind === 'uninstallComplete' && summary ? (
          <UninstallCompleteView
            name={summary.name}
            removedFiles={view.removedFiles}
            missingFiles={view.missingFiles}
            preservedModifiedFiles={view.preservedModifiedFiles}
            closePending={resultPending === 'close'}
            actionError={resultError}
            onClose={() => void runResultAction('close', installer.bridge.closeWindow)}
          />
        ) : view.kind === 'cancelled' ? (
          <CancelledView onBack={installer.retry} />
        ) : view.kind === 'error' ? (
          <ErrorView
            message={view.message}
            canRetry={view.canRetry}
            retryLabel={
              view.publisherMigrationRequired
                ? 'Настроить привязку издателя'
                : 'Вернуться к проверке'
            }
            onRetry={installer.retry}
          />
        ) : (
          <EmptyView />
        )}
      </main>
    </div>
  )
}

function actionError(error: unknown): string {
  return error instanceof Error && error.message.trim()
    ? error.message
    : 'Системное действие не выполнено.'
}

function currentStep(kind: ReturnType<typeof useInstaller>['view']['kind']): number {
  if (kind === 'running') return 2
  if (kind === 'installFinished') return 2
  if (kind === 'installComplete' || kind === 'uninstallComplete') return 3
  return 1
}

function railState(
  view: InstallerView,
  prepared: SetupAction | null,
): {
  action: InstallResultAction | SetupAction | null
  operation: 'install' | 'uninstall' | null
} {
  if (view.kind === 'running') {
    return view.operation === 'install'
      ? { action: view.action, operation: 'install' }
      : { action: null, operation: 'uninstall' }
  }
  if (view.kind === 'installComplete') return { action: view.action, operation: 'install' }
  if (view.kind === 'installFinished') return { action: view.action, operation: 'install' }
  if (view.kind === 'uninstallComplete') return { action: null, operation: 'uninstall' }
  return { action: prepared, operation: null }
}
