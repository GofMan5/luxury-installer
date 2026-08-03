export type AppMode = 'studio' | 'setup'
export type TargetOs = 'windows' | 'linux' | 'macos'
export type TargetArch = 'x86_64' | 'aarch64'
export type InstallScope = 'user' | 'system'
export type SetupAction = 'install' | 'update' | 'repair' | 'recover'
export type InstallResultAction = Exclude<SetupAction, 'recover'>
export type PackageTrust =
  | { kind: 'unsigned' }
  | { kind: 'trustedPublisher'; keyId: string }

export interface VerifiedPublisherRotation {
  signerKeyId: string
  nextKeyId: string
}

export interface FinishLink {
  label: string
  url: string
}

export interface InstallLog {
  files: string[]
  omittedFiles: number
}

export interface PackageSummary {
  name: string
  publisher: string
  version: string
  license: string | null
  targetOs: TargetOs
  targetArch: TargetArch
  installDirectory: string
  scope: InstallScope
  hasEntrypoint: boolean
  installLog: InstallLog | null
  finishLinks: FinishLink[]
  files: number
  bytes: number
  trust: PackageTrust
  publisherRotation: VerifiedPublisherRotation | null
}

export interface InstallerDestination {
  installBase: string
  installPath: string
}

export interface InstallerReview {
  package: PackageSummary
  destination: InstallerDestination | null
  action: SetupAction
  installedVersion: string | null
  publisherMigrationRequired: boolean
  spaceAvailable: boolean
  canUninstall: boolean
}

export interface StudioProject {
  projectPath: string
  formatVersion: 1 | 2 | 3
  schemaVersion: 1 | 2 | 3
  packageId: string
  name: string
  publisher: string
  version: string
  hasLicense: boolean
  targetOs: TargetOs
  targetArch: TargetArch
  installDirectory: string
  scope: InstallScope
  hasEntrypoint: boolean
  files: number
  bytes: number
}

export interface StudioBuildResult {
  outputPath: string
  project: StudioProject
}

export interface InstallRequest {
  allowUnsigned: boolean
  acceptLicense: boolean
  allowPublisherMigration: boolean
}

export type InstallPhase =
  | 'validating'
  | 'recovering'
  | 'verifying'
  | 'planning'
  | 'applying'
  | 'committing'
  | 'rollingBack'
  | 'completed'
  | 'cancelled'
  | 'failed'

export type UninstallPhase =
  | 'recovering'
  | 'loadingReceipt'
  | 'removing'
  | 'committing'
  | 'rollingBack'
  | 'completed'
  | 'cancelled'
  | 'failed'

export type SetupEvent =
  | { kind: 'action'; operationId: string; action: InstallResultAction }
  | { kind: 'phase'; operationId: string; phase: InstallPhase }
  | {
      kind: 'progress'
      operationId: string
      completedFiles: number
      totalFiles: number
      completedBytes: number
      totalBytes: number
    }
  | {
      kind: 'complete'
      operationId: string
      action: InstallResultAction
      installedFiles: number
      installedBytes: number
      review?: InstallerReview | undefined
    }
  | { kind: 'uninstallPhase'; operationId: string; phase: UninstallPhase }
  | {
      kind: 'uninstallProgress'
      operationId: string
      processedFiles: number
      totalFiles: number
    }
  | {
      kind: 'uninstallComplete'
      operationId: string
      removedFiles: number
      missingFiles: number
      preservedModifiedFiles: number
    }
  | {
      kind: 'error'
      operationId: string
      code: string
      message: string
      review?: InstallerReview | undefined
    }

export interface LuxuryBridge {
  getAppMode(): Promise<AppMode>
  getBootstrap(): Promise<InstallerReview>
  createProject(): Promise<StudioProject | null>
  openProject(): Promise<StudioProject | null>
  reloadProject(): Promise<StudioProject>
  revealProject(): Promise<void>
  buildProject(): Promise<StudioBuildResult | null>
  chooseDirectory(): Promise<InstallerReview | null>
  startInstall(input: InstallRequest): Promise<{ operationId: string }>
  startUninstall(): Promise<{ operationId: string }>
  cancelOperation(): Promise<void>
  onOperationEvent(listener: (event: SetupEvent) => void): () => void
  launchInstalled(): Promise<void>
  revealInstalled(): Promise<void>
  openFinishLink(index: number): Promise<void>
  minimizeWindow(): Promise<void>
  toggleMaximizeWindow(): Promise<void>
  closeWindow(): Promise<void>
}
