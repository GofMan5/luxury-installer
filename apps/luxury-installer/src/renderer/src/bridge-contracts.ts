import { z } from 'zod'

const text = z.string().min(1).max(1024)
const license = z
  .string()
  .min(1)
  .max(32_768)
  .refine((value) => value.trim().length > 0)
  .refine((value) => !/[\u0000-\u0008\u000b-\u000d\u000e-\u001f\u007f-\u009f]/u.test(value))
  .refine((value) => !/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(value))
const path = z
  .string()
  .min(1)
  .max(32_768)
  .refine((value) => !value.includes('\0'))
  .refine(
    (value) =>
      value.startsWith('/') || /^[A-Za-z]:[\\/]/.test(value) || value.startsWith('\\\\'),
  )
const count = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)
const requestId = z.string().min(1).max(128).regex(/^[A-Za-z0-9._:-]+$/)
const fingerprint = z.string().regex(/^[0-9a-f]{64}$/)
const targetOs = z.enum(['windows', 'linux', 'macos'])
const targetArch = z.enum(['x86_64', 'aarch64'])
const scope = z.enum(['user', 'system'])
const packageId = z
  .string()
  .min(3)
  .max(128)
  .regex(/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/)
const installAction = z.enum(['install', 'update', 'repair'])
const installDirectory = z.string().min(1).max(255).refine(
  (value) =>
    value !== '.' &&
    value !== '..' &&
    !value.includes('/') &&
    !value.includes('\\') &&
    !value.includes(':') &&
    !value.includes('\0') &&
    !value.endsWith('.') &&
    !value.endsWith(' '),
)
const installLogPath = z
  .string()
  .min(1)
  .max(512)
  .refine((value) => new TextEncoder().encode(value).length <= 512)
  .refine(
    (value) =>
      !value.startsWith('/') &&
      !/[\\\0:<>"|?*]/u.test(value) &&
      value.split('/').every(
        (component) =>
          component.length > 0 &&
          component !== '.' &&
          component !== '..' &&
          !component.endsWith('.') &&
          !component.endsWith(' ') &&
          !/[\u0000-\u001f\u007f-\u009f]/u.test(component),
      ),
  )
export const portablePath = z
  .string()
  .min(1)
  .max(4_096)
  .refine(
    (value) =>
      !value.startsWith('/') &&
      !value.startsWith('\\') &&
      !/[\\:\0]/u.test(value) &&
      value.split('/').every((component) => component.length > 0 && component !== '.' && component !== '..'),
  )
const installLog = z
  .object({ files: z.array(installLogPath).max(128), omittedFiles: count })
  .strict()
const finishLink = z
  .object({ label: text.max(48), url: z.string().max(2_048).refine(validHttpsUrl) })
  .strict()

const trust = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('unsigned') }).strict(),
  z.object({ kind: z.literal('trustedPublisher'), keyId: fingerprint }).strict(),
])

const rotation = z
  .object({ signerKeyId: fingerprint, nextKeyId: fingerprint })
  .strict()
  .nullable()

export const packageSummarySchema = z
  .object({
    name: text,
    publisher: text,
    version: text,
    license: license.nullable(),
    targetOs,
    targetArch,
    installDirectory,
    scope,
    hasEntrypoint: z.boolean(),
    installLog: installLog.nullable(),
    finishLinks: z.array(finishLink).max(4),
    files: count,
    bytes: count,
    trust,
    publisherRotation: rotation,
  })
  .strict()
  .superRefine((value, context) => {
    if (
      value.installLog &&
      value.installLog.files.length + value.installLog.omittedFiles !== value.files
    ) {
      context.addIssue({ code: 'custom', path: ['installLog'], message: 'invalid install log' })
    }
    if (
      value.publisherRotation &&
      (value.trust.kind !== 'trustedPublisher' ||
        value.publisherRotation.signerKeyId !== value.trust.keyId ||
        value.publisherRotation.signerKeyId === value.publisherRotation.nextKeyId)
    ) {
      context.addIssue({ code: 'custom', path: ['publisherRotation'], message: 'invalid rotation' })
    }
  })

function validHttpsUrl(value: string): boolean {
  if (
    !value.startsWith('https://') ||
    /[\s\\\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(value)
  ) return false
  const authority = value.slice(8).split(/[/?#]/u, 1)[0] ?? ''
  if (!authority || authority.includes('@') || !/^[\x00-\x7f]+$/u.test(authority)) return false
  const separator = authority.lastIndexOf(':')
  const host = separator < 0 ? authority : authority.slice(0, separator)
  const port = separator < 0 ? null : authority.slice(separator + 1)
  return host.length > 0 &&
    host.length <= 253 &&
    host.split('.').every(
      (label) =>
        label.length > 0 &&
        label.length <= 63 &&
        /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/u.test(label),
    ) &&
    (port === null || (/^[0-9]+$/u.test(port) && Number(port) > 0 && Number(port) <= 65_535))
}

export const installerReviewSchema = z
  .object({
    package: packageSummarySchema,
    destination: z.object({ installBase: path, installPath: path }).strict().nullable(),
    action: z.enum(['install', 'update', 'repair', 'recover']),
    installedVersion: text.nullable(),
    publisherMigrationRequired: z.boolean(),
    spaceAvailable: z.boolean(),
    canUninstall: z.boolean(),
  })
  .strict()
  .superRefine((value, context) => {
    if ((value.package.scope === 'system') !== (value.destination === null)) {
      context.addIssue({
        code: 'custom',
        path: ['destination'],
        message: 'system destination must stay pathless',
      })
    }
    const fresh = value.installedVersion === null
    const valid =
      (value.action === 'install' && fresh && !value.canUninstall) ||
      ((value.action === 'update' || value.action === 'repair') && !fresh && value.canUninstall) ||
      (value.action === 'recover' &&
        fresh &&
        !value.canUninstall &&
        !value.publisherMigrationRequired &&
        value.spaceAvailable)
    if (!valid) {
      context.addIssue({ code: 'custom', path: ['action'], message: 'inconsistent review' })
    }
  })

export const studioProjectSchema = z
  .object({
    projectPath: path,
    formatVersion: z.union([z.literal(1), z.literal(2), z.literal(3)]),
    schemaVersion: z.union([z.literal(1), z.literal(2), z.literal(3)]),
    packageId,
    name: text,
    publisher: text,
    version: text,
    description: text.nullable(),
    license: license.nullable(),
    hasLicense: z.boolean(),
    targetOs,
    targetArch,
    installDirectory,
    scope,
    allowDowngrade: z.boolean(),
    entrypoint: portablePath.nullable(),
    hasEntrypoint: z.boolean(),
    showInstallLog: z.boolean(),
    finishLinks: z.array(finishLink).max(4),
    executableFiles: count,
    files: count,
    bytes: count,
  })
  .strict()
  .superRefine((value, context) => {
    if (value.hasEntrypoint !== (value.entrypoint !== null) || (value.hasEntrypoint && value.schemaVersion < 2)) {
      context.addIssue({ code: 'custom', path: ['hasEntrypoint'], message: 'schema mismatch' })
    }
    if (value.hasLicense !== (value.license !== null) || (value.hasLicense && value.schemaVersion < 3)) {
      context.addIssue({ code: 'custom', path: ['hasLicense'], message: 'schema mismatch' })
    }
    if (value.executableFiles > value.files) {
      context.addIssue({ code: 'custom', path: ['executableFiles'], message: 'count mismatch' })
    }
  })

export const studioProjectUpdateSchema = z
  .object({
    packageId,
    name: text,
    publisher: text,
    version: text,
    description: text.nullable(),
    license: license.nullable(),
    targetOs,
    targetArch,
    installDirectory,
    scope,
    allowDowngrade: z.boolean(),
    entrypoint: portablePath.nullable(),
    showInstallLog: z.boolean(),
    finishLinks: z.array(finishLink).max(4),
  })
  .strict()

export const studioBuildResultSchema = z
  .object({ outputPath: path, project: studioProjectSchema })
  .strict()

export const recentProjectSchema = z
  .object({
    projectPath: path,
    name: text,
    publisher: text,
    version: text,
    targetOs,
    targetArch,
  })
  .strict()
export const recentProjectIndexSchema = z.number().int().min(0).max(5)
export const recentProjectsSchema = z.array(recentProjectSchema).max(6)

export const operationStartedSchema = z.object({ operationId: requestId }).strict()
export const eventEnvelopeSchema = z.object({ operationId: requestId }).passthrough()
export const appModeSchema = z.enum(['studio', 'setup'])
export const installRequestSchema = z
  .object({
    allowUnsigned: z.boolean(),
    acceptLicense: z.boolean(),
    allowPublisherMigration: z.boolean(),
  })
  .strict()

const installPhase = z.enum([
  'validating',
  'recovering',
  'verifying',
  'planning',
  'applying',
  'committing',
  'rollingBack',
  'completed',
  'cancelled',
  'failed',
])
const uninstallPhase = z.enum([
  'recovering',
  'loadingReceipt',
  'removing',
  'committing',
  'rollingBack',
  'completed',
  'cancelled',
  'failed',
])

export const setupEventSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('action'), operationId: requestId, action: installAction }).strict(),
  z.object({ kind: z.literal('phase'), operationId: requestId, phase: installPhase }).strict(),
  z
    .object({
      kind: z.literal('progress'),
      operationId: requestId,
      completedFiles: count,
      totalFiles: count,
      completedBytes: count,
      totalBytes: count,
    })
    .strict()
    .refine((value) => value.completedFiles <= value.totalFiles)
    .refine((value) => value.completedBytes <= value.totalBytes),
  z
    .object({
      kind: z.literal('complete'),
      operationId: requestId,
      action: installAction,
      installedFiles: count,
      installedBytes: count,
      review: installerReviewSchema.optional(),
    })
    .strict()
    .refine(
      (value) =>
        value.review === undefined ||
        (value.review.action === 'repair' &&
          value.review.installedVersion !== null &&
          value.review.canUninstall),
      { path: ['review'], message: 'complete event contains stale review' },
    ),
  z
    .object({ kind: z.literal('uninstallPhase'), operationId: requestId, phase: uninstallPhase })
    .strict(),
  z
    .object({
      kind: z.literal('uninstallProgress'),
      operationId: requestId,
      processedFiles: count,
      totalFiles: count,
    })
    .strict()
    .refine((value) => value.processedFiles <= value.totalFiles),
  z
    .object({
      kind: z.literal('uninstallComplete'),
      operationId: requestId,
      removedFiles: count,
      missingFiles: count,
      preservedModifiedFiles: count,
    })
    .strict()
    .refine(
      (value) =>
        value.removedFiles + value.missingFiles + value.preservedModifiedFiles <=
        Number.MAX_SAFE_INTEGER,
    ),
  z
    .object({
      kind: z.literal('error'),
      operationId: requestId,
      code: z.string().min(1).max(64).regex(/^[a-z0-9_]+$/),
      message: text,
      review: installerReviewSchema.optional(),
    })
    .strict(),
])

export const publicErrorSchema = z
  .object({
    code: z.string().min(1).max(64).regex(/^[a-z0-9_]+$/),
    message: text,
  })
  .strict()
