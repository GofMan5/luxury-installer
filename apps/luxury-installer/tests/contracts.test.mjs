import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import {
  eventEnvelopeSchema,
  installRequestSchema,
  installerReviewSchema,
  packageSummarySchema,
  recentProjectIndexSchema,
  recentProjectSchema,
  recentProjectsSchema,
  setupEventSchema,
  studioProjectSchema,
} from '../src/renderer/src/bridge-contracts.ts'
import { projectFrom } from '../src/renderer/src/use-studio.ts'
import { shortenPath } from '../src/renderer/src/features/installer/format.ts'

const packageSummary = {
  name: 'Luxury Demo',
  publisher: 'Luxury Software',
  version: '1.0.0',
  description: null,
  license: null,
  targetOs: 'windows',
  targetArch: 'x86_64',
  installDirectory: 'Luxury Demo',
  scope: 'user',
  hasEntrypoint: true,
  installLog: null,
  finishLinks: [],
  files: 1,
  bytes: 29,
  trust: { kind: 'unsigned' },
  publisherRotation: null,
}

const review = {
  package: packageSummary,
  destination: {
    installBase: String.raw`C:\Users\demo\AppData\Local\Programs`,
    installPath: String.raw`C:\Users\demo\AppData\Local\Programs\Luxury Demo`,
  },
  action: 'install',
  installedVersion: null,
  publisherMigrationRequired: false,
  spaceAvailable: true,
  canUninstall: false,
}

test('review contract keeps action, installed version, and maintenance state consistent', () => {
  assert.equal(installerReviewSchema.safeParse(review).success, true)
  assert.equal(
    installerReviewSchema.safeParse({ ...review, action: 'update' }).success,
    false,
  )
  assert.equal(
    installerReviewSchema.safeParse({ ...review, canUninstall: true }).success,
    false,
  )
})

test('system review stays pathless and never exposes a directory chooser authority', () => {
  const systemReview = {
    ...review,
    package: { ...packageSummary, scope: 'system' },
    destination: null,
  }
  assert.equal(installerReviewSchema.safeParse(systemReview).success, true)
  assert.equal(
    installerReviewSchema.safeParse({ ...systemReview, destination: review.destination }).success,
    false,
  )
  assert.equal(installerReviewSchema.safeParse({ ...review, destination: null }).success, false)
  assert.equal(
    installerReviewSchema.safeParse({
      ...systemReview,
      action: 'repair',
      installedVersion: '1.0.0',
      canUninstall: true,
    }).success,
    true,
  )
})

test('portable install directory rejects path syntax', () => {
  assert.equal(packageSummarySchema.safeParse(packageSummary).success, true)
  for (const installDirectory of ['../demo', 'demo/app', String.raw`demo\app`, 'demo:ads']) {
    assert.equal(
      packageSummarySchema.safeParse({ ...packageSummary, installDirectory }).success,
      false,
    )
  }
})

test('shortened UNC paths keep the server and share visible', () => {
  const path = String.raw`\\server\trusted-share\products\luxury\current\payload\Luxury Installer`
  const shortened = shortenPath(path)
  assert.equal(shortened.startsWith('\\\\server\\trusted-share\\…\\'), true)
  assert.equal(shortened.endsWith(String.raw`payload\Luxury Installer`), true)
})

test('package license stays bounded plain text', () => {
  assert.equal(
    packageSummarySchema.safeParse({ ...packageSummary, license: 'First line.\nSecond line.' })
      .success,
    true,
  )
  for (const license of [
    '',
    ' \n\t',
    'invalid\0license',
    'invalid\rlicense',
    'hidden\u202etext',
    'x'.repeat(32_769),
  ]) {
    assert.equal(packageSummarySchema.safeParse({ ...packageSummary, license }).success, false)
  }
})

test('authenticated package description stays bounded and reaches Setup review', async () => {
  assert.equal(
    packageSummarySchema.safeParse({ ...packageSummary, description: 'Human-facing app summary.' }).success,
    true,
  )
  assert.equal(packageSummarySchema.safeParse({ ...packageSummary, description: '' }).success, false)
  assert.equal(
    packageSummarySchema.safeParse({ ...packageSummary, description: 'x'.repeat(1025) }).success,
    false,
  )
  assert.equal(
    packageSummarySchema.safeParse({ ...packageSummary, description: '💚'.repeat(1024) }).success,
    true,
  )
  const reviewView = await readFile(
    new URL('../src/renderer/src/features/installer/ReviewView.tsx', import.meta.url),
    'utf8',
  )
  assert.match(reviewView, /summary\.description/)
})

test('install details and finish links stay bounded and safe', () => {
  const enhanced = {
    ...packageSummary,
    files: 3,
    installLog: { files: ['bin/app.exe', 'README.txt'], omittedFiles: 1 },
    finishLinks: [{ label: 'Документация', url: 'https://example.com/docs' }],
  }
  assert.equal(packageSummarySchema.safeParse(enhanced).success, true)
  assert.equal(
    packageSummarySchema.safeParse({
      ...enhanced,
      installLog: { files: ['../escape'], omittedFiles: 2 },
    }).success,
    false,
  )
  assert.equal(
    packageSummarySchema.safeParse({
      ...enhanced,
      finishLinks: [{ label: 'Локальный файл', url: 'file:///etc/passwd' }],
    }).success,
    false,
  )
  assert.equal(
    packageSummarySchema.safeParse({
      ...enhanced,
      installLog: { files: ['bin/app.exe'], omittedFiles: 1 },
    }).success,
    false,
  )
})

test('publisher rotation is bound to the verified signer', () => {
  const signer = 'a'.repeat(64)
  const next = 'b'.repeat(64)
  const rotating = {
    ...packageSummary,
    trust: { kind: 'trustedPublisher', keyId: signer },
    publisherRotation: { signerKeyId: signer, nextKeyId: next },
  }
  assert.equal(packageSummarySchema.safeParse(rotating).success, true)
  assert.equal(
    packageSummarySchema.safeParse({
      ...rotating,
      publisherRotation: { signerKeyId: next, nextKeyId: signer },
    }).success,
    false,
  )
})

test('operation events reject relational counter drift but keep a correlation envelope', () => {
  const progress = {
    kind: 'progress',
    operationId: 'tauri-1-1',
    completedFiles: 2,
    totalFiles: 1,
    completedBytes: 0,
    totalBytes: 0,
  }
  assert.equal(setupEventSchema.safeParse(progress).success, false)
  assert.equal(eventEnvelopeSchema.safeParse(progress).success, true)
  assert.equal(eventEnvelopeSchema.safeParse({ kind: 'progress' }).success, false)

  const completedReview = {
    ...review,
    action: 'repair',
    installedVersion: '1.0.0',
    canUninstall: true,
  }
  const complete = {
    kind: 'complete',
    operationId: 'tauri-1-1',
    action: 'install',
    installedFiles: 1,
    installedBytes: 29,
    review: completedReview,
  }
  assert.equal(setupEventSchema.safeParse(complete).success, true)
  assert.equal(
    setupEventSchema.safeParse({ ...complete, review }).success,
    false,
  )
  assert.equal(
    setupEventSchema.safeParse({
      kind: 'action',
      operationId: 'tauri-1-1',
      action: 'downgrade',
    }).success,
    false,
  )
  assert.equal(
    setupEventSchema.safeParse({
      kind: 'uninstallComplete',
      operationId: 'tauri-1-1',
      removedFiles: Number.MAX_SAFE_INTEGER,
      missingFiles: 1,
      preservedModifiedFiles: 0,
    }).success,
    false,
  )
})

test('Studio paths stay display-only and absolute', () => {
  const project = {
    projectPath: String.raw`C:\projects\demo`,
    formatVersion: 1,
    schemaVersion: 1,
    packageId: 'dev.luxury.demo',
    name: 'Luxury Demo',
    publisher: 'Luxury Software',
    version: '1.0.0',
    description: null,
    license: null,
    hasLicense: false,
    targetOs: 'windows',
    targetArch: 'x86_64',
    installDirectory: 'Luxury Demo',
    scope: 'user',
    allowDowngrade: false,
    entrypoint: null,
    hasEntrypoint: false,
    showInstallLog: false,
    finishLinks: [],
    executableFiles: 0,
    files: 1,
    bytes: 29,
  }
  assert.equal(studioProjectSchema.safeParse(project).success, true)
  assert.equal(projectFrom({ kind: 'refreshing', project }), project)
  assert.equal(
    studioProjectSchema.safeParse({ ...project, packageId: 'dev.foo--bar' }).success,
    true,
  )
  for (const packageId of ['devfoo', 'dev.foo-', 'dev..foo']) {
    assert.equal(studioProjectSchema.safeParse({ ...project, packageId }).success, false)
  }
  assert.equal(studioProjectSchema.safeParse({ ...project, projectPath: 'relative' }).success, false)
  assert.equal(
    studioProjectSchema.safeParse({ ...project, schemaVersion: 2, hasLicense: true }).success,
    false,
  )
  assert.equal(
    studioProjectSchema.safeParse({
      ...project,
      schemaVersion: 3,
      license: 'Terms',
      hasLicense: true,
    }).success,
    true,
  )
})

test('Studio publishes native installers and keeps the internal package format hidden', async () => {
  const [view, shell] = await Promise.all([
    readFile(new URL('../src/renderer/src/StudioApp.tsx', import.meta.url), 'utf8'),
    readFile(new URL('../src-tauri/src/studio.rs', import.meta.url), 'utf8'),
  ])
  assert.equal(view.toLowerCase().includes('luxpkg'), false)
  assert.match(view, /windows: 'Собрать \.exe'/)
  assert.match(view, /linux: 'Собрать \.deb \/ \.rpm'/)
  assert.match(view, /macos: 'Собрать \.dmg'/)
  assert.match(view, /Установщик готов/)
  assert.match(shell, /\.arg\("project-installer"\)/)
  assert.doesNotMatch(shell, /set_file_name\([^)]*luxpkg/i)
})

test('recent projects stay bounded display data and reopen by index only', () => {
  const recent = {
    projectPath: String.raw`C:\projects\demo`,
    name: 'Luxury Demo',
    publisher: 'Luxury Software',
    version: '1.0.0',
    targetOs: 'windows',
    targetArch: 'x86_64',
  }
  assert.equal(recentProjectSchema.safeParse(recent).success, true)
  assert.equal(recentProjectSchema.safeParse({ ...recent, projectPath: 'relative' }).success, false)
  assert.equal(recentProjectIndexSchema.safeParse(5).success, true)
  assert.equal(recentProjectIndexSchema.safeParse(6).success, false)
  assert.equal(recentProjectsSchema.safeParse(Array(6).fill(recent)).success, true)
  assert.equal(recentProjectsSchema.safeParse(Array(7).fill(recent)).success, false)
})

test('renderer invokes only consent and pathless intents', async () => {
  assert.equal(
    installRequestSchema.safeParse({
      allowUnsigned: true,
      acceptLicense: true,
      allowPublisherMigration: false,
    }).success,
    true,
  )
  assert.equal(
    installRequestSchema.safeParse({
      allowUnsigned: true,
      acceptLicense: false,
      packagePath: 'payload',
    }).success,
    false,
  )
  const bridge = await readFile(
    new URL('../src/renderer/src/tauri-bridge.ts', import.meta.url),
    'utf8',
  )
  for (const forbidden of ['packagePath', 'expectedFingerprint', 'stateRoot', 'installBase']) {
    assert.equal(bridge.includes(forbidden), false)
  }
  assert.match(bridge, /reloadProject: \(\) => parsedInvoke\('reload_project', studioProjectSchema\)/)
  assert.match(
    bridge,
    /importProjectFiles: \(\) => parsedInvoke\('import_project_files', studioProjectSchema\.nullable\(\)\)/,
  )
  assert.match(
    bridge,
    /importProjectDirectory: \(\) =>[\s\S]*?\{ replace: false \}/,
  )
  assert.match(
    bridge,
    /replaceProjectPayload: \(\) =>[\s\S]*?\{ replace: true \}/,
  )
  assert.match(
    bridge,
    /parsedInvoke\('choose_project_entrypoint', portablePath\.nullable\(\)\)/,
  )
  assert.match(bridge, /revealProject: \(\) => invokeCommand\('reveal_project'\)/)
  assert.match(bridge, /revealBuildOutput: \(\) => invokeCommand\('reveal_build_output'\)/)
  assert.match(bridge, /parsedInvoke\('open_recent_project', studioProjectSchema, \{[\s\S]*?index:/)
  assert.match(bridge, /openFinishLink: \(index\) => invokeCommand\('open_finish_link', \{ index \}\)/)
  assert.equal(bridge.includes('{ url'), false)
})

test('production renderer needs no inline script or style capability', async () => {
  const config = JSON.parse(
    await readFile(new URL('../src-tauri/tauri.conf.json', import.meta.url), 'utf8'),
  )
  assert.equal(config.app.security.csp.includes("'unsafe-inline'"), false)
  const progress = await readFile(
    new URL('../src/renderer/src/features/installer/ProgressView.tsx', import.meta.url),
    'utf8',
  )
  assert.equal(progress.includes('style={{'), false)
  assert.match(progress, /<progress/)
  assert.match(
    progress,
    /const installPhaseOrder:[\s\S]*?'validating',\s*'verifying',\s*'recovering'/,
  )
  assert.match(progress, /key: 'recovering',[\s\S]*?label: 'Проверка состояния'/)
})

test('desktop window is DPI-fitted, fixed, and has no maximize authority', async () => {
  const [configText, shell, chrome, bridge, types, capabilities, build] = await Promise.all([
    readFile(new URL('../src-tauri/tauri.conf.json', import.meta.url), 'utf8'),
    readFile(new URL('../src-tauri/src/lib.rs', import.meta.url), 'utf8'),
    readFile(new URL('../src/renderer/src/components/WindowChrome.tsx', import.meta.url), 'utf8'),
    readFile(new URL('../src/renderer/src/tauri-bridge.ts', import.meta.url), 'utf8'),
    readFile(new URL('../src/renderer/src/types.ts', import.meta.url), 'utf8'),
    readFile(new URL('../src-tauri/capabilities/main.json', import.meta.url), 'utf8'),
    readFile(new URL('../src-tauri/build.rs', import.meta.url), 'utf8'),
  ])
  const window = JSON.parse(configText).app.windows[0]
  assert.equal(window.resizable, false)
  assert.equal(window.maximizable, false)
  assert.equal('minWidth' in window, false)
  assert.equal('minHeight' in window, false)
  assert.match(shell, /fixed_window_size/)
  assert.match(shell, /work_area\(\)/)
  for (const source of [chrome, bridge, types, capabilities, build]) {
    assert.equal(source.includes('toggleMaximize'), false)
    assert.equal(source.includes('toggle_maximize'), false)
    assert.equal(source.includes('toggle-maximize'), false)
  }
})

test('completion screen separates optional links from primary completion actions', async () => {
  const [result, styles] = await Promise.all([
    readFile(new URL('../src/renderer/src/features/installer/ResultView.tsx', import.meta.url), 'utf8'),
    readFile(new URL('../src/renderer/src/styles.css', import.meta.url), 'utf8'),
  ])
  assert.match(result, /className="result-links"/)
  assert.match(result, /className="result-actions result-actions--complete"/)
  assert.match(result, /className="primary-button"[\s\S]*?'Закрываем…' : 'Готово'/)
  assert.match(styles, /\.result-links\s*\{[\s\S]*?grid-template-columns:/)
})

test('renderer keeps flat square Codex geometry', async () => {
  const [styles, emptyView] = await Promise.all([
    readFile(new URL('../src/renderer/src/styles.css', import.meta.url), 'utf8'),
    readFile(
      new URL('../src/renderer/src/features/installer/EmptyView.tsx', import.meta.url),
      'utf8',
    ),
  ])
  assert.doesNotMatch(styles, /(?:linear|radial|conic)-gradient|backdrop-filter/)
  assert.equal(emptyView.includes('empty-screen__ring'), false)
  const radii = [...styles.matchAll(/border-radius:\s*([^;]+);/g)].map((match) => match[1].trim())
  assert.ok(radii.length > 0)
  assert.deepEqual([...new Set(radii)], ['0'])
})
