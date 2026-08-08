import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import {
  buildCancellationResultSchema,
  eventEnvelopeSchema,
  installRequestSchema,
  installerReviewSchema,
  packageSummarySchema,
  recentProjectIndexSchema,
  recentProjectSchema,
  recentProjectsSchema,
  setupEventSchema,
  studioCloseQuerySchema,
  studioHostSchema,
  studioProjectSchema,
} from '../src/renderer/src/bridge-contracts.ts'
import { projectFrom } from '../src/renderer/src/use-studio.ts'
import { formatElapsedTime, shortenPath } from '../src/renderer/src/features/installer/format.ts'

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
  shortcuts: { applicationMenu: false, desktop: false },
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

test('opt-in install details remain expandable while installation is running', async () => {
  const [setup, progress] = await Promise.all([
    readFile(new URL('../src/renderer/src/SetupApp.tsx', import.meta.url), 'utf8'),
    readFile(
      new URL('../src/renderer/src/features/installer/ProgressView.tsx', import.meta.url),
      'utf8',
    ),
  ])
  const runningInstall = setup.match(
    /view\.kind === 'running' && view\.operation === 'install' && summary \? \(\s*<ProgressView([\s\S]*?)\/>/,
  )
  assert.ok(runningInstall)
  assert.match(runningInstall[1], /installLog=\{summary\.installLog\}/)
  assert.match(runningInstall[1], /destination=\{destination\}/)
  assert.match(progress, /\{installLog \? \([\s\S]*?<InstallDetails/)
  assert.doesNotMatch(progress, /finished && installLog/)
  assert.match(progress, /finished \? 'Детали установки' : 'Что устанавливается'/)
})

test('Setup cancellation transport errors stay inline and retryable', async () => {
  const [app, controller, progress] = await Promise.all([
    readFile(new URL('../src/renderer/src/SetupApp.tsx', import.meta.url), 'utf8'),
    readFile(new URL('../src/renderer/src/use-installer.ts', import.meta.url), 'utf8'),
    readFile(
      new URL('../src/renderer/src/features/installer/ProgressView.tsx', import.meta.url),
      'utf8',
    ),
  ])
  assert.equal([...app.matchAll(/cancellationError=\{view\.cancellationError\}/g)].length, 2)
  assert.match(
    controller,
    /catch \(error\) \{[\s\S]*?cancelPending\.current = false[\s\S]*?cancellationRequested: false,[\s\S]*?cancellationError: errorMessage\(error\)/,
  )
  assert.match(
    controller,
    /cancellationRequested: true, cancellationError: null/,
  )
  assert.match(progress, /props\.cancellationError \?[\s\S]*?role="alert"/)
  assert.match(progress, /rollingBack \? 'Отменяем…' : 'Отменить'/)
  assert.doesNotMatch(progress, /cancellationError[^\n]*cancellationDisabled/)
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
  assert.equal(setupEventSchema.safeParse({ ...complete, review: null }).success, true)
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
      review: null,
    }).success,
    false,
  )
  assert.equal(
    setupEventSchema.safeParse({
      kind: 'uninstallComplete',
      operationId: 'tauri-1-1',
      removedFiles: 1,
      missingFiles: 0,
      preservedModifiedFiles: 0,
      review: null,
    }).success,
    true,
  )
  const systemReview = {
    ...review,
    package: { ...packageSummary, scope: 'system' },
    destination: null,
  }
  assert.equal(
    setupEventSchema.safeParse({
      kind: 'uninstallComplete',
      operationId: 'tauri-1-1',
      removedFiles: 1,
      missingFiles: 0,
      preservedModifiedFiles: 0,
      review: systemReview,
    }).success,
    true,
  )
  assert.equal(
    setupEventSchema.safeParse({
      kind: 'uninstallComplete',
      operationId: 'tauri-1-1',
      removedFiles: 1,
      missingFiles: 0,
      preservedModifiedFiles: 0,
      review: {
        ...systemReview,
        action: 'repair',
        installedVersion: '1.0.0',
        canUninstall: true,
      },
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
    shortcuts: { applicationMenu: false, desktop: false },
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
  const shortcutProject = {
    ...project,
    schemaVersion: 4,
    entrypoint: 'bin/app.exe',
    hasEntrypoint: true,
    shortcuts: { applicationMenu: true, desktop: true },
  }
  assert.equal(studioProjectSchema.safeParse(shortcutProject).success, true)
  assert.equal(
    studioProjectSchema.safeParse({ ...shortcutProject, schemaVersion: 3 }).success,
    false,
  )
  assert.equal(
    studioProjectSchema.safeParse({ ...shortcutProject, entrypoint: null, hasEntrypoint: false }).success,
    false,
  )
})

test('shortcut intent is strict and visible in Studio and Setup', async () => {
  const shortcutSummary = {
    ...packageSummary,
    shortcuts: { applicationMenu: true, desktop: false },
  }
  assert.equal(packageSummarySchema.safeParse(shortcutSummary).success, true)
  assert.equal(
    packageSummarySchema.safeParse({
      ...shortcutSummary,
      hasEntrypoint: false,
    }).success,
    false,
  )
  assert.equal(
    packageSummarySchema.safeParse({
      ...shortcutSummary,
      shortcuts: { applicationMenu: true, desktop: false, target: 'other.exe' },
    }).success,
    false,
  )
  const [studio, setup] = await Promise.all([
    readFile(new URL('../src/renderer/src/StudioApp.tsx', import.meta.url), 'utf8'),
    readFile(new URL('../src/renderer/src/features/installer/ReviewView.tsx', import.meta.url), 'utf8'),
  ])
  assert.match(studio, /shortcuts\.applicationMenu/)
  assert.match(studio, /shortcuts\.desktop/)
  assert.match(studio, /Нативное создание ярлыков войдёт в следующий срез/)
  assert.match(setup, /summary\.shortcuts\.applicationMenu/)
  assert.match(setup, /summary\.shortcuts\.desktop/)
})

test('Studio publishes native installers from one parent-owned work directory', async () => {
  const [view, shell, staging] = await Promise.all([
    readFile(new URL('../src/renderer/src/StudioApp.tsx', import.meta.url), 'utf8'),
    readFile(new URL('../src-tauri/src/studio.rs', import.meta.url), 'utf8'),
    readFile(new URL('../../../xtask/src/runner/staging.rs', import.meta.url), 'utf8'),
  ])
  assert.equal(view.toLowerCase().includes('luxpkg'), false)
  assert.match(view, /windows: 'Собрать \.exe'/)
  assert.match(view, /linux: 'Собрать \.deb \/ \.rpm'/)
  assert.match(view, /macos: 'Собрать \.dmg'/)
  assert.match(view, /Установщик готов/)
  assert.match(shell, /\.arg\("__managed-project-installer"\)/)
  assert.match(shell, /\.prefix\("\.luxury-studio-build-"\)/)
  assert.match(shell, /\.tempdir_in\(output_parent\)/)
  assert.match(shell, /finish_managed_native_build\(result, work\)/)
  assert.match(staging, /canonical_path\.parent\(\) != Some\(canonical_parent\.as_path\(\)\)/)
  assert.match(staging, /managed Studio assembly directory is not empty/)
  assert.doesNotMatch(shell, /set_file_name\([^)]*luxpkg/i)
})

test('Studio native build has one pathless race-free cancellation action', async () => {
  const [view, controller, bridge, shell, app, capability, build] = await Promise.all([
    readFile(new URL('../src/renderer/src/StudioApp.tsx', import.meta.url), 'utf8'),
    readFile(new URL('../src/renderer/src/use-studio.ts', import.meta.url), 'utf8'),
    readFile(new URL('../src/renderer/src/tauri-bridge.ts', import.meta.url), 'utf8'),
    readFile(new URL('../src-tauri/src/studio.rs', import.meta.url), 'utf8'),
    readFile(new URL('../src-tauri/src/lib.rs', import.meta.url), 'utf8'),
    readFile(new URL('../src-tauri/capabilities/main.json', import.meta.url), 'utf8'),
    readFile(new URL('../src-tauri/build.rs', import.meta.url), 'utf8'),
  ])
  assert.equal(buildCancellationResultSchema.safeParse({ accepted: true }).success, true)
  assert.equal(buildCancellationResultSchema.safeParse({ accepted: true, path: 'x' }).success, false)
  assert.match(view, /onClick=\{onCancelBuild\}/)
  assert.match(view, /state\.cancellationRequested \? 'Отменяем…' : 'Отменить'/)
  assert.match(controller, /errorCode\(error\) === 'project_build_cancelled'/)
  assert.match(bridge, /parsedInvoke\('cancel_project_build', buildCancellationResultSchema\)/)
  assert.match(shell, /const BUILD_IDLE: u8 = 0;[\s\S]*?const BUILD_ACTIVE: u8 = 1;[\s\S]*?const BUILD_CANCELLED: u8 = 2;/)
  assert.match(shell, /let _active = state[\s\S]{0,160}?\.build[\s\S]{0,80}?\.start\(\)[\s\S]*?spawn_blocking/)
  assert.match(app, /studio::cancel_project_build/)
  assert.match(capability, /allow-cancel-project-build/)
  assert.match(build, /"cancel_project_build"/)
  assert.doesNotMatch(bridge, /cancel_project_build[^\n]*\{[^\n]*(path|project|output)/i)
})

test('Studio build elapsed time is monotonic, bounded, and silent to live regions', async () => {
  assert.equal(formatElapsedTime(-1), '0:00')
  assert.equal(formatElapsedTime(65.9), '1:05')
  assert.equal(formatElapsedTime(3661), '1:01:01')
  assert.equal(formatElapsedTime(Number.POSITIVE_INFINITY), '0:00')
  const [view, styles] = await Promise.all([
    readFile(new URL('../src/renderer/src/StudioApp.tsx', import.meta.url), 'utf8'),
    readFile(new URL('../src/renderer/src/styles.css', import.meta.url), 'utf8'),
  ])
  assert.match(view, /const started = performance\.now\(\)/)
  assert.match(view, /return \(\) => window\.clearInterval\(timer\)/)
  assert.match(view, /className="studio-build-progress__elapsed"[\s\S]*?aria-hidden="true"/)
  assert.match(styles, /\.studio-build-progress__elapsed\s*\{[\s\S]*?font-variant-numeric: tabular-nums;/)
})

test('Studio saves a valid dirty draft before starting the native build', async () => {
  const [view, controller] = await Promise.all([
    readFile(new URL('../src/renderer/src/StudioApp.tsx', import.meta.url), 'utf8'),
    readFile(new URL('../src/renderer/src/use-studio.ts', import.meta.url), 'utf8'),
  ])
  assert.match(view, /disabled=\{busy \|\| !buildable \|\| !hostCompatible\}/)
  assert.doesNotMatch(view, /disabled=\{busy \|\| !buildable \|\| dirty\}/)
  assert.match(view, /form\?\.reportValidity\(\)/)
  assert.match(view, /onBuild\(dirty \? draft : undefined\)/)
  assert.match(view, /Сохранить и \$\{nativeBuildLabel\(draft\.targetOs\)\.toLowerCase\(\)\}/)
  assert.match(controller, /async function buildProject\(input\?: StudioProjectUpdate\)/)
  assert.match(
    controller,
    /if \(input\) \{[\s\S]*?await bridge\.updateProject\(input\)[\s\S]*?kind: 'building'[\s\S]*?await bridge\.buildProject\(\)/,
  )
  assert.match(controller, /buildStarted && errorCode\(error\) === 'project_build_cancelled'/)
})

test('Studio blocks destructive draft actions and Rust owns close confirmation', async () => {
  assert.equal(studioCloseQuerySchema.safeParse({ requestId: 'studio-close-1' }).success, true)
  assert.equal(
    studioCloseQuerySchema.safeParse({ requestId: 'studio-close-1', dirty: false }).success,
    false,
  )
  const [view, chrome, bridge, shell, app, capability, build] = await Promise.all([
    readFile(new URL('../src/renderer/src/StudioApp.tsx', import.meta.url), 'utf8'),
    readFile(new URL('../src/renderer/src/components/WindowChrome.tsx', import.meta.url), 'utf8'),
    readFile(new URL('../src/renderer/src/tauri-bridge.ts', import.meta.url), 'utf8'),
    readFile(new URL('../src-tauri/src/studio.rs', import.meta.url), 'utf8'),
    readFile(new URL('../src-tauri/src/lib.rs', import.meta.url), 'utf8'),
    readFile(new URL('../src-tauri/capabilities/main.json', import.meta.url), 'utf8'),
    readFile(new URL('../src-tauri/build.rs', import.meta.url), 'utf8'),
  ])
  assert.equal([...view.matchAll(/disabled=\{busy \|\| draftDirty\}/g)].length, 3)
  assert.match(view, /bridge\.setStudioDraftDirty\(dirty\)/)
  assert.match(view, /useLayoutEffect\(\(\) => \{[\s\S]*?onDirtyChange\(dirty\)/)
  assert.match(view, /onClick=\{\(\) => setDraft\(baseline\)\}[\s\S]*?Отменить изменения/)
  assert.match(bridge, /listen<unknown>\(STUDIO_CLOSE_QUERY_EVENT/)
  assert.match(bridge, /requestId: parsed\.data\.requestId,[\s\S]*?dirty: studioDraftDirty/)
  assert.match(shell, /fn close_query_dirty\([\s\S]*?!emitted \|\| response\.unwrap_or\(true\)/)
  assert.match(shell, /recv_timeout\(STUDIO_CLOSE_QUERY_TIMEOUT\)/)
  assert.match(shell, /MessageDialogButtons::OkCancelCustom\([\s\S]*?Закрыть без сохранения/)
  assert.match(app, /studio::respond_studio_close/)
  assert.match(
    app,
    /studio::confirm_close\(&shutdown_window, &shutdown_state\)[\s\S]*?studio::shutdown\(&shutdown_state\)/,
  )
  assert.match(
    app,
    /if !close \{[\s\S]*?close_ready[\s\S]*?store\(false,[\s\S]*?close_started[\s\S]*?store\(false,[\s\S]*?return Ok\(\(\)\)/,
  )
  assert.match(capability, /allow-respond-studio-close/)
  assert.equal(
    JSON.parse(capability).permissions.some((permission) =>
      /^(?:dialog|fs|opener|process|shell):/.test(permission),
    ),
    false,
  )
  assert.match(build, /"respond_studio_close"/)
  assert.match(
    chrome,
    /await bridge\.closeWindow\(\)[\s\S]*?finally \{[\s\S]*?closingRef\.current = false/,
  )
})

test('Studio uses the Rust-owned host target before offering a native build', async () => {
  assert.equal(studioHostSchema.safeParse({ os: 'windows', arch: 'x86_64' }).success, true)
  assert.equal(
    studioHostSchema.safeParse({ os: 'windows', arch: 'x86_64', path: 'C:\\host' }).success,
    false,
  )
  const [view, controller, bridge, shell, app, capability, build] = await Promise.all([
    readFile(new URL('../src/renderer/src/StudioApp.tsx', import.meta.url), 'utf8'),
    readFile(new URL('../src/renderer/src/use-studio.ts', import.meta.url), 'utf8'),
    readFile(new URL('../src/renderer/src/tauri-bridge.ts', import.meta.url), 'utf8'),
    readFile(new URL('../src-tauri/src/studio.rs', import.meta.url), 'utf8'),
    readFile(new URL('../src-tauri/src/lib.rs', import.meta.url), 'utf8'),
    readFile(new URL('../src-tauri/capabilities/main.json', import.meta.url), 'utf8'),
    readFile(new URL('../src-tauri/build.rs', import.meta.url), 'utf8'),
  ])
  assert.match(view, /disabled=\{busy \|\| !buildable \|\| !hostCompatible\}/)
  assert.match(view, /Native project build в GitHub Actions/)
  assert.doesNotMatch(view, /navigator\.(?:platform|userAgent)/)
  assert.match(controller, /bridge\s*\.getStudioHost\(\)/)
  assert.match(bridge, /getStudioHost: \(\) => parsedInvoke\('get_studio_host', studioHostSchema\)/)
  assert.doesNotMatch(bridge, /get_studio_host[^\n]*\{/)
  assert.match(shell, /fn get_studio_host[\s\S]*?spawn_blocking[\s\S]*?state\.defaults\(\)\?\.target/)
  assert.match(app, /studio::get_studio_host/)
  assert.match(capability, /allow-get-studio-host/)
  assert.match(build, /"get_studio_host"/)
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

test('completion launch failure stays inline and close failure cannot relaunch the app', async () => {
  const [app, controller, result] = await Promise.all([
    readFile(new URL('../src/renderer/src/SetupApp.tsx', import.meta.url), 'utf8'),
    readFile(new URL('../src/renderer/src/use-installer.ts', import.meta.url), 'utf8'),
    readFile(new URL('../src/renderer/src/features/installer/ResultView.tsx', import.meta.url), 'utf8'),
  ])
  assert.match(app, /'launch' \| 'reveal' \| 'close' \| number \| null/)
  assert.match(
    app,
    /await installer\.bridge\.launchInstalled\(\)[\s\S]*?setLaunchSucceeded\(true\)[\s\S]*?await installer\.bridge\.closeWindow\(\)/,
  )
  assert.match(app, /canLaunch=\{summary\.hasEntrypoint && !launchSucceeded\}/)
  assert.match(result, /actionPending === 'launch'/)
  assert.doesNotMatch(result, /launchPending/)
  assert.doesNotMatch(controller, /launchPending|const launchInstalled/)
})

test('system completion reveal is pathless and derives fixed roots in Rust', async () => {
  const [app, bridge, shell, roots] = await Promise.all([
    readFile(new URL('../src/renderer/src/SetupApp.tsx', import.meta.url), 'utf8'),
    readFile(new URL('../src/renderer/src/tauri-bridge.ts', import.meta.url), 'utf8'),
    readFile(new URL('../src-tauri/src/setup.rs', import.meta.url), 'utf8'),
    readFile(new URL('../../../crates/luxury-system-roots/src/lib.rs', import.meta.url), 'utf8'),
  ])
  assert.match(app, /canReveal\s*\n/)
  assert.doesNotMatch(app, /canReveal=\{summary\.scope === 'user'\}/)
  assert.match(bridge, /revealInstalled: \(\) => invokeCommand\('reveal_installed'\)/)
  assert.match(shell, /let _starting = acquire_idle\(state\.inner\(\), &context\)\?;[\s\S]*?installed_reveal_path\(&context\)\?/)
  assert.match(shell, /let \(install_base, _\) = luxury_system_roots::get\(\)/)
  assert.match(shell, /if !context\.install_completed\.load\(Ordering::Acquire\)/)
  assert.match(roots, /PathBuf::from\("\/opt\/luxury-installer\/apps"\)/)
  assert.match(roots, /PathBuf::from\("\/Applications"\)/)
  assert.doesNotMatch(app, /systemInstallBase|installPath/)
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
