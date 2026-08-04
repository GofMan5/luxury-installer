Unicode true
Name "Luxury Installer"
OutFile "container-output\LuxuryInstallerSetup.dev.exe"

RequestExecutionLevel user
SilentInstall silent
AutoCloseWindow true
CRCCheck force
; ponytail: non-solid zlib keeps the unsigned development gate fast; tune only for signed releases.
SetCompressor zlib
ManifestDPIAware true
ManifestLongPathAware true

!include "FileFunc.nsh"

Var ChildExitCode
Var CleanupAttempts
Var Parameters

Section
  ${GetParameters} $Parameters
  StrCmp $Parameters "" extract
  StrCmp $Parameters "--verify-runner" extract
  StrCmp $Parameters "--verify-authenticated-transport" extract

extract:
  InitPluginsDir
  SetOutPath "$PLUGINSDIR\app"
  File /r "runner\*.*"

  ClearErrors
  StrCmp $Parameters "--verify-runner" verify
  StrCmp $Parameters "--verify-authenticated-transport" verify_authenticated
  StrCmp $Parameters "" normal normal_with_parameters

verify:
  ExecWait '"$PLUGINSDIR\app\Luxury Installer.exe" --verify-runner' $ChildExitCode
  Goto child_finished

verify_authenticated:
  ExecWait '"$PLUGINSDIR\app\Luxury Installer.exe" --verify-runner --verify-authenticated-transport --verify-container-parent' $ChildExitCode
  Goto child_finished

normal:
  ExecWait '"$PLUGINSDIR\app\Luxury Installer.exe"' $ChildExitCode
  Goto child_finished

normal_with_parameters:
  ExecWait '"$PLUGINSDIR\app\Luxury Installer.exe" $Parameters' $ChildExitCode

child_finished:
  IfErrors child_failed
  Goto cleanup

child_failed:
  StrCpy $ChildExitCode 70

cleanup:
  SetOutPath "$TEMP"
  StrCpy $CleanupAttempts 0

cleanup_retry:
  ClearErrors
  RMDir /r "$PLUGINSDIR\app"
  IfErrors cleanup_wait cleanup_done

cleanup_wait:
  IntOp $CleanupAttempts $CleanupAttempts + 1
  IntCmp $CleanupAttempts 20 cleanup_failed cleanup_retry_delay cleanup_failed

cleanup_retry_delay:
  Sleep 100
  Goto cleanup_retry

cleanup_done:
  SetErrorLevel $ChildExitCode
  Quit

cleanup_failed:
  SetErrorLevel 74
SectionEnd
