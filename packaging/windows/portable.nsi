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
Var InheritHandles
Var Parameters
Var StartupFlags

Function RunChild
  StrCpy $9 '"$PLUGINSDIR\app\Luxury Installer.exe" $Parameters'
  System::Call 'kernel32::GetStdHandle(i -10)p.r0'
  System::Call 'kernel32::GetStdHandle(i -11)p.r1'
  System::Call 'kernel32::GetStdHandle(i -12)p.r2'

  StrCpy $StartupFlags 0
  StrCpy $InheritHandles 0
  StrCmp $1 "0" no_standard_streams
  StrCmp $1 "-1" no_standard_streams
  StrCmp $2 "0" no_standard_streams
  StrCmp $2 "-1" no_standard_streams
  StrCmp $0 "0" use_output_as_input
  StrCmp $0 "-1" use_output_as_input streams_ready

use_output_as_input:
  StrCpy $0 $1

streams_ready:
  StrCpy $StartupFlags 256
  StrCpy $InheritHandles 1

no_standard_streams:
  ; NSIS is a 32-bit process: STARTUPINFOW is 68 bytes and PROCESS_INFORMATION is 16.
  System::Call '*(i 68, p 0, p 0, p 0, i 0, i 0, i 0, i 0, i 0, i 0, i 0, i $StartupFlags, &i2 0, &i2 0, p 0, p r0, p r1, p r2)p.r3'
  System::Call '*(p 0, p 0, i 0, i 0)p.r4'
  ClearErrors
  System::Call 'kernel32::CreateProcessW(p 0, w r9, p 0, p 0, i $InheritHandles, i 0, p 0, p 0, p r3, p r4)i.r5'
  StrCmp $5 "0" launch_failed
  System::Call '*$4(p .r6, p .r7)'
  System::Call 'kernel32::CloseHandle(p r7)'
  System::Call 'kernel32::WaitForSingleObject(p r6, i -1)i.r8'
  IntCmp $8 0 child_exited wait_failed wait_failed

child_exited:
  System::Call 'kernel32::GetExitCodeProcess(p r6, *i .r0)i.r5'
  StrCmp $5 "0" wait_failed
  StrCpy $ChildExitCode $0
  System::Call 'kernel32::CloseHandle(p r6)'
  System::Free $4
  System::Free $3
  ClearErrors
  Return

wait_failed:
  System::Call 'kernel32::CloseHandle(p r6)'

launch_failed:
  System::Free $4
  System::Free $3
  SetErrors
FunctionEnd

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
  StrCpy $Parameters "--verify-runner"
  Call RunChild
  Goto child_finished

verify_authenticated:
  StrCpy $Parameters "--verify-runner --verify-authenticated-transport --verify-container-parent"
  Call RunChild
  Goto child_finished

normal:
  StrCpy $Parameters ""
  Call RunChild
  Goto child_finished

normal_with_parameters:
  Call RunChild

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
