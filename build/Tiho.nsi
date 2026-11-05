Unicode true
!include "MUI2.nsh"
!include "x64.nsh"
!include "WinVer.nsh"

Name "Tiho"
OutFile "..\output\Tiho-Setup.exe"
InstallDir "$PROGRAMFILES64\Tiho"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
!define MUI_ICON "..\Tiho\Assets\app.ico"
!define MUI_UNICON "..\Tiho\Assets\app.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\Tiho.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Запустить Tiho"
!define MUI_FINISHPAGE_LINK "Исходный код компонентов и лицензии"
!define MUI_FINISHPAGE_LINK_LOCATION "$INSTDIR\THIRD-PARTY-NOTICES.txt"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Russian"

VIProductVersion "2.1.1.0"
VIAddVersionKey /LANG=1049 "ProductName" "Tiho"
VIAddVersionKey /LANG=1049 "FileDescription" "Установка Tiho"
VIAddVersionKey /LANG=1049 "FileVersion" "2.1.1"
VIAddVersionKey /LANG=1049 "LegalCopyright" "Tiho"

Function .onInit
  ${IfNot} ${AtLeastWin10}
    MessageBox MB_OK|MB_ICONSTOP "Tiho требует Windows 10 или Windows 11."
    Abort
  ${EndIf}
  ${IfNot} ${RunningX64}
    StrCpy $INSTDIR "$PROGRAMFILES\Tiho"
  ${EndIf}
FunctionEnd

Section "Tiho" SEC_MAIN
  SetShellVarContext all
  IfFileExists "$INSTDIR\Tiho.exe" 0 +3
    ExecWait '"$INSTDIR\Tiho.exe" --quit'
    nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -Command "Get-Process -Name Tiho -ErrorAction SilentlyContinue | Wait-Process -Timeout 20 -ErrorAction SilentlyContinue"'
  SetOutPath "$INSTDIR"
  ${If} ${IsNativeARM64}
    File /r "..\dist\win-arm64\*"
  ${ElseIf} ${RunningX64}
    File /r "..\dist\win-x64\*"
  ${Else}
    File /r "..\dist\win-x86\*"
  ${EndIf}
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\Tiho"
  CreateShortcut "$SMPROGRAMS\Tiho\Tiho.lnk" "$INSTDIR\Tiho.exe"
  CreateShortcut "$DESKTOP\Tiho.lnk" "$INSTDIR\Tiho.exe"
  ${If} ${RunningX64}
    SetRegView 64
  ${Else}
    SetRegView 32
  ${EndIf}
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Tiho" "DisplayName" "Tiho"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Tiho" "DisplayVersion" "2.1.1"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Tiho" "DisplayIcon" "$INSTDIR\Tiho.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Tiho" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Tiho" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Tiho" "NoRepair" 1
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  ExecWait '"$INSTDIR\Tiho.exe" --quit'
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -Command "Get-Process -Name Tiho -ErrorAction SilentlyContinue | Wait-Process -Timeout 20 -ErrorAction SilentlyContinue"'
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -Command "Get-ScheduledTask -TaskName $\"Tiho-*$\" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$$false"'
  Delete "$DESKTOP\Tiho.lnk"
  RMDir /r "$SMPROGRAMS\Tiho"
  ${If} ${RunningX64}
    SetRegView 64
  ${Else}
    SetRegView 32
  ${EndIf}
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Tiho"
  RMDir /r "$INSTDIR"
SectionEnd
