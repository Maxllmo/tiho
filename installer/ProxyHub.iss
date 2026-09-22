#define MyAppName "Proxy Hub"
#define MyAppVersion "1.1.0"
#define MyAppExeName "ProxyHub.exe"

[Setup]
AppId={{A7E3C1B4-9F2D-4A61-8C5E-1B6D0F4E2A90}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=Proxy Hub
DefaultDirName={localappdata}\Programs\ProxyHub
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=..
OutputBaseFilename=ProxyHub-Setup
SetupIconFile=..\ProxyHub\Assets\app.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
RestartApplications=no
AppMutex=ProxyHub.SingleInstance

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; GroupDescription: "Дополнительно:"

[Files]
Source: "..\dist\publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Запустить Proxy Hub"; Flags: nowait postinstall skipifsilent
