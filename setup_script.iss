; =============================================================================
; netwatch_setup.iss — NetWatch Agent Visual Installer
; =============================================================================

#define MyAppName      "NetWatch Agent"
#define MyAppVersion   "4.0"
#define MyAppPublisher "NetWatch"
#define MyAppExeName   "netwatch_agent.exe"

[Setup]
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}

; Default install location (puts it in standard Program Files or AppData)
DefaultDirName={autopf}\{#MyAppName}

; Start Menu folder name
DefaultGroupName={#MyAppName}

; Output
OutputDir=dist
OutputBaseFilename=NetWatchSetup-v{#MyAppVersion}

; Compression
Compression=lzma2/ultra64
SolidCompression=yes

; Wizard style (modern = the clean wizard with left sidebar)
WizardStyle=modern

; Per-user install = no UAC prompt needed.
PrivilegesRequired=lowest

; Uninstaller
UninstallDisplayName={#MyAppName}

; Minimum OS
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; ---  REQUIRED: Main agent binary with EXACT PATH  ---
Source: "C:\Users\tejas\Documents\Network Anomaly\dist\netwatch_agent.exe";    DestDir: "{app}";    Flags: ignoreversion

[Icons]
; Start Menu shortcut
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Comment: "NetWatch network monitoring agent"

; Start Menu uninstall shortcut
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"

; Desktop shortcut
Name: "{userdesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Comment: "Open NetWatch Agent"

[Run]
; ---  Launch agent after install (the GUI will appear)  ---
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName} now"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Kill any running instance before uninstalling files
Filename: "{cmd}"; Parameters: "/C taskkill /F /IM {#MyAppExeName}"; Flags: runhidden

[Messages]
; Custom Welcome page text explaining the UI to the client:
WelcomeLabel1=Welcome to {#MyAppName} Setup
WelcomeLabel2=This will install {#MyAppName} {#MyAppVersion} on your computer.%n%nNetWatch monitors your network activity and securely reports it to your operator for anomaly detection. You are always in control: you can start or stop monitoring at any time using the Start/Stop button in the application dashboard.%n%nClick Next to continue.