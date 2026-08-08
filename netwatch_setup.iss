; =============================================================================
; netwatch_setup.iss — NetWatch Agent Visual Installer
; =============================================================================
;
; PREREQUISITES — place these files in the same folder as this .iss:
;   netwatch_agent.exe        <- compiled by PyInstaller  (required)
;   assets\nw_icon.ico        <- optional: your app icon
;
; OPTIONAL BUNDLES (Snort + Npcap) — clearly marked below.
; Those sections are fully written; just uncomment when ready.
;
; BUILD:
;   1. Install Inno Setup from https://jrsoftware.org/isdl.php
;   2. Open this file in Inno Setup Compiler
;   3. Press F9  (Build -> Compile)
;   4. Output: dist\NetWatchSetup.exe
; =============================================================================

#define MyAppName      "NetWatch Agent"
#define MyAppVersion   "4.0"
#define MyAppPublisher "NetWatch"
#define MyAppExeName   "netwatch_agent.exe"

[Setup]
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}

; Default install location
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

; Optional: set this to your .ico path if you have one
; SetupIconFile=assets\nw_icon.ico

; Per-user install = no UAC prompt needed.
; Change to 'admin' if you want to install for ALL users (requires UAC).
PrivilegesRequired=lowest

; Uninstaller
UninstallDisplayName={#MyAppName}

; Minimum OS
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; ---  REQUIRED: Main agent binary  ---
Source: "dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
; ---  REQUIRED: Server connection settings  ---
Source: "agent_config.json";  DestDir: "{app}";    Flags: ignoreversion

; ---  OPTIONAL: Npcap (uncomment when bundling)  ---
; Download from https://npcap.com/#download
; Source: "npcap-setup.exe";   DestDir: "{tmp}";   Flags: deleteafterinstall

; ---  OPTIONAL: Snort IDS (uncomment when bundling)  ---
; Download from https://www.snort.org/downloads
; Source: "snort-setup.exe";   DestDir: "{tmp}";   Flags: deleteafterinstall

[Icons]
; Start Menu shortcut
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Comment: "NetWatch network monitoring agent"

; Start Menu uninstall shortcut
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"

; Desktop shortcut
Name: "{userdesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Comment: "Open NetWatch Agent"

[Run]
; ---  OPTIONAL: Install Npcap silently (uncomment with [Files] entry above)  ---
; Filename: "{tmp}\npcap-setup.exe";
;   Parameters: "/S";
;   StatusMsg: "Installing Npcap packet capture driver...";
;   Flags: waitprogramterminate

; ---  OPTIONAL: Install Snort silently (uncomment with [Files] entry above)  ---
; Filename: "{tmp}\snort-setup.exe";
;   Parameters: "/S";
;   StatusMsg: "Installing Snort IDS...";
;   Flags: waitprogramterminate

; ---  OPTIONAL: Create Snort log directory after Snort installs  ---
; Filename: "{cmd}";
;   Parameters: "/C mkdir ""C:\Snort\log""";
;   Flags: runhidden waitprogramterminate

; ---  Launch agent after install (the GUI will appear)  ---
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName} now"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Kill any running instance before uninstalling files
Filename: "{cmd}"; Parameters: "/C taskkill /F /IM {#MyAppExeName}"; Flags: runhidden

[Messages]
; Customise the Welcome page text (uncomment to activate):
; WelcomeLabel1=Welcome to {#MyAppName} Setup
; WelcomeLabel2=This will install {#MyAppName} {#MyAppVersion} on your computer.%n%nNetWatch monitors your network activity and securely reports it to your operator. You can start or stop monitoring at any time using the Start/Stop button in the application.%n%nClick Next to continue.
