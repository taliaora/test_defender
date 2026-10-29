<#
  Check-Compromise.ps1
  Quick triage of a Windows laptop after a phishing incident.
  Read-only checks, plus an optional Defender scan. Nothing is deleted or changed.

  HOW TO RUN
    1. Log in as the affected user (so browser/profile checks look at HER profile).
    2. Open PowerShell as Administrator (right-click > Run as administrator).
    3. Allow the script for this session only:
         Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    4. Run:
         .\Check-Compromise.ps1               # checks + Defender quick scan
         .\Check-Compromise.ps1 -FullScan     # checks + Defender full scan (can take 1h+)
         .\Check-Compromise.ps1 -Days 14      # look back 14 days instead of 30

  A report is saved to the Desktop as Compromise-Report-<date>.txt
#>

param(
    [int]$Days = 30,
    [switch]$FullScan,
    [switch]$NoScan
)

$ErrorActionPreference = 'SilentlyContinue'
$since  = (Get-Date).AddDays(-$Days)
$report = Join-Path ([Environment]::GetFolderPath('Desktop')) ("Compromise-Report-{0:yyyy-MM-dd_HHmm}.txt" -f (Get-Date))

function Section($title) {
    $line = "`n" + ('=' * 70) + "`n  $title`n" + ('=' * 70)
    Write-Host $line -ForegroundColor Cyan
    Add-Content -Path $report -Value $line
}
function Out-Report {
    param([Parameter(ValueFromPipeline)]$InputObject)
    begin { $items = @() }
    process { $items += $InputObject }
    end {
        if (-not $items) { $text = '  (nothing found)' }
        else { $text = ($items | Format-Table -AutoSize -Wrap | Out-String -Width 250) }
        Write-Host $text
        Add-Content -Path $report -Value $text
    }
}
function Flag($msg) {
    Write-Host "  [!] $msg" -ForegroundColor Yellow
    Add-Content -Path $report -Value "  [!] $msg"
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
"Compromise triage report - $env:COMPUTERNAME - user $env:USERNAME - $(Get-Date)`nLook-back window: $Days days (since $since)`nRunning as admin: $isAdmin" | Set-Content $report
if (-not $isAdmin) { Flag 'Not running as Administrator - some checks (Defender, services) may be incomplete.' }

# ---------------------------------------------------------------- Defender
Section 'Microsoft Defender status'
$mp = Get-MpComputerStatus
if ($mp) {
    $mp | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled,
        IsTamperProtected, AntivirusSignatureLastUpdated, QuickScanEndTime, FullScanEndTime | Out-Report
    if (-not $mp.RealTimeProtectionEnabled) { Flag 'Real-time protection is OFF - malware often disables it.' }
} else { Flag 'Could not read Defender status (another antivirus may be installed, or Defender is disabled).' }

Section 'Defender exclusions (attackers add these to hide malware)'
$pref = Get-MpPreference
$excl = @()
$excl += $pref.ExclusionPath      | ForEach-Object { [pscustomobject]@{Type='Path';      Value=$_} }
$excl += $pref.ExclusionProcess   | ForEach-Object { [pscustomobject]@{Type='Process';   Value=$_} }
$excl += $pref.ExclusionExtension | ForEach-Object { [pscustomobject]@{Type='Extension'; Value=$_} }
$excl | Out-Report
if ($excl) { Flag 'Exclusions exist - check that each one was set on purpose.' }

Section 'Threats Defender has already detected'
Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending |
    Select-Object InitialDetectionTime, ThreatID, ActionSuccess,
        @{n='Resources';e={($_.Resources -join '; ')}} | Out-Report
Get-MpThreat | Select-Object ThreatName, SeverityID, IsActive, DidThreatExecute | Out-Report

# ---------------------------------------------------------------- Installed software
Section "Programs installed in the last $Days days"
$uninstallKeys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
                 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
$apps = Get-ItemProperty $uninstallKeys | Where-Object DisplayName |
    Select-Object DisplayName, Publisher, DisplayVersion, InstallLocation,
        @{n='Installed';e={ try { [datetime]::ParseExact($_.InstallDate,'yyyyMMdd',$null) } catch { $null } }}
$apps | Where-Object { $_.Installed -and $_.Installed -ge $since } | Sort-Object Installed -Descending | Out-Report

Section 'Remote-access / remote-control tools (installed or running)'
$ratNames = 'AnyDesk','TeamViewer','ScreenConnect','ConnectWise','Splashtop','RustDesk','Atera',
            'NetSupport','Supremo','UltraViewer','LogMeIn','GoTo','RemotePC','Ammyy','AeroAdmin',
            'SimpleHelp','Zoho Assist','N-able','Kaseya','Action1','Level','TightVNC','UltraVNC','RealVNC'
$ratRegex = ($ratNames | ForEach-Object { [regex]::Escape($_) }) -join '|'
$ratApps  = $apps | Where-Object { $_.DisplayName -match $ratRegex }
$ratProcs = Get-Process | Where-Object { $_.ProcessName -match $ratRegex -or $_.Path -match $ratRegex } |
    Select-Object @{n='Running process';e={$_.ProcessName}}, Path
$ratApps  | Out-Report
$ratProcs | Out-Report
if ($ratApps -or $ratProcs) { Flag 'Remote-access software found - confirm she/IT installed it. Scammers use these to control the PC.' }

# ---------------------------------------------------------------- Persistence
Section 'Startup entries (Run keys and Startup folders)'
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | Out-Report

Section 'Scheduled tasks NOT from Microsoft'
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
    $info = $_ | Get-ScheduledTaskInfo
    [pscustomobject]@{
        Task     = $_.TaskPath + $_.TaskName
        State    = $_.State
        Author   = $_.Author
        LastRun  = $info.LastRunTime
        Action   = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
    }
} | Out-Report

Section 'Auto-start services running from unusual locations'
Get-CimInstance Win32_Service | Where-Object {
    $_.StartMode -eq 'Auto' -and $_.PathName -and
    $_.PathName -notmatch '(?i)\\Windows\\|\\Program Files( \(x86\))?\\|\\ProgramData\\Microsoft\\'
} | Select-Object Name, DisplayName, State, PathName | Out-Report

# ---------------------------------------------------------------- Files
Section "Risky files downloaded / created in the last $Days days"
$riskyExt = '.exe','.msi','.scr','.bat','.cmd','.ps1','.vbs','.js','.jse','.hta','.lnk',
            '.iso','.img','.vhd','.zip','.rar','.7z','.html','.htm','.svg','.one','.dll'
$folders  = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents",
              "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA\Temp",
              "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\Content.Outlook")
$files = foreach ($f in $folders | Select-Object -Unique) {
    if (Test-Path $f) {
        Get-ChildItem $f -Recurse -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.CreationTime -ge $since -and $riskyExt -contains $_.Extension.ToLower() }
    }
}
$files | Sort-Object CreationTime -Descending | Select-Object -First 200 CreationTime,
    @{n='KB';e={[math]::Round($_.Length/1KB)}}, FullName,
    @{n='Signed';e={ if ($_.Extension -in '.exe','.dll','.msi','.ps1') { (Get-AuthenticodeSignature $_.FullName).Status } }} | Out-Report

Section 'Executables in AppData / Temp (common malware hiding places)'
Get-ChildItem "$env:APPDATA","$env:LOCALAPPDATA","$env:TEMP" -Recurse -File -Include *.exe,*.dll,*.scr -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.CreationTime -ge $since } |
    ForEach-Object {
        $sig = Get-AuthenticodeSignature $_.FullName
        if ($sig.Status -ne 'Valid') {
            [pscustomobject]@{ Created=$_.CreationTime; Signature=$sig.Status; Path=$_.FullName }
        }
    } | Sort-Object Created -Descending | Out-Report

# ---------------------------------------------------------------- Network
Section 'Active outbound connections (with owning process)'
Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)' } |
    ForEach-Object {
        $p = Get-Process -Id $_.OwningProcess
        [pscustomobject]@{ Process=$p.ProcessName; PID=$_.OwningProcess; Remote="$($_.RemoteAddress):$($_.RemotePort)"; Path=$p.Path }
    } | Sort-Object Process | Out-Report

Section 'Hosts file entries (redirects)'
Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_ -match '^\s*[^#\s]' } |
    ForEach-Object { [pscustomobject]@{Entry=$_} } | Out-Report

Section 'Proxy settings'
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' |
    Select-Object ProxyEnable, ProxyServer, AutoConfigURL | Out-Report

# ---------------------------------------------------------------- Browsers
Section 'Browser extensions (Chrome / Edge / Brave) - check for unknown ones'
$browserRoots = @{
    'Chrome' = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    'Edge'   = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    'Brave'  = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
}
$exts = foreach ($b in $browserRoots.Keys) {
    $root = $browserRoots[$b]
    if (Test-Path $root) {
        Get-ChildItem "$root\*\Extensions\*\*\manifest.json" -ErrorAction SilentlyContinue | ForEach-Object {
            $m = Get-Content $_.FullName -Raw | ConvertFrom-Json
            [pscustomobject]@{
                Browser   = $b
                Profile   = $_.FullName.Split('\')[-5]
                Name      = $m.name
                ID        = $_.Directory.Parent.Name
                Installed = $_.Directory.CreationTime
            }
        }
    }
}
$exts | Sort-Object Installed -Descending | Out-Report
Add-Content $report '  Note: names like __MSG_appName__ are normal (localised). Look up unknown IDs in the Chrome Web Store.'

Section 'Firefox extensions'
Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles\*\extensions\*" -ErrorAction SilentlyContinue |
    Select-Object Name, CreationTime | Out-Report

# ---------------------------------------------------------------- Scan
if (-not $NoScan) {
    Section 'Defender scan'
    Write-Host '  Updating Defender signatures...' -ForegroundColor Gray
    Update-MpSignature
    $type = if ($FullScan) { 'FullScan' } else { 'QuickScan' }
    Write-Host "  Running $type - please wait (full scan can take an hour or more)..." -ForegroundColor Gray
    Start-MpScan -ScanType $type
    Add-Content $report "  $type finished at $(Get-Date). Results after scan:"
    Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -ge (Get-Date).AddHours(-3) } |
        Select-Object InitialDetectionTime, ThreatID, ActionSuccess, @{n='Resources';e={($_.Resources -join '; ')}} | Out-Report
}

Write-Host "`nDone. Report saved to: $report" -ForegroundColor Green
Write-Host 'Lines marked [!] need a closer look. For a deeper check, run a Defender Offline scan:  Start-MpWDOScan  (reboots the PC).' -ForegroundColor Green
