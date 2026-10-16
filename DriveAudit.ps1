#Requires -RunAsAdministrator
<#
    DriveAudit.ps1 - Read-only space audit for C: (Windows 10 / 11)

    What it does:
      1. Lists installed programs on C: with their real size on disk
      2. Finds when each program was last run (from the Windows Prefetch history)
      3. Flags programs not run in the last N days (default 60)
      4. Measures the usual hidden space wasters (hibernation file, update cache, temp, etc.)
      5. Lists the biggest AppData folders (old app caches often hide here)

    NOTHING is deleted or changed. Results are saved to a folder on your Desktop.

    Run from an Administrator PowerShell:
      powershell -ExecutionPolicy Bypass -File .\DriveAudit.ps1
      powershell -ExecutionPolicy Bypass -File .\DriveAudit.ps1 -DaysUnused 90
#>
param([int]$DaysUnused = 60)

$ErrorActionPreference = 'SilentlyContinue'
$cutoff = (Get-Date).AddDays(-$DaysUnused)
$outDir = Join-Path ([Environment]::GetFolderPath('Desktop')) ("DriveAudit_" + (Get-Date -Format 'yyyy-MM-dd_HHmm'))
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

# ---------- helpers ----------
function Get-SizeGB([string]$Path) {
    if (-not $Path) { return 0 }
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer) { return [math]::Round($item.Length / 1GB, 2) }
    $sum = (Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
    if (-not $sum) { $sum = 0 }
    return [math]::Round($sum / 1GB, 2)
}

function Get-PfKey([string]$ExeName) {
    # Prefetch stores the exe name in upper case, truncated to 29 characters
    $n = $ExeName.ToUpper()
    if ($n.Length -gt 29) { $n = $n.Substring(0, 29) }
    return $n
}

# ---------- 1. Prefetch run history ----------
Write-Host "Reading program run history (Prefetch)..." -ForegroundColor Cyan
$pfFiles = @(Get-ChildItem -Path "$env:WINDIR\Prefetch" -Filter *.pf -Force)
$lastRun = @{}
foreach ($pf in $pfFiles) {
    $key = ($pf.Name -replace '-[0-9A-Fa-f]{8}\.pf$', '').ToUpper()
    if (-not $lastRun.ContainsKey($key) -or $lastRun[$key] -lt $pf.LastWriteTime) {
        $lastRun[$key] = $pf.LastWriteTime
    }
}
$historyStart = $null
if ($pfFiles.Count -gt 0) {
    $historyStart = ($pfFiles | Sort-Object LastWriteTime | Select-Object -First 1).LastWriteTime
} else {
    Write-Warning "Prefetch is empty or disabled - last-run dates will be missing."
}

# Background exes that run without you opening the app (would make apps look 'used')
$backgroundPattern = 'unins|uninst|update|crash|report|helper|setup|install|elevat|service|svc|daemon|tray|notifier|launcher_bg'

# ---------- 2. Installed programs ----------
Write-Host "Collecting installed programs..." -ForegroundColor Cyan
$uninstallKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$entries = @(Get-ItemProperty -Path $uninstallKeys |
    Where-Object { $_.DisplayName -and $_.SystemComponent -ne 1 -and -not $_.ParentKeyName -and $_.ReleaseType -notmatch 'Update|Hotfix' } |
    Sort-Object DisplayName -Unique)

# Folders too generic to attribute to a single app
$generic = @($env:WINDIR, $env:ProgramFiles, ${env:ProgramFiles(x86)}, "$env:ProgramFiles\Common Files",
             "${env:ProgramFiles(x86)}\Common Files", $env:ProgramData, $env:LOCALAPPDATA, $env:APPDATA,
             "$env:LOCALAPPDATA\Programs", $env:USERPROFILE, 'C:') |
           Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\').ToLower() }

$cautionPattern = 'Visual C\+\+|\.NET|Runtime|Redistributable|Driver|Chipset|WebView2|DirectX|Windows SDK|Update Health|Bluetooth|Audio|Synaptics|Touchpad|BIOS|Firmware|Antivirus|Security|VPN'
$cautionPublisher = 'Intel|Advanced Micro Devices|AMD|NVIDIA|Realtek|Synaptics|Dell|Lenovo|HP Inc|ASUS|Acer|MSI'

$i = 0
$results = foreach ($e in $entries) {
    $i++
    Write-Progress -Activity "Analyzing installed programs ($i of $($entries.Count))" -Status $e.DisplayName -PercentComplete ([int]($i / $entries.Count * 100))

    # Find install folder
    $folder = $null
    if ($e.InstallLocation) { $folder = $e.InstallLocation.Trim().Trim('"').TrimEnd('\') }
    if (-not $folder -or -not (Test-Path -LiteralPath $folder -PathType Container)) {
        $folder = $null
        if ($e.DisplayIcon) {
            $iconPath = ($e.DisplayIcon -split ',')[0].Trim().Trim('"')
            if ($iconPath -and (Test-Path -LiteralPath $iconPath -PathType Leaf)) {
                $folder = Split-Path -Path $iconPath -Parent
            }
        }
    }
    if ($folder) {
        $low = $folder.TrimEnd('\').ToLower()
        if (($generic -contains $low) -or $low.StartsWith($env:WINDIR.ToLower())) { $folder = $null }
    }
    # Only programs on C: (or unknown location)
    if ($folder -and -not $folder.ToUpper().StartsWith('C:')) { continue }

    # Last run: newest Prefetch hit among the app's own exes (ignoring background exes)
    $last = $null
    if ($folder) {
        $exes = Get-ChildItem -LiteralPath $folder -Recurse -Force -File -Filter *.exe -ErrorAction SilentlyContinue
        foreach ($x in $exes) {
            if ($x.Name -match $backgroundPattern) { continue }
            $k = Get-PfKey $x.Name
            if ($lastRun.ContainsKey($k)) {
                if ($null -eq $last -or $lastRun[$k] -gt $last) { $last = $lastRun[$k] }
            }
        }
    }

    # Size
    $sizeGB = 0
    if ($folder) { $sizeGB = Get-SizeGB $folder }
    if ($sizeGB -eq 0 -and $e.EstimatedSize) { $sizeGB = [math]::Round($e.EstimatedSize / 1MB, 2) }

    # Status
    if ($last -and $last -ge $cutoff)  { $status = 'Used recently' }
    elseif ($last)                     { $status = "Not used $DaysUnused+ days" }
    elseif ($folder)                   { $status = 'No run record' }
    else                               { $status = 'Unknown (no install folder)' }

    $lastText = ''; $days = $null
    if ($last) { $lastText = $last.ToString('yyyy-MM-dd'); $days = [int]((Get-Date) - $last).TotalDays }

    $caution = ''
    if ($e.DisplayName -match $cautionPattern -or $e.Publisher -match $cautionPublisher) {
        $caution = 'System/driver - keep unless sure'
    }

    [pscustomobject]@{
        Program      = $e.DisplayName
        SizeGB       = $sizeGB
        Status       = $status
        LastRun      = $lastText
        DaysSinceRun = $days
        Caution      = $caution
        Publisher    = $e.Publisher
        Folder       = $folder
    }
}
Write-Progress -Activity "Analyzing installed programs" -Completed

$results = @($results | Sort-Object SizeGB -Descending)
$results | Export-Csv -Path "$outDir\Programs_all.csv" -NoTypeInformation -Encoding UTF8

$candidates = @($results | Where-Object {
    ($_.Status -eq "Not used $DaysUnused+ days" -or $_.Status -eq 'No run record') -and -not $_.Caution
})
$candidates | Export-Csv -Path "$outDir\Programs_unused_candidates.csv" -NoTypeInformation -Encoding UTF8

# ---------- 3. Hidden space wasters ----------
Write-Host "Measuring common space wasters..." -ForegroundColor Cyan
$hogList = @(
    @{ Item = 'Hibernation file (hiberfil.sys)';    Path = 'C:\hiberfil.sys';  Fix = 'powercfg /h off  (only if you never use Hibernate; also disables Fast Startup)' },
    @{ Item = 'Previous Windows install';            Path = 'C:\Windows.old';   Fix = 'Disk Cleanup > Clean up system files > Previous Windows installation(s)' },
    @{ Item = 'Windows Update download cache';       Path = "$env:WINDIR\SoftwareDistribution\Download"; Fix = 'Disk Cleanup > Clean up system files > Windows Update Cleanup' },
    @{ Item = 'Delivery Optimization cache';         Path = "$env:WINDIR\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization"; Fix = 'Disk Cleanup > Delivery Optimization Files' },
    @{ Item = 'Windows temp files';                  Path = "$env:WINDIR\Temp"; Fix = 'Settings > System > Storage > Temporary files' },
    @{ Item = 'Your temp files';                     Path = $env:TEMP;          Fix = 'Settings > System > Storage > Temporary files' },
    @{ Item = 'Recycle Bin';                         Path = 'C:\$Recycle.Bin';  Fix = 'Empty Recycle Bin' },
    @{ Item = 'Memory dump';                         Path = "$env:WINDIR\MEMORY.DMP"; Fix = 'Disk Cleanup > System error memory dump files' },
    @{ Item = 'App crash dumps';                     Path = "$env:LOCALAPPDATA\CrashDumps"; Fix = 'Safe to delete contents' },
    @{ Item = 'Downloads folder';                    Path = "$env:USERPROFILE\Downloads"; Fix = 'Review manually - old installers and files' },
    @{ Item = 'Videos folder';                       Path = "$env:USERPROFILE\Videos";    Fix = 'Move to external drive / cloud' },
    @{ Item = 'Desktop folder';                      Path = "$env:USERPROFILE\Desktop";   Fix = 'Review manually' },
    @{ Item = 'Documents folder';                    Path = "$env:USERPROFILE\Documents"; Fix = 'Review manually (game saves, video projects)' },
    @{ Item = 'Page file (pagefile.sys)';            Path = 'C:\pagefile.sys';  Fix = 'Leave it - managed by Windows' }
)
$hogs = foreach ($h in $hogList) {
    [pscustomobject]@{ Item = $h.Item; SizeGB = (Get-SizeGB $h.Path); HowToFree = $h.Fix; Path = $h.Path }
}
$hogs = @($hogs | Sort-Object SizeGB -Descending)
$hogs | Export-Csv -Path "$outDir\Space_wasters.csv" -NoTypeInformation -Encoding UTF8

# ---------- 4. Biggest AppData folders ----------
Write-Host "Measuring AppData folders..." -ForegroundColor Cyan
$appData = foreach ($root in @($env:LOCALAPPDATA, $env:APPDATA)) {
    Get-ChildItem -LiteralPath $root -Directory -Force | ForEach-Object {
        [pscustomobject]@{ Folder = $_.FullName; SizeGB = (Get-SizeGB $_.FullName); LastModified = $_.LastWriteTime.ToString('yyyy-MM-dd') }
    }
}
$appData = @($appData | Sort-Object SizeGB -Descending | Select-Object -First 25)
$appData | Export-Csv -Path "$outDir\AppData_biggest.csv" -NoTypeInformation -Encoding UTF8

# ---------- 5. Summary ----------
$drive = Get-PSDrive C
$freeGB = [math]::Round($drive.Free / 1GB, 1)
$totalGB = [math]::Round(($drive.Free + $drive.Used) / 1GB, 1)
$candGB = [math]::Round((($candidates | Measure-Object SizeGB -Sum).Sum), 1)

Write-Host ""
Write-Host "==================== C: DRIVE AUDIT ====================" -ForegroundColor Yellow
Write-Host ("Free space: {0} GB of {1} GB" -f $freeGB, $totalGB)
if ($historyStart) {
    Write-Host ("Run history available since: {0}" -f $historyStart.ToString('yyyy-MM-dd'))
    if ($historyStart -lt $cutoff) {
        Write-Host "  -> History covers the full $DaysUnused days, so 'No run record' = not opened in that period." -ForegroundColor Green
    } else {
        Write-Host "  -> History is SHORTER than $DaysUnused days; treat 'No run record' as 'probably unused', verify first." -ForegroundColor DarkYellow
    }
}
Write-Host ""
Write-Host ("Uninstall candidates (unused, not system/driver): {0} programs, ~{1} GB" -f $candidates.Count, $candGB) -ForegroundColor Yellow
$candidates | Select-Object -First 20 Program, SizeGB, Status, LastRun | Format-Table -AutoSize
Write-Host "Hidden space wasters:" -ForegroundColor Yellow
$hogs | Where-Object { $_.SizeGB -ge 0.1 } | Select-Object Item, SizeGB, HowToFree | Format-Table -AutoSize -Wrap
Write-Host "Biggest AppData folders (old app caches):" -ForegroundColor Yellow
$appData | Select-Object -First 10 | Format-Table -AutoSize
Write-Host "Full reports saved to: $outDir" -ForegroundColor Green
Write-Host "Nothing was deleted. Review the lists, then uninstall via Settings > Apps." -ForegroundColor Green

Invoke-Item $outDir
$candidates | Out-GridView -Title "Uninstall candidates - not used in $DaysUnused+ days (sortable)"
