#requires -version 5.1
<#
.SYNOPSIS
  Scoped post-repair verification. Prints a small verdict, not a pile of logs.

.DESCRIPTION
  A repair is verified by the narrowest check that could still falsify it.
  Re-running every scan after every fix is not thoroughness, it is 40 minutes
  of wall clock and a context window spent proving something nobody doubted.

  Pick the scope that matches what you changed:

    Integrity  DISM /ScanHealth + SFC /verifyonly        SLOW  ~10-25 min
    Storage    fsutil dirty + CHKDSK /scan               SLOW  ~2-20 min/volume
    Pnp        problem devices + driver/minifilter state  fast  seconds
    Events     high-signal events since -Since           fast  seconds
    Boot       BCD, WinRE, Secure Boot, VSS writers       fast  seconds
    Security   Defender, BitLocker, HVCI, firewall, UAC   fast  seconds
    Power      sleep states, Fast Startup, wake sources   fast  seconds

  Default is Events + Pnp: the cheap pair that catches "the repair worked but
  broke something else". Add the slow scopes only when the repair actually
  touched the component store or the filesystem.

.PARAMETER Only
  One or more scopes. Default: Events, Pnp.

.PARAMETER Since
  Start of the event comparison window. Default: 2 hours ago. Set this to the
  timestamp immediately before the repair so the comparison is meaningful.

.PARAMETER RunDir
  Existing audit run directory. Results land in <RunDir>\verification-<stamp>.
  Defaults to a standalone directory under %SystemDrive%\WindowsNoBullshitAudit.

.EXAMPLE
  # After a driver/service change
  .\verify-after-repair.ps1 -Since '2025-01-01T10:00:00'

.EXAMPLE
  # After DISM /RestoreHealth
  .\verify-after-repair.ps1 -Only Integrity -Since '2025-01-01T10:00:00'
#>
[CmdletBinding()]
param(
    [ValidateSet('Integrity','Storage','Pnp','Events','Boot','Security','Power','All')]
    [string[]]$Only = @('Events','Pnp'),
    [datetime]$Since = (Get-Date).AddHours(-2),
    [string]$RunDir,
    [string]$OutputDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

function Test-IsAdministrator {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

if (-not (Test-IsAdministrator)) {
    Write-Host 'ELEVATION REQUIRED.' -ForegroundColor Red
    Write-Host 'Un-elevated verification returns partial results that look clean.'
    Write-Host 'Run this from an administrator Terminal.'
    exit 740
}

if ($Only -contains 'All') { $Only = @('Integrity','Storage','Pnp','Events','Boot','Security','Power') }

if (-not $OutputDirectory) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $OutputDirectory = if ($RunDir) { Join-Path $RunDir "verification-$stamp" }
                       else { "$env:SystemDrive\WindowsNoBullshitAudit\Verification-$stamp" }
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

function Get-Prop {
    param($Object,[string]$Name,$Default=$null)
    if ($null -eq $Object) { return $Default }
    try {
        $p = $Object.PSObject.Properties[$Name]
        if ($null -eq $p -or $null -eq $p.Value) { return $Default }
        return $p.Value
    } catch { return $Default }
}

function Save-Native {
    param([string]$File,[string]$Exe,[string[]]$Arguments)
    $p = Join-Path $OutputDirectory $File
    try { & $Exe @Arguments 2>&1 | Out-File $p -Encoding utf8 -Width 4096 }
    catch { $_ | Out-String | Out-File $p -Encoding utf8 }
    try { return (Get-Content $p -Raw -ErrorAction Stop) } catch { return '' }
}

$result = [ordered]@{
    schema_version = '1.0'
    verified_at    = (Get-Date).ToString('o')
    since          = $Since.ToString('o')
    scopes         = @($Only)
    checks         = [ordered]@{}
    note           = 'Broad verification cannot replace a finding-specific discriminating test.'
}

Write-Host "Verification scopes: $($Only -join ', ')" -ForegroundColor Green
Write-Host "Comparison window starts: $($Since.ToString('u'))"

# --------------------------------------------------------------- Integrity --
if ($Only -contains 'Integrity') {
    Write-Host 'DISM /ScanHealth (slow) ...' -ForegroundColor Cyan
    $d = Save-Native 'DISM-ScanHealth.txt' 'dism.exe' @('/Online','/Cleanup-Image','/ScanHealth','/English')
    Write-Host 'SFC /verifyonly (slow) ...' -ForegroundColor Cyan
    $s = Save-Native 'SFC-VerifyOnly.txt' 'sfc.exe' @('/verifyonly')
    $result.checks['dism_scanhealth'] =
        if ($d -match 'No component store corruption detected') { 'CLEAN' }
        elseif ($d -match 'repairable|corruption detected') { 'STILL_CORRUPT' } else { 'UNKNOWN' }
    $result.checks['sfc_verifyonly'] =
        if ($s -match 'did not find any integrity violations') { 'CLEAN' }
        elseif ($s -match 'integrity violations|found corrupt files|was unable to fix') { 'STILL_CORRUPT' } else { 'UNKNOWN' }
}

# ----------------------------------------------------------------- Storage --
if ($Only -contains 'Storage') {
    $dirty = @(); $chk = @()
    try {
        foreach ($v in @(Get-Volume -ErrorAction Stop | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' -and $_.FileSystem -eq 'NTFS' })) {
            $drive = "$($v.DriveLetter):"
            $t = Save-Native "fsutil-dirty-$($v.DriveLetter).txt" 'fsutil.exe' @('dirty','query',$drive)
            if ($t -match 'is Dirty') { $dirty += $drive }
            Write-Host "CHKDSK /scan $drive (slow) ..." -ForegroundColor Cyan
            $c = Save-Native "chkdsk-$($v.DriveLetter)-scan.txt" 'chkdsk.exe' @($drive,'/scan')
            $chk += [pscustomobject]@{
                Volume=$drive
                Result=$(if ($c -match 'found no problems|no further action is required') { 'CLEAN' }
                         elseif ($c -match 'found problems') { 'PROBLEMS' } else { 'UNKNOWN' })
            }
        }
    } catch {}
    $result.checks['dirty_volumes'] = $dirty
    $result.checks['chkdsk'] = $chk
}

# --------------------------------------------------------------------- Pnp --
if ($Only -contains 'Pnp') {
    $problems = @()
    try {
        $problems = @(Get-CimInstance Win32_PnPEntity -ErrorAction Stop |
            Where-Object { $_.ConfigManagerErrorCode -and $_.ConfigManagerErrorCode -ne 0 } |
            Select-Object Name,PNPDeviceID,Service,ConfigManagerErrorCode)
    } catch {}
    $problems | Export-Csv (Join-Path $OutputDirectory 'pnp-problems.csv') -NoTypeInformation -Encoding UTF8
    $null = Save-Native 'fltmc-filters.txt' 'fltmc.exe' @('filters')
    $result.checks['pnp_problem_count'] = $problems.Count
    $result.checks['pnp_problems'] = @($problems | Select-Object -First 10 Name,ConfigManagerErrorCode,Service)
}

# ------------------------------------------------------------------ Events --
if ($Only -contains 'Events') {
    $providers = @(
        'Microsoft-Windows-WHEA-Logger','Microsoft-Windows-WER-SystemErrorReporting',
        'Microsoft-Windows-Kernel-Power','Microsoft-Windows-Kernel-PnP','Microsoft-Windows-CodeIntegrity',
        'Disk','Ntfs','stornvme','storahci','storport','volmgr','volsnap',
        'Service Control Manager','Application Error','Application Hang'
    )
    $ev = @()
    foreach ($log in @('System','Application')) {
        try {
            $ev += @(Get-WinEvent -FilterHashtable @{LogName=$log;StartTime=$Since;Level=1,2,3;ProviderName=$providers} -ErrorAction Stop)
        } catch {
            if ($_.Exception.Message -notmatch 'No events were found') { Write-Warning $_.Exception.Message }
        }
    }
    $ev | Select-Object TimeCreated,LogName,ProviderName,Id,LevelDisplayName,
                        @{n='Message';e={ (($_.Message -replace '\r?\n',' ') -replace '\s+',' ').Trim() }} |
        Export-Csv (Join-Path $OutputDirectory 'high-signal-events-since.csv') -NoTypeInformation -Encoding UTF8

    $grouped = @($ev | Group-Object ProviderName,Id | Sort-Object Count -Descending | Select-Object -First 15 |
        ForEach-Object {
            $g = @($_.Group)
            [pscustomobject]@{ Provider=$g[0].ProviderName; Id=$g[0].Id; Count=$_.Count }
        })
    $result.checks['high_signal_events_since'] = $ev.Count
    $result.checks['event_signatures_since'] = $grouped
}

# -------------------------------------------------------------------- Boot --
if ($Only -contains 'Boot') {
    $re = Save-Native 'reagentc-info.txt' 'reagentc.exe' @('/info')
    $null = Save-Native 'bcdedit-all.txt' 'bcdedit.exe' @('/enum','all')
    $vw = Save-Native 'vss-writers.txt' 'vssadmin.exe' @('list','writers')
    $sb = $null; try { $sb = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch {}
    $failed = @([regex]::Matches($vw, "(?s)Writer name: '([^']+)'.*?Last error: ([^\r\n]+)") |
        Where-Object { $_.Groups[2].Value.Trim() -ne 'No error' } |
        ForEach-Object { $_.Groups[1].Value })
    $result.checks['winre_enabled'] = if ($re -match '(?im)^\s*Windows RE status:\s*(\w+)') { ($Matches[1] -eq 'Enabled') } else { $null }
    $result.checks['secure_boot'] = $sb
    $result.checks['vss_writer_failures'] = $failed
}

# ---------------------------------------------------------------- Security --
if ($Only -contains 'Security') {
    $def = $null; try { $def = Get-MpComputerStatus -ErrorAction Stop } catch {}
    $dg  = $null; try { $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop } catch {}
    $bl  = @();   try { $bl = @(Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint,VolumeStatus,ProtectionStatus) } catch {}
    $fw  = @();   try { $fw = @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,Enabled) } catch {}
    $result.checks['defender_realtime'] = Get-Prop $def 'RealTimeProtectionEnabled'
    $result.checks['defender_tamper']   = Get-Prop $def 'IsTamperProtected'
    $result.checks['hvci_running']      = (@(Get-Prop $dg 'SecurityServicesRunning' @()) -contains 2)
    $result.checks['bitlocker']         = $bl
    $result.checks['firewall_disabled'] = @($fw | Where-Object { -not $_.Enabled } | Select-Object -ExpandProperty Name)
    $result.checks['uac_enabled']       = $(try { [bool](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction Stop).EnableLUA } catch { $null })
}

# ------------------------------------------------------------------- Power --
if ($Only -contains 'Power') {
    $null = Save-Native 'powercfg-a.txt' 'powercfg.exe' @('/a')
    $null = Save-Native 'powercfg-lastwake.txt' 'powercfg.exe' @('/lastwake')
    $null = Save-Native 'powercfg-requests.txt' 'powercfg.exe' @('/requests')
    $result.checks['fast_startup_enabled'] = $(try { [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction Stop).HiberbootEnabled } catch { $null })
}

# ------------------------------------------------------------------ verdict --

$json = $result | ConvertTo-Json -Depth 6
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'VERIFICATION.json'), $json, (New-Object Text.UTF8Encoding($false)))

Write-Host ''
Write-Host '--- verification result ---' -ForegroundColor Green
$json
Write-Host ''
Write-Host "Evidence: $OutputDirectory" -ForegroundColor DarkGray
Write-Host 'A clean broad pass is not proof that the specific finding is fixed.' -ForegroundColor Yellow
Write-Host 'Re-run the discriminating test that originally exposed it.' -ForegroundColor Yellow
