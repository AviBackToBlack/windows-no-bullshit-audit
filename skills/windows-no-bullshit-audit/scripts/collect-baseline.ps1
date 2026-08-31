#requires -version 5.1
<#
.SYNOPSIS
  Read-only Windows 11 audit collector that produces a token-bounded triage
  digest plus queryable raw evidence.

.DESCRIPTION
  Collects evidence only. It does not repair Windows, delete entries, install
  updates, modify boot/storage/security configuration, or enable Driver Verifier.

  Two artifact tiers are produced:

    TRIAGE.md / TRIAGE.json   small, capped, agent-facing digest. Read this.
    <numbered folders>        full raw evidence. Query it, never load it whole.

  The digest is the contract. Raw evidence exists so that a specific question
  can be answered later without re-running collection.

.PARAMETER OutputRoot
  Parent directory. Default: %SystemDrive%\WindowsNoBullshitAudit

.PARAMETER Depth
  Fast (default) - no DISM ScanHealth, SFC, CHKDSK, powercfg /energy, msinfo32
                   or dxdiag. Typically 1-3 minutes. Run collect-deep.ps1
                   afterwards for the slow scans.
  Full           - everything, including the slow scans. Typically 20-60 minutes.

.PARAMETER EventDays
  History window for events. Default: 14 for Fast, 60 for Full.

.PARAMETER MaxEventsPerLog
  Safety ceiling on events pulled per log. Default 20000. This bounds collection
  cost only; the digest is capped independently.

.PARAMETER Redact
  Pseudonymize machine identity in TRIAGE.md / TRIAGE.json: computer name, user
  names, serial numbers, MAC addresses and user profile paths. Use this when the
  digest will be pasted into a hosted chat. Raw evidence on disk is not
  rewritten, so nothing diagnostic is lost locally.

  Dotted quads are intentionally left alone: a version like 1.54.0.120 cannot be
  distinguished from an IPv4 address by pattern, and module versions are primary
  evidence. The digest carries no network configuration - that lives only in raw
  10-Network evidence, which is never meant to be pasted anywhere.

  A short hostname is matched on word boundaries, so an unrelated token that
  happens to equal the hostname may also be replaced. That is the safe direction
  to err.

.PARAMETER CopyToClipboard
  Copy TRIAGE.md to the clipboard when it is within the size cap.

.PARAMETER MaxTriageBytes
  Hard cap for TRIAGE.json. Default 60000 bytes (~15k tokens). Sections are
  trimmed in a documented order until the digest fits, and every trim is
  recorded in the digest itself.

  If trimming cannot reach the cap, the digest is written as
  TRIAGE-OVERSIZED.json instead of TRIAGE.json and the script exits 75.
  TRIAGE.md is still produced within its own budget, so a failed cap never
  leaves you with nothing after a multi-minute collection.

  Values far below the default cannot be met by any real machine and exist so
  the overflow path can be tested.

.PARAMETER NoZip
  Do not make a ZIP of the raw evidence.

.EXAMPLE
  .\collect-baseline.ps1
  Fast pass. Paste the printed TRIAGE.md into the audit conversation.

.EXAMPLE
  .\collect-baseline.ps1 -Redact -CopyToClipboard
  Fast pass, identity pseudonymized, digest on the clipboard.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot = "$env:SystemDrive\WindowsNoBullshitAudit",
    [ValidateSet('Fast','Full')][string]$Depth = 'Fast',
    [ValidateRange(1,3650)][int]$EventDays = 0,
    [ValidateRange(100,200000)][int]$MaxEventsPerLog = 20000,
    [switch]$Redact,
    [switch]$CopyToClipboard,
    # Lower bound is 1000 rather than something "sensible" so the overflow path
    # is actually testable. A real digest can never fit that, which is the
    # point: CI can force the failure deterministically on any machine.
    [ValidateRange(1000,400000)][int]$MaxTriageBytes = 60000,
    [switch]$NoZip
)

# Version 1.0 catches typo'd variables but tolerates missing properties. A
# collector that aborts a probe because one CIM object on one machine lacks one
# property is not robust, it is brittle with good intentions.
Set-StrictMode -Version 1.0
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# ---------------------------------------------------------------- elevation --

function Test-IsAdministrator {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

if (-not (Test-IsAdministrator)) {
    Write-Host ''
    Write-Host 'ELEVATION REQUIRED' -ForegroundColor Red
    Write-Host 'This collector reads driver, storage, security and servicing state that'
    Write-Host 'Windows only exposes to an administrator. Without elevation it would'
    Write-Host 'produce partial evidence that looks complete, which is worse than no'
    Write-Host 'evidence at all.'
    Write-Host ''
    Write-Host 'Close this window. Open Start > type "Terminal" > right-click >'
    Write-Host 'Run as administrator. Then run this script again.'
    Write-Host ''
    # 740 == ERROR_ELEVATION_REQUIRED
    exit 740
}

if ($EventDays -le 0) { $EventDays = if ($Depth -eq 'Full') { 60 } else { 14 } }

# --------------------------------------------------------------- run layout --

$StartTime    = Get-Date
$Since        = $StartTime.AddDays(-$EventDays)
$Timestamp    = $StartTime.ToString('yyyyMMdd-HHmmss')
$ComputerSafe = ($env:COMPUTERNAME -replace '[^A-Za-z0-9._-]','_')
$RunName      = "WindowsNoBullshitAudit-$ComputerSafe-$Timestamp"
$RunDir       = Join-Path $OutputRoot $RunName
$ZipPath      = Join-Path $OutputRoot "$RunName.zip"

$dirs = @(
    '00-System','01-Integrity','02-Storage','03-Drivers','04-Devices',
    '05-Events','06-WER','07-Dumps','08-Boot-Restore','09-Power',
    '10-Network','11-Software-Startup','12-Security','13-Performance','14-Updates',
    'findings'
)
New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
foreach ($d in $dirs) { New-Item -ItemType Directory -Force -Path (Join-Path $RunDir $d) | Out-Null }

$Journal   = New-Object System.Collections.ArrayList
$Warnings  = New-Object System.Collections.Generic.List[string]
$Trimmed   = New-Object System.Collections.Generic.List[string]

function Add-Journal {
    param([string]$Name,[string]$Status,[int]$ExitCode,[double]$Seconds,[string]$Path,[string]$Note='')
    $null = $Journal.Add([pscustomobject]@{
        Time=(Get-Date).ToString('o'); Name=$Name; Status=$Status; ExitCode=$ExitCode
        Seconds=[math]::Round($Seconds,2); OutputPath=$Path; Note=$Note
    })
}

function Get-Prop {
    param($Object,[string]$Name,$Default=$null)
    if ($null -eq $Object) { return $Default }
    try {
        $p = $Object.PSObject.Properties[$Name]
        if ($null -eq $p) { return $Default }
        if ($null -eq $p.Value) { return $Default }
        return $p.Value
    } catch { return $Default }
}

# --------------------------------------------------------------- redaction --

# Secret scrubbing always runs. Identity pseudonymization only runs with -Redact
# and only on the digest, so raw evidence stays diagnostically complete on disk.

function Protect-SensitiveText {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $s = $Text
    $s = $s -replace '(?i)((?:--?|/)(?:password|passwd|pwd|token|secret|api[-_]?key|client[-_]?secret|access[-_]?key|credential|auth)(?:\s*[:=]\s*|\s+))(?:(?:"[^"]*")|(?:''[^'']*'')|\S+)', '$1<REDACTED>'
    $s = $s -replace '(?i)\b((?:password|passwd|pwd|token|secret|api[-_]?key|client[-_]?secret|access[-_]?key|credential|auth)\s*=\s*)(?:(?:"[^"]*")|(?:''[^'']*'')|[^;\s]+)', '$1<REDACTED>'
    $s = $s -replace '([A-Za-z][A-Za-z0-9+.-]*://)[^/@:\s]+:[^/@\s]+@', '$1<REDACTED>@'
    return $s
}

$script:RedactMap = @{}
function Protect-Identity {
    param([AllowNull()]$Value)
    if (-not $Redact) { return $Value }
    if ($null -eq $Value) { return $null }
    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return $Value }
    # Longest literals first, so C:\Users\bob is replaced before bob.
    foreach ($k in @($script:RedactMap.Keys | Sort-Object -Property Length -Descending)) {
        if (-not $k) { continue }
        $s = $s -replace $script:RedactMap[$k].Pattern, $script:RedactMap[$k].Replacement
    }
    # MAC addresses have no benign lookalike in this data, so they are safe to
    # blanket-replace.
    $s = $s -replace '\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b', '<MAC>'
    # Deliberately NOT redacting dotted quads here. A four-part version such as
    # 1.54.0.120 is indistinguishable from an IPv4 address by pattern alone, and
    # faulting-module versions are primary diagnostic evidence. The digest
    # contains no network configuration - IP data lives only in raw 10-Network
    # evidence, which is never pasted into a chat.
    return $s
}
function Register-Redaction {
    param([AllowNull()][string]$Literal,[string]$Placeholder)
    if (-not $Redact -or [string]::IsNullOrWhiteSpace($Literal)) { return }
    # A short hostname such as "Z" must still be scrubbed, but a bare substring
    # replacement would mangle every unrelated "Z" in the text. Anchor short
    # literals on word boundaries; long ones are specific enough as-is.
    $escaped = [regex]::Escape($Literal)
    $pattern = if ($Literal.Length -lt 4) { "(?i)\b$escaped\b" } else { "(?i)$escaped" }
    $script:RedactMap[$Literal] = @{ Pattern = $pattern; Replacement = $Placeholder }
}

# Identity values that are printed as whole fields are substituted directly.
# Pattern matching is only for free text such as event messages, where we cannot
# know in advance where the name appears.
function Get-SafeField {
    param([AllowNull()]$Value,[string]$Placeholder)
    if ($Redact) { return $Placeholder }
    return $Value
}

# ------------------------------------------------------------ capture verbs --

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Exe,
        [string[]]$Arguments=@(),
        [Parameter(Mandatory)][string]$RelativeOutput
    )
    $out = Join-Path $RunDir $RelativeOutput
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $status='OK'; $code=0; $note=''
    try {
        $cmd = Get-Command $Exe -ErrorAction Stop
        $result = & $cmd.Source @Arguments 2>&1
        $code = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
        $result | Out-File -FilePath $out -Encoding utf8 -Width 4096
        if ($code -ne 0) { $status='NONZERO'; $note="Exit code $code" }
    } catch {
        $status='ERROR'; $code=-1; $note=$_.Exception.Message
        $_ | Out-String | Out-File -FilePath $out -Encoding utf8 -Width 4096
    } finally {
        $sw.Stop(); Add-Journal $Name $status $code $sw.Elapsed.TotalSeconds $RelativeOutput $note
    }
}

function Invoke-PSCapture {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory)][string]$RelativeOutput,
        [ValidateSet('Text','Csv','Json','Clixml')][string]$Format='Text'
    )
    $out = Join-Path $RunDir $RelativeOutput
    $sw = [Diagnostics.Stopwatch]::StartNew(); $status='OK'; $note=''
    $result = $null
    try {
        $result = & $ScriptBlock
        # A probe that finds nothing must still produce a file, otherwise
        # "empty" and "never ran" become indistinguishable on disk. But do NOT
        # coerce $result itself: callers use $null to mean "this probe did not
        # work", and turning that into an empty array made a failed Get-Tpm
        # report tpm_present=False instead of unknown. Missing data must never
        # read as clean data.
        $forFile = if ($null -eq $result) { @() } else { $result }
        switch ($Format) {
            'Csv'    { if (@($forFile).Count) { $forFile | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8 } else { '' | Out-File -FilePath $out -Encoding utf8 } }
            'Json'   { $forFile | ConvertTo-Json -Depth 10 | Out-File -FilePath $out -Encoding utf8 -Width 4096 }
            'Clixml' { $forFile | Export-Clixml -Path $out -Depth 8 }
            default  { $forFile | Out-File -FilePath $out -Encoding utf8 -Width 4096 }
        }
    } catch {
        $status='ERROR'; $note=$_.Exception.Message
        $Warnings.Add("$Name failed: $note")
        $_ | Out-String | Out-File -FilePath $out -Encoding utf8 -Width 4096
    } finally {
        $sw.Stop(); Add-Journal $Name $status 0 $sw.Elapsed.TotalSeconds $RelativeOutput $note
    }
    return $result
}

function Export-EventLogIfPresent {
    param([string]$LogName)
    try {
        $null = Get-WinEvent -ListLog $LogName -ErrorAction Stop
        $safe = ($LogName -replace '[\\/:\s]','_') + '.evtx'
        $rel  = "05-Events\$safe"; $out = Join-Path $RunDir $rel
        $sw = [Diagnostics.Stopwatch]::StartNew()
        & wevtutil.exe epl $LogName $out /ow:true 2>&1 | Out-Null
        $code = $LASTEXITCODE; $sw.Stop()
        Add-Journal "Export EVTX $LogName" $(if($code -eq 0){'OK'}else{'NONZERO'}) $code $sw.Elapsed.TotalSeconds $rel
    } catch {
        $Warnings.Add("Event log unavailable: $LogName")
    }
}

function Get-CpuSeconds {
    param($Process)
    try { return [math]::Round($Process.TotalProcessorTime.TotalSeconds,1) } catch { return $null }
}

# Certificate subjects quote CNs that contain commas, e.g.
#   CN="Oracle America, Inc.", O=...
# A naive CN=([^,]+) truncates those to 'Oracle America'.
function Get-SignerCommonName {
    param([AllowNull()][string]$Subject)
    if ([string]::IsNullOrWhiteSpace($Subject)) { return $Subject }
    if ($Subject -match 'CN="([^"]+)"') { return $Matches[1] }
    if ($Subject -match 'CN=([^,]+)')   { return $Matches[1].Trim() }
    return $Subject
}

function Compress-Message {
    param([AllowNull()][string]$Text,[int]$Max=220)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $s = (($Text -replace '\r?\n',' ') -replace '\s+',' ').Trim()
    if ($s.Length -gt $Max) { $s = $s.Substring(0,$Max) + '...' }
    return $s
}

Write-Host "Windows No-Bullshit Audit baseline ($Depth)" -ForegroundColor Green
Write-Host "Evidence directory: $RunDir"
Write-Host "Event window: $EventDays days | Mode: read-only evidence collection" -ForegroundColor Yellow
if ($Depth -eq 'Full') { Write-Host 'Full depth includes slow scans. Expect 20-60 minutes.' -ForegroundColor Yellow }

# ===================================================================== 00 ====
# System / firmware baseline

$os   = Invoke-PSCapture 'OS' { Get-CimInstance Win32_OperatingSystem } '00-System\os.txt'
$cs   = Invoke-PSCapture 'ComputerSystem' { Get-CimInstance Win32_ComputerSystem } '00-System\computer-system.txt'
$bios = Invoke-PSCapture 'BIOS' { Get-CimInstance Win32_BIOS } '00-System\bios.txt'
$cpu  = Invoke-PSCapture 'Processor' { Get-CimInstance Win32_Processor } '00-System\processor.txt'
Invoke-PSCapture 'BaseBoard' { Get-CimInstance Win32_BaseBoard | Format-List * } '00-System\baseboard.txt' | Out-Null
Invoke-PSCapture 'Video controllers' { Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion,DriverDate,AdapterRAM,PNPDeviceID,Status } '00-System\video.csv' Csv | Out-Null

$cv = $null
try { $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop } catch {}

Register-Redaction $env:COMPUTERNAME '<COMPUTER>'
Register-Redaction $env:USERNAME     '<USER>'
Register-Redaction $env:USERPROFILE  '<USERPROFILE>'
Register-Redaction (Get-Prop $bios 'SerialNumber') '<SERIAL>'
Register-Redaction (Get-Prop $cs 'UserName')       '<USER>'

Invoke-PSCapture 'Environment metadata' {
    Get-ChildItem Env: | Sort-Object Name |
        Select-Object Name,@{n='Value';e={'<REDACTED_BY_COLLECTOR>'}},
                      @{n='ValueLength';e={ if($null -eq $_.Value){0}else{$_.Value.Length} }}
} '00-System\environment-metadata.csv' Csv | Out-Null

Invoke-PSCapture 'PATH entries' {
    if ($env:Path) {
        $env:Path -split ';' | Where-Object { $_ } |
            ForEach-Object { [pscustomobject]@{Path=$_;Exists=(Test-Path -LiteralPath $_)} }
    }
} '00-System\path-entries.csv' Csv | Out-Null

if ($Depth -eq 'Full') {
    Invoke-NativeCapture 'systeminfo' 'systeminfo.exe' @() '00-System\systeminfo.txt'
    try {
        $nfo = Join-Path $RunDir '00-System\msinfo32.nfo'; $sw=[Diagnostics.Stopwatch]::StartNew()
        $p = Start-Process msinfo32.exe -ArgumentList @('/nfo',"`"$nfo`"") -PassThru
        $null = $p.WaitForExit(180000)
        if (-not $p.HasExited) {
            try { $p.Kill() } catch {}
            Add-Journal 'msinfo32' 'TIMEOUT' -1 $sw.Elapsed.TotalSeconds '00-System\msinfo32.nfo' 'Timed out after 180s'
        } else {
            Add-Journal 'msinfo32' 'OK' $p.ExitCode $sw.Elapsed.TotalSeconds '00-System\msinfo32.nfo'
        }
    } catch { $Warnings.Add("msinfo32 failed: $($_.Exception.Message)") }
    try {
        $dx = Join-Path $RunDir '00-System\dxdiag.txt'
        Start-Process dxdiag.exe -ArgumentList @('/dontskip','/t',"`"$dx`"") -Wait -WindowStyle Hidden -ErrorAction Stop | Out-Null
    } catch { $Warnings.Add("dxdiag failed: $($_.Exception.Message)") }
}

# ===================================================================== 01 ====
# Servicing / component store integrity

Invoke-NativeCapture 'DISM CheckHealth' 'dism.exe' @('/Online','/Cleanup-Image','/CheckHealth','/English') '01-Integrity\DISM-CheckHealth.txt'
Invoke-NativeCapture 'DISM AnalyzeComponentStore' 'dism.exe' @('/Online','/Cleanup-Image','/AnalyzeComponentStore','/English') '01-Integrity\DISM-AnalyzeComponentStore.txt'
if ($Depth -eq 'Full') {
    Invoke-NativeCapture 'DISM ScanHealth' 'dism.exe' @('/Online','/Cleanup-Image','/ScanHealth','/English') '01-Integrity\DISM-ScanHealth.txt'
    Invoke-NativeCapture 'SFC VerifyOnly' 'sfc.exe' @('/verifyonly') '01-Integrity\SFC-VerifyOnly.txt'
}

# ===================================================================== 02 ====
# Storage

$physicalDisks = Invoke-PSCapture 'Physical disks' {
    Get-PhysicalDisk | Select-Object FriendlyName,SerialNumber,MediaType,BusType,HealthStatus,OperationalStatus,Size,SpindleSpeed
} '02-Storage\physical-disks.csv' Csv

$volumes = Invoke-PSCapture 'Volumes' {
    Get-Volume | Select-Object DriveLetter,FileSystemLabel,FileSystem,DriveType,HealthStatus,OperationalStatus,Size,SizeRemaining,Path
} '02-Storage\volumes.csv' Csv

Invoke-PSCapture 'Disks' { Get-Disk | Select-Object Number,FriendlyName,SerialNumber,BusType,PartitionStyle,OperationalStatus,HealthStatus,Size,IsBoot,IsSystem } '02-Storage\disks.csv' Csv | Out-Null
Invoke-PSCapture 'Partitions' { Get-Partition | Select-Object DiskNumber,PartitionNumber,DriveLetter,Type,GptType,MbrType,Size,Offset,IsBoot,IsSystem,IsActive,IsHidden } '02-Storage\partitions.csv' Csv | Out-Null
Invoke-PSCapture 'DiskDrive CIM' { Get-CimInstance Win32_DiskDrive | Select-Object Model,SerialNumber,InterfaceType,PNPDeviceID,SCSIPort,SCSIBus,SCSITargetId,SCSILogicalUnit,Size,Status } '02-Storage\diskdrive-cim.csv' Csv | Out-Null
Invoke-NativeCapture 'mountvol' 'mountvol.exe' @() '02-Storage\mountvol.txt'

$reliability = Invoke-PSCapture 'Storage reliability counters' {
    foreach ($pd in Get-PhysicalDisk) {
        try {
            $r = $pd | Get-StorageReliabilityCounter -ErrorAction Stop
            [pscustomobject]@{
                FriendlyName=$pd.FriendlyName; SerialNumber=$pd.SerialNumber
                Temperature=$r.Temperature; TemperatureMax=$r.TemperatureMax; Wear=$r.Wear
                PowerOnHours=$r.PowerOnHours
                ReadErrorsTotal=$r.ReadErrorsTotal; ReadErrorsUncorrected=$r.ReadErrorsUncorrected
                WriteErrorsTotal=$r.WriteErrorsTotal; WriteErrorsUncorrected=$r.WriteErrorsUncorrected
                FlushLatencyMax=$r.FlushLatencyMax; ReadLatencyMax=$r.ReadLatencyMax; WriteLatencyMax=$r.WriteLatencyMax
                LoadUnloadCycleCount=$r.LoadUnloadCycleCount; StartStopCycleCount=$r.StartStopCycleCount
            }
        } catch {
            [pscustomobject]@{FriendlyName=$pd.FriendlyName;SerialNumber=$pd.SerialNumber;Error=$_.Exception.Message}
        }
    }
} '02-Storage\storage-reliability.csv' Csv

$fixedNtfs = @()
try {
    $fixedNtfs = @(Get-Volume -ErrorAction Stop | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' -and $_.FileSystem -eq 'NTFS' })
} catch {}

$dirtyVolumes = New-Object System.Collections.Generic.List[string]
foreach ($v in $fixedNtfs) {
    $drive = "$($v.DriveLetter):"
    Invoke-NativeCapture "FSUTIL dirty $drive" 'fsutil.exe' @('dirty','query',$drive) "02-Storage\fsutil-dirty-$($v.DriveLetter).txt"
    try {
        $txt = Get-Content (Join-Path $RunDir "02-Storage\fsutil-dirty-$($v.DriveLetter).txt") -Raw -ErrorAction Stop
        if ($txt -match 'is Dirty') { $dirtyVolumes.Add($drive) }
    } catch {}
    if ($Depth -eq 'Full') {
        Invoke-NativeCapture "CHKDSK scan $drive" 'chkdsk.exe' @($drive,'/scan') "02-Storage\chkdsk-$($v.DriveLetter)-scan.txt"
    }
}

# =================================================================== 03/04 ===
# Drivers and devices

Invoke-NativeCapture 'PnP problem devices' 'pnputil.exe' @('/enum-devices','/problem','/deviceids') '04-Devices\pnputil-problem-devices.txt'
Invoke-NativeCapture 'Minifilters' 'fltmc.exe' @('filters') '03-Drivers\fltmc-filters.txt'
Invoke-NativeCapture 'Minifilter instances' 'fltmc.exe' @('instances') '03-Drivers\fltmc-instances.txt'
Invoke-NativeCapture 'Driver store' 'pnputil.exe' @('/enum-drivers') '03-Drivers\pnputil-driver-store.txt'

if ($Depth -eq 'Full') {
    # Very large outputs. Only worth the disk and collection time on a deep pass.
    Invoke-NativeCapture 'PnP device tree' 'pnputil.exe' @('/enum-devicetree','/connected','/stack','/drivers','/services') '04-Devices\pnputil-device-tree.txt'
    Invoke-NativeCapture 'driverquery' 'driverquery.exe' @('/v','/fo','csv') '03-Drivers\driverquery.csv'
    Invoke-NativeCapture 'Driver services' 'sc.exe' @('query','type=','driver','state=','all') '03-Drivers\sc-driver-services.txt'
}

$pnpEntities = @()
try { $pnpEntities = @(Get-CimInstance Win32_PnPEntity -ErrorAction Stop) } catch { $Warnings.Add("Win32_PnPEntity failed: $($_.Exception.Message)") }

# Name is frequently empty for exactly the devices that have a problem code,
# which is the worst possible time to lose the label.
$pnpProjection = $pnpEntities | Select-Object Name,Description,PNPDeviceID,Manufacturer,Service,Status,ConfigManagerErrorCode
$pnpProjection | Export-Csv (Join-Path $RunDir '04-Devices\all-pnp-entities.csv') -NoTypeInformation -Encoding UTF8
$pnpProblems = @($pnpProjection | Where-Object { $_.ConfigManagerErrorCode -and $_.ConfigManagerErrorCode -ne 0 })
$pnpProblems | Export-Csv (Join-Path $RunDir '04-Devices\configmanager-problems.csv') -NoTypeInformation -Encoding UTF8
Add-Journal 'PnP entities' 'OK' 0 0 '04-Devices\all-pnp-entities.csv' "$($pnpProjection.Count) devices, $($pnpProblems.Count) with a problem code"

Invoke-PSCapture 'PnP signed drivers' {
    Get-CimInstance Win32_PnPSignedDriver |
        Select-Object DeviceName,DeviceID,Manufacturer,DriverProviderName,DriverVersion,DriverDate,InfName,IsSigned,Signer
} '03-Drivers\pnp-signed-drivers.csv' Csv | Out-Null

$runningDrivers = Invoke-PSCapture 'Running system drivers' {
    Get-CimInstance Win32_SystemDriver | Where-Object State -eq 'Running' |
        Select-Object Name,DisplayName,StartMode,State,PathName,ServiceType
} '03-Drivers\running-system-drivers.csv' Csv

# Authenticode signer lookup, cached per path. This is the single most useful
# reduction in the whole collector: it turns ~300 drivers into the ~10 that a
# human would actually look at.
$script:SignerCache = @{}
function Get-SignerSubject {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $p = $Path -replace '^\\\?\?\\','' -replace '^\\SystemRoot\\', "$env:SystemRoot\"
    if ($p -notmatch '^[A-Za-z]:\\') { $p = Join-Path $env:SystemRoot $p.TrimStart('\') }
    if ($script:SignerCache.ContainsKey($p)) { return $script:SignerCache[$p] }
    $subject = $null
    try {
        if (Test-Path -LiteralPath $p) {
            $sig = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
            if ($sig -and $sig.SignerCertificate) { $subject = $sig.SignerCertificate.Subject }
            elseif ($sig) { $subject = "UNSIGNED/$($sig.Status)" }
        } else { $subject = 'FILE_NOT_FOUND' }
    } catch { $subject = 'SIGNATURE_ERROR' }
    $script:SignerCache[$p] = $subject
    return $subject
}
function Test-MicrosoftSigner {
    param([AllowNull()][string]$Subject)
    if ([string]::IsNullOrWhiteSpace($Subject)) { return $false }
    return ($Subject -match 'O=Microsoft Corporation' -or $Subject -match 'CN=Microsoft Windows')
}

$thirdPartyDrivers = New-Object System.Collections.ArrayList
foreach ($d in @($runningDrivers)) {
    $path = Get-Prop $d 'PathName'
    $subj = Get-SignerSubject $path
    if (-not (Test-MicrosoftSigner $subj)) {
        $cn = Get-SignerCommonName $subj
        $null = $thirdPartyDrivers.Add([pscustomobject]@{
            Name=(Get-Prop $d 'Name'); Display=(Get-Prop $d 'DisplayName')
            StartMode=(Get-Prop $d 'StartMode'); Path=$path; Signer=$cn
        })
    }
}
$thirdPartyDrivers | Export-Csv (Join-Path $RunDir '03-Drivers\third-party-running-drivers.csv') -NoTypeInformation -Encoding UTF8
Add-Journal 'Third-party running drivers' 'OK' 0 0 '03-Drivers\third-party-running-drivers.csv' "$($thirdPartyDrivers.Count) of $(@($runningDrivers).Count) running drivers are not Microsoft-signed"

# Minifilters are the classic source of "why is my filesystem slow / why did
# the update fail" and there are rarely more than ~15 of them.
$minifilters = New-Object System.Collections.ArrayList
try {
    $driverByName = @{}
    foreach ($d in @($runningDrivers)) { $driverByName[[string](Get-Prop $d 'Name')] = $d }
    $fltLines = Get-Content (Join-Path $RunDir '03-Drivers\fltmc-filters.txt') -ErrorAction Stop
    foreach ($line in $fltLines) {
        if ($line -match '^\s*([A-Za-z0-9_.\-]+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$') {
            $fname = $Matches[1]
            $drv = $driverByName[$fname]
            $subj = Get-SignerSubject (Get-Prop $drv 'PathName')
            $cn = Get-SignerCommonName $subj
            $null = $minifilters.Add([pscustomobject]@{
                Filter=$fname; Instances=$Matches[3]; Altitude=$Matches[4]
                Microsoft=(Test-MicrosoftSigner $subj); Signer=$cn
            })
        }
    }
} catch { $Warnings.Add("Minifilter parse failed: $($_.Exception.Message)") }
$minifilters | Export-Csv (Join-Path $RunDir '03-Drivers\minifilters-resolved.csv') -NoTypeInformation -Encoding UTF8

# ===================================================================== 05 ====
# Events. One enumeration pass, server-side filtering, capped digest.

$rawLogs = @(
    'System','Application','Setup',
    'Microsoft-Windows-WindowsUpdateClient/Operational',
    'Microsoft-Windows-CodeIntegrity/Operational',
    'Microsoft-Windows-Kernel-Boot/Operational',
    'Microsoft-Windows-Kernel-PnP/Configuration',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-Storage-Storport/Operational',
    'Microsoft-Windows-DriverFrameworks-UserMode/Operational'
)
foreach ($log in $rawLogs) { Export-EventLogIfPresent $log }

$HighSignalProviders = @(
    'Microsoft-Windows-WHEA-Logger','Microsoft-Windows-Kernel-Power','Microsoft-Windows-Kernel-Boot',
    'Microsoft-Windows-Kernel-PnP','Microsoft-Windows-Kernel-General','Microsoft-Windows-WER-SystemErrorReporting',
    'Microsoft-Windows-CodeIntegrity','Microsoft-Windows-WindowsUpdateClient','Microsoft-Windows-Winlogon',
    'Disk','Ntfs','stornvme','storahci','storport','iaStorA','iaStorAC','volmgr','volsnap','partmgr',
    'Service Control Manager','Application Error','Application Hang','Windows Error Reporting',
    '.NET Runtime','Display','EventLog','BugCheck','DCOM','User32','VSS','Microsoft-Windows-DistributedCOM'
)

# ONE pass over the window. Everything downstream is computed from this array
# instead of re-querying the event log, which used to cost 2-3 full scans.
$allEvents = @()
$truncatedLogs = @()
$swEvents = [Diagnostics.Stopwatch]::StartNew()
foreach ($log in @('System','Application')) {
    try {
        $filter = @{LogName=$log;StartTime=$Since;Level=1,2,3}
        $batch = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEventsPerLog -ErrorAction Stop)
        # Get-WinEvent returns the NEWEST N and says nothing about the rest, so
        # a busy log would silently lose its oldest faults and hand us a
        # first-seen date that is simply wrong. Cost one extra count query to
        # find out, and label the window instead of pretending it is complete.
        if ($batch.Count -ge $MaxEventsPerLog) {
            $total = $null
            try { $total = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop).Count } catch {}
            $truncatedLogs += [pscustomobject]@{
                Log = $log; Returned = $batch.Count; Available = $total; Cap = $MaxEventsPerLog
            }
            $Warnings.Add("$log hit the $MaxEventsPerLog event cap. Counts are lower bounds and first-seen dates are not the true earliest occurrence.")
        }
        $allEvents += $batch
    } catch {
        if ($_.Exception.Message -notmatch 'No events were found') { $Warnings.Add("Event query failed for ${log}: $($_.Exception.Message)") }
    }
}
$swEvents.Stop()
Add-Journal 'Event enumeration' $(if ($truncatedLogs.Count) { 'TRUNCATED' } else { 'OK' }) 0 $swEvents.Elapsed.TotalSeconds '05-Events' "$($allEvents.Count) warning/error/critical events in $EventDays days"

$allEvents |
    Select-Object TimeCreated,LogName,ProviderName,Id,Level,LevelDisplayName,
                  @{n='Message';e={ Compress-Message $_.Message 600 }} |
    Export-Csv (Join-Path $RunDir '05-Events\warn-error-critical.csv') -NoTypeInformation -Encoding UTF8

$signatures = @(
    $allEvents | Group-Object -Property LogName,ProviderName,Id,Level | ForEach-Object {
        $g = @($_.Group | Sort-Object TimeCreated)
        [pscustomobject]@{
            LogName=$g[0].LogName; ProviderName=$g[0].ProviderName; EventId=$g[0].Id
            Level=$g[0].Level; LevelName=$g[0].LevelDisplayName; Count=$_.Count
            FirstSeen=$g[0].TimeCreated; LastSeen=$g[-1].TimeCreated
            HighSignal=($HighSignalProviders -contains $g[0].ProviderName)
            SampleMessage=(Compress-Message $g[-1].Message 400)
        }
    } | Sort-Object @{e='HighSignal';Descending=$true},@{e='Level';Ascending=$true},@{e='Count';Descending=$true}
)
$signatures | Export-Csv (Join-Path $RunDir '05-Events\event-signatures.csv') -NoTypeInformation -Encoding UTF8

Invoke-PSCapture 'Reliability records' {
    Get-CimInstance -Namespace root\cimv2 -Class Win32_ReliabilityRecords -ErrorAction SilentlyContinue |
        Where-Object TimeGenerated -ge $Since | Sort-Object TimeGenerated -Descending |
        Select-Object TimeGenerated,SourceName,ProductName,EventIdentifier,LogFile,
                      @{n='Message';e={ Compress-Message $_.Message 300 }}
} '05-Events\reliability-records.csv' Csv | Out-Null

function Measure-Events {
    param([string]$Provider,[int[]]$Id)
    $m = @($allEvents | Where-Object { $_.ProviderName -eq $Provider -and ($null -eq $Id -or $Id -contains $_.Id) })
    return $m.Count
}
$countWhea      = Measure-Events 'Microsoft-Windows-WHEA-Logger' $null
$countBugCheck  = Measure-Events 'Microsoft-Windows-WER-SystemErrorReporting' @(1001)
$countUnexpShut = @($allEvents | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' -and $_.Id -eq 41 }).Count
$countAppCrash  = Measure-Events 'Application Error' $null
$countAppHang   = Measure-Events 'Application Hang' $null
$countScm       = Measure-Events 'Service Control Manager' $null
$countDiskNtfs  = @($allEvents | Where-Object { $_.ProviderName -in @('Disk','Ntfs','stornvme','storahci','storport','volmgr','volsnap') }).Count
$countCodeInt   = Measure-Events 'Microsoft-Windows-CodeIntegrity' $null

# ===================================================================== 06/07 =
# WER manifests and dump inventory (metadata only, never payloads)

$werRoots = @(
    "$env:ProgramData\Microsoft\Windows\WER\ReportArchive",
    "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"
)
Invoke-PSCapture 'WER file inventory' {
    foreach ($root in $werRoots) {
        if (Test-Path $root) {
            Get-ChildItem $root -File -Recurse -Force -ErrorAction SilentlyContinue |
                Select-Object @{n='Root';e={$root}},FullName,Length,CreationTimeUtc,LastWriteTimeUtc,Extension
        }
    }
} '06-WER\wer-file-inventory.csv' Csv | Out-Null

$werCopy = Join-Path $RunDir '06-WER\Report-wers'
New-Item -ItemType Directory -Force $werCopy | Out-Null
foreach ($root in $werRoots) {
    if (Test-Path $root) {
        Get-ChildItem $root -Filter Report.wer -File -Recurse -Force -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 60 | ForEach-Object {
                try {
                    if ($_.Length -le 512KB) {
                        $safe = (($_.Directory.Name -replace '[^A-Za-z0-9._-]','_') + '-' +
                                 ([guid]::NewGuid().ToString('N').Substring(0,8)) + '-Report.wer')
                        Copy-Item $_.FullName (Join-Path $werCopy $safe) -Force
                    }
                } catch {}
            }
    }
}

$dumpRoots = @("$env:SystemRoot\Minidump","$env:SystemRoot\LiveKernelReports","$env:SystemRoot\MEMORY.DMP","$env:LOCALAPPDATA\CrashDumps")
$dumps = Invoke-PSCapture 'Dump inventory' {
    foreach ($root in $dumpRoots) {
        if (Test-Path -LiteralPath $root) {
            $i = Get-Item -LiteralPath $root -Force -ErrorAction SilentlyContinue
            if ($i -and -not $i.PSIsContainer) { $i | Select-Object FullName,Length,CreationTimeUtc,LastWriteTimeUtc,Extension }
            else { Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue | Select-Object FullName,Length,CreationTimeUtc,LastWriteTimeUtc,Extension }
        }
    }
} '07-Dumps\dump-inventory.csv' Csv

# ===================================================================== 08 ====
# Boot / recovery / restore

Invoke-NativeCapture 'BCD all' 'bcdedit.exe' @('/enum','all') '08-Boot-Restore\bcdedit-all.txt'
Invoke-NativeCapture 'WinRE info' 'reagentc.exe' @('/info') '08-Boot-Restore\reagentc-info.txt'
Invoke-NativeCapture 'VSS writers' 'vssadmin.exe' @('list','writers') '08-Boot-Restore\vss-writers.txt'
Invoke-NativeCapture 'VSS providers' 'vssadmin.exe' @('list','providers') '08-Boot-Restore\vss-providers.txt'
Invoke-NativeCapture 'VSS shadows' 'vssadmin.exe' @('list','shadows') '08-Boot-Restore\vss-shadows.txt'
Invoke-NativeCapture 'VSS shadowstorage' 'vssadmin.exe' @('list','shadowstorage') '08-Boot-Restore\vss-shadowstorage.txt'
Invoke-PSCapture 'System Restore registry' { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -ErrorAction SilentlyContinue | Format-List * } '08-Boot-Restore\system-restore-registry.txt' | Out-Null
$restorePoints = Invoke-PSCapture 'Restore points' { Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Sort-Object CreationTime -Descending | Select-Object SequenceNumber,Description,RestorePointType,EventType,CreationTime } '08-Boot-Restore\restore-points.csv' Csv

$secureBoot = $null
try { $secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $secureBoot = $null }

$winreEnabled = $null
try {
    $re = Get-Content (Join-Path $RunDir '08-Boot-Restore\reagentc-info.txt') -Raw -ErrorAction Stop
    if ($re -match '(?im)^\s*Windows RE status:\s*(\w+)') { $winreEnabled = ($Matches[1] -eq 'Enabled') }
} catch {}

$vssWriterFailures = @()
try {
    $vw = Get-Content (Join-Path $RunDir '08-Boot-Restore\vss-writers.txt') -Raw -ErrorAction Stop
    $vssWriterFailures = @([regex]::Matches($vw, "(?s)Writer name: '([^']+)'.*?State: \[\d+\] (\w+).*?Last error: ([^\r\n]+)") |
        Where-Object { $_.Groups[3].Value.Trim() -ne 'No error' } |
        ForEach-Object { [pscustomobject]@{Writer=$_.Groups[1].Value;State=$_.Groups[2].Value;LastError=$_.Groups[3].Value.Trim()} })
} catch {}

# ===================================================================== 09 ====
# Power

foreach ($x in @(
    @{N='available states'; A=@('/a');               F='powercfg-a.txt'},
    @{N='active scheme';    A=@('/getactivescheme'); F='powercfg-active-scheme.txt'},
    @{N='requests';         A=@('/requests');        F='powercfg-requests.txt'},
    @{N='lastwake';         A=@('/lastwake');        F='powercfg-lastwake.txt'},
    @{N='waketimers';       A=@('/waketimers');      F='powercfg-waketimers.txt'}
)) { Invoke-NativeCapture "powercfg $($x.N)" 'powercfg.exe' $x.A "09-Power\$($x.F)" }

$fastStartup = $null; $hiberPresent = $false
try { $fastStartup = [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction Stop).HiberbootEnabled } catch {}
try { $hiberPresent = [bool](Get-Item "$env:SystemDrive\hiberfil.sys" -Force -ErrorAction Stop) } catch {}
[pscustomobject]@{HiberbootEnabled=$fastStartup;HiberfilePresent=$hiberPresent} |
    ConvertTo-Json | Out-File (Join-Path $RunDir '09-Power\hibernation-fast-startup.json') -Encoding utf8

if ($Depth -eq 'Full') {
    $energy = Join-Path $RunDir '09-Power\energy.html'
    Invoke-NativeCapture 'powercfg energy' 'powercfg.exe' @('/energy','/duration','30','/output',$energy) '09-Power\powercfg-energy-command.txt'
}

# ===================================================================== 10 ====
# Network

Invoke-NativeCapture 'ipconfig all' 'ipconfig.exe' @('/all') '10-Network\ipconfig-all.txt'
Invoke-NativeCapture 'route print' 'route.exe' @('print') '10-Network\route-print.txt'
Invoke-NativeCapture 'winsock catalog' 'netsh.exe' @('winsock','show','catalog') '10-Network\winsock-catalog.txt'
$adapters = Invoke-PSCapture 'Network adapters' {
    Get-NetAdapter -IncludeHidden |
        Select-Object Name,InterfaceDescription,InterfaceIndex,Status,MacAddress,LinkSpeed,MediaType,PhysicalMediaType,DriverInformation,DriverFileName,DriverVersion
} '10-Network\net-adapters.csv' Csv
Invoke-PSCapture 'IP configuration' { Get-NetIPConfiguration -All | Select-Object InterfaceAlias,InterfaceIndex,NetProfile,IPv4Address,IPv6Address,IPv4DefaultGateway,IPv6DefaultGateway,DNSServer } '10-Network\net-ip.clixml' Clixml | Out-Null
Invoke-PSCapture 'TCP listeners' {
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object LocalAddress,LocalPort,OwningProcess,
                      @{n='ProcessName';e={ try{(Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName}catch{$null} }} |
        Sort-Object LocalPort
} '10-Network\tcp-listeners.csv' Csv | Out-Null
$firewall = Invoke-PSCapture 'Firewall profiles' {
    Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,NotifyOnListen,AllowInboundRules,AllowLocalFirewallRules,AllowLocalIPsecRules
} '10-Network\firewall-profiles.csv' Csv

# ===================================================================== 11 ====
# Services / tasks / startup / installed software

$services = Invoke-PSCapture 'Services' {
    Get-CimInstance Win32_Service |
        Select-Object Name,DisplayName,State,StartMode,StartName,ProcessId,
                      @{n='PathName';e={ Protect-SensitiveText $_.PathName }} |
        Sort-Object Name
} '11-Software-Startup\services.csv' Csv

Invoke-PSCapture 'Scheduled tasks' {
    Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
        $t = $_
        $acts = @($t.Actions | ForEach-Object { Protect-SensitiveText ((($_.Execute + ' ' + $_.Arguments)).Trim()) })
        [pscustomobject]@{TaskPath=$t.TaskPath;TaskName=$t.TaskName;State=$t.State;Author=$t.Author;Actions=($acts -join ' | ')}
    }
} '11-Software-Startup\scheduled-tasks.csv' Csv | Out-Null

$startupCommands = Invoke-PSCapture 'Startup commands' {
    Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue |
        Select-Object Name,Location,User,@{n='Command';e={ Protect-SensitiveText $_.Command }}
} '11-Software-Startup\startup-commands.csv' Csv

$software = Invoke-PSCapture 'Installed software' {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation,PSChildName |
        Sort-Object DisplayName
} '11-Software-Startup\installed-software.csv' Csv

# Auto-start services whose image is not Microsoft-signed. Same reduction trick
# as the drivers: this is the list a human would actually read.
$thirdPartyAutoServices = New-Object System.Collections.ArrayList
foreach ($s in @($services | Where-Object { $_.StartMode -eq 'Auto' })) {
    $img = Get-Prop $s 'PathName'
    if (-not $img) { continue }
    $exe = if ($img -match '^\s*"([^"]+)"') { $Matches[1] } elseif ($img -match '^\s*(\S+\.exe)') { $Matches[1] } else { $img }
    $subj = Get-SignerSubject $exe
    if (-not (Test-MicrosoftSigner $subj)) {
        $cn = Get-SignerCommonName $subj
        $null = $thirdPartyAutoServices.Add([pscustomobject]@{
            Name=(Get-Prop $s 'Name'); Display=(Get-Prop $s 'DisplayName')
            State=(Get-Prop $s 'State'); Image=$exe; Signer=$cn
        })
    }
}
$thirdPartyAutoServices | Export-Csv (Join-Path $RunDir '11-Software-Startup\third-party-auto-services.csv') -NoTypeInformation -Encoding UTF8

# ===================================================================== 12 ====
# Security

$defender = Invoke-PSCapture 'Defender status' { Get-MpComputerStatus -ErrorAction SilentlyContinue } '12-Security\defender-status.txt'
Invoke-PSCapture 'Defender preferences' {
    try {
        $p = Get-MpPreference -ErrorAction Stop
        [pscustomobject]@{
            DisableRealtimeMonitoring=$p.DisableRealtimeMonitoring; DisableBehaviorMonitoring=$p.DisableBehaviorMonitoring
            DisableIOAVProtection=$p.DisableIOAVProtection; DisableScriptScanning=$p.DisableScriptScanning
            MAPSReporting=$p.MAPSReporting; SubmitSamplesConsent=$p.SubmitSamplesConsent; PUAProtection=$p.PUAProtection
            ExclusionPath=$p.ExclusionPath; ExclusionProcess=$p.ExclusionProcess; ExclusionExtension=$p.ExclusionExtension
        }
    } catch { $_ }
} '12-Security\defender-preferences.clixml' Clixml | Out-Null

$deviceGuard = Invoke-PSCapture 'Device Guard' {
    Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
} '12-Security\device-guard.txt'
$tpm = Invoke-PSCapture 'TPM' { try { Get-Tpm -ErrorAction Stop } catch { $null } } '12-Security\tpm.txt'
$bitlocker = Invoke-PSCapture 'BitLocker volumes' {
    try { Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint,VolumeType,VolumeStatus,ProtectionStatus,EncryptionMethod,EncryptionPercentage,AutoUnlockEnabled,LockStatus } catch { $null }
} '12-Security\bitlocker.csv' Csv

$uacEnabled = $null; $runAsPPL = $null
try { $uacEnabled = [bool](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction Stop).EnableLUA } catch {}
try { $runAsPPL   = [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction Stop).RunAsPPL } catch {}
[pscustomobject]@{EnableLUA=$uacEnabled;RunAsPPL=$runAsPPL} | ConvertTo-Json |
    Out-File (Join-Path $RunDir '12-Security\uac-lsa.json') -Encoding utf8

Invoke-PSCapture 'Enabled optional features' {
    Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue | Where-Object State -eq Enabled | Select-Object FeatureName
} '12-Security\enabled-optional-features.csv' Csv | Out-Null

# ===================================================================== 13 ====
# Lightweight performance baseline

$perf = $null
try {
    $c = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction SilentlyContinue
    $y = Get-CimInstance Win32_PerfFormattedData_PerfOS_System -ErrorAction SilentlyContinue
    $m = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory -ErrorAction SilentlyContinue
    $k = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" -ErrorAction SilentlyContinue
    $perf = [pscustomobject]@{
        CPUPercent=(Get-Prop $c 'PercentProcessorTime'); DPCPercent=(Get-Prop $c 'PercentDPCTime')
        InterruptPercent=(Get-Prop $c 'PercentInterruptTime'); ProcessorQueueLength=(Get-Prop $y 'ProcessorQueueLength')
        AvailableMBytes=(Get-Prop $m 'AvailableMBytes'); PagesPerSec=(Get-Prop $m 'PagesPersec')
        DiskQueueLength=(Get-Prop $k 'CurrentDiskQueueLength'); PercentDiskTime=(Get-Prop $k 'PercentDiskTime')
    }
    $perf | ConvertTo-Json | Out-File (Join-Path $RunDir '13-Performance\perf-baseline.json') -Encoding utf8
} catch { $Warnings.Add("Performance baseline failed: $($_.Exception.Message)") }

$allProcesses = Invoke-PSCapture 'Processes' {
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{
            Name=$_.ProcessName; Id=$_.Id
            CPUSeconds=(Get-CpuSeconds $_)
            WorkingSetMB=[math]::Round($_.WorkingSet64/1MB,1)
            PrivateMB=[math]::Round($_.PrivateMemorySize64/1MB,1)
            Handles=$_.HandleCount
        }
    }
} '13-Performance\processes.csv' Csv

# Both rankings must come from the full set. Ranking memory inside the CPU
# top-60 hides the classic case: a process that burns no CPU and eats all the RAM.
$topByCpu    = @($allProcesses | Sort-Object CPUSeconds -Descending  | Select-Object -First 10 Name,CPUSeconds,WorkingSetMB)
$topByMemory = @($allProcesses | Sort-Object WorkingSetMB -Descending | Select-Object -First 10 Name,WorkingSetMB,CPUSeconds)

# ===================================================================== 14 ====
# Updates / pending reboot

$hotfixes = Invoke-PSCapture 'Hotfixes' { Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID,Description,InstalledOn } '14-Updates\hotfixes.csv' Csv

$pendingCbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
$pendingWu  = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
$pendingRen = [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)
[pscustomobject]@{CBSRebootPending=$pendingCbs;WURebootRequired=$pendingWu;PendingFileRenameOperations=$pendingRen} |
    ConvertTo-Json | Out-File (Join-Path $RunDir '14-Updates\pending-reboot.json') -Encoding utf8

# =================================================================== servicing
# CBS/DISM logs are copied only when there is a reason to read them. CBS.log is
# routinely 5-50 MB and is useless unless a scan actually reported corruption.

function Read-Text([string]$rel) { try { return Get-Content (Join-Path $RunDir $rel) -Raw -ErrorAction Stop } catch { return '' } }

$dismText = Read-Text '01-Integrity\DISM-ScanHealth.txt'
if (-not $dismText) { $dismText = Read-Text '01-Integrity\DISM-CheckHealth.txt' }
$sfcText  = Read-Text '01-Integrity\SFC-VerifyOnly.txt'

$dismClass = if ($dismText -match 'No component store corruption detected') { 'CLEAN' }
             elseif ($dismText -match 'repairable|corruption detected') { 'ATTENTION' }
             elseif (-not $dismText) { 'NOT_RUN' } else { 'UNKNOWN' }
$sfcClass  = if ($Depth -ne 'Full') { 'NOT_RUN' }
             elseif ($sfcText -match 'did not find any integrity violations') { 'CLEAN' }
             elseif ($sfcText -match 'integrity violations|found corrupt files') { 'ATTENTION' }
             else { 'UNKNOWN' }

if ($dismClass -eq 'ATTENTION' -or $sfcClass -eq 'ATTENTION') {
    foreach ($src in @("$env:SystemRoot\Logs\CBS\CBS.log","$env:SystemRoot\Logs\DISM\dism.log")) {
        if (Test-Path $src) {
            try { Copy-Item $src (Join-Path $RunDir '01-Integrity') -Force -ErrorAction Stop }
            catch { $Warnings.Add("Could not copy ${src}: $($_.Exception.Message)") }
        }
    }
} else {
    'CBS.log and dism.log were not copied because no scan reported corruption. Re-run with -Depth Full, or copy them manually if a servicing question arises.' |
        Out-File (Join-Path $RunDir '01-Integrity\SERVICING-LOGS-SKIPPED.txt') -Encoding utf8
}

# ================================================================== TRIAGE ===
# Everything below is deliberate token engineering. The agent reads this and
# nothing else unless it has a specific question.

$uptimeHours = $null
try { $uptimeHours = [math]::Round(((Get-Date) - (Get-Prop $os 'LastBootUpTime')).TotalHours,1) } catch {}

$hvciRunning = $null
try {
    $svcRunning = @(Get-Prop $deviceGuard 'SecurityServicesRunning')
    $hvciRunning = ($svcRunning -contains 2)
} catch {}

$volumeDigest = @(
    $volumes | Where-Object { $_.DriveLetter } | ForEach-Object {
        $size = [double](Get-Prop $_ 'Size' 0); $free = [double](Get-Prop $_ 'SizeRemaining' 0)
        [pscustomobject]@{
            Letter=[string]$_.DriveLetter; FileSystem=$_.FileSystem
            SizeGB=[math]::Round($size/1GB,1); FreeGB=[math]::Round($free/1GB,1)
            FreePercent=$(if ($size -gt 0) { [math]::Round(100*$free/$size,1) } else { $null })
            Health=$_.HealthStatus
            Dirty=($dirtyVolumes -contains "$($_.DriveLetter):")
        }
    }
)

$diskDigest = @(
    $physicalDisks | ForEach-Object {
        $pd = $_
        $rc = $reliability | Where-Object { $_.SerialNumber -eq (Get-Prop $pd 'SerialNumber') } | Select-Object -First 1
        [pscustomobject]@{
            Model=(Protect-Identity (Get-Prop $pd 'FriendlyName'))
            # A disk serial is a persistent hardware identifier and is never
            # needed to reason about disk health. Protect-Identity only rewrites
            # registered literals, so it would have passed this straight through
            # while the digest claimed to be redacted.
            Serial=(Get-SafeField (Get-Prop $pd 'SerialNumber') '<SERIAL>')
            Media=(Get-Prop $pd 'MediaType'); Bus=(Get-Prop $pd 'BusType')
            SizeGB=[math]::Round([double](Get-Prop $pd 'Size' 0)/1GB,1)
            Health=(Get-Prop $pd 'HealthStatus')
            WearPercent=(Get-Prop $rc 'Wear'); PowerOnHours=(Get-Prop $rc 'PowerOnHours')
            TempC=(Get-Prop $rc 'Temperature')
            ReadErrUncorrected=(Get-Prop $rc 'ReadErrorsUncorrected')
            WriteErrUncorrected=(Get-Prop $rc 'WriteErrorsUncorrected')
        }
    }
)

$dumpArray = @($dumps)
$recentSoftware = @($software | Where-Object { $_.InstallDate } | Sort-Object InstallDate -Descending | Select-Object -First 15 |
    ForEach-Object { [pscustomobject]@{Name=$_.DisplayName;Version=$_.DisplayVersion;Publisher=$_.Publisher;Installed=$_.InstallDate} })

$failedProbes = @($Journal | Where-Object { $_.Status -in @('ERROR','TIMEOUT') } | Select-Object -ExpandProperty Name -Unique)

# A native tool exiting non-zero is not automatically a failure: pnputil
# /enum-devices /problem exits non-zero when there are no problem devices, and
# several powercfg/fsutil queries do the same. Folding these into failed_probes
# would drown the real failures. But the reviewer's underlying point stands -
# a genuinely broken native probe would otherwise look like an empty, healthy
# result. So surface them as their own category and let the agent judge.
$nonZeroProbes = @($Journal | Where-Object { $_.Status -eq 'NONZERO' } |
    Select-Object @{n='Probe';e={$_.Name}},ExitCode -Unique)

$triage = [ordered]@{
    schema_version = '1.0'
    generated_at   = (Get-Date).ToString('o')
    run_id         = (Protect-Identity $RunName)
    evidence_root  = (Protect-Identity $RunDir)
    depth          = $Depth
    redacted       = [bool]$Redact

    target = [ordered]@{
        computer        = (Get-SafeField $env:COMPUTERNAME '<COMPUTER>')
        os_caption      = (Get-Prop $os 'Caption')
        os_build        = (Get-Prop $os 'BuildNumber')
        display_version = (Get-Prop $cv 'DisplayVersion')
        edition_id      = (Get-Prop $cv 'EditionID')
        architecture    = (Get-Prop $os 'OSArchitecture')
        manufacturer    = (Get-Prop $cs 'Manufacturer')
        model           = (Get-Prop $cs 'Model')
        cpu             = (Get-Prop ($cpu | Select-Object -First 1) 'Name')
        ram_gb          = [math]::Round([double](Get-Prop $cs 'TotalPhysicalMemory' 0)/1GB,1)
        bios_version    = (Get-Prop $bios 'SMBIOSBIOSVersion')
        bios_date       = $(try { (Get-Prop $bios 'ReleaseDate').ToString('yyyy-MM-dd') } catch { $null })
        virtualized     = (Get-Prop $cs 'HypervisorPresent')
        uptime_hours    = $uptimeHours
    }

    collection = [ordered]@{
        started            = $StartTime.ToString('o')
        duration_minutes   = [math]::Round(((Get-Date) - $StartTime).TotalMinutes,1)
        event_window_days  = $EventDays
        events_examined    = $allEvents.Count
        elevated           = $true
        failed_probes      = $failedProbes
        nonzero_probes     = $nonZeroProbes
        truncated_logs     = @($truncatedLogs)
        warnings           = @($Warnings)
    }

    flags = [ordered]@{
        dism_component_store   = $dismClass
        sfc_verify             = $sfcClass
        pending_reboot         = [bool]($pendingCbs -or $pendingWu -or $pendingRen)
        dirty_volumes          = @($dirtyVolumes)
        secure_boot            = $secureBoot
        winre_enabled          = $winreEnabled
        restore_point_count    = @($restorePoints).Count
        vss_writer_failures    = @($vssWriterFailures)
        fast_startup_enabled   = $fastStartup
        hiberfile_present      = $hiberPresent
        uac_enabled            = $uacEnabled
        lsa_protection         = $runAsPPL
        hvci_running           = $hvciRunning
        # No $false default. Get-Tpm succeeds un-elevated but returns empty
        # properties, so defaulting turned "cannot tell" into a confident
        # "no TPM present" - a security-relevant field reading as a real
        # negative when it was actually unknown.
        tpm_present            = (Get-Prop $tpm 'TpmPresent')
        tpm_ready              = (Get-Prop $tpm 'TpmReady')
        defender_realtime      = (Get-Prop $defender 'RealTimeProtectionEnabled')
        defender_tamper        = (Get-Prop $defender 'IsTamperProtected')
        defender_signature_age = (Get-Prop $defender 'AntivirusSignatureAge')
        firewall_disabled_profiles = @($firewall | Where-Object { -not $_.Enabled } | Select-Object -ExpandProperty Name)
        bitlocker              = @($bitlocker | Select-Object MountPoint,VolumeStatus,ProtectionStatus)
        crash_dumps_present    = $dumpArray.Count
        latest_dump            = $(if ($dumpArray.Count) { (@($dumpArray | Sort-Object LastWriteTimeUtc -Descending)[0]).LastWriteTimeUtc.ToString('o') } else { $null })
    }

    counters = [ordered]@{
        whea                 = $countWhea
        bugcheck             = $countBugCheck
        unexpected_shutdown  = $countUnexpShut
        pnp_problem_devices  = $pnpProblems.Count
        app_crashes          = $countAppCrash
        app_hangs            = $countAppHang
        service_control_mgr  = $countScm
        disk_filesystem      = $countDiskNtfs
        code_integrity       = $countCodeInt
        distinct_signatures  = @($signatures).Count
    }

    storage      = [ordered]@{ disks = $diskDigest; volumes = $volumeDigest }
    pnp_problems = @($pnpProblems | Select-Object @{n='Name';e={Protect-Identity (@($_.Name,$_.Description,$_.PNPDeviceID) | Where-Object { $_ } | Select-Object -First 1)}},
                                                  @{n='DeviceId';e={Protect-Identity $_.PNPDeviceID}},
                                                  @{n='ErrorCode';e={$_.ConfigManagerErrorCode}},Service)

    top_event_signatures = @($signatures | Select-Object -First 40 |
        Select-Object LogName,ProviderName,EventId,LevelName,Count,
                      @{n='FirstSeen';e={ try { $_.FirstSeen.ToString('yyyy-MM-dd HH:mm') } catch { $null } }},
                      @{n='LastSeen'; e={ try { $_.LastSeen.ToString('yyyy-MM-dd HH:mm') } catch { $null } }},
                      @{n='Sample';   e={ Protect-Identity $_.SampleMessage }})

    third_party_kernel_drivers = @($thirdPartyDrivers | Select-Object Name,StartMode,Signer)
    third_party_minifilters    = @($minifilters | Where-Object { -not $_.Microsoft } | Select-Object Filter,Altitude,Signer)
    third_party_auto_services  = @($thirdPartyAutoServices | Select-Object Name,State,Signer)
    startup_entries            = @($startupCommands | Select-Object Name,Location,@{n='User';e={Protect-Identity $_.User}})

    performance = [ordered]@{
        snapshot       = $perf
        top_by_cpu     = $topByCpu
        top_by_memory  = $topByMemory
    }

    recent_software = $recentSoftware
    recent_hotfixes = @($hotfixes | Select-Object -First 8)

    trimmed = @()
}

# --- cap enforcement -------------------------------------------------------
# The cap is a promise about the operator's context budget, so it has to hold on
# a machine with 200 problem devices and 40 disks, not just on a tidy one.
#
# Three stages:
#   1. a deliberate plan - least discriminating evidence goes first;
#   2. a generic fallback that halves every remaining list section, including
#      the ones the plan does not name, until it fits;
#   3. a hard post-serialization check that accounts for the trim metadata
#      itself, because `trimmed` and `digest_bytes` are added after measuring.
#
# Every reduction is recorded, so a short section always means "trimmed, go
# query the raw evidence" and never "the machine was clean".

$trimPlan = @(
    @{ Path='startup_entries';            Keep=15 },
    @{ Path='recent_software';            Keep=8  },
    @{ Path='third_party_auto_services';  Keep=15 },
    @{ Path='top_event_signatures';       Keep=25 },
    @{ Path='third_party_kernel_drivers'; Keep=20 },
    @{ Path='top_event_signatures';       Keep=15 },
    @{ Path='recent_software';            Keep=0  },
    @{ Path='startup_entries';            Keep=0  }
)

# Ordered least to most diagnostically valuable. pnp_problems and storage come
# last on purpose: losing them is losing the point of the audit.
$fallbackOrder = @(
    'recent_hotfixes','startup_entries','recent_software','third_party_auto_services',
    'third_party_minifilters','third_party_kernel_drivers','top_event_signatures',
    'pnp_problems'
)

function Measure-TriageBytes {
    param($Object)
    return [Text.Encoding]::UTF8.GetByteCount(($Object | ConvertTo-Json -Depth 8 -Compress))
}

function Set-TrimmedSection {
    param([string]$Key,[int]$Keep)
    $current = @($triage[$Key])
    if ($current.Count -le $Keep) { return $false }
    $triage[$Key] = @($current | Select-Object -First $Keep)
    $Trimmed.Add("$Key`: $($current.Count) -> $Keep (query raw evidence for the rest)")
    return $true
}

# Reserve room for the trim metadata that has not been added yet.
$reserve = 400
$budget = $MaxTriageBytes - $reserve
$size = Measure-TriageBytes $triage

foreach ($step in $trimPlan) {
    if ($size -le $budget) { break }
    if (Set-TrimmedSection $step.Path $step.Keep) { $size = Measure-TriageBytes $triage }
}

# Stage 2: nothing in the plan is left, so halve everything repeatedly.
$guard = 0
while ($size -gt $budget -and $guard -lt 40) {
    $guard++
    $shrunk = $false
    foreach ($key in $fallbackOrder) {
        if ($size -le $budget) { break }
        $count = @($triage[$key]).Count
        if ($count -le 1) { continue }
        if (Set-TrimmedSection $key ([math]::Max(1,[int][math]::Floor($count / 2)))) {
            $shrunk = $true
            $size = Measure-TriageBytes $triage
        }
    }
    if (-not $shrunk) { break }
}

# Stage 3: the storage section is machine-dependent and not in either list.
if ($size -gt $budget -and @($triage.storage.volumes).Count -gt 8) {
    $n = @($triage.storage.volumes).Count
    $triage.storage.volumes = @($triage.storage.volumes | Select-Object -First 8)
    $Trimmed.Add("storage.volumes: $n -> 8 (see 02-Storage\volumes.csv)")
    $size = Measure-TriageBytes $triage
}

$triage['trimmed'] = @($Trimmed)
$triage['digest_bytes'] = Measure-TriageBytes $triage

$triageJson = $triage | ConvertTo-Json -Depth 8 -Compress
$finalBytes = [Text.Encoding]::UTF8.GetByteCount($triageJson)

# If trimming could not reach the budget, do not ship a file called TRIAGE.json:
# that name is a promise about size. Write the data under a name that says what
# it is, keep going so the operator still gets a usable TRIAGE.md, and exit
# non-zero at the very end. Failing loudly must not mean handing back nothing
# after a multi-minute collection.
$digestOverBudget = ($finalBytes -gt $MaxTriageBytes)
if ($digestOverBudget) {
    $Warnings.Add("TRIAGE.json is $finalBytes bytes after all trimming, over the $MaxTriageBytes cap. Written as TRIAGE-OVERSIZED.json instead.")
    [IO.File]::WriteAllText((Join-Path $RunDir 'TRIAGE-OVERSIZED.json'), $triageJson, (New-Object Text.UTF8Encoding($false)))
} else {
    [IO.File]::WriteAllText((Join-Path $RunDir 'TRIAGE.json'), $triageJson, (New-Object Text.UTF8Encoding($false)))
}

# --- markdown digest -------------------------------------------------------

$md = New-Object System.Text.StringBuilder
$null = $md.AppendLine("# Windows No-Bullshit Audit - TRIAGE")
$null = $md.AppendLine()
$null = $md.AppendLine("Depth **$Depth** | window **$EventDays d** | generated $($StartTime.ToString('u')) | digest $($triage['digest_bytes']) bytes")
if ($Redact) { $null = $md.AppendLine(); $null = $md.AppendLine('> Identity fields are pseudonymized (`-Redact`).') }
$null = $md.AppendLine()
$null = $md.AppendLine("**Target:** $(Get-SafeField $env:COMPUTERNAME '<COMPUTER>') | $(Get-Prop $os 'Caption') $(Get-Prop $cv 'DisplayVersion') build $(Get-Prop $os 'BuildNumber') $(Get-Prop $os 'OSArchitecture') | $(Get-Prop $cs 'Manufacturer') $(Get-Prop $cs 'Model') | $($triage.target.ram_gb) GB RAM | up $uptimeHours h")
$null = $md.AppendLine()

$null = $md.AppendLine('## Health flags')
$null = $md.AppendLine()
$null = $md.AppendLine('| Flag | Value |')
$null = $md.AppendLine('|---|---|')
foreach ($k in $triage.flags.Keys) {
    $v = $triage.flags[$k]
    $text = if ($null -eq $v) { 'unknown' }
            elseif ($v -is [bool]) { $v.ToString().ToLower() }
            elseif (($v -is [array]) -or (($v -is [System.Collections.IEnumerable]) -and ($v -isnot [string]))) {
                $a = @($v); if ($a.Count -eq 0) { 'none' } else { ($a | ForEach-Object { if ($_ -is [string]) { $_ } else { ($_ | ConvertTo-Json -Compress -Depth 3) } }) -join '; ' }
            } else { [string]$v }
    if ($text.Length -gt 160) { $text = $text.Substring(0,160) + '...' }
    $null = $md.AppendLine("| $k | $text |")
}
$null = $md.AppendLine()

$null = $md.AppendLine('## Counters (event window)')
$null = $md.AppendLine()
$null = $md.AppendLine('| Counter | Count |')
$null = $md.AppendLine('|---|---:|')
foreach ($k in $triage.counters.Keys) { $null = $md.AppendLine("| $k | $($triage.counters[$k]) |") }
$null = $md.AppendLine()

$null = $md.AppendLine('## Storage')
$null = $md.AppendLine()
$null = $md.AppendLine('| Disk | Media | Bus | GB | Health | Wear% | PoH | TempC | RdUncorr | WrUncorr |')
$null = $md.AppendLine('|---|---|---|---:|---|---:|---:|---:|---:|---:|')
foreach ($d in $triage.storage.disks) {
    $null = $md.AppendLine("| $($d.Model) | $($d.Media) | $($d.Bus) | $($d.SizeGB) | $($d.Health) | $($d.WearPercent) | $($d.PowerOnHours) | $($d.TempC) | $($d.ReadErrUncorrected) | $($d.WriteErrUncorrected) |")
}
$null = $md.AppendLine()
$null = $md.AppendLine('| Volume | FS | GB | Free GB | Free % | Health | Dirty |')
$null = $md.AppendLine('|---|---|---:|---:|---:|---|---|')
foreach ($v in $triage.storage.volumes) {
    $null = $md.AppendLine("| $($v.Letter): | $($v.FileSystem) | $($v.SizeGB) | $($v.FreeGB) | $($v.FreePercent) | $($v.Health) | $($v.Dirty) |")
}
$null = $md.AppendLine()

if (@($triage.pnp_problems).Count) {
    $null = $md.AppendLine('## Devices with a problem code')
    $null = $md.AppendLine()
    $null = $md.AppendLine('| Device | Code | Service | Device ID |')
    $null = $md.AppendLine('|---|---:|---|---|')
    foreach ($p in $triage.pnp_problems) { $null = $md.AppendLine("| $($p.Name) | $($p.ErrorCode) | $($p.Service) | $($p.DeviceId) |") }
    $null = $md.AppendLine()
}

$null = $md.AppendLine('## Top event signatures')
$null = $md.AppendLine()
$null = $md.AppendLine('| Log | Provider | ID | Level | Count | First | Last | Sample |')
$null = $md.AppendLine('|---|---|---:|---|---:|---|---|---|')
foreach ($s in $triage.top_event_signatures) {
    $sample = ([string]$s.Sample) -replace '\|','/'
    if ($sample.Length -gt 180) { $sample = $sample.Substring(0,180) + '...' }
    $null = $md.AppendLine("| $($s.LogName) | $($s.ProviderName) | $($s.EventId) | $($s.LevelName) | $($s.Count) | $($s.FirstSeen) | $($s.LastSeen) | $sample |")
}
$null = $md.AppendLine()

$null = $md.AppendLine('## Non-Microsoft kernel surface')
$null = $md.AppendLine()
$null = $md.AppendLine("Running drivers: $(@($triage.third_party_kernel_drivers).Count) | Minifilters: $(@($triage.third_party_minifilters).Count) | Auto services: $(@($triage.third_party_auto_services).Count)")
$null = $md.AppendLine()
foreach ($d in $triage.third_party_kernel_drivers) { $null = $md.AppendLine("- driver ``$($d.Name)`` ($($d.StartMode)) - $($d.Signer)") }
foreach ($f in $triage.third_party_minifilters)    { $null = $md.AppendLine("- minifilter ``$($f.Filter)`` alt $($f.Altitude) - $($f.Signer)") }
foreach ($s in $triage.third_party_auto_services)  { $null = $md.AppendLine("- service ``$($s.Name)`` ($($s.State)) - $($s.Signer)") }
$null = $md.AppendLine()

$null = $md.AppendLine('## Performance snapshot')
$null = $md.AppendLine()
$null = $md.AppendLine('```json')
$null = $md.AppendLine(($perf | ConvertTo-Json -Compress))
$null = $md.AppendLine('```')
$null = $md.AppendLine("Top CPU: " + (($triage.performance.top_by_cpu | ForEach-Object { "$($_.Name)=$($_.CPUSeconds)s" }) -join ', '))
$null = $md.AppendLine()
$null = $md.AppendLine("Top RSS: " + (($triage.performance.top_by_memory | ForEach-Object { "$($_.Name)=$($_.WorkingSetMB)MB" }) -join ', '))
$null = $md.AppendLine()

if (@($Trimmed).Count -or @($failedProbes).Count -or @($nonZeroProbes).Count -or
    @($truncatedLogs).Count -or @($Warnings).Count) {
    $null = $md.AppendLine('## Gaps in this digest')
    $null = $md.AppendLine()
    $null = $md.AppendLine('Anything listed here is **unknown**, not healthy.')
    $null = $md.AppendLine()
    foreach ($t in $Trimmed)      { $null = $md.AppendLine("- trimmed: $t") }
    foreach ($f in $failedProbes) { $null = $md.AppendLine("- probe failed: $f") }
    foreach ($l in $truncatedLogs) {
        $null = $md.AppendLine("- **log truncated**: $($l.Log) returned $($l.Returned) of $($l.Available) events (cap $($l.Cap)). Counts are lower bounds and FirstSeen is not the true earliest occurrence.")
    }
    foreach ($n in @($nonZeroProbes) | Select-Object -First 12) {
        $null = $md.AppendLine("- non-zero exit: $($n.Probe) returned $($n.ExitCode) (often normal for query tools - check the output before treating it as a failure)")
    }
    foreach ($w in @($Warnings) | Select-Object -First 10) { $null = $md.AppendLine("- warning: $w") }
    $null = $md.AppendLine()
}

$null = $md.AppendLine('## How to use this')
$null = $md.AppendLine()
$null = $md.AppendLine('This digest is the intended input for triage. Raw evidence lives under the evidence root and is meant to be **queried**, not loaded.')
if ($Depth -ne 'Full') {
    $null = $md.AppendLine()
    $null = $md.AppendLine('Slow scans (DISM ScanHealth, SFC, CHKDSK, powercfg /energy) were **not** run. Start them in the background with:')
    $null = $md.AppendLine()
    $null = $md.AppendLine('```powershell')
    $null = $md.AppendLine(".\collect-deep.ps1 -RunDir '$(Protect-Identity $RunDir)'")
    $null = $md.AppendLine('```')
}
$null = $md.AppendLine()
$null = $md.AppendLine('Do not "fix" every Event Viewer error. Correlate first, repair second, verify last.')

$mdText = $md.ToString()

# TRIAGE.md is what gets pasted into a chat, so it needs its own runtime bound
# rather than an assumption that trimming TRIAGE.json is enough. The Markdown
# is roughly two thirds the size of the compact JSON in practice, but "in
# practice" is exactly the assumption that fails on an unusual machine.
$mdBudget = [int]($MaxTriageBytes * 0.75)
$mdBytes = [Text.Encoding]::UTF8.GetByteCount($mdText)
if ($mdBytes -gt $mdBudget) {
    $notice = @"

---

> **This digest was truncated to stay within $mdBudget bytes.**
> The full structured digest is TRIAGE.json in the evidence root. Sections after
> this point are missing, not empty - query the raw evidence for them.
"@
    # Reserve room for the notice before cutting. Appending it afterwards is
    # exactly the measure-then-append mistake that made the JSON cap advisory.
    $noticeBytes = [Text.Encoding]::UTF8.GetByteCount($notice)
    $keepBytes = $mdBudget - $noticeBytes
    if ($keepBytes -lt 200) {
        # Budget too small for prose. Emit the pointer and nothing else.
        $mdText = $notice.TrimStart()
    } else {
        $keep = [math]::Min($mdText.Length, $keepBytes)
        while ($keep -gt 0 -and [Text.Encoding]::UTF8.GetByteCount($mdText.Substring(0, $keep)) -gt $keepBytes) { $keep-- }
        $mdText = $mdText.Substring(0, $keep) + $notice
    }
    $Warnings.Add("TRIAGE.md exceeded $mdBudget bytes and was truncated. Use the structured digest for the complete picture.")
}
[IO.File]::WriteAllText((Join-Path $RunDir 'TRIAGE.md'), $mdText, (New-Object Text.UTF8Encoding($false)))

# ------------------------------------------------------------- run artifacts -

$Journal | Export-Csv (Join-Path $RunDir 'COMMAND-JOURNAL.csv') -NoTypeInformation -Encoding UTF8
if ($Warnings.Count) { $Warnings | Out-File (Join-Path $RunDir 'COLLECTOR-WARNINGS.txt') -Encoding utf8 }
try { if ($PSCommandPath) { Copy-Item $PSCommandPath (Join-Path $RunDir 'collect-baseline.ps1') -Force } } catch {}

if (-not $NoZip) {
    try {
        if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
        Compress-Archive -Path (Join-Path $RunDir '*') -DestinationPath $ZipPath -CompressionLevel Optimal -Force
        Add-Journal 'ZIP' 'OK' 0 0 $ZipPath
    } catch { Write-Warning "ZIP creation failed: $($_.Exception.Message)" }
}

if ($CopyToClipboard) {
    try { Set-Clipboard -Value $mdText; Write-Host 'TRIAGE.md copied to clipboard.' -ForegroundColor Green }
    catch { $Warnings.Add("Clipboard copy failed: $($_.Exception.Message)") }
}

$mdBytes = [Text.Encoding]::UTF8.GetByteCount($mdText)
Write-Host ''
Write-Host ('=' * 72) -ForegroundColor DarkGray
Write-Host "Baseline complete in $([math]::Round(((Get-Date)-$StartTime).TotalMinutes,1)) minutes." -ForegroundColor Green
Write-Host ''
Write-Host 'PASTE THIS FILE INTO THE AUDIT CONVERSATION:' -ForegroundColor Cyan
Write-Host "  $(Join-Path $RunDir 'TRIAGE.md')  ($mdBytes bytes)" -ForegroundColor Cyan
Write-Host ''
Write-Host 'Do NOT paste the ZIP or the raw CSV/EVTX files. They are for targeted follow-up queries only.'
Write-Host "Raw evidence: $RunDir"
if (-not $NoZip) { Write-Host "ZIP:          $ZipPath" }
Write-Host ('=' * 72) -ForegroundColor DarkGray

if ($digestOverBudget) {
    Write-Host ''
    Write-Host "DIGEST BUDGET EXCEEDED: $finalBytes bytes > $MaxTriageBytes after all trimming." -ForegroundColor Red
    Write-Host 'The structured digest was written as TRIAGE-OVERSIZED.json rather than'
    Write-Host 'TRIAGE.json, because that name is a promise about size. TRIAGE.md above is'
    Write-Host 'still within its own budget and is safe to paste.'
    Write-Host 'Re-run with a larger -MaxTriageBytes only if you accept the context cost.'
    exit 75
}

# Explicit success. Without this the script inherits $LASTEXITCODE from whatever
# native tool ran last, and several of them exit non-zero as a normal query
# result, so callers could not tell a real failure from fsutil saying "not dirty".
exit 0
