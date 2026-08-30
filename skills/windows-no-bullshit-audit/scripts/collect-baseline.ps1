#requires -version 5.1
<#
.SYNOPSIS
  Broad read-only Windows 11 audit collector for windows-no-bullshit-audit.

.DESCRIPTION
  Collects evidence only. It does not repair Windows, delete entries, install
  updates, modify boot/storage/security configuration, or enable Driver Verifier.

.PARAMETER OutputRoot
  Parent directory. Default: C:\WindowsNoBullshitAudit

.PARAMETER EventDays
  History window for summarized events. Default: 60.

.PARAMETER MaxEventsPerLog
  Maximum detailed warning/error/critical events per major log. Default: 30000.

.PARAMETER SkipSlowScans
  Skip DISM ScanHealth, SFC VerifyOnly, CHKDSK /scan, and powercfg /energy.

.PARAMETER NoZip
  Do not make a ZIP at the end.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot = "$env:SystemDrive\WindowsNoBullshitAudit",
    [ValidateRange(1,3650)][int]$EventDays = 60,
    [ValidateRange(100,200000)][int]$MaxEventsPerLog = 30000,
    [switch]$SkipSlowScans,
    [switch]$NoZip
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

function Test-IsAdministrator {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

if (-not (Test-IsAdministrator)) {
    Write-Error 'Run from an elevated Windows PowerShell / Terminal (Run as administrator).'
    exit 740
}

$StartTime = Get-Date
$Since = $StartTime.AddDays(-$EventDays)
$Timestamp = $StartTime.ToString('yyyyMMdd-HHmmss')
$ComputerSafe = ($env:COMPUTERNAME -replace '[^A-Za-z0-9._-]','_')
$RunName = "WindowsNoBullshitAudit-$ComputerSafe-$Timestamp"
$RunDir = Join-Path $OutputRoot $RunName
$ZipPath = Join-Path $OutputRoot "$RunName.zip"

$dirs = @(
    '00-System','01-Integrity','02-Storage','03-Drivers','04-Devices',
    '05-Events','06-WER','07-Dumps','08-Boot-Restore','09-Power',
    '10-Network','11-Software-Startup','12-Security','13-Performance','14-Updates'
)
New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
foreach ($d in $dirs) { New-Item -ItemType Directory -Force -Path (Join-Path $RunDir $d) | Out-Null }

$Journal = New-Object System.Collections.Generic.List[object]
$Warnings = New-Object System.Collections.Generic.List[string]

function Add-Journal {
    param([string]$Name,[string]$Status,[int]$ExitCode,[double]$Seconds,[string]$Path,[string]$Note='')
    $Journal.Add([pscustomobject]@{
        Time=(Get-Date).ToString('o'); Name=$Name; Status=$Status; ExitCode=$ExitCode;
        Seconds=[math]::Round($Seconds,2); OutputPath=$Path; Note=$Note
    })
}

function Protect-SensitiveText {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $s = $Text
    $s = $s -replace '(?i)((?:--?|/)(?:password|passwd|pwd|token|secret|api[-_]?key|client[-_]?secret|access[-_]?key|credential|auth)(?:\s*[:=]\s*|\s+))(?:(?:"[^"]*")|(?:''[^'']*'')|\S+)', '$1<REDACTED>'
    $s = $s -replace '(?i)\b((?:password|passwd|pwd|token|secret|api[-_]?key|client[-_]?secret|access[-_]?key|credential|auth)\s*=\s*)(?:(?:"[^"]*")|(?:''[^'']*'')|[^;\s]+)', '$1<REDACTED>'
    $s = $s -replace '([A-Za-z][A-Za-z0-9+.-]*://)[^/@:\s]+:[^/@\s]+@', '$1<REDACTED>@'
    return $s
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Exe,
        [string[]]$Arguments=@(),
        [Parameter(Mandatory=$true)][string]$RelativeOutput
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
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory=$true)][string]$RelativeOutput,
        [ValidateSet('Text','Csv','Json','Clixml')][string]$Format='Text'
    )
    $out = Join-Path $RunDir $RelativeOutput
    $sw = [Diagnostics.Stopwatch]::StartNew(); $status='OK'; $note=''
    try {
        $result = & $ScriptBlock
        switch ($Format) {
            'Csv' { $result | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8 }
            'Json' { $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $out -Encoding utf8 -Width 4096 }
            'Clixml' { $result | Export-Clixml -Path $out -Depth 8 }
            default { $result | Out-File -FilePath $out -Encoding utf8 -Width 4096 }
        }
    } catch {
        $status='ERROR'; $note=$_.Exception.Message
        $_ | Out-String | Out-File -FilePath $out -Encoding utf8 -Width 4096
    } finally {
        $sw.Stop(); Add-Journal $Name $status 0 $sw.Elapsed.TotalSeconds $RelativeOutput $note
    }
}

function Export-EventLogIfPresent {
    param([string]$LogName)
    try {
        $null = Get-WinEvent -ListLog $LogName -ErrorAction Stop
        $safe = ($LogName -replace '[\\/:\s]','_') + '.evtx'
        $rel = "05-Events\$safe"; $out = Join-Path $RunDir $rel
        $sw=[Diagnostics.Stopwatch]::StartNew()
        & wevtutil.exe epl $LogName $out /ow:true 2>&1 | Out-Null
        $code=$LASTEXITCODE; $sw.Stop()
        Add-Journal "Export EVTX $LogName" $(if($code -eq 0){'OK'}else{'NONZERO'}) $code $sw.Elapsed.TotalSeconds $rel
    } catch {
        $Warnings.Add("Event log unavailable: $LogName")
    }
}

Write-Host "Windows No-Bullshit Audit baseline" -ForegroundColor Green
Write-Host "Evidence directory: $RunDir"
Write-Host "Mode: read-only evidence collection" -ForegroundColor Yellow

# 00 - System
Invoke-NativeCapture 'systeminfo' 'systeminfo.exe' @() '00-System\systeminfo.txt'
Invoke-PSCapture 'OS' { Get-CimInstance Win32_OperatingSystem | Format-List * } '00-System\os.txt'
Invoke-PSCapture 'ComputerSystem' { Get-CimInstance Win32_ComputerSystem | Format-List * } '00-System\computer-system.txt'
Invoke-PSCapture 'BIOS' { Get-CimInstance Win32_BIOS | Format-List * } '00-System\bios.txt'
Invoke-PSCapture 'Processor' { Get-CimInstance Win32_Processor | Format-List * } '00-System\processor.txt'
Invoke-PSCapture 'BaseBoard' { Get-CimInstance Win32_BaseBoard | Format-List * } '00-System\baseboard.txt'
Invoke-PSCapture 'Video controllers' { Get-CimInstance Win32_VideoController | Select Name,DriverVersion,DriverDate,AdapterRAM,PNPDeviceID,Status } '00-System\video.csv' Csv
Invoke-PSCapture 'Hotfixes' { Get-HotFix | Sort InstalledOn -Descending } '00-System\hotfixes.csv' Csv
Invoke-PSCapture 'Environment metadata' {
    Get-ChildItem Env: | Sort Name | Select Name,@{n='Value';e={'<REDACTED_BY_COLLECTOR>'}},@{n='ValueLength';e={if($null -eq $_.Value){0}else{$_.Value.Length}}}
} '00-System\environment-metadata.csv' Csv
Invoke-PSCapture 'PATH entries' {
    if ($env:Path) { $env:Path -split ';' | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{Path=$_;Exists=(Test-Path -LiteralPath $_)} } }
} '00-System\path-entries.csv' Csv

try {
    $nfo=Join-Path $RunDir '00-System\msinfo32.nfo'; $sw=[Diagnostics.Stopwatch]::StartNew()
    $p=Start-Process msinfo32.exe -ArgumentList @('/nfo',"`"$nfo`"") -PassThru
    $null=$p.WaitForExit(180000)
    if(-not $p.HasExited){ try{$p.Kill()}catch{}; Add-Journal 'msinfo32' 'TIMEOUT' -1 $sw.Elapsed.TotalSeconds '00-System\msinfo32.nfo' 'Timed out after 180s' }
    else { Add-Journal 'msinfo32' 'OK' $p.ExitCode $sw.Elapsed.TotalSeconds '00-System\msinfo32.nfo' }
} catch { $Warnings.Add("msinfo32 failed: $($_.Exception.Message)") }
try {
    $dx=Join-Path $RunDir '00-System\dxdiag.txt'; Start-Process dxdiag.exe -ArgumentList @('/dontskip','/t',"`"$dx`"") -Wait -WindowStyle Hidden -ErrorAction Stop | Out-Null
} catch { $Warnings.Add("dxdiag failed: $($_.Exception.Message)") }

# 01 - Integrity
Invoke-NativeCapture 'DISM CheckHealth' 'dism.exe' @('/Online','/Cleanup-Image','/CheckHealth','/English') '01-Integrity\DISM-CheckHealth.txt'
Invoke-NativeCapture 'DISM AnalyzeComponentStore' 'dism.exe' @('/Online','/Cleanup-Image','/AnalyzeComponentStore','/English') '01-Integrity\DISM-AnalyzeComponentStore.txt'
if(-not $SkipSlowScans){
    Invoke-NativeCapture 'DISM ScanHealth' 'dism.exe' @('/Online','/Cleanup-Image','/ScanHealth','/English') '01-Integrity\DISM-ScanHealth.txt'
    Invoke-NativeCapture 'SFC VerifyOnly' 'sfc.exe' @('/verifyonly') '01-Integrity\SFC-VerifyOnly.txt'
}
foreach($src in @('C:\Windows\Logs\CBS\CBS.log','C:\Windows\Logs\DISM\dism.log')){
    if(Test-Path $src){ try{ Copy-Item $src (Join-Path $RunDir '01-Integrity') -Force -ErrorAction Stop } catch { $Warnings.Add("Could not copy $src: $($_.Exception.Message)") } }
}

# 02 - Storage
Invoke-PSCapture 'Disks' { Get-Disk | Select Number,FriendlyName,SerialNumber,BusType,PartitionStyle,OperationalStatus,HealthStatus,Size,IsBoot,IsSystem } '02-Storage\disks.csv' Csv
Invoke-PSCapture 'Partitions' { Get-Partition | Select DiskNumber,PartitionNumber,DriveLetter,Type,GptType,MbrType,Size,Offset,IsBoot,IsSystem,IsActive,IsHidden } '02-Storage\partitions.csv' Csv
Invoke-PSCapture 'Volumes' { Get-Volume | Select DriveLetter,FileSystemLabel,FileSystem,DriveType,HealthStatus,OperationalStatus,Size,SizeRemaining,Path } '02-Storage\volumes.csv' Csv
Invoke-PSCapture 'Physical disks' { Get-PhysicalDisk | Select FriendlyName,SerialNumber,MediaType,BusType,HealthStatus,OperationalStatus,Size,SpindleSpeed } '02-Storage\physical-disks.csv' Csv
Invoke-PSCapture 'DiskDrive CIM' { Get-CimInstance Win32_DiskDrive | Select Model,SerialNumber,InterfaceType,PNPDeviceID,SCSIPort,SCSIBus,SCSITargetId,SCSILogicalUnit,Size,Status } '02-Storage\diskdrive-cim.csv' Csv
Invoke-PSCapture 'Storage reliability counters' {
    foreach($pd in Get-PhysicalDisk){
        try{
            $r=$pd | Get-StorageReliabilityCounter -ErrorAction Stop
            [pscustomobject]@{FriendlyName=$pd.FriendlyName;SerialNumber=$pd.SerialNumber;Temperature=$r.Temperature;TemperatureMax=$r.TemperatureMax;Wear=$r.Wear;PowerOnHours=$r.PowerOnHours;ReadErrorsTotal=$r.ReadErrorsTotal;ReadErrorsUncorrected=$r.ReadErrorsUncorrected;WriteErrorsTotal=$r.WriteErrorsTotal;WriteErrorsUncorrected=$r.WriteErrorsUncorrected;FlushLatencyMax=$r.FlushLatencyMax;ReadLatencyMax=$r.ReadLatencyMax;WriteLatencyMax=$r.WriteLatencyMax;LoadUnloadCycleCount=$r.LoadUnloadCycleCount;StartStopCycleCount=$r.StartStopCycleCount}
        } catch { [pscustomobject]@{FriendlyName=$pd.FriendlyName;SerialNumber=$pd.SerialNumber;Error=$_.Exception.Message} }
    }
} '02-Storage\storage-reliability.csv' Csv
Invoke-NativeCapture 'mountvol' 'mountvol.exe' @() '02-Storage\mountvol.txt'
try{
    $fixed=Get-Volume -ErrorAction Stop | Where-Object {$_.DriveLetter -and $_.DriveType -eq 'Fixed' -and $_.FileSystem -eq 'NTFS'}
    foreach($v in $fixed){
        $drive="$($v.DriveLetter):"
        Invoke-NativeCapture "FSUTIL dirty $drive" 'fsutil.exe' @('dirty','query',$drive) "02-Storage\fsutil-dirty-$($v.DriveLetter).txt"
        if(-not $SkipSlowScans){ Invoke-NativeCapture "CHKDSK scan $drive" 'chkdsk.exe' @($drive,'/scan') "02-Storage\chkdsk-$($v.DriveLetter)-scan.txt" }
    }
}catch{}

# 03/04 - Drivers and Devices
Invoke-NativeCapture 'PnP problem devices' 'pnputil.exe' @('/enum-devices','/problem','/deviceids') '04-Devices\pnputil-problem-devices.txt'
Invoke-NativeCapture 'PnP connected drivers' 'pnputil.exe' @('/enum-devices','/connected','/drivers') '04-Devices\pnputil-connected-drivers.txt'
Invoke-NativeCapture 'PnP device tree' 'pnputil.exe' @('/enum-devicetree','/connected','/stack','/drivers','/services','/interfaces') '04-Devices\pnputil-device-tree.txt'
Invoke-NativeCapture 'Driver store' 'pnputil.exe' @('/enum-drivers','/files') '03-Drivers\pnputil-driver-store.txt'
Invoke-NativeCapture 'driverquery' 'driverquery.exe' @('/v','/fo','csv') '03-Drivers\driverquery.csv'
Invoke-NativeCapture 'Driver services' 'sc.exe' @('query','type=','driver','state=','all') '03-Drivers\sc-driver-services.txt'
Invoke-NativeCapture 'Minifilters' 'fltmc.exe' @('filters') '03-Drivers\fltmc-filters.txt'
Invoke-NativeCapture 'Minifilter instances' 'fltmc.exe' @('instances') '03-Drivers\fltmc-instances.txt'
Invoke-PSCapture 'PnP signed drivers' { Get-CimInstance Win32_PnPSignedDriver | Select DeviceName,DeviceID,Manufacturer,DriverProviderName,DriverVersion,DriverDate,InfName,IsSigned,Signer } '03-Drivers\pnp-signed-drivers.csv' Csv
Invoke-PSCapture 'Running system drivers' { Get-CimInstance Win32_SystemDriver | Where State -eq 'Running' | Select Name,DisplayName,StartMode,State,PathName,ServiceType } '03-Drivers\running-system-drivers.csv' Csv
Invoke-PSCapture 'PnP problems' { Get-CimInstance Win32_PnPEntity | Where ConfigManagerErrorCode -ne 0 | Select Name,PNPDeviceID,Manufacturer,Service,Status,ConfigManagerErrorCode } '04-Devices\configmanager-problems.csv' Csv
Invoke-PSCapture 'All PnP entities' { Get-CimInstance Win32_PnPEntity | Select Name,PNPDeviceID,Manufacturer,Service,Status,ConfigManagerErrorCode } '04-Devices\all-pnp-entities.csv' Csv

# 05 - Events / Reliability
$rawLogs=@(
    'System','Application','Setup',
    'Microsoft-Windows-WindowsUpdateClient/Operational',
    'Microsoft-Windows-CodeIntegrity/Operational',
    'Microsoft-Windows-Kernel-Boot/Operational',
    'Microsoft-Windows-Kernel-PnP/Configuration',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-Storage-Storport/Operational',
    'Microsoft-Windows-DriverFrameworks-UserMode/Operational'
)
foreach($log in $rawLogs){ Export-EventLogIfPresent $log }

foreach($log in @('System','Application')){
    $logCopy=$log
    Invoke-PSCapture "$log warning/error/critical" {
        Get-WinEvent -FilterHashtable @{LogName=$logCopy;StartTime=$Since;Level=1,2,3} -MaxEvents $MaxEventsPerLog -ErrorAction SilentlyContinue |
            Select TimeCreated,LogName,ProviderName,Id,Level,LevelDisplayName,TaskDisplayName,OpcodeDisplayName,MachineName,Message
    }.GetNewClosure() "05-Events\$log-warn-error-critical.csv" Csv
}

Invoke-PSCapture 'Event aggregate' {
    $events=foreach($log in @('System','Application')){
        Get-WinEvent -FilterHashtable @{LogName=$log;StartTime=$Since;Level=1,2,3} -MaxEvents $MaxEventsPerLog -ErrorAction SilentlyContinue
    }
    $events | Group-Object LogName,ProviderName,Id,Level | ForEach-Object {
        $g=@($_.Group | Sort TimeCreated)
        [pscustomobject]@{LogName=$g[0].LogName;ProviderName=$g[0].ProviderName;EventId=$g[0].Id;Level=$g[0].Level;LevelName=$g[0].LevelDisplayName;Count=$_.Count;FirstSeen=$g[0].TimeCreated;LastSeen=$g[-1].TimeCreated;SampleMessage=((($g[-1].Message -replace '\r?\n',' ') -replace '\s+',' ').Trim())}
    } | Sort Count -Descending
} '05-Events\event-aggregate.csv' Csv

$providers=@('Microsoft-Windows-WHEA-Logger','Disk','Ntfs','stornvme','storahci','storport','volmgr','Microsoft-Windows-Kernel-Power','Microsoft-Windows-Kernel-Boot','Microsoft-Windows-Kernel-PnP','Service Control Manager','Application Error','Application Hang','Windows Error Reporting','.NET Runtime','Display','Microsoft-Windows-WindowsUpdateClient','Microsoft-Windows-CodeIntegrity','User32')
Invoke-PSCapture 'Interesting provider events' {
    Get-WinEvent -FilterHashtable @{LogName='System','Application';StartTime=$Since} -ErrorAction SilentlyContinue |
        Where-Object {$providers -contains $_.ProviderName} |
        Select TimeCreated,LogName,ProviderName,Id,Level,LevelDisplayName,Message
} '05-Events\interesting-provider-events.csv' Csv
Invoke-PSCapture 'Reliability records' { Get-CimInstance -Namespace root\cimv2 -Class Win32_ReliabilityRecords -ErrorAction SilentlyContinue | Where TimeGenerated -ge $Since | Sort TimeGenerated -Descending | Select TimeGenerated,SourceName,ProductName,EventIdentifier,LogFile,Message } '05-Events\reliability-records.csv' Csv

# 06/07 - WER / dumps
$werRoots=@('C:\ProgramData\Microsoft\Windows\WER\ReportArchive','C:\ProgramData\Microsoft\Windows\WER\ReportQueue')
Invoke-PSCapture 'WER file inventory' {
    foreach($root in $werRoots){ if(Test-Path $root){ Get-ChildItem $root -File -Recurse -Force -ErrorAction SilentlyContinue | Select @{n='Root';e={$root}},FullName,Length,CreationTimeUtc,LastWriteTimeUtc,Extension } }
} '06-WER\wer-file-inventory.csv' Csv
$werCopy=Join-Path $RunDir '06-WER\Report-wers'; New-Item -ItemType Directory -Force $werCopy | Out-Null
foreach($root in $werRoots){
    if(Test-Path $root){ Get-ChildItem $root -Filter Report.wer -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        try{
            if($_.Length -le 2MB){
                $safe=(($_.Directory.Name -replace '[^A-Za-z0-9._-]','_') + '-' + ([guid]::NewGuid().ToString('N').Substring(0,8)) + '-Report.wer')
                Copy-Item $_.FullName (Join-Path $werCopy $safe) -Force
            }
        }catch{}
    }}
}
$dumpRoots=@('C:\Windows\Minidump','C:\Windows\LiveKernelReports','C:\Windows\MEMORY.DMP',"$env:LOCALAPPDATA\CrashDumps")
Invoke-PSCapture 'Dump inventory' {
    foreach($root in $dumpRoots){
        if(Test-Path -LiteralPath $root){
            $i=Get-Item -LiteralPath $root -Force -ErrorAction SilentlyContinue
            if($i -and -not $i.PSIsContainer){ $i | Select FullName,Length,CreationTimeUtc,LastWriteTimeUtc,Extension }
            else { Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue | Select FullName,Length,CreationTimeUtc,LastWriteTimeUtc,Extension }
        }
    }
} '07-Dumps\dump-inventory.csv' Csv

# 08 - Boot / restore / VSS
Invoke-NativeCapture 'BCD all' 'bcdedit.exe' @('/enum','all') '08-Boot-Restore\bcdedit-all.txt'
Invoke-NativeCapture 'WinRE info' 'reagentc.exe' @('/info') '08-Boot-Restore\reagentc-info.txt'
Invoke-NativeCapture 'VSS writers' 'vssadmin.exe' @('list','writers') '08-Boot-Restore\vss-writers.txt'
Invoke-NativeCapture 'VSS providers' 'vssadmin.exe' @('list','providers') '08-Boot-Restore\vss-providers.txt'
Invoke-NativeCapture 'VSS shadows' 'vssadmin.exe' @('list','shadows') '08-Boot-Restore\vss-shadows.txt'
Invoke-NativeCapture 'VSS shadowstorage' 'vssadmin.exe' @('list','shadowstorage') '08-Boot-Restore\vss-shadowstorage.txt'
Invoke-PSCapture 'System Restore registry' { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -ErrorAction SilentlyContinue | Format-List * } '08-Boot-Restore\system-restore-registry.txt'
Invoke-PSCapture 'Restore points' { Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Sort CreationTime -Descending | Select SequenceNumber,Description,RestorePointType,EventType,CreationTime } '08-Boot-Restore\restore-points.csv' Csv
Invoke-PSCapture 'Secure Boot' { try{[pscustomobject]@{Enabled=(Confirm-SecureBootUEFI -ErrorAction Stop)}}catch{[pscustomobject]@{Enabled=$null;Error=$_.Exception.Message}} } '08-Boot-Restore\secure-boot.json' Json

# 09 - Power
foreach($x in @(
    @{N='available states';A=@('/a');F='powercfg-a.txt'},
    @{N='active scheme';A=@('/getactivescheme');F='powercfg-active-scheme.txt'},
    @{N='requests';A=@('/requests');F='powercfg-requests.txt'},
    @{N='lastwake';A=@('/lastwake');F='powercfg-lastwake.txt'},
    @{N='waketimers';A=@('/waketimers');F='powercfg-waketimers.txt'}
)){ Invoke-NativeCapture "powercfg $($x.N)" 'powercfg.exe' $x.A "09-Power\$($x.F)" }
Invoke-PSCapture 'Fast Startup and hiberfile' {
    $hiber=$null; try{$hiber=Get-Item "$env:SystemDrive\hiberfil.sys" -Force -ErrorAction Stop}catch{}
    $hbe=$null; try{$hbe=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction Stop).HiberbootEnabled}catch{}
    [pscustomobject]@{HiberbootEnabled=$hbe;HiberfilePresent=[bool]$hiber;HiberfileBytes=if($hiber){$hiber.Length}else{0}}
} '09-Power\hibernation-fast-startup.json' Json
if(-not $SkipSlowScans){
    $energy=Join-Path $RunDir '09-Power\energy.html'
    Invoke-NativeCapture 'powercfg energy' 'powercfg.exe' @('/energy','/duration','30','/output',$energy) '09-Power\powercfg-energy-command.txt'
}

# 10 - Network
Invoke-NativeCapture 'ipconfig all' 'ipconfig.exe' @('/all') '10-Network\ipconfig-all.txt'
Invoke-NativeCapture 'route print' 'route.exe' @('print') '10-Network\route-print.txt'
Invoke-NativeCapture 'winsock catalog' 'netsh.exe' @('winsock','show','catalog') '10-Network\winsock-catalog.txt'
Invoke-PSCapture 'Network adapters' { Get-NetAdapter -IncludeHidden | Select Name,InterfaceDescription,InterfaceIndex,Status,MacAddress,LinkSpeed,MediaType,PhysicalMediaType,DriverInformation,DriverFileName,DriverVersion } '10-Network\net-adapters.csv' Csv
Invoke-PSCapture 'IP configuration' { Get-NetIPConfiguration -All | Select InterfaceAlias,InterfaceIndex,NetProfile,IPv4Address,IPv6Address,IPv4DefaultGateway,IPv6DefaultGateway,DNSServer } '10-Network\net-ip.clixml' Clixml
Invoke-PSCapture 'TCP listeners' { Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select LocalAddress,LocalPort,OwningProcess,@{n='ProcessName';e={try{(Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName}catch{$null}}} | Sort LocalPort } '10-Network\tcp-listeners.csv' Csv
Invoke-PSCapture 'Firewall profiles' { Get-NetFirewallProfile | Select Name,Enabled,DefaultInboundAction,DefaultOutboundAction,NotifyOnListen,AllowInboundRules,AllowLocalFirewallRules,AllowLocalIPsecRules } '10-Network\firewall-profiles.csv' Csv

# 11 - Software / services / tasks / startup
Invoke-PSCapture 'Services' {
    Get-CimInstance Win32_Service | Select Name,DisplayName,State,StartMode,StartName,ProcessId,@{n='PathName';e={Protect-SensitiveText $_.PathName}},Description | Sort Name
} '11-Software-Startup\services.csv' Csv
Invoke-PSCapture 'Scheduled tasks' {
    Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
        $t=$_; $acts=@($t.Actions | ForEach-Object { Protect-SensitiveText ((($_.Execute + ' ' + $_.Arguments).Trim())) })
        [pscustomobject]@{TaskPath=$t.TaskPath;TaskName=$t.TaskName;State=$t.State;Author=$t.Author;Description=$t.Description;Actions=($acts -join ' | ')}
    }
} '11-Software-Startup\scheduled-tasks.csv' Csv
Invoke-PSCapture 'Startup commands' { Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | Select Name,Location,User,@{n='Command';e={Protect-SensitiveText $_.Command}} } '11-Software-Startup\startup-commands.csv' Csv
Invoke-PSCapture 'Installed software' {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object {$_.DisplayName} | Select DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation,PSChildName | Sort DisplayName
} '11-Software-Startup\installed-software.csv' Csv

# 12 - Security
Invoke-PSCapture 'Defender status' { Get-MpComputerStatus -ErrorAction SilentlyContinue | Format-List * } '12-Security\defender-status.txt'
Invoke-PSCapture 'Defender preferences' {
    try{
        $p=Get-MpPreference -ErrorAction Stop
        [pscustomobject]@{DisableRealtimeMonitoring=$p.DisableRealtimeMonitoring;DisableBehaviorMonitoring=$p.DisableBehaviorMonitoring;DisableIOAVProtection=$p.DisableIOAVProtection;DisableScriptScanning=$p.DisableScriptScanning;MAPSReporting=$p.MAPSReporting;SubmitSamplesConsent=$p.SubmitSamplesConsent;PUAProtection=$p.PUAProtection;ExclusionPath=$p.ExclusionPath;ExclusionProcess=$p.ExclusionProcess;ExclusionExtension=$p.ExclusionExtension}
    }catch{$_}
} '12-Security\defender-preferences.clixml' Clixml
Invoke-PSCapture 'Device Guard' { Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue | Format-List * } '12-Security\device-guard.txt'
Invoke-PSCapture 'TPM' { try{Get-Tpm -ErrorAction Stop | Format-List *}catch{$_} } '12-Security\tpm.txt'
Invoke-PSCapture 'BitLocker volumes' { try{Get-BitLockerVolume -ErrorAction Stop | Select MountPoint,VolumeType,VolumeStatus,ProtectionStatus,EncryptionMethod,EncryptionPercentage,AutoUnlockEnabled,LockStatus}catch{$_} } '12-Security\bitlocker.txt'
Invoke-PSCapture 'UAC and LSA policy' {
    [pscustomobject]@{
        EnableLUA=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
        ConsentPromptBehaviorAdmin=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
        RunAsPPL=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
    }
} '12-Security\uac-lsa.json' Json
Invoke-PSCapture 'Enabled optional features' { Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue | Where State -eq Enabled | Select FeatureName,State } '12-Security\enabled-optional-features.csv' Csv

# 13 - Lightweight performance baseline
Invoke-PSCapture 'Perf formatted baseline' {
    $cpu=Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction SilentlyContinue
    $sys=Get-CimInstance Win32_PerfFormattedData_PerfOS_System -ErrorAction SilentlyContinue
    $mem=Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory -ErrorAction SilentlyContinue
    $disk=Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" -ErrorAction SilentlyContinue
    [pscustomobject]@{Timestamp=(Get-Date);CPUPercent=$cpu.PercentProcessorTime;DPCPercent=$cpu.PercentDPCTime;InterruptPercent=$cpu.PercentInterruptTime;ProcessorQueueLength=$sys.ProcessorQueueLength;AvailableMBytes=$mem.AvailableMBytes;PagesPerSec=$mem.PagesPersec;DiskReadBytesPerSec=$disk.DiskReadBytesPersec;DiskWriteBytesPerSec=$disk.DiskWriteBytesPersec;CurrentDiskQueueLength=$disk.CurrentDiskQueueLength;PercentDiskTime=$disk.PercentDiskTime}
} '13-Performance\perf-baseline.json' Json
Invoke-PSCapture 'Top processes' {
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{Name=$_.ProcessName;Id=$_.Id;CPUSeconds=try{$_.TotalProcessorTime.TotalSeconds}catch{$null};WorkingSetMB=[math]::Round($_.WorkingSet64/1MB,1);PrivateMB=[math]::Round($_.PrivateMemorySize64/1MB,1);Handles=$_.HandleCount;Threads=try{$_.Threads.Count}catch{$null}}
    } | Sort CPUSeconds -Descending | Select -First 100
} '13-Performance\top-processes.csv' Csv

# 14 - Updates / pending reboot
Invoke-PSCapture 'Recent hotfixes' { Get-HotFix | Sort InstalledOn -Descending } '14-Updates\hotfixes.csv' Csv
Invoke-PSCapture 'Pending reboot markers' {
    [pscustomobject]@{
        CBSRebootPending=Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        WURebootRequired=Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        PendingFileRenameOperations=[bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)
    }
} '14-Updates\pending-reboot.json' Json

# Summary helpers
function Read-Text([string]$rel){ try{return Get-Content (Join-Path $RunDir $rel) -Raw -ErrorAction Stop}catch{return ''} }
$dism=Read-Text '01-Integrity\DISM-ScanHealth.txt'; if(-not $dism){$dism=Read-Text '01-Integrity\DISM-CheckHealth.txt'}
$sfc=Read-Text '01-Integrity\SFC-VerifyOnly.txt'
$dismClass=if($dism -match 'No component store corruption detected'){'CLEAN'}elseif($dism -match 'repairable|corruption detected'){'ATTENTION'}else{'UNKNOWN'}
$sfcClass=if($sfc -match 'did not find any integrity violations'){'CLEAN'}elseif($sfc -match 'integrity violations|found corrupt files'){'ATTENTION'}else{'UNKNOWN'}
$pnpCount=0; try{$pnpCount=@(Import-Csv (Join-Path $RunDir '04-Devices\configmanager-problems.csv')).Count}catch{}
$whea=0; $bug=0
try{$whea=@(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-WHEA-Logger';StartTime=$Since} -ErrorAction SilentlyContinue).Count}catch{}
try{$bug=@(Get-WinEvent -FilterHashtable @{LogName='System';Id=1001;ProviderName='Microsoft-Windows-WER-SystemErrorReporting';StartTime=$Since} -ErrorAction SilentlyContinue).Count}catch{}
$duration=(Get-Date)-$StartTime
$summary=@"
# Windows No-Bullshit Audit Baseline

**Computer:** $env:COMPUTERNAME  
**Started:** $($StartTime.ToString('u'))  
**Finished:** $((Get-Date).ToString('u'))  
**Duration:** $([math]::Round($duration.TotalMinutes,1)) minutes  
**History window:** $EventDays days  
**Mode:** read-only evidence collection

## High-signal baseline

| Check | Result |
|---|---|
| DISM component store | **$dismClass** |
| SFC VerifyOnly | **$sfcClass** |
| PnP problem devices | **$pnpCount** |
| WHEA events | **$whea** |
| BugCheck/WER system error events | **$bug** |

## Start analysis here

1. `01-Integrity`
2. `02-Storage`
3. `04-Devices\configmanager-problems.csv`
4. `05-Events\event-aggregate.csv`
5. `05-Events\interesting-provider-events.csv`
6. raw high-signal EVTX files, especially storage/Code Integrity when implicated
7. `06-WER` and `07-Dumps\dump-inventory.csv`
8. `03-Drivers\fltmc-filters.txt` and running drivers
9. `08-Boot-Restore` / `09-Power`
10. `11-Software-Startup`
11. `12-Security`
12. `13-Performance` (baseline only; use the dedicated WPR collector for ETW)

## Safety and privacy

This collector did not run repair commands or delete/modify Windows configuration.
Environment variable values are redacted. Service/task/startup command lines use best-effort secret redaction.
Raw EVTX, WER manifests, file paths, hostnames, IP configuration, software inventory, and security configuration can still be sensitive.
Crash dump payloads are inventoried but not copied.

Do not "fix" every Event Viewer error. Correlate first, repair second, verify last.
"@
$summary | Out-File (Join-Path $RunDir 'SUMMARY.md') -Encoding utf8 -Width 4096
$Journal | Export-Csv (Join-Path $RunDir 'COMMAND-JOURNAL.csv') -NoTypeInformation -Encoding UTF8
$Journal | ConvertTo-Json -Depth 5 | Out-File (Join-Path $RunDir 'COMMAND-JOURNAL.json') -Encoding utf8
if($Warnings.Count){$Warnings | Out-File (Join-Path $RunDir 'COLLECTOR-WARNINGS.txt') -Encoding utf8}
try{ if($PSCommandPath){ Copy-Item $PSCommandPath (Join-Path $RunDir 'collect-baseline.ps1') -Force } }catch{}

if(-not $NoZip){
    try{
        if(Test-Path $ZipPath){Remove-Item $ZipPath -Force}
        Compress-Archive -Path (Join-Path $RunDir '*') -DestinationPath $ZipPath -CompressionLevel Optimal -Force
        Write-Host "ZIP: $ZipPath" -ForegroundColor Green
    }catch{ Write-Warning "ZIP creation failed: $($_.Exception.Message)" }
}
Write-Host "Audit baseline complete: $RunDir" -ForegroundColor Green
