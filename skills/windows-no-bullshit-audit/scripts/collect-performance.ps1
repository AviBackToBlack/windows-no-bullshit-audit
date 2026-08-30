#requires -version 5.1
[CmdletBinding()]
param(
    [string]$OutputDirectory = "$env:SystemDrive\WindowsNoBullshitAudit\Performance-$(Get-Date -Format yyyyMMdd-HHmmss)",
    [ValidateRange(15,300)][int]$Seconds = 60,
    [switch]$SkipWpr
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Continue'
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

# Language-independent CIM performance snapshots, one per second.
$samples=New-Object System.Collections.Generic.List[object]
for($i=0;$i -lt $Seconds;$i++){
    try{
        $cpu=Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction Stop
        $sys=Get-CimInstance Win32_PerfFormattedData_PerfOS_System -ErrorAction Stop
        $mem=Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory -ErrorAction Stop
        $disk=Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" -ErrorAction SilentlyContinue
        $samples.Add([pscustomobject]@{Timestamp=(Get-Date).ToString('o');CPUPercent=$cpu.PercentProcessorTime;DPCPercent=$cpu.PercentDPCTime;InterruptPercent=$cpu.PercentInterruptTime;ProcessorQueueLength=$sys.ProcessorQueueLength;AvailableMBytes=$mem.AvailableMBytes;PagesPerSec=$mem.PagesPersec;DiskReadBytesPerSec=$disk.DiskReadBytesPersec;DiskWriteBytesPerSec=$disk.DiskWriteBytesPersec;DiskQueue=$disk.CurrentDiskQueueLength;PercentDiskTime=$disk.PercentDiskTime})
    }catch{}
    Start-Sleep -Seconds 1
}
$samples | Export-Csv (Join-Path $OutputDirectory 'perf-samples.csv') -NoTypeInformation -Encoding UTF8

Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{Name=$_.ProcessName;Id=$_.Id;CPUSeconds=try{$_.TotalProcessorTime.TotalSeconds}catch{$null};WorkingSetMB=[math]::Round($_.WorkingSet64/1MB,1);PrivateMB=[math]::Round($_.PrivateMemorySize64/1MB,1);Handles=$_.HandleCount;Threads=try{$_.Threads.Count}catch{$null}}
} | Sort CPUSeconds -Descending | Select -First 200 | Export-Csv (Join-Path $OutputDirectory 'process-snapshot.csv') -NoTypeInformation -Encoding UTF8

if(-not $SkipWpr){
    $wpr=Get-Command wpr.exe -ErrorAction SilentlyContinue
    if($wpr){
        $etl=Join-Path $OutputDirectory 'general-runtime.etl'
        $start=& $wpr.Source -start GeneralProfile -filemode 2>&1
        $startCode=$LASTEXITCODE
        $start | Out-File (Join-Path $OutputDirectory 'wpr-start.txt') -Encoding utf8
        if($startCode -eq 0){
            # Capture a bounded trace. The CIM sampling above already lasted $Seconds seconds;
            # use a fresh short trace to avoid runaway ETL size.
            Start-Sleep -Seconds ([math]::Min($Seconds,60))
            $stop=& $wpr.Source -stop $etl 'Windows No-Bullshit Audit runtime baseline' 2>&1
            $stopCode=$LASTEXITCODE
            $stop | Out-File (Join-Path $OutputDirectory 'wpr-stop.txt') -Encoding utf8
            [pscustomobject]@{WprPresent=$true;StartExitCode=$startCode;StopExitCode=$stopCode;ETL=$etl} | ConvertTo-Json | Out-File (Join-Path $OutputDirectory 'wpr-metadata.json') -Encoding utf8
        }else{
            [pscustomobject]@{WprPresent=$true;StartExitCode=$startCode;Note='WPR start failed or another trace/session may already be active. Existing sessions were not cancelled.'} | ConvertTo-Json | Out-File (Join-Path $OutputDirectory 'wpr-metadata.json') -Encoding utf8
        }
    }else{
        'wpr.exe was not found. Ask whether to install official Microsoft Windows Performance Toolkit or have the operator install it manually.' | Out-File (Join-Path $OutputDirectory 'WPR-NOT-FOUND.txt') -Encoding utf8
    }
}
Write-Host "Performance evidence: $OutputDirectory" -ForegroundColor Green
