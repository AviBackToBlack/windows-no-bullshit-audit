#requires -version 5.1
[CmdletBinding()]
param(
    [string]$OutputDirectory = "$env:SystemDrive\WindowsNoBullshitAudit\Verification-$(Get-Date -Format yyyyMMdd-HHmmss)",
    [datetime]$Since = (Get-Date).AddHours(-2),
    [switch]$SkipIntegrity,
    [switch]$SkipStorage
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Continue'
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

function Save-Native([string]$Name,[string]$Exe,[string[]]$Args){
    $p=Join-Path $OutputDirectory $Name
    try{ & $Exe @Args 2>&1 | Out-File $p -Encoding utf8 -Width 4096 }catch{ $_ | Out-String | Out-File $p -Encoding utf8 }
}

if(-not $SkipIntegrity){
    Save-Native 'DISM-ScanHealth.txt' 'dism.exe' @('/Online','/Cleanup-Image','/ScanHealth','/English')
    Save-Native 'SFC-VerifyOnly.txt' 'sfc.exe' @('/verifyonly')
}

if(-not $SkipStorage){
    try{
        Get-Volume | Where-Object {$_.DriveLetter -and $_.DriveType -eq 'Fixed' -and $_.FileSystem -eq 'NTFS'} | ForEach-Object {
            $d="$($_.DriveLetter):"
            Save-Native "fsutil-dirty-$($_.DriveLetter).txt" 'fsutil.exe' @('dirty','query',$d)
            Save-Native "chkdsk-$($_.DriveLetter)-scan.txt" 'chkdsk.exe' @($d,'/scan')
        }
    }catch{}
}
Save-Native 'pnp-problem-devices.txt' 'pnputil.exe' @('/enum-devices','/problem','/deviceids')
Save-Native 'fltmc-filters.txt' 'fltmc.exe' @('filters')
Save-Native 'vss-writers.txt' 'vssadmin.exe' @('list','writers')

Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$Since;Level=1,2,3} -ErrorAction SilentlyContinue |
    Where-Object {$_.ProviderName -in @('Microsoft-Windows-WHEA-Logger','Disk','Ntfs','stornvme','storahci','storport','Microsoft-Windows-Kernel-Power','Microsoft-Windows-Kernel-PnP','Service Control Manager','Microsoft-Windows-WER-SystemErrorReporting')} |
    Select TimeCreated,ProviderName,Id,Level,LevelDisplayName,Message |
    Export-Csv (Join-Path $OutputDirectory 'high-signal-events-since.csv') -NoTypeInformation -Encoding UTF8

Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | Where ConfigManagerErrorCode -ne 0 | Select Name,PNPDeviceID,Manufacturer,Service,Status,ConfigManagerErrorCode | Export-Csv (Join-Path $OutputDirectory 'pnp-problems.csv') -NoTypeInformation -Encoding UTF8

[pscustomobject]@{VerificationTime=(Get-Date).ToString('o');Since=$Since.ToString('o');Note='This pass verifies broad health after a repair. A finding-specific discriminating test may still be required.'} | ConvertTo-Json | Out-File (Join-Path $OutputDirectory 'verification-metadata.json') -Encoding utf8
Write-Host "Verification evidence: $OutputDirectory" -ForegroundColor Green
