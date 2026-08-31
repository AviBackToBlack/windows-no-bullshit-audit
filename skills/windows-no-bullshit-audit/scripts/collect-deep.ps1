#requires -version 5.1
<#
.SYNOPSIS
  Slow Windows integrity/storage scans, separated from the fast baseline so the
  agent never has to sit in a polling loop with a full context attached.

.DESCRIPTION
  Runs the expensive read-only scans that collect-baseline.ps1 -Depth Fast
  deliberately skips:

    DISM /ScanHealth        component store integrity        ~5-15 min
    SFC /verifyonly         protected system file check      ~5-10 min
    CHKDSK /scan            online NTFS consistency scan     ~2-20 min per volume
    powercfg /energy        30s energy trace + report        ~1 min

  None of these repair anything. CHKDSK /scan is the online, non-mutating scan;
  it does not imply /f or /r.

  Progress is written to DEEP-STATUS.json after every step. Poll that one small
  file instead of re-reading logs:

      Get-Content <RunDir>\DEEP-STATUS.json -Raw | ConvertFrom-Json

  When state reaches "complete", read DEEP-TRIAGE.md. That is the only file the
  agent needs from this script.

.PARAMETER RunDir
  Existing evidence directory created by collect-baseline.ps1. Required so the
  deep results land next to the baseline they belong to.

.PARAMETER Only
  Restrict to a subset: Integrity, Storage, Power. Default: all three.

.PARAMETER TimeoutMinutes
  Per-step wall-clock ceiling. A step that exceeds it is recorded as TIMEOUT
  rather than hanging the audit. Default 45.

.EXAMPLE
  # Foreground
  .\collect-deep.ps1 -RunDir 'C:\WindowsNoBullshitAudit\WindowsNoBullshitAudit-PC-20250101-120000'

.EXAMPLE
  # Background, so the operator/agent can keep working
  Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass',
    '-File','.\collect-deep.ps1','-RunDir','C:\WindowsNoBullshitAudit\<run>'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunDir,
    [ValidateSet('Integrity','Storage','Power')][string[]]$Only = @('Integrity','Storage','Power'),
    [ValidateRange(5,600)][int]$TimeoutMinutes = 45
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
    Write-Host 'ELEVATION REQUIRED. Run this from an administrator Terminal.' -ForegroundColor Red
    exit 740
}
if (-not (Test-Path -LiteralPath $RunDir)) {
    Write-Error "RunDir does not exist: $RunDir. Run collect-baseline.ps1 first."
    exit 2
}

foreach ($d in @('01-Integrity','02-Storage','09-Power')) {
    New-Item -ItemType Directory -Force -Path (Join-Path $RunDir $d) | Out-Null
}

$StatusPath = Join-Path $RunDir 'DEEP-STATUS.json'
$Start = Get-Date
$Steps = New-Object System.Collections.ArrayList

function Save-Status {
    param([string]$State,[string]$Current='')
    $obj = [ordered]@{
        schema_version = '1.0'
        state          = $State           # running | complete | failed
        current_step   = $Current
        started        = $Start.ToString('o')
        updated        = (Get-Date).ToString('o')
        elapsed_minutes= [math]::Round(((Get-Date)-$Start).TotalMinutes,1)
        steps          = @($Steps)
    }
    [IO.File]::WriteAllText($StatusPath, ($obj | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
}

function Invoke-Step {
    param([string]$Name,[string]$Exe,[string[]]$Arguments,[string]$RelativeOutput)
    Save-Status 'running' $Name
    Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] $Name ..." -ForegroundColor Cyan
    $out = Join-Path $RunDir $RelativeOutput
    $sw  = [Diagnostics.Stopwatch]::StartNew()
    $status = 'OK'; $code = 0; $note = ''
    try {
        $psi = New-Object Diagnostics.ProcessStartInfo
        $psi.FileName = (Get-Command $Exe -ErrorAction Stop).Source
        $psi.Arguments = ($Arguments | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $proc = [Diagnostics.Process]::Start($psi)
        $stdout = $proc.StandardOutput.ReadToEndAsync()
        $stderr = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit($TimeoutMinutes * 60 * 1000)) {
            try { $proc.Kill() } catch {}
            $status = 'TIMEOUT'; $code = -1; $note = "Exceeded $TimeoutMinutes minutes"
        } else {
            $code = $proc.ExitCode
            if ($code -ne 0) { $status = 'NONZERO'; $note = "Exit code $code" }
        }
        $text = ''
        try { $text = $stdout.Result } catch {}
        try { $errText = $stderr.Result; if ($errText) { $text += "`r`n--- stderr ---`r`n$errText" } } catch {}
        # Some of these tools emit NUL-padded UTF-16-ish output; strip NULs.
        $text = $text -replace "`0",''
        [IO.File]::WriteAllText($out, $text, (New-Object Text.UTF8Encoding($false)))
    } catch {
        $status = 'ERROR'; $code = -1; $note = $_.Exception.Message
        [IO.File]::WriteAllText($out, ($_ | Out-String), (New-Object Text.UTF8Encoding($false)))
    } finally {
        $sw.Stop()
        $null = $Steps.Add([pscustomobject]@{
            Name=$Name; Status=$status; ExitCode=$code
            Minutes=[math]::Round($sw.Elapsed.TotalMinutes,1); Output=$RelativeOutput; Note=$note
        })
        Save-Status 'running' $Name
        Write-Host "    -> $status in $([math]::Round($sw.Elapsed.TotalMinutes,1)) min" -ForegroundColor DarkGray
    }
}

Save-Status 'running' 'starting'
Write-Host "Deep scans for $RunDir" -ForegroundColor Green
Write-Host "Steps: $($Only -join ', ') | per-step timeout ${TimeoutMinutes}m" -ForegroundColor Yellow
Write-Host "Poll: $StatusPath"
Write-Host ''

if ($Only -contains 'Integrity') {
    Invoke-Step 'DISM ScanHealth' 'dism.exe' @('/Online','/Cleanup-Image','/ScanHealth','/English') '01-Integrity\DISM-ScanHealth.txt'
    Invoke-Step 'SFC VerifyOnly'  'sfc.exe'  @('/verifyonly')                                        '01-Integrity\SFC-VerifyOnly.txt'
}

if ($Only -contains 'Storage') {
    $fixed = @()
    try { $fixed = @(Get-Volume -ErrorAction Stop | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' -and $_.FileSystem -eq 'NTFS' }) } catch {}
    foreach ($v in $fixed) {
        $drive = "$($v.DriveLetter):"
        Invoke-Step "CHKDSK scan $drive" 'chkdsk.exe' @($drive,'/scan') "02-Storage\chkdsk-$($v.DriveLetter)-scan.txt"
    }
}

if ($Only -contains 'Power') {
    $energy = Join-Path $RunDir '09-Power\energy.html'
    Invoke-Step 'powercfg energy' 'powercfg.exe' @('/energy','/duration','30','/output',$energy) '09-Power\powercfg-energy-command.txt'
}

# ------------------------------------------------------------------ digest --

function Read-Text([string]$rel) { try { return Get-Content (Join-Path $RunDir $rel) -Raw -ErrorAction Stop } catch { return '' } }

# Only report scopes this invocation actually executed. A previous full run
# leaves DISM-ScanHealth.txt on disk, and reading it after `-Only Storage`
# would present a stale result as a fresh verdict - which is precisely the
# "repair succeeded, therefore healthy" mistake this skill exists to prevent.
$ranIntegrity = $Only -contains 'Integrity'
$ranStorage   = $Only -contains 'Storage'
$ranPower     = $Only -contains 'Power'

$dism = if ($ranIntegrity) { Read-Text '01-Integrity\DISM-ScanHealth.txt' } else { '' }
$sfc  = if ($ranIntegrity) { Read-Text '01-Integrity\SFC-VerifyOnly.txt' }  else { '' }

$dismClass = if (-not $ranIntegrity) { 'NOT_RUN_THIS_INVOCATION' }
             elseif (-not $dism) { 'NOT_RUN' }
             elseif ($dism -match 'No component store corruption detected') { 'CLEAN' }
             elseif ($dism -match 'repairable|corruption detected') { 'ATTENTION' }
             else { 'UNKNOWN' }
$sfcClass  = if (-not $ranIntegrity) { 'NOT_RUN_THIS_INVOCATION' }
             elseif (-not $sfc) { 'NOT_RUN' }
             elseif ($sfc -match 'did not find any integrity violations') { 'CLEAN' }
             elseif ($sfc -match 'was unable to fix') { 'ATTENTION' }
             elseif ($sfc -match 'integrity violations|found corrupt files') { 'ATTENTION' }
             else { 'UNKNOWN' }

$chkdsk = @()
if ($ranStorage) {
    # Only files written by a step in THIS run, matched through the journal
    # rather than by globbing the directory.
    $storageOutputs = @($Steps | Where-Object { $_.Output -like '02-Storage\chkdsk-*' })
    foreach ($s in $storageOutputs) {
        $t = ''
        try { $t = Get-Content (Join-Path $RunDir $s.Output) -Raw -ErrorAction Stop } catch {}
        $cls = if ($s.Status -ne 'OK' -and $s.Status -ne 'NONZERO') { 'UNKNOWN' }
               elseif ($t -match 'found no problems|no further action is required') { 'CLEAN' }
               elseif ($t -match 'found problems|errors') { 'ATTENTION' }
               else { 'UNKNOWN' }
        $vol = ([IO.Path]::GetFileNameWithoutExtension($s.Output)) -replace '^chkdsk-|-scan$',''
        $chkdsk += [pscustomobject]@{ Volume=$vol; Result=$cls; Status=$s.Status }
    }
}

# powercfg /energy writes errors/warnings counts into the HTML; extract only the
# headline numbers, never the HTML itself.
$energyErrors = $null; $energyWarnings = $null
if ($ranPower) {
    try {
        $eh = Get-Content (Join-Path $RunDir '09-Power\energy.html') -Raw -ErrorAction Stop
        if ($eh -match '(?s)Errors.*?(\d+)')   { $energyErrors   = [int]$Matches[1] }
        if ($eh -match '(?s)Warnings.*?(\d+)') { $energyWarnings = [int]$Matches[1] }
    } catch {}
}

# Copy servicing logs only if a scan actually found something. CBS.log is
# routinely 5-50 MB and is pure noise on a clean machine.
if ($dismClass -eq 'ATTENTION' -or $sfcClass -eq 'ATTENTION') {
    foreach ($src in @("$env:SystemRoot\Logs\CBS\CBS.log","$env:SystemRoot\Logs\DISM\dism.log")) {
        if (Test-Path $src) { try { Copy-Item $src (Join-Path $RunDir '01-Integrity') -Force -ErrorAction Stop } catch {} }
    }
}

$digest = [ordered]@{
    schema_version   = '1.0'
    generated_at     = (Get-Date).ToString('o')
    duration_minutes = [math]::Round(((Get-Date)-$Start).TotalMinutes,1)
    scopes_run       = @($Only)
    dism_scanhealth  = $dismClass
    sfc_verifyonly   = $sfcClass
    chkdsk           = $chkdsk
    energy_errors    = $energyErrors
    energy_warnings  = $energyWarnings
    servicing_logs_copied = ($dismClass -eq 'ATTENTION' -or $sfcClass -eq 'ATTENTION')
    steps            = @($Steps)
}
[IO.File]::WriteAllText((Join-Path $RunDir 'DEEP-TRIAGE.json'), ($digest | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))

$md = @()
$md += '# Deep scan results'
$md += ''
$md += "Completed in $($digest.duration_minutes) minutes. Scopes run: **$($Only -join ', ')**."
$md += ''
$md += '| Scan | Result |'
$md += '|---|---|'
$md += "| DISM /ScanHealth | **$dismClass** |"
$md += "| SFC /verifyonly | **$sfcClass** |"
if ($ranStorage) {
    foreach ($c in $chkdsk) { $md += "| CHKDSK /scan $($c.Volume): | **$($c.Result)** |" }
    if (-not $chkdsk.Count) { $md += '| CHKDSK /scan | no fixed NTFS volume found |' }
} else {
    $md += '| CHKDSK /scan | **NOT_RUN_THIS_INVOCATION** |'
}
if ($ranPower) {
    $md += "| powercfg /energy | $energyErrors errors, $energyWarnings warnings |"
} else {
    $md += '| powercfg /energy | **NOT_RUN_THIS_INVOCATION** |'
}
$md += ''
if ($Only.Count -lt 3) {
    $md += "> Scopes outside ``$($Only -join ', ')`` were not executed in this run. Any result for them from an earlier run is deliberately not reported here, because a stale scan must never read as a fresh verdict."
    $md += ''
}
foreach ($s in $Steps | Where-Object { $_.Status -ne 'OK' }) {
    $md += "- step ``$($s.Name)`` finished as **$($s.Status)** ($($s.Note)). Treat its result as UNKNOWN, not clean."
}
$md += ''
if ($digest.servicing_logs_copied) {
    $md += 'A scan reported corruption, so `CBS.log` / `dism.log` were copied into `01-Integrity`. Query them with `Select-String`; do not read them whole.'
} else {
    $md += 'No scan reported corruption, so servicing logs were not copied.'
}
[IO.File]::WriteAllText((Join-Path $RunDir 'DEEP-TRIAGE.md'), (($md -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding($false)))

Save-Status 'complete' ''
Write-Host ''
Write-Host 'Deep scans complete.' -ForegroundColor Green
Write-Host "Read: $(Join-Path $RunDir 'DEEP-TRIAGE.md')" -ForegroundColor Cyan
