#requires -version 5.1
<#
.SYNOPSIS
  Sysinternals Autoruns collection reduced to the entries a human would
  actually review.

.DESCRIPTION
  Autorunsc emits several thousand entries, the overwhelming majority of them
  Microsoft-signed and uninteresting. This script keeps the full XML on disk as
  queryable evidence and additionally emits:

    AUTORUNS-TRIAGE.md    capped review list, agent-facing
    autoruns-review.csv   the same list, queryable
    autoruns.xml          full raw output, never meant to be read whole

  Selection rule for the review list: an entry is included when it is NOT
  Microsoft-signed, OR its image is missing, OR its signature is invalid. That
  is the set where a decision is even possible.

  Note: "File not found" is a review trigger, never a deletion verdict. Some
  registry semantics legitimately produce it.

.PARAMETER OutputDirectory
  Where to write. Defaults to a timestamped directory under the audit root.

.PARAMETER AutorunscPath
  Explicit path to autorunsc.exe / autorunsc64.exe if it is not on PATH.

.PARAMETER VirusTotal
  Submit file hashes to VirusTotal. Off by default because it shares hashes
  with a third party. Requires operator approval.

.PARAMETER Redact
  Pseudonymize user names and profile paths in the digest.

.PARAMETER MaxReviewEntries
  Cap for the review list. Default 60. Overflow is reported, not silently cut.
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = "$env:SystemDrive\WindowsNoBullshitAudit\Autoruns-$(Get-Date -Format yyyyMMdd-HHmmss)",
    [string]$AutorunscPath,
    [switch]$VirusTotal,
    [switch]$Redact,
    [ValidateRange(10,500)][int]$MaxReviewEntries = 60
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

if (-not (Test-IsAdministrator)) {
    Write-Host 'ELEVATION REQUIRED.' -ForegroundColor Red
    Write-Host 'Un-elevated Autoruns silently omits services, drivers and machine-wide'
    Write-Host 'entries, which is exactly the part that matters. Run from an'
    Write-Host 'administrator Terminal.'
    exit 740
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

function Find-Autorunsc {
    param([string]$Explicit)
    if ($Explicit -and (Test-Path -LiteralPath $Explicit)) { return (Resolve-Path $Explicit).Path }
    $names = if ($env:PROCESSOR_ARCHITECTURE -match 'ARM64') { @('autorunsc64a.exe','autorunsc64.exe','autorunsc.exe') }
             else { @('autorunsc64.exe','autorunsc.exe','autorunsc64a.exe') }
    foreach ($n in $names) {
        $c = Get-Command $n -ErrorAction SilentlyContinue
        if ($c) { return $c.Source }
    }
    $roots = @("$env:ProgramFiles\Sysinternals","$env:ProgramFiles\Autoruns","$env:LOCALAPPDATA\Microsoft\WinGet\Packages") |
        Where-Object { Test-Path $_ }
    foreach ($r in $roots) {
        foreach ($n in $names) {
            $hit = Get-ChildItem -LiteralPath $r -Filter $n -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($hit) { return $hit.FullName }
        }
    }
    return $null
}

$exe = Find-Autorunsc $AutorunscPath
if (-not $exe) {
    @'
Autorunsc was not found.

Install Microsoft Sysinternals Autoruns from an official Microsoft source
(Microsoft Store, WinGet `Microsoft.Sysinternals.Autoruns`, or
https://learn.microsoft.com/sysinternals/downloads/autoruns), or rerun with
-AutorunscPath <path>.

Do not use an unofficial mirror.
'@ | Out-File (Join-Path $OutputDirectory 'AUTORUNS-NOT-FOUND.txt') -Encoding utf8
    Write-Error 'Autorunsc not found.'
    exit 3
}

$xmlPath = Join-Path $OutputDirectory 'autoruns.xml'
$arArgs  = @('-accepteula','-a','*','-x','-h','-s','-t')
if ($VirusTotal) { $arArgs += @('-v','-vt') }

$stderrPath = Join-Path $OutputDirectory 'autoruns-stderr.txt'
$xmlText = & $exe @arArgs 2> $stderrPath
$code = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
# Autorunsc declares UTF-16 XML. Explicit Unicode output keeps the declaration
# and the bytes consistent.
$xmlText | Out-File -FilePath $xmlPath -Encoding Unicode -Width 1000000

[pscustomobject]@{
    Autorunsc=$exe; ExitCode=$code; VirusTotal=[bool]$VirusTotal
    Output=$xmlPath; Timestamp=(Get-Date).ToString('o')
} | ConvertTo-Json | Out-File (Join-Path $OutputDirectory 'autoruns-metadata.json') -Encoding utf8

if ($code -ne 0) { Write-Error "Autorunsc exited $code"; exit $code }

$xml = $null
try { $xml = [xml](Get-Content $xmlPath -Raw) }
catch { Write-Error "Autoruns XML did not parse: $($_.Exception.Message)"; exit 4 }

# ------------------------------------------------------------------ digest --

$redactMap = @{}
if ($Redact) {
    if ($env:USERNAME)    { $redactMap[$env:USERNAME]    = '<USER>' }
    if ($env:USERPROFILE) { $redactMap[$env:USERPROFILE] = '<USERPROFILE>' }
    if ($env:COMPUTERNAME){ $redactMap[$env:COMPUTERNAME]= '<COMPUTER>' }
}
function Protect-Identity {
    param([AllowNull()][string]$Value)
    if (-not $Redact -or [string]::IsNullOrEmpty($Value)) { return $Value }
    $s = $Value
    foreach ($k in $redactMap.Keys) { $s = $s -replace [regex]::Escape($k), $redactMap[$k] }
    return $s
}
function Get-Node {
    param($Item,[string]$Name)
    try {
        $n = $Item.SelectSingleNode($Name)
        if ($n) { return ([string]$n.InnerText).Trim() }
    } catch {}
    return ''
}

$items = @()
try { $items = @($xml.autoruns.item) } catch {}

$all = foreach ($i in $items) {
    if ($null -eq $i) { continue }
    [pscustomobject]@{
        Location  = Get-Node $i 'location'
        Entry     = Get-Node $i 'itemname'
        Enabled   = Get-Node $i 'enabled'
        Company   = Get-Node $i 'company'
        Signer    = Get-Node $i 'signer'
        Image     = Get-Node $i 'imagepath'
        LaunchStr = Get-Node $i 'launchstring'
        Sha256    = Get-Node $i 'sha256'
        Version   = Get-Node $i 'version'
    }
}

function Test-MicrosoftEntry {
    param($Row)
    $sig = [string]$Row.Signer
    if ($sig -match '^\(Verified\)\s+Microsoft (Corporation|Windows)') { return $true }
    if ($sig -match '^\(Verified\)' -and ([string]$Row.Company) -match '^Microsoft (Corporation|Windows)') { return $true }
    return $false
}

$review = @($all | Where-Object {
    $missing   = ([string]$_.Image -match '(?i)file not found') -or ([string]$_.Signer -match '(?i)file not found')
    $unsigned  = -not ([string]$_.Signer -match '^\(Verified\)')
    $notMs     = -not (Test-MicrosoftEntry $_)
    $missing -or $unsigned -or $notMs
} | Sort-Object Location,Entry)

$reviewProjection = @($review | ForEach-Object {
    [pscustomobject]@{
        Location = $_.Location
        Entry    = Protect-Identity $_.Entry
        Enabled  = $_.Enabled
        Company  = $_.Company
        Signer   = ($_.Signer -replace '^\(Verified\)\s*','')
        Verified = [bool]([string]$_.Signer -match '^\(Verified\)')
        Missing  = [bool](([string]$_.Image -match '(?i)file not found') -or ([string]$_.Signer -match '(?i)file not found'))
        Image    = Protect-Identity $_.Image
    }
})

$reviewProjection | Export-Csv (Join-Path $OutputDirectory 'autoruns-review.csv') -NoTypeInformation -Encoding UTF8

$shown = @($reviewProjection | Select-Object -First $MaxReviewEntries)
$overflow = $reviewProjection.Count - $shown.Count

$md = @()
$md += '# Autoruns triage'
$md += ''
$md += "Total entries: **$($all.Count)** | needing a decision: **$($reviewProjection.Count)** | shown: **$($shown.Count)**"
$md += ''
$md += 'Included when an entry is not Microsoft-signed, is unsigned/unverified, or its image is missing. Everything else is on disk in `autoruns.xml` and `autoruns-review.csv`.'
$md += ''
$md += '| Location | Entry | On | Verified | Missing | Signer | Image |'
$md += '|---|---|---|---|---|---|---|'
foreach ($r in $shown) {
    $img = [string]$r.Image; if ($img.Length -gt 90) { $img = '...' + $img.Substring($img.Length-87) }
    $md += "| $($r.Location) | $($r.Entry) | $($r.Enabled) | $($r.Verified) | $($r.Missing) | $($r.Signer) | $img |"
}
$md += ''
if ($overflow -gt 0) {
    $md += "> $overflow further entries were trimmed from this digest. Query ``autoruns-review.csv`` with a filter instead of raising the cap."
    $md += ''
}
$md += '## Before deleting anything'
$md += ''
$md += '1. `File not found` is not proof of an orphan. Inspect the raw registry/service/task entry.'
$md += '2. If the owning product is still registered as installed, use its official uninstaller first.'
$md += '3. Prefer disabling as an A/B test over deleting.'
$md += '4. Print the exact object before acting. A substring match is not an identification.'

[IO.File]::WriteAllText((Join-Path $OutputDirectory 'AUTORUNS-TRIAGE.md'), (($md -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding($false)))

Write-Host ''
Write-Host "Autoruns entries: $($all.Count) total, $($reviewProjection.Count) need a decision." -ForegroundColor Green
Write-Host "Read: $(Join-Path $OutputDirectory 'AUTORUNS-TRIAGE.md')" -ForegroundColor Cyan
Write-Host "Raw:  $xmlPath (query it, do not read it whole)" -ForegroundColor DarkGray
