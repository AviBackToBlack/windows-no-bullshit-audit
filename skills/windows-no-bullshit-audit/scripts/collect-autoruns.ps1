#requires -version 5.1
[CmdletBinding()]
param(
    [string]$OutputDirectory = "$env:SystemDrive\WindowsNoBullshitAudit\Autoruns-$(Get-Date -Format yyyyMMdd-HHmmss)",
    [string]$AutorunscPath,
    [switch]$VirusTotal
)

Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

function Find-Autorunsc {
    param([string]$Explicit)
    if($Explicit -and (Test-Path -LiteralPath $Explicit)){ return (Resolve-Path $Explicit).Path }
    $names = if($env:PROCESSOR_ARCHITECTURE -match 'ARM64'){ @('autorunsc64a.exe','autorunsc64.exe','autorunsc.exe') } else { @('autorunsc64.exe','autorunsc.exe','autorunsc64a.exe') }
    foreach($n in $names){
        $c=Get-Command $n -ErrorAction SilentlyContinue
        if($c){return $c.Source}
    }
    $roots=@("$env:ProgramFiles\Sysinternals","$env:ProgramFiles\Autoruns","$env:LOCALAPPDATA\Microsoft\WinGet\Packages") | Where-Object {Test-Path $_}
    foreach($r in $roots){
        foreach($n in $names){
            $hit=Get-ChildItem -LiteralPath $r -Filter $n -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if($hit){return $hit.FullName}
        }
    }
    return $null
}

$exe=Find-Autorunsc $AutorunscPath
if(-not $exe){
    @"
Autorunsc was not found.
Install Microsoft Sysinternals Autoruns from an official Microsoft source, or rerun with -AutorunscPath <path>.
Do not use an unofficial mirror.
"@ | Out-File (Join-Path $OutputDirectory 'AUTORUNS-NOT-FOUND.txt') -Encoding utf8
    Write-Error 'Autorunsc not found.'
    exit 3
}

$out=Join-Path $OutputDirectory 'autoruns.xml'
$args=@('-accepteula','-a','*','-x','-h','-s','-t')
if($VirusTotal){$args += @('-v','-vt')}

$stderr=Join-Path $OutputDirectory 'autoruns-stderr.txt'
$xmlText = & $exe @args 2> $stderr
$code = if($null -eq $LASTEXITCODE){0}else{[int]$LASTEXITCODE}
# Autorunsc declares UTF-16 XML. Windows PowerShell's explicit Unicode output keeps the declaration and bytes consistent.
$xmlText | Out-File -FilePath $out -Encoding Unicode -Width 1000000
[pscustomobject]@{Autorunsc=$exe;ExitCode=$code;VirusTotal=[bool]$VirusTotal;Output=$out;Timestamp=(Get-Date).ToString('o')} | ConvertTo-Json | Out-File (Join-Path $OutputDirectory 'autoruns-metadata.json') -Encoding utf8
if($code -ne 0){Write-Error "Autorunsc exited $code";exit $code}
try{ [xml](Get-Content $out -Raw) | Out-Null }catch{Write-Error "Autoruns XML did not parse: $($_.Exception.Message)";exit 4}
Write-Host "Autoruns XML: $out" -ForegroundColor Green
