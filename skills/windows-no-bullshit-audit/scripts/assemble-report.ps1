#requires -version 5.1
<#
.SYNOPSIS
  Build REPORT.md and refresh audit-state.json from append-only finding files.

.DESCRIPTION
  Findings are written one file at a time to <RunDir>\findings\<id>.json and
  never rewritten as a set. This script assembles them.

  Why this exists: regenerating a full report inside the model after every
  finding costs the whole report in output tokens, then the whole report again
  in input tokens on the next turn, repeatedly. Assembling deterministically
  costs nothing and cannot drift from the underlying data.

  Run it once at FINAL_VALIDATION, and optionally at checkpoints before a
  reboot. Do not run it after every finding; there is no reason to.

  Finding file shape (see assets/finding-template.json):

    {
      "id": "F-001",
      "domain": "storage",
      "title": "...",
      "state": "healthy|observe|action|critical|historical",
      "confidence": "HIGH|MEDIUM|LOW|UNKNOWN",
      "local_evidence": ["..."],
      "lifecycle_context": ["..."],
      "external_evidence": ["https://..."],
      "conclusion": "...",
      "recommended_action": "...",
      "verification": "...",
      "remaining_uncertainty": "...",
      "initial_state": "action"
    }

.PARAMETER RunDir
  Audit run directory containing findings\.

.PARAMETER Validate
  Only validate the finding files and print problems. Writes nothing.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunDir,
    [switch]$Validate
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

if (-not (Test-Path -LiteralPath $RunDir)) { Write-Error "RunDir not found: $RunDir"; exit 2 }
$findingsDir = Join-Path $RunDir 'findings'
if (-not (Test-Path -LiteralPath $findingsDir)) { New-Item -ItemType Directory -Force -Path $findingsDir | Out-Null }

$ValidStates      = @('healthy','observe','action','critical','historical')
$ValidConfidence  = @('HIGH','MEDIUM','LOW','UNKNOWN')
$StateGlyph = @{
    healthy    = [char]0x2705                                  # white heavy check mark
    observe    = [string][char]0xD83D + [string][char]0xDFE1    # yellow circle
    action     = [string][char]0xD83D + [string][char]0xDFE0    # orange circle
    critical   = [string][char]0xD83D + [string][char]0xDD34    # red circle
    historical = [char]0x26AA                                  # medium white circle
}
$StateLabel = [ordered]@{
    critical   = 'Critical'
    action     = 'Action recommended'
    observe    = 'Observe / Intentional / Validation pending'
    healthy    = 'Healthy / Verified'
    historical = 'Historical / Noise / Informational'
}

function Get-Prop {
    param($Object,[string]$Name,$Default=$null)
    if ($null -eq $Object) { return $Default }
    try {
        $p = $Object.PSObject.Properties[$Name]
        if ($null -eq $p -or $null -eq $p.Value) { return $Default }
        return $p.Value
    } catch { return $Default }
}

$problems = New-Object System.Collections.Generic.List[string]
$findings = New-Object System.Collections.ArrayList

foreach ($f in @(Get-ChildItem $findingsDir -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
    $obj = $null
    try { $obj = Get-Content $f.FullName -Raw -ErrorAction Stop | ConvertFrom-Json }
    catch { $problems.Add("$($f.Name): invalid JSON - $($_.Exception.Message)"); continue }

    foreach ($req in @('id','domain','title','state','confidence')) {
        if (-not (Get-Prop $obj $req)) { $problems.Add("$($f.Name): missing required field '$req'") }
    }
    $state = [string](Get-Prop $obj 'state')
    if ($state -and $ValidStates -notcontains $state) { $problems.Add("$($f.Name): state '$state' is not one of $($ValidStates -join '/')") }
    $conf = [string](Get-Prop $obj 'confidence')
    if ($conf -and $ValidConfidence -notcontains $conf) { $problems.Add("$($f.Name): confidence '$conf' is not one of $($ValidConfidence -join '/')") }

    # An action/critical finding with no next step is how audits quietly end
    # with unresolved items. Refuse to let that pass silently.
    if ($state -in @('action','critical')) {
        if (-not (Get-Prop $obj 'recommended_action') -and -not (Get-Prop $obj 'remaining_uncertainty')) {
            $problems.Add("$($f.Name): state '$state' requires recommended_action or remaining_uncertainty")
        }
    }
    if ($conf -eq 'UNKNOWN' -and -not (Get-Prop $obj 'remaining_uncertainty')) {
        $problems.Add("$($f.Name): confidence UNKNOWN requires remaining_uncertainty (the next discriminating test)")
    }
    $null = $findings.Add($obj)
}

if ($problems.Count) {
    Write-Host "Finding validation problems ($($problems.Count)):" -ForegroundColor Yellow
    $problems | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
} else {
    Write-Host "Finding validation: OK ($($findings.Count) findings)" -ForegroundColor Green
}
if ($Validate) { exit $(if ($problems.Count) { 1 } else { 0 }) }

# ------------------------------------------------------------------ counts --

$finalCounts   = [ordered]@{}
$initialCounts = [ordered]@{}
foreach ($s in $StateLabel.Keys) {
    $finalCounts[$s]   = @($findings | Where-Object { (Get-Prop $_ 'state') -eq $s }).Count
    $initialCounts[$s] = @($findings | Where-Object { ([string](Get-Prop $_ 'initial_state' (Get-Prop $_ 'state'))) -eq $s }).Count
}

# ------------------------------------------------------------------ triage --

$triage = $null
$triagePath = Join-Path $RunDir 'TRIAGE.json'
if (Test-Path $triagePath) { try { $triage = Get-Content $triagePath -Raw | ConvertFrom-Json } catch {} }

$target = Get-Prop $triage 'target'
$computer = Get-Prop $target 'computer' $env:COMPUTERNAME
$winDesc  = (@((Get-Prop $target 'os_caption'), (Get-Prop $target 'display_version'),
                "build $(Get-Prop $target 'os_build')", (Get-Prop $target 'architecture')) |
             Where-Object { $_ }) -join ' '

# ------------------------------------------------------------------ report --

$md = New-Object System.Text.StringBuilder
$null = $md.AppendLine('# Windows No-Bullshit Audit Report')
$null = $md.AppendLine()
$null = $md.AppendLine("**Run:** $(Split-Path -Leaf $RunDir)  ")
$null = $md.AppendLine("**Computer:** $computer  ")
$null = $md.AppendLine("**Windows:** $winDesc  ")
$null = $md.AppendLine("**Generated:** $((Get-Date).ToString('u'))  ")
$null = $md.AppendLine()
$null = $md.AppendLine('## Dashboard')
$null = $md.AppendLine()
$null = $md.AppendLine('| State | Initial | Final |')
$null = $md.AppendLine('|---|---:|---:|')
foreach ($s in $StateLabel.Keys) {
    $null = $md.AppendLine("| $($StateGlyph[$s]) $($StateLabel[$s]) | $($initialCounts[$s]) | $($finalCounts[$s]) |")
}
$null = $md.AppendLine()

$unresolved = @($findings | Where-Object { (Get-Prop $_ 'state') -in @('critical','action') })
$unknowns   = @($findings | Where-Object { (Get-Prop $_ 'confidence') -eq 'UNKNOWN' })

$null = $md.AppendLine('## Executive verdict')
$null = $md.AppendLine()
if ($unresolved.Count -eq 0) {
    $null = $md.AppendLine('No critical or action-recommended findings remain open.')
} else {
    $null = $md.AppendLine("$($unresolved.Count) finding(s) remain open:")
    $null = $md.AppendLine()
    foreach ($u in $unresolved) {
        $null = $md.AppendLine("- $($StateGlyph[[string](Get-Prop $u 'state')]) **$(Get-Prop $u 'id')** $(Get-Prop $u 'title') - $(Get-Prop $u 'recommended_action' 'no action recorded')")
    }
}
if ($unknowns.Count) {
    $null = $md.AppendLine()
    $null = $md.AppendLine("$($unknowns.Count) finding(s) are explicitly UNKNOWN rather than guessed. See the last section.")
}
$null = $md.AppendLine()

$null = $md.AppendLine('## Findings')
$null = $md.AppendLine()
$order = @{ critical=0; action=1; observe=2; healthy=3; historical=4 }
foreach ($f in @($findings | Sort-Object @{e={ $order[[string](Get-Prop $_ 'state')] }},@{e={ [string](Get-Prop $_ 'id') }})) {
    $st = [string](Get-Prop $f 'state')
    $null = $md.AppendLine("### $($StateGlyph[$st]) $(Get-Prop $f 'id') - $(Get-Prop $f 'title')")
    $null = $md.AppendLine()
    $null = $md.AppendLine("- **Domain:** $(Get-Prop $f 'domain')")
    $null = $md.AppendLine("- **State:** $($StateLabel[$st])")
    $null = $md.AppendLine("- **Confidence:** $(Get-Prop $f 'confidence')")
    foreach ($pair in @(
        @{ Key='local_evidence';       Label='Local evidence' },
        @{ Key='lifecycle_context';    Label='Lifecycle/context' },
        @{ Key='external_evidence';    Label='Current external evidence' }
    )) {
        $vals = @(Get-Prop $f $pair.Key @())
        if ($vals.Count) {
            $null = $md.AppendLine("- **$($pair.Label):**")
            foreach ($v in $vals) { $null = $md.AppendLine("  - $v") }
        }
    }
    foreach ($pair in @(
        @{ Key='conclusion';            Label='Conclusion' },
        @{ Key='recommended_action';    Label='Action' },
        @{ Key='verification';          Label='Verification' },
        @{ Key='remaining_uncertainty'; Label='Remaining uncertainty / next test' }
    )) {
        $v = Get-Prop $f $pair.Key
        if ($v) { $null = $md.AppendLine("- **$($pair.Label):** $v") }
    }
    $null = $md.AppendLine()
}

if ($unknowns.Count) {
    $null = $md.AppendLine('## Unknown / next discriminating tests')
    $null = $md.AppendLine()
    foreach ($u in $unknowns) {
        $null = $md.AppendLine("- **$(Get-Prop $u 'id')** $(Get-Prop $u 'title'): $(Get-Prop $u 'remaining_uncertainty' 'no next test recorded')")
    }
    $null = $md.AppendLine()
}

if ($problems.Count) {
    $null = $md.AppendLine('## Report generation warnings')
    $null = $md.AppendLine()
    foreach ($p in $problems) { $null = $md.AppendLine("- $p") }
    $null = $md.AppendLine()
}

$reportPath = Join-Path $RunDir 'REPORT.md'
[IO.File]::WriteAllText($reportPath, $md.ToString(), (New-Object Text.UTF8Encoding($false)))

# -------------------------------------------------------------- state file --

$statePath = Join-Path $RunDir 'audit-state.json'
$state = $null
if (Test-Path $statePath) { try { $state = Get-Content $statePath -Raw | ConvertFrom-Json } catch {} }

$out = [ordered]@{
    schema_version    = '1.1'
    run_id            = (Get-Prop $state 'run_id' (Split-Path -Leaf $RunDir))
    phase             = (Get-Prop $state 'phase' 'FINAL_VALIDATION')
    computer          = $computer
    windows           = (Get-Prop $state 'windows' $target)
    started_at        = (Get-Prop $state 'started_at')
    updated_at        = (Get-Date).ToString('o')
    preflight_confirmed = [bool](Get-Prop $state 'preflight_confirmed' $false)
    target_attestation  = (Get-Prop $state 'target_attestation' ([ordered]@{ locality_status='UNCONFIRMED'; operator_confirmed=$false }))
    counts            = [ordered]@{ initial=$initialCounts; final=$finalCounts }
    findings          = @($findings)
    pending_approvals = @(Get-Prop $state 'pending_approvals' @())
    remediations      = @(Get-Prop $state 'remediations' @())
    checkpoints       = @(Get-Prop $state 'checkpoints' @())
}
[IO.File]::WriteAllText($statePath, ($out | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))

Write-Host ''
Write-Host "REPORT.md      $reportPath" -ForegroundColor Green
Write-Host "audit-state    $statePath" -ForegroundColor Green
Write-Host ("Dashboard      " + (($StateLabel.Keys | ForEach-Object { "$($StateGlyph[$_])$($finalCounts[$_])" }) -join ' ')) -ForegroundColor Cyan
if ($problems.Count) { Write-Host "Warnings       $($problems.Count) (listed in REPORT.md)" -ForegroundColor Yellow }
