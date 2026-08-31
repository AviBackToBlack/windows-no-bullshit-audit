# Throwaway verification helper for the v0.2.0 elevated validation.
# Not part of the skill. Delete after use.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$RunDir)

$ok = 0; $bad = 0
function Check($label, $value, $requirement = 'non-null') {
    $script:total++
    $pass = switch ($requirement) {
        'non-null' { $null -ne $value -and "$value" -ne '' }
        'true'     { $value -eq $true }
        'numeric'  { $null -ne $value -and $value -is [ValueType] }
        default    { $false }
    }
    if ($pass) { $script:ok++;  Write-Host ("  PASS  {0,-28} {1}" -f $label, $value) -ForegroundColor Green }
    else       { $script:bad++; Write-Host ("  FAIL  {0,-28} {1}" -f $label, '<null/unknown - needs elevation?>') -ForegroundColor Red }
}

$t = Get-Content (Join-Path $RunDir 'TRIAGE.json') -Raw | ConvertFrom-Json

Write-Host ''
Write-Host "Run: $RunDir" -ForegroundColor Cyan
Write-Host "Digest: TRIAGE.json $((Get-Item (Join-Path $RunDir 'TRIAGE.json')).Length) b | TRIAGE.md $((Get-Item (Join-Path $RunDir 'TRIAGE.md')).Length) b"
Write-Host "Collected in $($t.collection.duration_minutes) min | elevated flag: $($t.collection.elevated)"
Write-Host ''

Write-Host 'Elevated-only evidence (all of these were unknown in un-elevated testing):' -ForegroundColor Yellow
Check 'secure_boot'        $t.flags.secure_boot
Check 'winre_enabled'      $t.flags.winre_enabled
Check 'tpm_present'        $t.flags.tpm_present
Check 'defender_realtime'  $t.flags.defender_realtime
$d = $t.storage.disks | Select-Object -First 1
Check 'disk PowerOnHours'  $d.PowerOnHours
Check 'disk TempC'         $d.TempC
Check 'disk ReadErrUncorr' $d.ReadErrUncorrected 'numeric'

Write-Host ''
Write-Host 'Collection health:' -ForegroundColor Yellow
$fp = @($t.collection.failed_probes)
if ($fp.Count -eq 0) { Write-Host '  PASS  no failed probes' -ForegroundColor Green; $ok++ }
else { Write-Host "  WARN  $($fp.Count) failed probes:" -ForegroundColor Yellow; $fp | ForEach-Object { Write-Host "          - $_" } }
Write-Host "  info  nonzero_probes: $(@($t.collection.nonzero_probes).Count) (normal for query tools)"
Write-Host "  info  truncated_logs: $(@($t.collection.truncated_logs).Count)"
Write-Host "  info  trimmed:        $(@($t.trimmed).Count)"
Write-Host "  info  events examined: $($t.collection.events_examined) over $($t.collection.event_window_days) d"

Write-Host ''
Write-Host 'Budget:' -ForegroundColor Yellow
$j = (Get-Item (Join-Path $RunDir 'TRIAGE.json')).Length
$m = (Get-Item (Join-Path $RunDir 'TRIAGE.md')).Length
if ($j -le 60000) { Write-Host "  PASS  TRIAGE.json $j b <= 60000" -ForegroundColor Green } else { Write-Host "  FAIL  TRIAGE.json $j b > 60000" -ForegroundColor Red; $bad++ }
if ($m -le 45000) { Write-Host "  PASS  TRIAGE.md   $m b <= 45000" -ForegroundColor Green } else { Write-Host "  FAIL  TRIAGE.md   $m b > 45000" -ForegroundColor Red; $bad++ }

Write-Host ''
if ($bad -eq 0) { Write-Host 'ELEVATED RUN LOOKS GOOD.' -ForegroundColor Green }
else { Write-Host "$bad check(s) failed - paste the output back." -ForegroundColor Red }
Write-Host ''
