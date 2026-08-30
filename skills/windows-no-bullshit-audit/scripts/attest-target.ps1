<#
.SYNOPSIS
  Identify the machine that is actually executing commands.

.DESCRIPTION
  First probe of every audit. Deliberately does NOT require administrator
  rights: it must succeed in a sandbox, a container, a helper VM and a locked
  down user session, because proving "this is the wrong machine" is exactly as
  important as proving "this is the right one".

  Output is small on purpose. It is the only thing the agent needs to decide
  CONFIRMED_TARGET / NOT_TARGET / UNCONFIRMED / UNAVAILABLE.

  Collects no serial numbers, product keys or licence identifiers. Machine
  identity does not require them.

.PARAMETER OutFile
  Optional path for the JSON.

.PARAMETER Redact
  Pseudonymize computer name, user names and profile path. Use when the result
  will be pasted into a hosted chat. The operator still sees the real values on
  screen before redaction is applied to the output.
#>
[CmdletBinding()]
param(
    [string]$OutFile,
    [switch]$Redact
)

$ErrorActionPreference = 'Stop'

$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

$identity = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }
$elevated = try {
    $wi = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object System.Security.Principal.WindowsPrincipal($wi)).IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $null }

$virtText = @($cs.Manufacturer, $cs.Model) -join ' '
$virtPatterns = @(
    'Virtual Machine','VMware','VirtualBox','KVM','QEMU','HVM domU',
    'Amazon EC2','Google Compute Engine','Microsoft Corporation Virtual',
    'Parallels','Xen','Hyper-V'
)
$virtHits = @($virtPatterns | Where-Object { $virtText -match [regex]::Escape($_) })

$psPath = try { (Get-Process -Id $PID).Path } catch { $null }

function Protect-Value {
    param([AllowNull()]$Value,[string]$Placeholder)
    if (-not $Redact) { return $Value }
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $Value }
    return $Placeholder
}

$result = [ordered]@{
    schema_version          = '1.1'
    collected_at            = (Get-Date).ToString('o')
    redacted                = [bool]$Redact
    computer_name           = (Protect-Value $env:COMPUTERNAME '<COMPUTER>')
    os_caption              = $os.Caption
    os_version              = $os.Version
    os_build                = $os.BuildNumber
    display_version         = $cv.DisplayVersion
    edition_id              = $cv.EditionID
    os_architecture         = $os.OSArchitecture
    processor_architecture  = $env:PROCESSOR_ARCHITECTURE
    manufacturer            = $cs.Manufacturer
    model                   = $cs.Model
    hypervisor_present      = [bool]$cs.HypervisorPresent
    likely_virtualized      = ($virtHits.Count -gt 0)
    virtualization_indicators = $virtHits
    current_identity        = (Protect-Value $identity '<USER>')
    interactive_user        = (Protect-Value $cs.UserName '<USER>')
    is_elevated             = $elevated
    system_drive            = $env:SystemDrive
    user_profile            = (Protect-Value $env:USERPROFILE '<USERPROFILE>')
    powershell_edition      = $PSVersionTable.PSEdition
    powershell_version      = $PSVersionTable.PSVersion.ToString()
    powershell_process_path = $psPath
    session_name            = $env:SESSIONNAME
    is_windows_11_candidate = ($os.Caption -match 'Windows 11')
}

$json = $result | ConvertTo-Json -Depth 4

if ($OutFile) {
    $parent = Split-Path -Parent $OutFile
    if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [System.IO.File]::WriteAllText($OutFile, $json, (New-Object System.Text.UTF8Encoding($false)))
}

$json

if ($elevated -eq $false) {
    Write-Host ''
    Write-Host 'Note: this session is NOT elevated. Attestation does not need it, but' -ForegroundColor Yellow
    Write-Host 'collect-baseline.ps1 does. Reopen Terminal as administrator for that step.' -ForegroundColor Yellow
}
