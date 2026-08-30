[CmdletBinding()]
param(
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'

$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

$identity = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }
$interactive = try { (Get-CimInstance Win32_ComputerSystem).UserName } catch { $null }

$virtText = @($cs.Manufacturer, $cs.Model) -join ' '
$virtPatterns = @(
    'Virtual Machine', 'VMware', 'VirtualBox', 'KVM', 'QEMU', 'HVM domU',
    'Amazon EC2', 'Google Compute Engine', 'Microsoft Corporation Virtual',
    'Parallels', 'Xen'
)
$virtHits = @($virtPatterns | Where-Object { $virtText -match [regex]::Escape($_) })

$psPath = try { (Get-Process -Id $PID).Path } catch { $null }

$result = [ordered]@{
    schema_version = '1.0'
    collected_at = (Get-Date).ToString('o')
    computer_name = $env:COMPUTERNAME
    os_caption = $os.Caption
    os_version = $os.Version
    os_build = $os.BuildNumber
    display_version = $cv.DisplayVersion
    edition_id = $cv.EditionID
    os_architecture = $os.OSArchitecture
    processor_architecture = $env:PROCESSOR_ARCHITECTURE
    manufacturer = $cs.Manufacturer
    model = $cs.Model
    hypervisor_present = [bool]$cs.HypervisorPresent
    likely_virtualized = ($virtHits.Count -gt 0)
    virtualization_indicators = $virtHits
    current_identity = $identity
    interactive_user = $interactive
    system_drive = $env:SystemDrive
    user_profile = $env:USERPROFILE
    powershell_edition = $PSVersionTable.PSEdition
    powershell_version = $PSVersionTable.PSVersion.ToString()
    powershell_process_path = $psPath
    session_name = $env:SESSIONNAME
    is_windows_11_candidate = ($os.Caption -match 'Windows 11')
}

$json = $result | ConvertTo-Json -Depth 4

if ($OutFile) {
    $parent = Split-Path -Parent $OutFile
    if ($parent -and -not (Test-Path $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($OutFile, $json, [System.Text.Encoding]::UTF8)
}

$json
