#Requires -Version 5.1
#Requires -RunAsAdministrator
#Requires -Modules Hyper-V

[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'config\LabConfig.psd1'),
    [PSCredential]$Credential,
    [string]$GuestConfigurationName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Assert-LabAdministrator
Assert-LabPowerShellDirectClient
$config = Import-LabConfig -Path $ConfigPath
$vmName = [string]$config.Lab.VMName

if ($null -eq $Credential) {
    $Credential = Get-Credential -Message "Enter a current administrator credential for VM '$vmName'."
}

$vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
if ($null -eq $vm) { throw "VM '$vmName' does not exist on this Hyper-V host." }
if ($vm.State -ne 'Running') { throw "VM '$vmName' must be running; current state is '$($vm.State)'." }

$adapters = @(Get-VMNetworkAdapter -VMName $vmName -ErrorAction Stop)
if ($adapters.Count -ne 1) { throw "VM '$vmName' must have exactly one NIC; found $($adapters.Count)." }
$adapter = $adapters[0]
if ([string]$adapter.SwitchName -ine [string]$config.Network.SwitchName) {
    throw "VM '$vmName' is connected to switch '$($adapter.SwitchName)', expected '$($config.Network.SwitchName)'. Use Set-VMNetwork.ps1 explicitly if this is intentional."
}

$switch = Get-VMSwitch -Name ([string]$config.Network.SwitchName) -ErrorAction SilentlyContinue
if ($null -eq $switch) { throw "Hyper-V switch '$($config.Network.SwitchName)' does not exist." }
if ([string]$switch.SwitchType -ine [string]$config.Network.SwitchType) {
    throw "Hyper-V switch '$($switch.Name)' is '$($switch.SwitchType)', expected '$($config.Network.SwitchType)'."
}

$secureBoot = 'NotApplicable'
if ([int]$vm.Generation -eq 2) {
    $firmware = Get-VMFirmware -VMName $vmName -ErrorAction Stop
    $secureBoot = [string]$firmware.SecureBoot
}

$session = $null
try {
    $sessionParameters = @{
        VMName      = $vmName
        Credential  = $Credential
        ErrorAction = 'Stop'
    }
    if (-not [string]::IsNullOrWhiteSpace($GuestConfigurationName)) {
        $sessionParameters.ConfigurationName = $GuestConfigurationName
    }
    $session = New-PSSession @sessionParameters
    $actualConfigurationName = [string]$session.ConfigurationName
    $guest = Invoke-Command -Session $session -ScriptBlock {
        [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            PowerShellEdition = [string]$PSVersionTable.PSEdition
        }
    } -ErrorAction Stop
}
catch {
    throw "PowerShell Direct connection to '$vmName' failed: $($_.Exception.Message)"
}
finally {
    if ($null -ne $session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
}

if ([version]$guest.PowerShellVersion -lt [version]'5.1') {
    throw "Guest PowerShell 5.1 or newer is required; found '$($guest.PowerShellVersion)'."
}

[pscustomobject]@{
    PSTypeName        = 'ADLab.HyperVPrerequisiteResult'
    VMName            = $vm.Name
    State             = [string]$vm.State
    Generation        = [int]$vm.Generation
    SecureBoot        = $secureBoot
    AutomaticCheckpointsEnabled = [bool]$vm.AutomaticCheckpointsEnabled
    NICCount          = $adapters.Count
    SwitchName        = [string]$adapter.SwitchName
    SwitchType        = [string]$switch.SwitchType
    GuestComputerName = [string]$guest.ComputerName
    GuestPowerShell   = [string]$guest.PowerShellVersion
    GuestPSEdition    = [string]$guest.PowerShellEdition
    GuestConfigurationName = $actualConfigurationName
    PowerShellDirect  = $true
}
