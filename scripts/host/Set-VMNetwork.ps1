#Requires -Version 5.1
#Requires -RunAsAdministrator
#Requires -Modules Hyper-V

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$ConfigPath = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'config\LabConfig.psd1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Assert-LabAdministrator
$config = Import-LabConfig -Path $ConfigPath
$vmName = [string]$config.Lab.VMName
$switchName = [string]$config.Network.SwitchName

$vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
if ($null -eq $vm) { throw "VM '$vmName' does not exist." }
$switch = Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue
if ($null -eq $switch) { throw "Hyper-V switch '$switchName' does not exist. This script does not create switches." }
if ([string]$switch.SwitchType -ine 'Private') { throw "Switch '$switchName' must be Private; found '$($switch.SwitchType)'." }

$adapters = @(Get-VMNetworkAdapter -VMName $vmName -ErrorAction Stop)
if ($adapters.Count -ne 1) { throw "VM '$vmName' must have exactly one NIC; found $($adapters.Count)." }
if ([string]$adapters[0].SwitchName -ieq $switchName) {
    Write-Host "VM '$vmName' is already connected to '$switchName'."
    return
}

if ($PSCmdlet.ShouldProcess("$vmName/$($adapters[0].Name)", "Connect to private switch '$switchName'")) {
    Connect-VMNetworkAdapter -VMName $vmName -Name $adapters[0].Name -SwitchName $switchName -ErrorAction Stop
    Write-Host "Connected VM '$vmName' to '$switchName'."
}
