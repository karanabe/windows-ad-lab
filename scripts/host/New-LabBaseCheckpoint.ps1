#Requires -Version 5.1
#Requires -RunAsAdministrator
#Requires -Modules Hyper-V

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$ConfigPath = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'config\LabConfig.psd1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$checkpointName = '01-Updated'
$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Assert-LabAdministrator

$config = Import-LabConfig -Path $ConfigPath
$vmName = [string]$config.Lab.VMName
$switchName = [string]$config.Network.SwitchName

$vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
if ($null -eq $vm) { throw "VM '$vmName' does not exist." }
if ($vm.State -ne 'Running') {
    throw "VM '$vmName' must be running before checkpoint '$checkpointName' is created; current state is '$($vm.State)'."
}
if ([bool]$vm.AutomaticCheckpointsEnabled) {
    throw "Automatic checkpoints must be disabled for VM '$vmName' before creating '$checkpointName'."
}
if ([string]$vm.CheckpointType -ine 'Standard') {
    throw "Checkpoint type for VM '$vmName' must be Standard before creating '$checkpointName'; current type is '$($vm.CheckpointType)'."
}

$adapters = @(Get-VMNetworkAdapter -VMName $vmName -ErrorAction Stop)
if ($adapters.Count -ne 1) { throw "VM '$vmName' must have exactly one NIC; found $($adapters.Count)." }
if ([string]$adapters[0].SwitchName -ine $switchName) {
    throw "VM '$vmName' is connected to '$($adapters[0].SwitchName)'. Connect it to private switch '$switchName' with Set-VMNetwork.ps1 before creating '$checkpointName'."
}
$switch = Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue
if ($null -eq $switch) { throw "Hyper-V switch '$switchName' does not exist." }
if ([string]$switch.SwitchType -ine 'Private') {
    throw "Switch '$switchName' must be Private before creating '$checkpointName'; found '$($switch.SwitchType)'."
}

$existing = @(Get-VMCheckpoint -VMName $vmName -Name $checkpointName -ErrorAction SilentlyContinue)
if ($existing.Count -gt 1) {
    throw "More than one checkpoint named '$checkpointName' exists for VM '$vmName'. Resolve the ambiguity manually."
}
if ($existing.Count -eq 1) {
    Write-LabLog -Phase 'HostVm' -Action 'CreateCheckpoint' -Status 'Unchanged' -Target $checkpointName -Message "VM '$vmName' already has one '$checkpointName' checkpoint."
    return [pscustomobject]@{
        PSTypeName = 'ADLab.BaseCheckpointResult'
        VMName     = $vmName
        Name       = $checkpointName
        Status     = 'Unchanged'
        WhatIf     = $false
    }
}

if ($PSCmdlet.ShouldProcess($vmName, "Create checkpoint '$checkpointName'")) {
    Checkpoint-VM -Name $vmName -SnapshotName $checkpointName -ErrorAction Stop | Out-Host
    Start-Sleep -Seconds 10
    $deadline = (Get-Date).AddSeconds(120)
    do {
        $created = @(Get-VMCheckpoint -VMName $vmName -Name $checkpointName -ErrorAction SilentlyContinue)
        if ($created.Count -ge 1) { break }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    if ($created.Count -ne 1) {
        throw "Checkpoint '$checkpointName' was not found exactly once on VM '$vmName' within 120 seconds after the initial 10-second wait; found $($created.Count)."
    }
    Write-LabLog -Phase 'HostVm' -Action 'CreateCheckpoint' -Status 'Changed' -Target $checkpointName -Message "Created on VM '$vmName'."
}

[pscustomobject]@{
    PSTypeName = 'ADLab.BaseCheckpointResult'
    VMName     = $vmName
    Name       = $checkpointName
    Status     = $(if ($WhatIfPreference) { 'WhatIf' } else { 'Created' })
    WhatIf     = [bool]$WhatIfPreference
}
