#Requires -Version 5.1
#Requires -RunAsAdministrator
#Requires -Modules Hyper-V

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$ConfigPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'config\LabConfig.psd1'),
    [ValidateSet('05-ADCS-Baseline', '06-ADCS-HTTP-CDP')]
    [string]$CheckpointName = '06-ADCS-HTTP-CDP',
    [switch]$AcknowledgeDataLoss,
    [switch]$StartVM
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Assert-LabAdministrator
$config = Import-LabConfig -Path $ConfigPath
$vmName = [string]$config.Lab.VMName

if (-not $WhatIfPreference -and -not $AcknowledgeDataLoss) {
    throw 'Restoring a checkpoint discards later VM changes. Rerun with -AcknowledgeDataLoss after reviewing -WhatIf output.'
}

$vm = Get-VM -Name $vmName -ErrorAction Stop
if ([bool]$vm.AutomaticCheckpointsEnabled) {
    throw "Automatic checkpoints must be disabled for VM '$vmName'."
}
if ([string]$vm.CheckpointType -ine 'Standard') {
    throw "VM '$vmName' must use Standard checkpoints; current type is '$($vm.CheckpointType)'."
}

$targets = @(Get-VMCheckpoint -VMName $vmName -Name $CheckpointName -ErrorAction SilentlyContinue)
if ($targets.Count -ne 1) {
    throw "Expected exactly one checkpoint named '$CheckpointName' for VM '$vmName'; found $($targets.Count)."
}

$target = $targets[0]
$targetSummary = [pscustomobject]@{
    VMName             = $vmName
    CheckpointName     = [string]$target.Name
    CheckpointId       = [string]$target.Id
    CreationTime       = $target.CreationTime
    CurrentVMState     = [string]$vm.State
    StartAfterRestore  = [bool]$StartVM
}
$targetSummary | Format-List | Out-Host

$operation = "Restore checkpoint '$CheckpointName' and discard all later VM changes"
if (-not $PSCmdlet.ShouldProcess("VM '$vmName'; CheckpointId '$($target.Id)'", $operation)) {
    return $targetSummary
}

$target | Restore-VMCheckpoint -Confirm:$false -ErrorAction Stop
$restoredVm = Get-VM -Name $vmName -ErrorAction Stop
if ($StartVM -and $restoredVm.State -eq 'Off') {
    Start-VM -Name $vmName -ErrorAction Stop | Out-Null
    $restoredVm = Get-VM -Name $vmName -ErrorAction Stop
}

[pscustomobject]@{
    PSTypeName         = 'ADLab.ScenarioBaselineRestoreResult'
    Status             = 'Restored'
    VMName             = $vmName
    CheckpointName     = $CheckpointName
    CheckpointId       = [string]$target.Id
    VMState            = [string]$restoredVm.State
    StartedAfterRestore = [bool]($StartVM -and $restoredVm.State -eq 'Running')
}
