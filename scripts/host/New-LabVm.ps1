#Requires -Version 5.1
#Requires -RunAsAdministrator
#Requires -Modules Hyper-V

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [string]$IsoPath,

    [string]$ConfigPath = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'config\LabConfig.psd1'),

    [string]$ExternalSwitchName,

    [ValidateRange(1, 64)]
    [int]$ProcessorCount = 4,

    [uint64]$MemoryStartupBytes = 8192MB,

    [uint64]$VhdSizeBytes = 80GB
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Assert-LabAdministrator

if (-not (Test-Path -LiteralPath $IsoPath -PathType Leaf)) {
    throw "Installation ISO was not found: $IsoPath"
}
$resolvedIso = (Resolve-Path -LiteralPath $IsoPath).Path
if ([System.IO.Path]::GetExtension($resolvedIso) -ine '.iso') {
    throw "Installation media must be an ISO file: $resolvedIso"
}

$config = Import-LabConfig -Path $ConfigPath
$vmName = [string]$config.Lab.VMName
$privateSwitchName = [string]$config.Network.SwitchName
if ([string]$config.Network.SwitchType -ine 'Private') {
    throw "Lab switch '$privateSwitchName' must be Private in '$ConfigPath'."
}

$existingVm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
if ($null -ne $existingVm) {
    throw "VM '$vmName' already exists. This script does not change an existing VM's memory, processor, or disk."
}

$vhdRoot = [string](Get-VMHost).VirtualHardDiskPath
if ([string]::IsNullOrWhiteSpace($vhdRoot)) {
    throw 'Hyper-V has no virtual hard disk path. Set one with Set-VMHost before creating the lab VM.'
}
$vhdPath = Join-Path $vhdRoot "$vmName.vhdx"
if (Test-Path -LiteralPath $vhdPath) {
    throw "VHD already exists and will not be replaced: $vhdPath"
}

$attachSwitchName = $privateSwitchName
if (-not [string]::IsNullOrWhiteSpace($ExternalSwitchName)) {
    $updateSwitch = Get-VMSwitch -Name $ExternalSwitchName -ErrorAction SilentlyContinue
    if ($null -eq $updateSwitch) {
        throw "Switch '$ExternalSwitchName' does not exist. This script does not create a switch for Windows Update."
    }
    if ([string]$updateSwitch.SwitchType -ieq 'Private') {
        throw "Switch '$ExternalSwitchName' is Private and cannot provide Windows Update connectivity."
    }
    $attachSwitchName = [string]$updateSwitch.Name
}

$privateSwitch = Get-VMSwitch -Name $privateSwitchName -ErrorAction SilentlyContinue
if ($null -eq $privateSwitch) {
    if ($PSCmdlet.ShouldProcess($privateSwitchName, 'Create private Hyper-V switch')) {
        New-VMSwitch -Name $privateSwitchName -SwitchType Private -ErrorAction Stop | Out-Null
        Write-LabLog -Phase 'HostVm' -Action 'CreateSwitch' -Status 'Changed' -Target $privateSwitchName -Message 'Private switch created.'
    }
}
elseif ([string]$privateSwitch.SwitchType -ine 'Private') {
    throw "Hyper-V switch '$privateSwitchName' is '$($privateSwitch.SwitchType)'. The lab switch must be Private."
}
else {
    Write-LabLog -Phase 'HostVm' -Action 'CreateSwitch' -Status 'Unchanged' -Target $privateSwitchName -Message 'Private switch already exists.'
}

if ($WhatIfPreference -and $null -eq (Get-VMSwitch -Name $attachSwitchName -ErrorAction SilentlyContinue)) {
    Write-LabLog -Phase 'HostVm' -Action 'CreateVm' -Status 'Info' -Target $vmName -Message "WhatIf: VM creation waits until switch '$attachSwitchName' exists."
    return [pscustomobject]@{
        PSTypeName                   = 'ADLab.VmCreateResult'
        VMName                       = $vmName
        Generation                   = 2
        ProcessorCount               = $ProcessorCount
        MemoryStartupBytes           = $MemoryStartupBytes
        DynamicMemoryEnabled         = $false
        VhdPath                      = $vhdPath
        VhdSizeBytes                 = $VhdSizeBytes
        SwitchName                   = $attachSwitchName
        PrivateSwitchName            = $privateSwitchName
        IsoPath                      = $resolvedIso
        AutomaticCheckpointsEnabled  = $false
        CheckpointType               = 'Standard'
        WhatIf                       = $true
    }
}

if ($PSCmdlet.ShouldProcess($vmName, "Create Generation 2 VM with $ProcessorCount vCPU, $MemoryStartupBytes bytes, and $VhdSizeBytes byte VHD")) {
    New-VM `
        -Name $vmName `
        -Generation 2 `
        -MemoryStartupBytes $MemoryStartupBytes `
        -SwitchName $attachSwitchName `
        -NewVHDPath $vhdPath `
        -NewVHDSizeBytes $VhdSizeBytes `
        -ErrorAction Stop | Out-Null

    Set-VMProcessor -VMName $vmName -Count $ProcessorCount -ErrorAction Stop
    Set-VMMemory -VMName $vmName -DynamicMemoryEnabled $false -StartupBytes $MemoryStartupBytes -ErrorAction Stop
    Set-VM `
        -Name $vmName `
        -AutomaticCheckpointsEnabled $false `
        -CheckpointType Standard `
        -AutomaticStartAction Nothing `
        -AutomaticStopAction ShutDown `
        -ErrorAction Stop
    Set-VMFirmware -VMName $vmName -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows -ErrorAction Stop

    Add-VMDvdDrive -VMName $vmName -Path $resolvedIso -ErrorAction Stop
    $dvd = @(Get-VMDvdDrive -VMName $vmName -ErrorAction Stop)
    $disk = @(Get-VMHardDiskDrive -VMName $vmName -ErrorAction Stop)
    if ($dvd.Count -ne 1) { throw "VM '$vmName' must have exactly one DVD drive after ISO attachment; found $($dvd.Count)." }
    if ($disk.Count -ne 1) { throw "VM '$vmName' must have exactly one hard disk; found $($disk.Count)." }
    Set-VMFirmware -VMName $vmName -BootOrder $dvd[0], $disk[0] -ErrorAction Stop

    Start-VM -Name $vmName -ErrorAction Stop
    Write-LabLog -Phase 'HostVm' -Action 'CreateVm' -Status 'Changed' -Target $vmName -Message "Started from '$resolvedIso' on switch '$attachSwitchName'."
}

[pscustomobject]@{
    PSTypeName                  = 'ADLab.VmCreateResult'
    VMName                      = $vmName
    Generation                  = 2
    ProcessorCount              = $ProcessorCount
    MemoryStartupBytes          = $MemoryStartupBytes
    DynamicMemoryEnabled        = $false
    VhdPath                     = $vhdPath
    VhdSizeBytes                = $VhdSizeBytes
    SwitchName                  = $attachSwitchName
    PrivateSwitchName           = $privateSwitchName
    IsoPath                     = $resolvedIso
    AutomaticCheckpointsEnabled = $false
    CheckpointType              = 'Standard'
    WhatIf                      = [bool]$WhatIfPreference
}
