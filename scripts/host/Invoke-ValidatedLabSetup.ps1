#Requires -Version 5.1
#Requires -RunAsAdministrator
#Requires -Modules Hyper-V

[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'config\LabConfig.psd1'),
    [PSCredential]$LocalCredential,
    [PSCredential]$DomainCredential,
    [Security.SecureString]$DsrmPassword,
    [Security.SecureString]$DefaultUserPassword,
    [string]$SecretsPath,
    [string]$GuestConfigurationName,
    [switch]$ResetExistingPasswords,
    [switch]$SkipDcDiag,
    [ValidateRange(60, 3600)][int]$RestartTimeoutSeconds = 600
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$testConfigPath = Join-Path $repositoryRoot 'scripts\Test-LabConfig.ps1'
$staticValidationPath = Join-Path $repositoryRoot 'tests\Invoke-StaticValidation.ps1'
$bootstrapPath = Join-Path $repositoryRoot 'bootstrap\Invoke-LabBootstrap.ps1'
$allPhases = @(
    'Prerequisites'
    'OSBaseline'
    'NewForest'
    'ADBaseline'
    'DefensiveAuditing'
    'ADCS'
    'ADCSHttpCdp'
    'Validation'
)

function Write-ValidatedSetupStep {
    param([Parameter(Mandatory = $true)][string]$Name, [string]$Status = 'Running')
    Write-Host ("{0} ValidatedSetup Step={1} Status={2}" -f (Get-Date).ToString('o'), $Name, $Status)
}

function New-ValidatedSetupCheckpoint {
    param([Parameter(Mandatory = $true)][string]$Name)

    $existing = @(Get-VMCheckpoint -VMName $vmName -Name $Name -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 1) {
        throw "More than one checkpoint named '$Name' exists for VM '$vmName'. Resolve the ambiguity manually."
    }
    if ($existing.Count -eq 1) {
        Write-Host ("{0} ValidatedSetup Checkpoint={1} Status=Unchanged" -f (Get-Date).ToString('o'), $Name)
        return
    }

    Write-Host ("{0} ValidatedSetup Checkpoint={1} Status=Creating" -f (Get-Date).ToString('o'), $Name)
    try {
        Checkpoint-VM -Name $vmName -SnapshotName $Name -ErrorAction Stop | Out-Host
        Start-Sleep -Seconds 10
        $deadline = (Get-Date).AddSeconds(120)
        do {
            $created = @(Get-VMCheckpoint -VMName $vmName -Name $Name -ErrorAction SilentlyContinue)
            if ($created.Count -ge 1) { break }
            Start-Sleep -Seconds 2
        } while ((Get-Date) -lt $deadline)
        if ($created.Count -ne 1) {
            throw "Checkpoint '$Name' was not found exactly once on VM '$vmName' within 120 seconds after the initial 10-second wait; found $($created.Count)."
        }
        Write-Host ("{0} ValidatedSetup Checkpoint={1} Status=Created" -f (Get-Date).ToString('o'), $Name)
    }
    catch {
        Write-Host ("{0} ValidatedSetup Checkpoint={1} Status=Failed Message={2}" -f (Get-Date).ToString('o'), $Name, $_.Exception.Message)
        throw
    }
}

function Invoke-ValidatedBootstrapStage {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string[]]$Phase,
        [Parameter(Mandatory = $true)][string]$ExpectedLastSuccessfulPhase
    )

    Write-ValidatedSetupStep -Name $Name
    try {
        $stageParameters = $bootstrapParameters.Clone()
        $stageParameters['Phase'] = $Phase
        $stageOutput = & $bootstrapPath @stageParameters
        $stageResults = @($stageOutput | Where-Object {
            $null -ne $_ -and
            $_.PSObject.Properties.Match('Status').Count -gt 0 -and
            $_.PSObject.Properties.Match('LastSuccessfulPhase').Count -gt 0
        })
        if ($stageResults.Count -eq 0) {
            throw "Bootstrap stage '$Name' did not return a completion result."
        }

        $stageCompletion = $stageResults[-1]
        if ([string]$stageCompletion.Status -ne 'Succeeded' -or
            [string]$stageCompletion.LastSuccessfulPhase -ne $ExpectedLastSuccessfulPhase) {
            throw "Bootstrap stage '$Name' did not finish successfully. Status='$($stageCompletion.Status)'; LastSuccessfulPhase='$($stageCompletion.LastSuccessfulPhase)'."
        }
        $stageCompletion | Format-List | Out-Host
        Write-ValidatedSetupStep -Name $Name -Status 'Succeeded'
        $stageCompletion
    }
    catch {
        Write-ValidatedSetupStep -Name $Name -Status 'Failed'
        throw
    }
}

Write-ValidatedSetupStep -Name 'ValidateConfig'
$configResult = & $testConfigPath -ConfigPath $ConfigPath
$configResult | Format-List | Out-Host
$ConfigPath = [string]$configResult.ConfigPath
$config = Import-PowerShellDataFile -LiteralPath $ConfigPath

Write-ValidatedSetupStep -Name 'StaticValidation'
$staticResult = & $staticValidationPath
$staticResult | Format-List | Out-Host

Write-ValidatedSetupStep -Name 'ValidateCheckpointSettings'
$vmName = [string]$configResult.VMName
$vm = Get-VM -Name $vmName -ErrorAction Stop
if ([bool]$vm.AutomaticCheckpointsEnabled) {
    throw "Automatic checkpoints must be disabled for VM '$vmName'. Change the setting explicitly before rerunning."
}
if ([string]$vm.CheckpointType -ine 'Standard') {
    throw "Checkpoint type for VM '$vmName' must be Standard; current type is '$($vm.CheckpointType)'. Change the setting explicitly before rerunning."
}
$baseCheckpoints = @(Get-VMCheckpoint -VMName $vmName -Name '01-Updated' -ErrorAction SilentlyContinue)
if ($baseCheckpoints.Count -ne 1) {
    throw "Exactly one manual base checkpoint named '01-Updated' is required; found $($baseCheckpoints.Count)."
}

if ($null -eq $LocalCredential -and [string]::IsNullOrWhiteSpace($SecretsPath)) {
    $localPassword = Read-Host 'Enter the local Administrator password set during Windows installation' -AsSecureString
    if ($null -eq $localPassword -or $localPassword.Length -eq 0) {
        throw 'The local Administrator password is required for a full lab setup.'
    }
    try {
        $LocalCredential = New-Object Management.Automation.PSCredential(
            '.\Administrator',
            $localPassword.Copy())
    }
    finally {
        $localPassword.Dispose()
    }
}
if ($null -eq $DomainCredential -and
    $null -ne $LocalCredential -and
    [string]::IsNullOrWhiteSpace($SecretsPath)) {
    $DomainCredential = New-Object Management.Automation.PSCredential(
        "$($config.Domain.NetBIOSName)\Administrator",
        $LocalCredential.Password
    )
}
if ([string]::IsNullOrWhiteSpace($SecretsPath) -and $null -eq $DsrmPassword) {
    $DsrmPassword = Read-Host 'Enter the DSRM password' -AsSecureString
    if ($null -eq $DsrmPassword -or $DsrmPassword.Length -eq 0) {
        throw 'The DSRM password is required for a full lab setup.'
    }
}
if ([string]::IsNullOrWhiteSpace($SecretsPath) -and $null -eq $DefaultUserPassword) {
    $DefaultUserPassword = Read-Host 'Enter the password for new lab users' -AsSecureString
    if ($null -eq $DefaultUserPassword -or $DefaultUserPassword.Length -eq 0) {
        throw 'The password for new lab users is required for a full lab setup.'
    }
}

$bootstrapParameters = @{
    ConfigPath               = $ConfigPath
    LocalCredential          = $LocalCredential
    DomainCredential         = $DomainCredential
    DsrmPassword             = $DsrmPassword
    DefaultUserPassword      = $DefaultUserPassword
    SecretsPath              = $SecretsPath
    GuestConfigurationName   = $GuestConfigurationName
    ResetExistingPasswords   = [bool]$ResetExistingPasswords
    SkipDcDiag               = [bool]$SkipDcDiag
    RestartTimeoutSeconds    = $RestartTimeoutSeconds
}

Write-ValidatedSetupStep -Name 'BootstrapPlan'
$planOutput = & $bootstrapPath @bootstrapParameters -Phase $allPhases -WhatIf
$planResults = @($planOutput | Where-Object {
    $null -ne $_ -and
    $_.PSObject.Properties.Match('WhatIf').Count -gt 0 -and
    $_.PSObject.Properties.Match('LastSuccessfulPhase').Count -gt 0
})
if ($planResults.Count -eq 0 -or -not [bool]$planResults[-1].WhatIf) {
    throw 'Bootstrap planning did not complete successfully.'
}
$planResults[-1] | Format-List | Out-Host

$null = Invoke-ValidatedBootstrapStage `
    -Name 'OSBaseline' `
    -Phase @('OSBaseline') `
    -ExpectedLastSuccessfulPhase 'OSBaseline'
New-ValidatedSetupCheckpoint -Name '02-Baseline'

$null = Invoke-ValidatedBootstrapStage `
    -Name 'NewForest' `
    -Phase @('NewForest') `
    -ExpectedLastSuccessfulPhase 'NewForest'
New-ValidatedSetupCheckpoint -Name '03-Forest'

$null = Invoke-ValidatedBootstrapStage `
    -Name 'ADBaselineAndAuditing' `
    -Phase @('ADBaseline', 'DefensiveAuditing') `
    -ExpectedLastSuccessfulPhase 'DefensiveAuditing'
New-ValidatedSetupCheckpoint -Name '04-AD-Baseline'

$completion = Invoke-ValidatedBootstrapStage `
    -Name 'ADCSAndValidation' `
    -Phase @('ADCS', 'Validation') `
    -ExpectedLastSuccessfulPhase 'Validation'
New-ValidatedSetupCheckpoint -Name '05-ADCS-Baseline'

$completion = Invoke-ValidatedBootstrapStage `
    -Name 'ADCSHttpCdpAndValidation' `
    -Phase @('ADCSHttpCdp', 'Validation') `
    -ExpectedLastSuccessfulPhase 'Validation'
New-ValidatedSetupCheckpoint -Name '06-ADCS-HTTP-CDP'

Write-ValidatedSetupStep -Name 'Completed'
$completion
