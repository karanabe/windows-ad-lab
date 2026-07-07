#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$FailOnValidationError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Validation.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Esc12CaKeyStorage.Common.psm1') -Force -DisableNameChecking -ErrorAction Stop
Assert-LabAdministrator
$phase = Get-Esc12ScenarioName
$log = Start-LabTranscript -Phase $phase
$results = New-Object System.Collections.Generic.List[object]
$validationResults = @()
$summary = $null
$failedNames = @()

function Add-Esc12Result {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [string]$Message = ''
    )

    $status = if ($Passed) { 'Passed' } else { 'Failed' }
    [void]$results.Add((New-LabValidationResult -Category 'ESC12CaKeyStorage' -Name $Name -Status $status -Expected $Expected -Actual $Actual -Message $Message))
}

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "Transcript=$log"
    $state = Get-Esc12CaKeyStorageState
    $yubiHsmName = Get-Esc12YubiHsmProviderName

    Add-Esc12Result -Name 'Certification Authority service installed' -Passed ([bool]$state.CertSvcInstalled) -Expected 'CertSvc installed' -Actual "Status=$($state.CertSvcStatus); StartType=$($state.CertSvcStartType)"
    Add-Esc12Result -Name 'Certification Authority service running' -Passed ([string]$state.CertSvcStatus -eq 'Running') -Expected 'Running' -Actual "Status=$($state.CertSvcStatus)"
    Add-Esc12Result -Name 'CA CSP readable' -Passed ([bool]$state.CspReadable) -Expected 'Active CA CSP Provider and KeyContainer readable' -Actual "CA=$($state.ActiveCaName); Path=$($state.CspPath); Error=$($state.CspRegistryError)"
    Add-Esc12Result -Name 'Software Key Storage Provider' -Passed ([bool]$state.UsesSoftwareProvider) -Expected 'Microsoft software CSP/KSP' -Actual "Provider='$($state.Provider)'; ProviderType=$($state.ProviderType)" -Message 'This lab CA stores its key in a software provider. That is not YubiHSM ESC12 hardware, but shell access to the CA still implies CA-key use.'
    Add-Esc12Result -Name 'YubiHSM Key Storage Provider absent' -Passed (-not [bool]$state.UsesYubiHsmProvider) -Expected "Provider is not $yubiHsmName" -Actual "Provider='$($state.Provider)'" -Message 'Published ESC12 is YubiHSM-specific. This lab does not install YubiHSM.'
    Add-Esc12Result -Name 'YubiHSM host software absent' -Passed (-not [bool]$state.Esc12HardwareClassPresent) -Expected 'No YubiHSM registry, ProgramData, or KSP' -Actual "Registry=$($state.YubiHsmRegistryPresent); ProgramData=$($state.YubiHsmProgramDataPresent); ConfigFiles=$((@($state.YubiHsmConfigFiles) -join ','))"
    Add-Esc12Result -Name 'Private key not exported' -Passed (-not [bool]$state.PrivateKeyExported -and -not [bool]$state.PrivateKeyMaterialRead) -Expected 'Scenario does not read or export CA private key material' -Actual "PrivateKeyMaterialRead=$($state.PrivateKeyMaterialRead); PrivateKeyExported=$($state.PrivateKeyExported)" -Message 'This is a configuration observation. It does not export a PFX or forge certificates.'

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Join-Path $env:ProgramData "ADLabBootstrap\Logs\$(Get-Date -Format 'yyyyMMdd-HHmmss')-$phase-validation.json"
    }
    $validationResults = $results.ToArray()
    $summary = Export-LabValidationResults -Results $validationResults -Path $OutputPath
    Write-LabLog -Phase $phase -Action 'ExportJSON' -Status Changed -Target $summary.Path -Message "Passed=$($summary.Passed); Failed=$($summary.Failed); Skipped=$($summary.Skipped)"
    $failedNames = @($validationResults | Where-Object Status -eq 'Failed' | ForEach-Object { "$($_.Category)/$($_.Name)" })
    if ($failedNames.Count -gt 0) {
        Write-LabLog -Phase $phase -Action 'FailedChecks' -Status Failed -Target 'Validation' -Message ($failedNames -join '; ')
    }
}
catch {
    Write-LabLog -Phase $phase -Action 'Validate' -Status Failed -Target $env:COMPUTERNAME -Message $_.Exception.Message
    throw
}
finally {
    Stop-LabTranscript
}

$validationResults
if ($FailOnValidationError -and $summary.Failed -gt 0) {
    throw "$($summary.Failed) validation check(s) failed: $($failedNames -join '; '). See '$OutputPath'."
}
New-LabPhaseResult -Phase $phase -Status Succeeded -Changed $false -Message "JSON=$OutputPath; Passed=$($summary.Passed); Failed=$($summary.Failed); Skipped=$($summary.Skipped); Provider='$($state.Provider)'"
