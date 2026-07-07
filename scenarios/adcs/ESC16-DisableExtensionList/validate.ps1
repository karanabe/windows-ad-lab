#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [ValidateSet('Hardened', 'Vulnerable')]
    [string]$ExpectedState = 'Hardened',
    [string]$OutputPath,
    [switch]$FailOnValidationError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Validation.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Esc16DisableExtensionList.Common.psm1') -Force -DisableNameChecking -ErrorAction Stop
Assert-LabAdministrator
$phase = Get-Esc16ScenarioName
$log = Start-LabTranscript -Phase $phase
$results = New-Object System.Collections.Generic.List[object]
$validationResults = @()
$summary = $null
$failedNames = @()

function Add-Esc16Result {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [string]$Message = ''
    )

    $status = if ($Passed) { 'Passed' } else { 'Failed' }
    [void]$results.Add((New-LabValidationResult -Category 'ESC16DisableExtensionList' -Name $Name -Status $status -Expected $Expected -Actual $Actual -Message $Message))
}

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "ExpectedState=$ExpectedState; Transcript=$log"
    $state = Get-Esc16DisableExtensionListState
    $extensions = (@($state.DisableExtensionList) -join ',')
    if ([string]::IsNullOrWhiteSpace($extensions)) {
        $extensions = '<none>'
    }
    $oid = Get-Esc16NtdsCaSecurityExtOid

    Add-Esc16Result -Name 'Certification Authority service installed' -Passed ([bool]$state.CertSvcInstalled) -Expected 'CertSvc installed' -Actual "Status=$($state.CertSvcStatus); StartType=$($state.CertSvcStartType)"
    Add-Esc16Result -Name 'Certification Authority service running' -Passed ([string]$state.CertSvcStatus -eq 'Running') -Expected 'Running' -Actual "Status=$($state.CertSvcStatus)"
    Add-Esc16Result -Name 'DisableExtensionList readable' -Passed ([bool]$state.DisableExtensionListReadable) -Expected 'Policy module DisableExtensionList readable' -Actual "CA=$($state.ActiveCaName); Path=$($state.PolicyModulePath); Error=$($state.DisableExtensionListError)"

    if ($ExpectedState -eq 'Vulnerable') {
        Add-Esc16Result -Name 'SID security extension disabled' -Passed ([bool]$state.SidSecurityExtensionDisabled) -Expected "$oid in policy\DisableExtensionList" -Actual "DisableExtensionList=$extensions" -Message 'This is a configuration check only; no certificate is requested and CT_FLAG_NO_SECURITY_EXTENSION is not set on a template.'
        Add-Esc16Result -Name 'ESC16 vulnerable state' -Passed ([bool]$state.Vulnerable) -Expected 'CA configured and szOID_NTDS_CA_SECURITY_EXT disabled globally' -Actual "Vulnerable=$($state.Vulnerable)"
    }
    else {
        Add-Esc16Result -Name 'SID security extension enabled' -Passed (-not [bool]$state.SidSecurityExtensionDisabled) -Expected "$oid absent from policy\DisableExtensionList" -Actual "DisableExtensionList=$extensions"
        Add-Esc16Result -Name 'ESC16 hardened state' -Passed ([bool]$state.Hardened) -Expected 'CA configured and szOID_NTDS_CA_SECURITY_EXT not disabled globally' -Actual "Hardened=$($state.Hardened)" -Message 'This scenario is ESC16, not ESC9. The template CT_FLAG_NO_SECURITY_EXTENSION flag is not used.'
    }

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
New-LabPhaseResult -Phase $phase -Status Succeeded -Changed $false -Message "ExpectedState=$ExpectedState; JSON=$OutputPath; Passed=$($summary.Passed); Failed=$($summary.Failed); Skipped=$($summary.Skipped)"
