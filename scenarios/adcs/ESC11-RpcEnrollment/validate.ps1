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
Import-Module (Join-Path $PSScriptRoot 'Esc11RpcEnrollment.Common.psm1') -Force -DisableNameChecking -ErrorAction Stop
Assert-LabAdministrator
$phase = Get-Esc11ScenarioName
$log = Start-LabTranscript -Phase $phase
$results = New-Object System.Collections.Generic.List[object]
$validationResults = @()
$summary = $null
$failedNames = @()

function Add-Esc11Result {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [string]$Message = ''
    )

    $status = if ($Passed) { 'Passed' } else { 'Failed' }
    [void]$results.Add((New-LabValidationResult -Category 'ESC11RpcEnrollment' -Name $Name -Status $status -Expected $Expected -Actual $Actual -Message $Message))
}

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "ExpectedState=$ExpectedState; Transcript=$log"
    $state = Get-Esc11RpcEnrollmentState
    $flagNames = (@($state.InterfaceFlagNames) -join ',')
    if ([string]::IsNullOrWhiteSpace($flagNames)) {
        $flagNames = '<none>'
    }

    Add-Esc11Result -Name 'Certification Authority service installed' -Passed ([bool]$state.CertSvcInstalled) -Expected 'CertSvc installed' -Actual "Status=$($state.CertSvcStatus); StartType=$($state.CertSvcStartType)"
    Add-Esc11Result -Name 'Certification Authority service running' -Passed ([string]$state.CertSvcStatus -eq 'Running') -Expected 'Running' -Actual "Status=$($state.CertSvcStatus)"
    Add-Esc11Result -Name 'Active CA registry available' -Passed ([bool]$state.InterfaceFlagsReadable) -Expected 'Active CA and InterfaceFlags readable' -Actual "CA=$($state.ActiveCaName); Path=$($state.CaConfigurationPath); Error=$($state.InterfaceFlagsRegistryError)"
    Add-Esc11Result -Name 'RPC certificate enrollment enabled' -Passed (-not [bool]$state.RpcCertificateEnrollmentDisabled) -Expected 'IF_NORPCICERTREQUEST absent' -Actual "InterfaceFlags=$($state.InterfaceFlagsHex); Flags=$flagNames"

    if ($ExpectedState -eq 'Vulnerable') {
        Add-Esc11Result -Name 'RPC packet privacy not enforced' -Passed (-not [bool]$state.PacketPrivacyEnforced) -Expected 'IF_ENFORCEENCRYPTICERTREQUEST absent' -Actual "InterfaceFlags=$($state.InterfaceFlagsHex); Flags=$flagNames"
        Add-Esc11Result -Name 'ESC11 relay preconditions' -Passed ([bool]$state.RelayPrerequisitesPresent) -Expected 'CA + running CertSvc + RPC enrollment + no packet privacy requirement' -Actual "RelayPrerequisitesPresent=$($state.RelayPrerequisitesPresent)" -Message 'This is a configuration check only; no NTLM relay or certificate request is executed.'
    }
    else {
        Add-Esc11Result -Name 'RPC packet privacy required' -Passed ([bool]$state.PacketPrivacyEnforced) -Expected 'IF_ENFORCEENCRYPTICERTREQUEST present' -Actual "InterfaceFlags=$($state.InterfaceFlagsHex); Flags=$flagNames"
        Add-Esc11Result -Name 'ESC11 relay preconditions disabled' -Passed (-not [bool]$state.RelayPrerequisitesPresent) -Expected 'Relay prerequisites are not simultaneously present' -Actual "RelayPrerequisitesPresent=$($state.RelayPrerequisitesPresent)" -Message 'Packet privacy prevents relaying an unencrypted RPC enrollment session.'
        Add-Esc11Result -Name 'Hardened state' -Passed ([bool]$state.Hardened) -Expected 'CA configured and IF_ENFORCEENCRYPTICERTREQUEST present' -Actual "Hardened=$($state.Hardened)"
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
