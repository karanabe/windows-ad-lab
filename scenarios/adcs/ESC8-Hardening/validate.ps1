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
Import-Module (Join-Path $PSScriptRoot 'Esc8Hardening.Common.psm1') -Force -DisableNameChecking -ErrorAction Stop
Assert-LabAdministrator
$phase = Get-Esc8ScenarioName
$log = Start-LabTranscript -Phase $phase
$results = New-Object System.Collections.Generic.List[object]
$validationResults = @()
$summary = $null
$failedNames = @()

function Add-Esc8Result {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [string]$Message = ''
    )

    $status = if ($Passed) { 'Passed' } else { 'Failed' }
    [void]$results.Add((New-LabValidationResult -Category 'ESC8Hardening' -Name $Name -Status $status -Expected $Expected -Actual $Actual -Message $Message))
}

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "ExpectedState=$ExpectedState; Transcript=$log"
    $state = Get-Esc8WebEnrollmentState
    $providersText = (@($state.Providers) -join ',')

    Add-Esc8Result -Name 'ADCS-Web-Enrollment feature' -Passed ([bool]$state.FeatureInstalled) -Expected 'Installed' -Actual ([string]$state.FeatureState)
    Add-Esc8Result -Name 'CertSrv IIS application' -Passed ([bool]$state.CertSrvExists) -Expected 'Default Web Site/CertSrv present' -Actual $(if ([bool]$state.CertSrvExists) { 'Present' } else { "Missing; IIS=$($state.IisAvailable); Error=$($state.IisError)" })
    Add-Esc8Result -Name 'W3SVC running' -Passed ([string]$state.W3SvcStatus -eq 'Running') -Expected 'Running' -Actual "Status=$($state.W3SvcStatus); StartType=$($state.W3SvcStartType)"
    Add-Esc8Result -Name 'Windows Authentication enabled' -Passed ($state.WindowsAuthentication -eq $true) -Expected 'Enabled' -Actual $state.WindowsAuthentication
    Add-Esc8Result -Name 'Anonymous Authentication disabled' -Passed ($state.AnonymousAuthentication -eq $false) -Expected 'Disabled' -Actual $state.AnonymousAuthentication

    if ($ExpectedState -eq 'Vulnerable') {
        Add-Esc8Result -Name 'HTTP enrollment allowed' -Passed ([bool]$state.HttpAllowed) -Expected 'Require SSL disabled' -Actual "SslFlags=$($state.SslFlags)"
        Add-Esc8Result -Name 'EPA not required' -Passed (-not [bool]$state.EpaRequired) -Expected 'tokenChecking is None or Allow' -Actual "tokenChecking=$($state.TokenChecking)"
        Add-Esc8Result -Name 'NTLM provider present' -Passed ([bool]$state.NtlmProviderPresent) -Expected 'Providers include NTLM' -Actual $providersText
        Add-Esc8Result -Name 'ESC8 relay preconditions' -Passed ([bool]$state.RelayPrerequisitesPresent) -Expected 'Web Enrollment + HTTP + NTLM + no required EPA' -Actual "RelayPrerequisitesPresent=$($state.RelayPrerequisitesPresent)" -Message 'This is a configuration check only; no relay is executed.'
    }
    else {
        Add-Esc8Result -Name 'HTTPS binding ready' -Passed ([bool]$state.HttpsReady) -Expected 'HTTPS binding has a certificate' -Actual "Exists=$($state.HttpsBindingExists); Binding=$($state.HttpsBindingInformation); Certificate=$($state.HttpsBindingCertificate)"
        Add-Esc8Result -Name 'HTTP enrollment blocked by SSL requirement' -Passed (-not [bool]$state.HttpAllowed) -Expected 'Require SSL enabled' -Actual "SslFlags=$($state.SslFlags)"
        Add-Esc8Result -Name 'EPA required' -Passed ([bool]$state.EpaRequired) -Expected 'tokenChecking=Require' -Actual "tokenChecking=$($state.TokenChecking); flags=$($state.EpaFlags)"
        Add-Esc8Result -Name 'NTLM provider removed' -Passed (-not [bool]$state.NtlmProviderPresent) -Expected 'Providers do not include NTLM' -Actual $providersText
        Add-Esc8Result -Name 'Kerberos-only provider' -Passed ([bool]$state.KerberosOnlyProvider) -Expected 'Providers=Negotiate:Kerberos' -Actual $providersText
        Add-Esc8Result -Name 'ESC8 relay preconditions disabled' -Passed (-not [bool]$state.RelayPrerequisitesPresent) -Expected 'Relay prerequisites are not simultaneously present' -Actual "RelayPrerequisitesPresent=$($state.RelayPrerequisitesPresent)"
        Add-Esc8Result -Name 'Hardened state' -Passed ([bool]$state.Hardened) -Expected 'HTTPS + EPA Require + Kerberos-only Windows auth' -Actual "Hardened=$($state.Hardened)"
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
