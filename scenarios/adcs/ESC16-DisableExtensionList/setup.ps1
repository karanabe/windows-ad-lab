#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Hardened', 'Vulnerable')]
    [string]$Stage = 'Hardened',
    [string]$ConfigPath = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'config\LabConfig.psd1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Esc16DisableExtensionList.Common.psm1') -Force -DisableNameChecking -ErrorAction Stop
Assert-LabAdministrator
$config = Import-LabConfig -Path $ConfigPath
$phase = Get-Esc16ScenarioName
$log = Start-LabTranscript -Phase $phase
$changed = $false
$result = $null

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "Stage=$Stage; Transcript=$log"
    Get-LabCurrentDomain -Config $config | Out-Null
    if (-not [bool]$config.ADCS.Install) {
        throw 'AD CS is disabled in LabConfig. ESC16 DisableExtensionList validation requires the lab CA.'
    }
    if ($env:COMPUTERNAME -ine [string]$config.ADCS.TargetComputerName) {
        throw "AD CS target is '$($config.ADCS.TargetComputerName)', but this computer is '$env:COMPUTERNAME'."
    }

    $state = Initialize-Esc16ScenarioState
    Write-LabLog -Phase $phase -Action 'State' -Status Info -Target (Get-Esc16StatePath) -Message "CreatedAt=$($state.CreatedAt)"

    if (Ensure-Esc16CertSvcRunning) {
        $changed = $true
        Write-LabLog -Phase $phase -Action 'StartService' -Status Changed -Target 'CertSvc'
    }
    else {
        Write-LabLog -Phase $phase -Action 'StartService' -Status Unchanged -Target 'CertSvc'
    }

    $disableSidExtension = ($Stage -eq 'Vulnerable')
    if (Set-Esc16SidSecurityExtensionDisabled -Disabled $disableSidExtension) {
        $changed = $true
        Write-LabLog -Phase $phase -Action 'ConfigureDisableExtensionList' -Status Changed -Target 'policy\DisableExtensionList' -Message "szOID_NTDS_CA_SECURITY_EXT disabled=$disableSidExtension"
        if (Restart-Esc16CertSvc) {
            Write-LabLog -Phase $phase -Action 'RestartService' -Status Changed -Target 'CertSvc' -Message 'Applied CA DisableExtensionList.'
        }
    }
    else {
        Write-LabLog -Phase $phase -Action 'ConfigureDisableExtensionList' -Status Unchanged -Target 'policy\DisableExtensionList' -Message "szOID_NTDS_CA_SECURITY_EXT disabled=$disableSidExtension"
    }

    $state = Update-Esc16ScenarioState -State $state -LastStage $Stage
    $current = Get-Esc16DisableExtensionListState
    $message = "Stage=$Stage; SidSecurityExtensionDisabled=$($current.SidSecurityExtensionDisabled); DisableExtensionList=$((@($current.DisableExtensionList) -join ',')); State=$($state.UpdatedAt)"
    $result = New-LabPhaseResult -Phase $phase -Status Succeeded -Changed $changed -Message $message
}
catch {
    Write-LabLog -Phase $phase -Action 'Apply' -Status Failed -Target $env:COMPUTERNAME -Message $_.Exception.Message
    throw
}
finally {
    Stop-LabTranscript
}

$result
