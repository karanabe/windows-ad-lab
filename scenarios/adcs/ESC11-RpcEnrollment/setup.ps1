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
Import-Module (Join-Path $PSScriptRoot 'Esc11RpcEnrollment.Common.psm1') -Force -DisableNameChecking -ErrorAction Stop
Assert-LabAdministrator
$config = Import-LabConfig -Path $ConfigPath
$phase = Get-Esc11ScenarioName
$log = Start-LabTranscript -Phase $phase
$changed = $false
$result = $null

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "Stage=$Stage; Transcript=$log"
    Get-LabCurrentDomain -Config $config | Out-Null
    if (-not [bool]$config.ADCS.Install) {
        throw 'AD CS is disabled in LabConfig. ESC11 RPC enrollment validation requires the lab CA.'
    }
    if ($env:COMPUTERNAME -ine [string]$config.ADCS.TargetComputerName) {
        throw "AD CS target is '$($config.ADCS.TargetComputerName)', but this computer is '$env:COMPUTERNAME'."
    }

    $state = Initialize-Esc11ScenarioState
    Write-LabLog -Phase $phase -Action 'State' -Status Info -Target (Get-Esc11StatePath) -Message "CreatedAt=$($state.CreatedAt)"

    if (Ensure-Esc11CertSvcRunning) {
        $changed = $true
        Write-LabLog -Phase $phase -Action 'StartService' -Status Changed -Target 'CertSvc'
    }
    else {
        Write-LabLog -Phase $phase -Action 'StartService' -Status Unchanged -Target 'CertSvc'
    }

    $requirePacketPrivacy = ($Stage -eq 'Hardened')
    if (Set-Esc11PacketPrivacyRequirement -Required $requirePacketPrivacy) {
        $changed = $true
        Write-LabLog -Phase $phase -Action 'ConfigureInterfaceFlags' -Status Changed -Target 'CA\InterfaceFlags' -Message "IF_ENFORCEENCRYPTICERTREQUEST required=$requirePacketPrivacy"
        if (Restart-Esc11CertSvc) {
            Write-LabLog -Phase $phase -Action 'RestartService' -Status Changed -Target 'CertSvc' -Message 'Applied CA InterfaceFlags.'
        }
    }
    else {
        Write-LabLog -Phase $phase -Action 'ConfigureInterfaceFlags' -Status Unchanged -Target 'CA\InterfaceFlags' -Message "IF_ENFORCEENCRYPTICERTREQUEST required=$requirePacketPrivacy"
    }

    $state = Update-Esc11ScenarioState -State $state -LastStage $Stage
    $current = Get-Esc11RpcEnrollmentState
    $message = "Stage=$Stage; PacketPrivacyEnforced=$($current.PacketPrivacyEnforced); RelayPrerequisitesPresent=$($current.RelayPrerequisitesPresent); InterfaceFlags=$($current.InterfaceFlagsHex); State=$($state.UpdatedAt)"
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
