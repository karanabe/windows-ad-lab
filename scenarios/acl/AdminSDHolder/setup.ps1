#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$DelegateMemberSamAccountName = 'john.smith',
    [string]$DelegateGroupName = 'GG_AdminSD_Resetters',
    [string]$ProtectedUserSamAccountName = 'yagami_adm',
    [bool]$RequireDelegateMemberNonPrivileged = $false,
    [bool]$TriggerSdProp = $true,
    [ValidateRange(0, 120)][int]$PostSdPropWaitSeconds = 15,
    [ValidateRange(1, 300)][int]$PropagationTimeoutSeconds = 90,
    [string]$Server,
    [string]$ConfigPath = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'config\LabConfig.psd1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'AdminSDHolder.Common.psm1') -Force -DisableNameChecking -ErrorAction Stop
Assert-LabAdministrator
$config = Import-LabConfig -Path $ConfigPath
$phase = Get-AdminSdHolderScenarioName
$log = Start-LabTranscript -Phase $phase
$result = $null

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "DelegateMember=$DelegateMemberSamAccountName; DelegateGroup=$DelegateGroupName; ProtectedUser=$ProtectedUserSamAccountName; TriggerSdProp=$TriggerSdProp; Transcript=$log"
    $domain = Get-LabCurrentDomain -Config $config
    $groupsOuDn = Get-LabOuDistinguishedName `
        -RootOU ([string]$config.Organization.RootOU) `
        -RelativePath @('Groups') `
        -DomainDistinguishedName ([string]$domain.DistinguishedName)

    $summary = Set-AdminSdHolderScenario `
        -DelegateMemberSamAccountName $DelegateMemberSamAccountName `
        -DelegateGroupName $DelegateGroupName `
        -ProtectedUserSamAccountName $ProtectedUserSamAccountName `
        -GroupsOuDistinguishedName $groupsOuDn `
        -RequireDelegateMemberNonPrivileged $RequireDelegateMemberNonPrivileged `
        -TriggerSdProp $TriggerSdProp `
        -PostSdPropWaitSeconds $PostSdPropWaitSeconds `
        -PropagationTimeoutSeconds $PropagationTimeoutSeconds `
        -Server $Server `
        -WhatIf:$WhatIfPreference

    $status = if ([bool]$summary.Changed) { 'Changed' } else { 'Unchanged' }
    Write-LabLog -Phase $phase -Action 'Apply' -Status $status -Target ([string]$summary.AdminSdHolder) -Message "AdminSDHolderAceCount=$($summary.AdminSdHolderAceCount); ProtectedUserAceCount=$($summary.ProtectedUserAceCount); State=$($summary.StatePath)"
    $message = "DelegateGroup=$($summary.DelegateGroup); ProtectedUser=$($summary.ProtectedUser); AdminSDHolderAceCount=$($summary.AdminSdHolderAceCount); ProtectedUserAceCount=$($summary.ProtectedUserAceCount); DelegateMemberPrivilegedGroups=$(@($summary.DelegateMemberPrivilegedGroups) -join ','); PasswordResetExecuted=$($summary.PasswordResetExecuted)"
    $result = New-LabPhaseResult -Phase $phase -Status Succeeded -Changed ([bool]$summary.Changed) -Message $message
}
catch {
    Write-LabLog -Phase $phase -Action 'Apply' -Status Failed -Target $env:COMPUTERNAME -Message $_.Exception.Message
    throw
}
finally {
    Stop-LabTranscript
}

$result
