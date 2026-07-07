#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$DelegateMemberSamAccountName = 'john.smith',
    [string]$DelegateGroupName = 'GG_AdminSD_Resetters',
    [string]$ProtectedUserSamAccountName = 'yagami_adm',
    [bool]$RequireDelegateMemberNonPrivileged = $false,
    [bool]$ExpectPropagatedAce = $true,
    [string]$OutputPath,
    [string]$Server,
    [switch]$IncludeAcl,
    [switch]$FailOnValidationError,
    [string]$ConfigPath = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'config\LabConfig.psd1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Validation.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'AdminSDHolder.Common.psm1') -Force -DisableNameChecking -ErrorAction Stop
Assert-LabAdministrator
$config = Import-LabConfig -Path $ConfigPath
$phase = Get-AdminSdHolderScenarioName
$log = Start-LabTranscript -Phase $phase
$results = New-Object System.Collections.Generic.List[object]
$validationResults = @()
$summary = $null
$failedNames = @()

function Add-AdminSdHolderResult {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [string]$Message = ''
    )

    $status = if ($Passed) { 'Passed' } else { 'Failed' }
    [void]$results.Add((New-LabValidationResult -Category 'AdminSDHolder' -Name $Name -Status $status -Expected $Expected -Actual $Actual -Message $Message))
}

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "DelegateGroup=$DelegateGroupName; ProtectedUser=$ProtectedUserSamAccountName; RequireDelegateMemberNonPrivileged=$RequireDelegateMemberNonPrivileged; ExpectPropagatedAce=$ExpectPropagatedAce; Transcript=$log"
    Get-LabCurrentDomain -Config $config | Out-Null
    $posture = Get-AdminSdHolderScenarioPosture `
        -DelegateMemberSamAccountName $DelegateMemberSamAccountName `
        -DelegateGroupName $DelegateGroupName `
        -ProtectedUserSamAccountName $ProtectedUserSamAccountName `
        -Server $Server `
        -IncludeAcl:$IncludeAcl

    Add-AdminSdHolderResult -Name 'AdminSDHolder container exists' -Passed ([bool]$posture.AdminSdHolderExists) -Expected 'CN=AdminSDHolder,CN=System exists' -Actual $posture.AdminSdHolderDistinguishedName
    Add-AdminSdHolderResult -Name 'Delegate member exists' -Passed ([bool]$posture.DelegateMemberExists) -Expected $DelegateMemberSamAccountName -Actual $posture.DelegateMemberDistinguishedName
    Add-AdminSdHolderResult -Name 'Delegate group exists' -Passed ([bool]$posture.DelegateGroupExists) -Expected $DelegateGroupName -Actual $posture.DelegateGroupDistinguishedName
    Add-AdminSdHolderResult -Name 'Delegate group marker' -Passed ([string]$posture.DelegateGroupMarker -ceq (Get-AdminSdHolderMarker)) -Expected (Get-AdminSdHolderMarker) -Actual ([string]$posture.DelegateGroupMarker)
    Add-AdminSdHolderResult -Name 'Delegate member is in delegate group' -Passed ([bool]$posture.DelegateMembershipPresent) -Expected "$DelegateMemberSamAccountName member of $DelegateGroupName" -Actual "Present=$($posture.DelegateMembershipPresent)"
    $delegateMemberPrivileged = (@($posture.DelegateMemberPrivilegedGroupMatches).Count -gt 0)
    $delegateMemberPrivilegeActual = if ($delegateMemberPrivileged) { (@($posture.DelegateMemberPrivilegedGroupMatches) -join '; ') } else { (@($posture.DelegateMemberGroupSamAccountNames) -join '; ') }
    if ($RequireDelegateMemberNonPrivileged) {
        Add-AdminSdHolderResult -Name 'Delegate member is not a privileged admin' -Passed (-not $delegateMemberPrivileged) -Expected 'No Domain Admins, Enterprise Admins, Administrators, Account Operators, Backup Operators, or Server Operators membership' -Actual $delegateMemberPrivilegeActual
    }
    else {
        Add-AdminSdHolderResult -Name 'Delegate member privilege context observed' -Passed $true -Expected 'Observed only; set RequireDelegateMemberNonPrivileged = $true to enforce' -Actual $delegateMemberPrivilegeActual
    }
    Add-AdminSdHolderResult -Name 'Protected user exists' -Passed ([bool]$posture.ProtectedUserExists) -Expected $ProtectedUserSamAccountName -Actual $posture.ProtectedUserDistinguishedName
    Add-AdminSdHolderResult -Name 'Protected user is Domain Admin' -Passed (@($posture.ProtectedUserGroupSamAccountNames) -icontains 'Domain Admins') -Expected 'Domain Admins membership' -Actual (@($posture.ProtectedUserGroupSamAccountNames) -join '; ')
    Add-AdminSdHolderResult -Name 'Protected user has adminCount=1' -Passed ([string]$posture.ProtectedUserAdminCount -eq '1') -Expected 'adminCount=1' -Actual ([string]$posture.ProtectedUserAdminCount)
    Add-AdminSdHolderResult -Name 'Protected user ACL inheritance disabled' -Passed ([bool]$posture.ProtectedUserAccessRulesProtected) -Expected 'AreAccessRulesProtected=True' -Actual "AreAccessRulesProtected=$($posture.ProtectedUserAccessRulesProtected)"
    Add-AdminSdHolderResult -Name 'AdminSDHolder has delegate Reset Password ACE' -Passed ([int]$posture.AdminSdHolderResetPasswordAceCount -eq 1) -Expected 'One explicit Reset Password ACE for delegate group' -Actual "Count=$($posture.AdminSdHolderResetPasswordAceCount);Guid=$($posture.ResetPasswordControlAccessGuid)"

    if ($ExpectPropagatedAce) {
        Add-AdminSdHolderResult -Name 'Protected user has propagated Reset Password ACE' -Passed ([int]$posture.ProtectedUserResetPasswordAceCount -eq 1) -Expected 'One explicit Reset Password ACE after SDProp' -Actual "Count=$($posture.ProtectedUserResetPasswordAceCount)"
    }
    else {
        Add-AdminSdHolderResult -Name 'Protected user propagated ACE not required' -Passed $true -Expected 'Expectation disabled' -Actual "Count=$($posture.ProtectedUserResetPasswordAceCount)"
    }

    if ($ExpectPropagatedAce) {
        Add-AdminSdHolderResult -Name 'AdminCount objects with scenario ACE observed' -Passed (@($posture.AdminCountObjectsWithScenarioAce).Count -gt 0) -Expected 'At least one adminCount=1 object has the scenario ACE after SDProp' -Actual (@($posture.AdminCountObjectsWithScenarioAce) -join ' | ')
    }
    else {
        Add-AdminSdHolderResult -Name 'AdminCount object propagation not required' -Passed $true -Expected 'Expectation disabled' -Actual (@($posture.AdminCountObjectsWithScenarioAce) -join ' | ')
    }
    Add-AdminSdHolderResult -Name 'Password reset is not automated' -Passed (-not [bool]$posture.PasswordResetExecuted) -Expected 'No protected account password reset' -Actual "PasswordResetExecuted=$($posture.PasswordResetExecuted)"

    if ($IncludeAcl) {
        Add-AdminSdHolderResult -Name 'AdminSDHolder delegate ACE summary' -Passed (@($posture.AdminSdHolderAceSummary).Count -gt 0) -Expected 'Explicit delegate ACE summary' -Actual (@($posture.AdminSdHolderAceSummary) -join ' | ')
        if ($ExpectPropagatedAce) {
            Add-AdminSdHolderResult -Name 'Protected user delegate ACE summary' -Passed (@($posture.ProtectedUserAceSummary).Count -gt 0) -Expected 'Explicit delegate ACE summary on protected user' -Actual (@($posture.ProtectedUserAceSummary) -join ' | ')
        }
        else {
            Add-AdminSdHolderResult -Name 'Protected user delegate ACE summary not required' -Passed $true -Expected 'Expectation disabled' -Actual (@($posture.ProtectedUserAceSummary) -join ' | ')
        }
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
New-LabPhaseResult -Phase $phase -Status Succeeded -Changed $false -Message "JSON=$OutputPath; Passed=$($summary.Passed); Failed=$($summary.Failed); Skipped=$($summary.Skipped)"
