#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Esc8Hardening.Common.psm1') -Force -DisableNameChecking -ErrorAction Stop
Assert-LabAdministrator
$phase = Get-Esc8ScenarioName
$log = Start-LabTranscript -Phase $phase
$changed = $false
$result = $null

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "Transcript=$log"
    $state = Read-Esc8ScenarioState
    if ($null -eq $state) {
        Write-LabLog -Phase $phase -Action 'State' -Status Info -Target (Get-Esc8StatePath) -Message 'State file is absent; cleanup will only remove scenario-marked certificates.'
        $removedCertificates = Remove-Esc8ScenarioCertificate -State $null
        if ($removedCertificates -gt 0) { $changed = $true }
        $result = New-LabPhaseResult -Phase $phase -Status Succeeded -Changed $changed -Message "State=Missing; RemovedCertificates=$removedCertificates"
        return $result
    }

    $webEnrollmentInstalledBefore = [bool](Get-Esc8PropertyValue -InputObject $state -Name 'WebEnrollmentFeatureInstalledBefore' -Default $false)
    $certSrvExistedBefore = [bool](Get-Esc8PropertyValue -InputObject $state -Name 'CertSrvExistsBefore' -Default $false)

    if ($webEnrollmentInstalledBefore -and $certSrvExistedBefore) {
        if (Restore-Esc8IisSecurityState -State $state) {
            $changed = $true
            Write-LabLog -Phase $phase -Action 'RestoreIis' -Status Changed -Target 'Default Web Site/CertSrv'
        }
        else {
            Write-LabLog -Phase $phase -Action 'RestoreIis' -Status Unchanged -Target 'Default Web Site/CertSrv'
        }
    }

    if (Restore-Esc8HttpsBinding -State $state) {
        $changed = $true
        Write-LabLog -Phase $phase -Action 'RestoreHttpsBinding' -Status Changed -Target 'Default Web Site:443'
    }
    else {
        Write-LabLog -Phase $phase -Action 'RestoreHttpsBinding' -Status Unchanged -Target 'Default Web Site:443'
    }

    $removedCertificates = Remove-Esc8ScenarioCertificate -State $state
    if ($removedCertificates -gt 0) {
        $changed = $true
        Write-LabLog -Phase $phase -Action 'RemoveCertificate' -Status Changed -Target 'Cert:\LocalMachine\My' -Message "Count=$removedCertificates"
    }
    else {
        Write-LabLog -Phase $phase -Action 'RemoveCertificate' -Status Unchanged -Target 'Cert:\LocalMachine\My'
    }

    if (-not $webEnrollmentInstalledBefore) {
        if (Uninstall-Esc8WebEnrollment) {
            $changed = $true
            Write-LabLog -Phase $phase -Action 'UninstallWebEnrollment' -Status Changed -Target 'ADCS-Web-Enrollment'
        }
        else {
            Write-LabLog -Phase $phase -Action 'UninstallWebEnrollment' -Status Unchanged -Target 'ADCS-Web-Enrollment'
        }
    }
    else {
        Write-LabLog -Phase $phase -Action 'UninstallWebEnrollment' -Status Info -Target 'ADCS-Web-Enrollment' -Message 'Role existed before the scenario; leaving installed.'
    }

    $stateRoot = Get-Esc8StateRoot
    if (Test-Path -LiteralPath $stateRoot -PathType Container) {
        if ($PSCmdlet.ShouldProcess($stateRoot, 'Remove scenario state directory')) {
            Remove-Item -LiteralPath $stateRoot -Recurse -Force -ErrorAction Stop
            $changed = $true
            Write-LabLog -Phase $phase -Action 'RemoveState' -Status Changed -Target $stateRoot
        }
    }
    else {
        Write-LabLog -Phase $phase -Action 'RemoveState' -Status Unchanged -Target $stateRoot
    }

    $result = New-LabPhaseResult -Phase $phase -Status Succeeded -Changed $changed -Message "WebEnrollmentInstalledBefore=$webEnrollmentInstalledBefore; RemovedCertificates=$removedCertificates"
}
catch {
    Write-LabLog -Phase $phase -Action 'Cleanup' -Status Failed -Target $env:COMPUTERNAME -Message $_.Exception.Message
    throw
}
finally {
    Stop-LabTranscript
}

$result
