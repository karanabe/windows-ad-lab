#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Esc11RpcEnrollment.Common.psm1') -Force -DisableNameChecking -ErrorAction Stop
Assert-LabAdministrator
$phase = Get-Esc11ScenarioName
$log = Start-LabTranscript -Phase $phase
$changed = $false
$result = $null

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "Transcript=$log"
    $state = Read-Esc11ScenarioState
    if ($null -eq $state) {
        Write-LabLog -Phase $phase -Action 'State' -Status Info -Target (Get-Esc11StatePath) -Message 'State file is absent; cleanup will not change CA InterfaceFlags.'
        $result = New-LabPhaseResult -Phase $phase -Status Succeeded -Changed $false -Message 'State=Missing; InterfaceFlags unchanged.'
        return $result
    }

    if (Restore-Esc11InterfaceFlags -State $state) {
        $changed = $true
        Write-LabLog -Phase $phase -Action 'RestoreInterfaceFlags' -Status Changed -Target 'CA\InterfaceFlags'
        if (Restart-Esc11CertSvc) {
            Write-LabLog -Phase $phase -Action 'RestartService' -Status Changed -Target 'CertSvc' -Message 'Applied restored CA InterfaceFlags.'
        }
    }
    else {
        Write-LabLog -Phase $phase -Action 'RestoreInterfaceFlags' -Status Unchanged -Target 'CA\InterfaceFlags'
    }

    $stateRoot = Get-Esc11StateRoot
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

    $result = New-LabPhaseResult -Phase $phase -Status Succeeded -Changed $changed -Message 'BaselineRestored'
}
catch {
    Write-LabLog -Phase $phase -Action 'Cleanup' -Status Failed -Target $env:COMPUTERNAME -Message $_.Exception.Message
    throw
}
finally {
    Stop-LabTranscript
}

$result
