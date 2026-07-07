#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Esc16DisableExtensionList.Common.psm1') -Force -DisableNameChecking -ErrorAction Stop
Assert-LabAdministrator
$phase = Get-Esc16ScenarioName
$log = Start-LabTranscript -Phase $phase
$changed = $false
$result = $null

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "Transcript=$log"
    $state = Read-Esc16ScenarioState
    if ($null -eq $state) {
        Write-LabLog -Phase $phase -Action 'State' -Status Info -Target (Get-Esc16StatePath) -Message 'State file is absent; cleanup will not change DisableExtensionList.'
        $result = New-LabPhaseResult -Phase $phase -Status Succeeded -Changed $false -Message 'State=Missing; DisableExtensionList unchanged.'
        return $result
    }

    if (Restore-Esc16DisableExtensionList -State $state) {
        $changed = $true
        Write-LabLog -Phase $phase -Action 'RestoreDisableExtensionList' -Status Changed -Target 'policy\DisableExtensionList'
        if (Restart-Esc16CertSvc) {
            Write-LabLog -Phase $phase -Action 'RestartService' -Status Changed -Target 'CertSvc' -Message 'Applied restored DisableExtensionList.'
        }
    }
    else {
        Write-LabLog -Phase $phase -Action 'RestoreDisableExtensionList' -Status Unchanged -Target 'policy\DisableExtensionList'
    }

    $stateRoot = Get-Esc16StateRoot
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
