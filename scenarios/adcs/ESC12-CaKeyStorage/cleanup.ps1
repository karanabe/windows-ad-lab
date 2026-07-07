#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Esc12CaKeyStorage.Common.psm1') -Force -DisableNameChecking -ErrorAction Stop
Assert-LabAdministrator
$phase = Get-Esc12ScenarioName
$log = Start-LabTranscript -Phase $phase
$changed = $false
$result = $null

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "Transcript=$log"
    $stateRoot = Get-Esc12StateRoot
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

    $result = New-LabPhaseResult -Phase $phase -Status Succeeded -Changed $changed -Message 'Observation state removed; CA CSP unchanged.'
}
catch {
    Write-LabLog -Phase $phase -Action 'Cleanup' -Status Failed -Target $env:COMPUTERNAME -Message $_.Exception.Message
    throw
}
finally {
    Stop-LabTranscript
}

$result
