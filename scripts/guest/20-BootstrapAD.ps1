#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ConfigPath = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'config\LabConfig.psd1'),
    [Security.SecureString]$DefaultUserPassword,
    [switch]$ResetExistingPasswords
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $repositoryRoot 'modules\Lab.ActiveDirectory.psm1') -Force -ErrorAction Stop
Assert-LabAdministrator
$config = Import-LabConfig -Path $ConfigPath
$phase = 'ADBaseline'
$log = Start-LabTranscript -Phase $phase
$result = $null

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "Transcript=$log"
    Get-LabCurrentDomain -Config $config | Out-Null
    if ($null -eq $DefaultUserPassword -and -not $WhatIfPreference -and (Test-LabNeedsUserPassword -Config $config -ResetExistingPasswords:$ResetExistingPasswords)) {
        $DefaultUserPassword = Read-Host 'Enter the password for new lab users' -AsSecureString
    }
    $summary = Set-LabADBaseline -Config $config -DefaultUserPassword $DefaultUserPassword -ResetExistingPasswords:$ResetExistingPasswords
    $result = New-LabPhaseResult -Phase $phase -Status Succeeded -Changed ([bool]$summary.Changed) -Message "Domain=$($summary.Domain); RootOU=$($summary.RootOU)"
}
catch {
    Write-LabLog -Phase $phase -Action 'Apply' -Status Failed -Target $env:COMPUTERNAME -Message $_.Exception.Message
    throw
}
finally {
    Stop-LabTranscript
}

$result
