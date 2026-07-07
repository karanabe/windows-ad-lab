#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ConfigPath = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'config\LabConfig.psd1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Esc12CaKeyStorage.Common.psm1') -Force -DisableNameChecking -ErrorAction Stop
Assert-LabAdministrator
$config = Import-LabConfig -Path $ConfigPath
$phase = Get-Esc12ScenarioName
$log = Start-LabTranscript -Phase $phase
$changed = $false
$result = $null

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "Transcript=$log"
    Get-LabCurrentDomain -Config $config | Out-Null
    if (-not [bool]$config.ADCS.Install) {
        throw 'AD CS is disabled in LabConfig. ESC12 CA key-storage observation requires the lab CA.'
    }
    if ($env:COMPUTERNAME -ine [string]$config.ADCS.TargetComputerName) {
        throw "AD CS target is '$($config.ADCS.TargetComputerName)', but this computer is '$env:COMPUTERNAME'."
    }

    $state = Initialize-Esc12ScenarioState
    Write-LabLog -Phase $phase -Action 'State' -Status Info -Target (Get-Esc12StatePath) -Message "CreatedAt=$($state.CreatedAt); Provider=$($state.ProviderBefore)"

    if (Ensure-Esc12CertSvcRunning) {
        $changed = $true
        Write-LabLog -Phase $phase -Action 'StartService' -Status Changed -Target 'CertSvc'
    }
    else {
        Write-LabLog -Phase $phase -Action 'StartService' -Status Unchanged -Target 'CertSvc'
    }

    $current = Get-Esc12CaKeyStorageState
    if (-not [bool]$current.CspReadable) {
        throw "CA CSP could not be read: $($current.CspRegistryError)"
    }

    $state = Update-Esc12ScenarioState -State $state
    $message = "Provider='$($current.Provider)'; KeyContainer='$($current.KeyContainer)'; UsesSoftwareProvider=$($current.UsesSoftwareProvider); Esc12HardwareClassPresent=$($current.Esc12HardwareClassPresent); PrivateKeyExported=$($current.PrivateKeyExported)"
    Write-LabLog -Phase $phase -Action 'ObserveCsp' -Status Info -Target $current.CspPath -Message $message
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
