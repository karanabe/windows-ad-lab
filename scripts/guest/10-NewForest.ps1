#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ConfigPath = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'config\LabConfig.psd1'),
    [Security.SecureString]$DsrmPassword,
    [switch]$DeferRestart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Assert-LabAdministrator
$config = Import-LabConfig -Path $ConfigPath
$phase = 'NewForest'
$log = Start-LabTranscript -Phase $phase
$changed = $false
$result = $null

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "Transcript=$log"
    if ($env:COMPUTERNAME -ine [string]$config.Lab.ComputerName) {
        throw "Computer name is '$env:COMPUTERNAME'; expected '$($config.Lab.ComputerName)'. Run OS baseline and restart first."
    }

    $computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ([int]$computerSystem.DomainRole -ge 4) {
        $domain = Get-LabCurrentDomain -Config $config
        Write-LabLog -Phase $phase -Action 'CreateForest' -Status Unchanged -Target $domain.DNSRoot
        $result = New-LabPhaseResult -Phase $phase -Status Succeeded -Changed $false -Message 'The configured forest already exists.'
    }
    else {
        $feature = Get-WindowsFeature -Name AD-Domain-Services -ErrorAction Stop
        if (-not $feature.Installed -and $PSCmdlet.ShouldProcess('Local server', 'Install AD DS and management tools')) {
            Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -ErrorAction Stop | Out-Null
            $changed = $true
            Write-LabLog -Phase $phase -Action 'InstallFeature' -Status Changed -Target 'AD-Domain-Services'
        }
        elseif ($feature.Installed) {
            Write-LabLog -Phase $phase -Action 'InstallFeature' -Status Unchanged -Target 'AD-Domain-Services'
        }

        if (-not $feature.Installed -and $WhatIfPreference) {
            $result = New-LabPhaseResult -Phase $phase -Status Skipped -Message 'WhatIf: AD DS feature and forest would be installed.'
        }
        else {
            Import-Module ADDSDeployment -ErrorAction Stop
            if ($PSCmdlet.ShouldProcess([string]$config.Domain.DnsName, 'Create AD DS forest and install DNS')) {
            if ($null -eq $DsrmPassword) {
                $DsrmPassword = Read-Host 'Enter the DSRM password' -AsSecureString
            }
            $params = @{
                DomainName = [string]$config.Domain.DnsName
                DomainNetbiosName = [string]$config.Domain.NetBIOSName
                InstallDns = $true
                SafeModeAdministratorPassword = $DsrmPassword
                Force = $true
            }
            if ([string]$config.Domain.DomainMode -ine 'Default') { $params.DomainMode = [string]$config.Domain.DomainMode }
            if ([string]$config.Domain.ForestMode -ine 'Default') { $params.ForestMode = [string]$config.Domain.ForestMode }
            if ($DeferRestart) { $params.NoRebootOnCompletion = $true }
            Install-ADDSForest @params | Out-Null
            $changed = $true
            Write-LabLog -Phase $phase -Action 'CreateForest' -Status Changed -Target ([string]$config.Domain.DnsName) -Message 'Restart required'
            $result = New-LabPhaseResult -Phase $phase -Status Succeeded -Changed $true -RebootRequired $true -Message 'Forest creation completed.'
            }
            else {
                $result = New-LabPhaseResult -Phase $phase -Status Skipped -Message 'WhatIf: forest creation was not applied.'
            }
        }
    }
}
catch {
    Write-LabLog -Phase $phase -Action 'Apply' -Status Failed -Target $env:COMPUTERNAME -Message $_.Exception.Message
    throw
}
finally {
    Stop-LabTranscript
}

$result
