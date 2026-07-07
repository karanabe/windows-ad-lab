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
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Validation.psm1') -Force -ErrorAction Stop
Assert-LabAdministrator
$config = Import-LabConfig -Path $ConfigPath
$phase = 'DefensiveAuditing'
$log = Start-LabTranscript -Phase $phase
$changed = $false
$result = $null

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "Transcript=$log"
    Get-LabCurrentDomain -Config $config | Out-Null

    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $legacyOverride = 0
    $legacyConfiguration = Get-ItemProperty -Path $lsaPath -Name SCENoApplyLegacyAuditPolicy -ErrorAction SilentlyContinue
    if ($null -ne $legacyConfiguration) { $legacyOverride = [int]$legacyConfiguration.SCENoApplyLegacyAuditPolicy }
    if ([int]$legacyOverride -ne 1 -and $PSCmdlet.ShouldProcess($lsaPath, 'Force advanced audit policy over legacy policy')) {
        New-ItemProperty -Path $lsaPath -Name SCENoApplyLegacyAuditPolicy -PropertyType DWord -Value 1 -Force | Out-Null
        $changed = $true
        Write-LabLog -Phase $phase -Action 'SetRegistry' -Status Changed -Target 'SCENoApplyLegacyAuditPolicy'
    }

    if ([bool]$config.Audit.IncludeProcessCommandLine) {
        $processAuditPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
        $commandLineValue = 0
        $commandLineConfiguration = Get-ItemProperty -Path $processAuditPath -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue
        if ($null -ne $commandLineConfiguration) { $commandLineValue = [int]$commandLineConfiguration.ProcessCreationIncludeCmdLine_Enabled }
        if ([int]$commandLineValue -ne 1 -and $PSCmdlet.ShouldProcess($processAuditPath, 'Include command lines in process creation events')) {
            New-Item -Path $processAuditPath -Force | Out-Null
            New-ItemProperty -Path $processAuditPath -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value 1 -Force | Out-Null
            $changed = $true
            Write-LabLog -Phase $phase -Action 'SetRegistry' -Status Changed -Target 'ProcessCreationIncludeCmdLine_Enabled'
        }
    }

    $hasCa = $null -ne (Get-Service -Name CertSvc -ErrorAction SilentlyContinue)
    foreach ($subcategory in @($config.Audit.Subcategories)) {
        if ([bool]$subcategory.RequiresADCS -and -not $hasCa) {
            Write-LabLog -Phase $phase -Action 'SetAuditPolicy' -Status Info -Target ([string]$subcategory.Name) -Message 'Skipped until AD CS is installed.'
            continue
        }
        $current = Get-LabAuditPolicyValue -SubcategoryGuid ([guid]$subcategory.Guid)
        if ($current.Success -eq [bool]$subcategory.Success -and $current.Failure -eq [bool]$subcategory.Failure) {
            Write-LabLog -Phase $phase -Action 'SetAuditPolicy' -Status Unchanged -Target ([string]$subcategory.Name)
            continue
        }
        $success = if ([bool]$subcategory.Success) { 'enable' } else { 'disable' }
        $failure = if ([bool]$subcategory.Failure) { 'enable' } else { 'disable' }
        if ($PSCmdlet.ShouldProcess([string]$subcategory.Name, 'Configure advanced audit policy')) {
            & auditpol.exe /set "/subcategory:$($subcategory.Guid)" "/success:$success" "/failure:$failure" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "auditpol failed for '$($subcategory.Name)' with exit code $LASTEXITCODE." }
            $verified = Get-LabAuditPolicyValue -SubcategoryGuid ([guid]$subcategory.Guid)
            if ($verified.Success -ne [bool]$subcategory.Success -or $verified.Failure -ne [bool]$subcategory.Failure) {
                throw "Audit policy did not converge for '$($subcategory.Name)'."
            }
            $changed = $true
            Write-LabLog -Phase $phase -Action 'SetAuditPolicy' -Status Changed -Target ([string]$subcategory.Name)
        }
    }

    Write-Warning 'Local audit policy can be overridden by a domain GPO. Move this baseline into a GPO before adding more domain controllers.'
    $result = New-LabPhaseResult -Phase $phase -Status Succeeded -Changed $changed -Message 'Configured audit settings were read back through the Windows Audit API.'
}
catch {
    Write-LabLog -Phase $phase -Action 'Apply' -Status Failed -Target $env:COMPUTERNAME -Message $_.Exception.Message
    throw
}
finally {
    Stop-LabTranscript
}

$result
