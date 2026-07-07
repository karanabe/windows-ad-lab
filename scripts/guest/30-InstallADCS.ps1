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
$phase = 'ADCS'
$log = Start-LabTranscript -Phase $phase
$changed = $false
$result = $null

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "Transcript=$log"
    Get-LabCurrentDomain -Config $config | Out-Null

    if (-not [bool]$config.ADCS.Install) {
        Write-LabLog -Phase $phase -Action 'InstallCA' -Status Info -Target $env:COMPUTERNAME -Message 'ADCS.Install=false'
        $result = New-LabPhaseResult -Phase $phase -Status Skipped -Message 'AD CS installation is disabled in the configuration.'
    }
    else {
        if ($env:COMPUTERNAME -ine [string]$config.ADCS.TargetComputerName) {
            throw "AD CS target is '$($config.ADCS.TargetComputerName)', but this computer is '$env:COMPUTERNAME'."
        }
        Write-Warning 'This lab co-locates an Enterprise Root CA on a domain controller. Do not use this topology for a production PKI.'

        $activeCa = $null
        $caRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
        $caConfiguration = Get-ItemProperty -Path $caRoot -Name Active -ErrorAction SilentlyContinue
        if ($null -ne $caConfiguration) { $activeCa = [string]$caConfiguration.Active }
        $expectedCa = [string]$config.ADCS.CACommonName

        if (-not [string]::IsNullOrWhiteSpace($activeCa) -and $activeCa -ine $expectedCa) {
            throw "A different CA is already configured: '$activeCa' (expected '$expectedCa'). Automatic replacement is intentionally blocked."
        }

        if ([string]::IsNullOrWhiteSpace($activeCa)) {
            $feature = Get-WindowsFeature -Name ADCS-Cert-Authority -ErrorAction Stop
            if (-not $feature.Installed -and $PSCmdlet.ShouldProcess('Local server', 'Install AD CS Certification Authority role')) {
                Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools -ErrorAction Stop | Out-Null
                $changed = $true
                Write-LabLog -Phase $phase -Action 'InstallFeature' -Status Changed -Target 'ADCS-Cert-Authority'
            }
            elseif ($feature.Installed) {
                Write-LabLog -Phase $phase -Action 'InstallFeature' -Status Unchanged -Target 'ADCS-Cert-Authority'
            }

            Import-Module ADCSDeployment -ErrorAction Stop
            $caParams = @{
                CAType = [string]$config.ADCS.CAType
                CACommonName = $expectedCa
                CryptoProviderName = [string]$config.ADCS.CryptoProviderName
                KeyLength = [int]$config.ADCS.KeyLength
                HashAlgorithmName = [string]$config.ADCS.HashAlgorithmName
                ValidityPeriod = [string]$config.ADCS.ValidityPeriod
                ValidityPeriodUnits = [int]$config.ADCS.ValidityPeriodUnits
                Force = $true
            }
            if ($PSCmdlet.ShouldProcess($expectedCa, "Install $($config.ADCS.CAType)")) {
                Install-AdcsCertificationAuthority @caParams | Out-Null
                $changed = $true
                $activeCa = $expectedCa
                Write-LabLog -Phase $phase -Action 'InstallCA' -Status Changed -Target $expectedCa
            }
        }
        else {
            Write-LabLog -Phase $phase -Action 'InstallCA' -Status Unchanged -Target $expectedCa
        }

        $certService = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
        if ([bool]$config.ADCS.EnableFullAuditing -and $null -ne $certService) {
            $restartCaForAudit = $false
            $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
            $legacyOverride = 0
            $legacyConfiguration = Get-ItemProperty -Path $lsaPath -Name SCENoApplyLegacyAuditPolicy -ErrorAction SilentlyContinue
            if ($null -ne $legacyConfiguration) { $legacyOverride = [int]$legacyConfiguration.SCENoApplyLegacyAuditPolicy }
            if ($legacyOverride -ne 1 -and $PSCmdlet.ShouldProcess($lsaPath, 'Force advanced audit policy over legacy policy')) {
                New-ItemProperty -Path $lsaPath -Name SCENoApplyLegacyAuditPolicy -PropertyType DWord -Value 1 -Force | Out-Null
                $changed = $true
                Write-LabLog -Phase $phase -Action 'SetRegistry' -Status Changed -Target 'SCENoApplyLegacyAuditPolicy'
            }

            $auditPath = Join-Path $caRoot $activeCa
            $auditFilter = 0
            $auditConfiguration = Get-ItemProperty -Path $auditPath -Name AuditFilter -ErrorAction SilentlyContinue
            if ($null -ne $auditConfiguration) { $auditFilter = [int]$auditConfiguration.AuditFilter }
            if ([int]$auditFilter -ne 127 -and $PSCmdlet.ShouldProcess($expectedCa, 'Enable all CA audit categories')) {
                & certutil.exe -setreg 'CA\AuditFilter' 127 | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "certutil failed with exit code $LASTEXITCODE." }
                $changed = $true
                $restartCaForAudit = $true
                Write-LabLog -Phase $phase -Action 'EnableCAAuditing' -Status Changed -Target $expectedCa
            }

            $certAudit = @($config.Audit.Subcategories | Where-Object { [bool]$_.RequiresADCS })[0]
            $success = if ([bool]$certAudit.Success) { 'enable' } else { 'disable' }
            $failure = if ([bool]$certAudit.Failure) { 'enable' } else { 'disable' }
            $current = Get-LabAuditPolicyValue -SubcategoryGuid ([guid]$certAudit.Guid)
            if ($current.Success -ne [bool]$certAudit.Success -or $current.Failure -ne [bool]$certAudit.Failure) {
                if ($PSCmdlet.ShouldProcess('Certification Services', 'Configure advanced audit policy')) {
                    & auditpol.exe /set "/subcategory:$($certAudit.Guid)" "/success:$success" "/failure:$failure" | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw "auditpol failed with exit code $LASTEXITCODE." }
                    $verified = Get-LabAuditPolicyValue -SubcategoryGuid ([guid]$certAudit.Guid)
                    if ($verified.Success -ne [bool]$certAudit.Success -or $verified.Failure -ne [bool]$certAudit.Failure) {
                        throw 'Certification Services audit policy did not converge.'
                    }
                    $changed = $true
                    Write-LabLog -Phase $phase -Action 'SetAuditPolicy' -Status Changed -Target 'Certification Services'
                }
            }
            else {
                Write-LabLog -Phase $phase -Action 'SetAuditPolicy' -Status Unchanged -Target 'Certification Services'
            }
            if ($restartCaForAudit) {
                Restart-Service -Name CertSvc -Force -ErrorAction Stop
                Write-LabLog -Phase $phase -Action 'RestartService' -Status Changed -Target 'CertSvc' -Message 'Applied CA AuditFilter.'
            }
        }

        $result = New-LabPhaseResult -Phase $phase -Status Succeeded -Changed $changed -Message "CA=$expectedCa"
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
