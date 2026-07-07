#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Hardened', 'Vulnerable')]
    [string]$Stage = 'Hardened',
    [string]$ConfigPath = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'config\LabConfig.psd1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Esc8Hardening.Common.psm1') -Force -DisableNameChecking -ErrorAction Stop
Assert-LabAdministrator
$config = Import-LabConfig -Path $ConfigPath
$phase = Get-Esc8ScenarioName
$log = Start-LabTranscript -Phase $phase
$changed = $false
$result = $null

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "Stage=$Stage; Transcript=$log"
    $domain = Get-LabCurrentDomain -Config $config
    if (-not [bool]$config.ADCS.Install) {
        throw 'AD CS is disabled in LabConfig. ESC8 hardening requires the lab CA.'
    }
    if ($env:COMPUTERNAME -ine [string]$config.ADCS.TargetComputerName) {
        throw "AD CS target is '$($config.ADCS.TargetComputerName)', but this computer is '$env:COMPUTERNAME'."
    }

    $state = Initialize-Esc8ScenarioState
    Write-LabLog -Phase $phase -Action 'State' -Status Info -Target (Get-Esc8StatePath) -Message "CreatedAt=$($state.CreatedAt)"

    $activeCa = Get-Esc8ActiveCaName
    $caConfig = "$env:COMPUTERNAME\$activeCa"
    if (Ensure-Esc8WebEnrollmentInstalled -CAConfig $caConfig) {
        $changed = $true
        Write-LabLog -Phase $phase -Action 'InstallWebEnrollment' -Status Changed -Target $caConfig
    }
    else {
        Write-LabLog -Phase $phase -Action 'InstallWebEnrollment' -Status Unchanged -Target $caConfig
    }

    if (Ensure-Esc8ServiceRunning -Name 'W3SVC') {
        $changed = $true
        Write-LabLog -Phase $phase -Action 'StartService' -Status Changed -Target 'W3SVC'
    }
    else {
        Write-LabLog -Phase $phase -Action 'StartService' -Status Unchanged -Target 'W3SVC'
    }

    $scenarioCertificateThumbprint = ''
    if ($Stage -eq 'Vulnerable') {
        if (Set-Esc8IisSecurityState -RequireSsl $false -TokenChecking None -Providers @('Negotiate', 'NTLM') -WindowsAuthenticationEnabled $true -AnonymousAuthenticationEnabled $false) {
            $changed = $true
            Write-LabLog -Phase $phase -Action 'ConfigureIis' -Status Changed -Target 'Default Web Site/CertSrv' -Message 'HTTP allowed; EPA=None; Providers=Negotiate,NTLM'
        }
        else {
            Write-LabLog -Phase $phase -Action 'ConfigureIis' -Status Unchanged -Target 'Default Web Site/CertSrv' -Message 'Vulnerable comparison state already present.'
        }
    }
    else {
        $httpsOutput = @(Ensure-Esc8HttpsBinding -DomainDnsName ([string]$domain.DNSRoot))
        $https = @($httpsOutput | Where-Object {
            $null -ne $_ -and
            $null -ne $_.PSObject.Properties['Changed'] -and
            $null -ne $_.PSObject.Properties['BindingCertificateThumbprint']
        } | Select-Object -Last 1)
        if ($https.Count -ne 1) {
            $outputTypes = @($httpsOutput | ForEach-Object { $_.GetType().FullName })
            throw "Ensure-Esc8HttpsBinding did not return a single operation result. OutputTypes=$($outputTypes -join ',')"
        }
        $https = $https[0]
        if ([bool]$https.Changed) {
            $changed = $true
            Write-LabLog -Phase $phase -Action 'ConfigureHttps' -Status Changed -Target 'Default Web Site:443' -Message "Certificate=$($https.BindingCertificateThumbprint)"
        }
        else {
            Write-LabLog -Phase $phase -Action 'ConfigureHttps' -Status Unchanged -Target 'Default Web Site:443' -Message "Certificate=$($https.BindingCertificateThumbprint)"
        }
        $scenarioCertificateThumbprint = [string]$https.ScenarioCertificateThumbprint

        if (Ensure-Esc8HttpsFirewallRule) {
            $changed = $true
            Write-LabLog -Phase $phase -Action 'EnableFirewallRule' -Status Changed -Target 'IIS-WebServerRole-HTTPS-In-TCP'
        }
        else {
            Write-LabLog -Phase $phase -Action 'EnableFirewallRule' -Status Unchanged -Target 'IIS-WebServerRole-HTTPS-In-TCP'
        }

        if (Set-Esc8IisSecurityState -RequireSsl $true -TokenChecking Require -Providers @('Negotiate:Kerberos') -WindowsAuthenticationEnabled $true -AnonymousAuthenticationEnabled $false) {
            $changed = $true
            Write-LabLog -Phase $phase -Action 'ConfigureIis' -Status Changed -Target 'Default Web Site/CertSrv' -Message 'Require SSL; EPA=Require; Providers=Negotiate:Kerberos'
        }
        else {
            Write-LabLog -Phase $phase -Action 'ConfigureIis' -Status Unchanged -Target 'Default Web Site/CertSrv' -Message 'Hardened state already present.'
        }
    }

    $state = Update-Esc8ScenarioState -State $state -LastStage $Stage -ScenarioCertificateThumbprint $scenarioCertificateThumbprint
    $current = Get-Esc8WebEnrollmentState
    $message = "Stage=$Stage; RelayPrerequisitesPresent=$($current.RelayPrerequisitesPresent); Hardened=$($current.Hardened); State=$($state.UpdatedAt)"
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
