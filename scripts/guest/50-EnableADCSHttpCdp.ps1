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
Assert-LabAdministrator
$config = Import-LabConfig -Path $ConfigPath
$phase = 'ADCSHttpCdp'
$log = Start-LabTranscript -Phase $phase
$changed = $false
$result = $null

$script:CertEnrollVirtualDirectory = 'CertEnroll'
$script:CrlHttpUrl = 'http://%1/CertEnroll/%3%8%9.crl'
$script:AiaHttpUrl = 'http://%1/CertEnroll/%1_%3%4.crt'
$script:AddToIssuedCertificateFlag = 0x00000002
$script:AddToFreshestCrlFlag = 0x00000004

function Get-ActiveCaName {
    $caRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
    $active = (Get-ItemProperty -Path $caRoot -Name Active -ErrorAction Stop).Active
    if ([string]::IsNullOrWhiteSpace([string]$active)) {
        throw 'No active local Certification Authority was found.'
    }
    return [string]$active
}

function Invoke-CertUtil {
    param(
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [Parameter(Mandatory = $true)][string]$Action,
        [ValidateRange(1, 60)][int]$RetryCount = 1,
        [ValidateRange(1, 60)][int]$RetryDelaySeconds = 5
    )

    $lastExitCode = 0
    $lastOutput = @()
    $retryableExitCodes = @(-2147023174, 1722)
    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        $lastOutput = @(& certutil.exe @ArgumentList 2>&1)
        $lastExitCode = $LASTEXITCODE
        if ($lastExitCode -eq 0) {
            return $lastOutput
        }

        $outputText = $lastOutput -join [Environment]::NewLine
        $isRetryable = (
            $retryableExitCodes -contains [int]$lastExitCode -or
            $outputText -match 'RPC_S_SERVER_UNAVAILABLE|The RPC server is unavailable'
        )
        if ($isRetryable -and $attempt -lt $RetryCount) {
            $lastLine = if ($lastOutput.Count -eq 0) { '<no output>' } else { [string]$lastOutput[-1] }
            Write-LabLog -Phase $phase -Action 'WaitCertSvcRpc' -Status Info -Target $Action -Message "Attempt=$attempt/$RetryCount; ExitCode=$lastExitCode; LastOutput=$lastLine"
            Start-Sleep -Seconds $RetryDelaySeconds
            continue
        }

        throw "certutil $Action failed with exit code $lastExitCode. Output: $outputText"
    }
}

function ConvertFrom-CaPublicationEntry {
    param([Parameter(Mandatory = $true)][string]$Entry)

    if ($Entry -notmatch '^(?<Flags>\d+):(?<Url>.+)$') {
        throw "CA publication URL entry has an unexpected format: '$Entry'"
    }
    return [pscustomobject]@{
        Flags = [int]$matches.Flags
        Url   = [string]$matches.Url
    }
}

function Set-CaPublicationUrlFlag {
    param(
        [Parameter(Mandatory = $true)][string]$RegistryPath,
        [Parameter(Mandatory = $true)][string]$PropertyName,
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][int]$RequiredFlags
    )

    $currentEntries = @((Get-ItemProperty -Path $RegistryPath -Name $PropertyName -ErrorAction Stop).$PropertyName)
    $updatedEntries = New-Object 'System.Collections.Generic.List[string]'
    $found = $false
    $changed = $false

    foreach ($entry in @($currentEntries)) {
        $parsed = ConvertFrom-CaPublicationEntry -Entry ([string]$entry)
        if ([string]$parsed.Url -ieq $Url) {
            $found = $true
            $newFlags = ([int]$parsed.Flags -bor $RequiredFlags)
            if ($newFlags -ne [int]$parsed.Flags) {
                $changed = $true
            }
            $updatedEntries.Add(('{0}:{1}' -f $newFlags, $parsed.Url))
        }
        else {
            $updatedEntries.Add([string]$entry)
        }
    }

    if (-not $found) {
        $updatedEntries.Add(('{0}:{1}' -f $RequiredFlags, $Url))
        $changed = $true
    }

    if ($changed -and $PSCmdlet.ShouldProcess("$RegistryPath\$PropertyName", "Set CA publication URL flags for $Url")) {
        Set-ItemProperty -Path $RegistryPath -Name $PropertyName -Value ([string[]]$updatedEntries.ToArray()) -ErrorAction Stop
    }

    return [pscustomobject]@{
        Changed = $changed
        Entries = [string[]]$updatedEntries.ToArray()
    }
}

function Ensure-WindowsFeatureInstalled {
    param([Parameter(Mandatory = $true)][string[]]$Name)

    $missing = @()
    foreach ($featureName in @($Name)) {
        $feature = Get-WindowsFeature -Name $featureName -ErrorAction Stop
        if (-not [bool]$feature.Installed) {
            $missing += $featureName
        }
    }

    if ($missing.Count -eq 0) {
        Write-LabLog -Phase $phase -Action 'InstallFeature' -Status Unchanged -Target ($Name -join ',')
        return $false
    }

    if ($PSCmdlet.ShouldProcess(($missing -join ','), 'Install IIS features for HTTP certificate publication')) {
        Install-WindowsFeature -Name $missing -IncludeManagementTools -ErrorAction Stop | Out-Null
        Write-LabLog -Phase $phase -Action 'InstallFeature' -Status Changed -Target ($missing -join ',')
        return $true
    }
    return $false
}

function Ensure-CertEnrollWebConfig {
    param([Parameter(Mandatory = $true)][string]$Path)

    $webConfigPath = Join-Path $Path 'web.config'
    $desired = @'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <security>
      <requestFiltering allowDoubleEscaping="true" />
    </security>
    <staticContent>
      <remove fileExtension=".crl" />
      <mimeMap fileExtension=".crl" mimeType="application/pkix-crl" />
      <remove fileExtension=".crt" />
      <mimeMap fileExtension=".crt" mimeType="application/pkix-cert" />
    </staticContent>
    <directoryBrowse enabled="false" />
  </system.webServer>
</configuration>
'@

    $current = $null
    if (Test-Path -LiteralPath $webConfigPath -PathType Leaf) {
        $current = Get-Content -LiteralPath $webConfigPath -Raw -ErrorAction Stop
    }
    $normalizedCurrent = if ($null -eq $current) { $null } else { $current.Replace("`r`n", "`n") }
    $normalizedDesired = $desired.Replace("`r`n", "`n")
    if ($normalizedCurrent -eq $normalizedDesired) {
        Write-LabLog -Phase $phase -Action 'WriteWebConfig' -Status Unchanged -Target $webConfigPath
        return $false
    }

    if ($PSCmdlet.ShouldProcess($webConfigPath, 'Write IIS static-content configuration for CA files')) {
        Set-Content -LiteralPath $webConfigPath -Value $desired -Encoding UTF8 -NoNewline -ErrorAction Stop
        Write-LabLog -Phase $phase -Action 'WriteWebConfig' -Status Changed -Target $webConfigPath
        return $true
    }
    return $false
}

function Ensure-CertEnrollVirtualDirectory {
    param([Parameter(Mandatory = $true)][string]$PhysicalPath)

    Import-Module WebAdministration -ErrorAction Stop
    $siteName = 'Default Web Site'
    $site = Get-Website -Name $siteName -ErrorAction Stop
    $changed = $false
    if ([string]$site.State -ne 'Started') {
        if ($PSCmdlet.ShouldProcess($siteName, 'Start IIS website')) {
            Start-Website -Name $siteName -ErrorAction Stop
            $changed = $true
            Write-LabLog -Phase $phase -Action 'StartWebsite' -Status Changed -Target $siteName
        }
    }
    else {
        Write-LabLog -Phase $phase -Action 'StartWebsite' -Status Unchanged -Target $siteName
    }

    $virtualDirectory = Get-WebVirtualDirectory -Site $siteName -Name $script:CertEnrollVirtualDirectory -ErrorAction SilentlyContinue
    if ($null -eq $virtualDirectory) {
        if ($PSCmdlet.ShouldProcess("$siteName/$script:CertEnrollVirtualDirectory", "Create virtual directory to $PhysicalPath")) {
            New-WebVirtualDirectory -Site $siteName -Name $script:CertEnrollVirtualDirectory -PhysicalPath $PhysicalPath -ErrorAction Stop | Out-Null
            Write-LabLog -Phase $phase -Action 'CreateVirtualDirectory' -Status Changed -Target "$siteName/$script:CertEnrollVirtualDirectory"
            return $true
        }
        return $changed
    }

    if ([string]$virtualDirectory.physicalPath -ine $PhysicalPath) {
        if ($PSCmdlet.ShouldProcess("$siteName/$script:CertEnrollVirtualDirectory", "Update physicalPath to $PhysicalPath")) {
            Set-ItemProperty -Path "IIS:\Sites\$siteName\$script:CertEnrollVirtualDirectory" -Name physicalPath -Value $PhysicalPath -ErrorAction Stop
            Write-LabLog -Phase $phase -Action 'UpdateVirtualDirectory' -Status Changed -Target "$siteName/$script:CertEnrollVirtualDirectory"
            return $true
        }
        return $changed
    }

    Write-LabLog -Phase $phase -Action 'CreateVirtualDirectory' -Status Unchanged -Target "$siteName/$script:CertEnrollVirtualDirectory"
    return $changed
}

function Ensure-ServiceRunning {
    param([Parameter(Mandatory = $true)][string]$Name)

    $service = Get-Service -Name $Name -ErrorAction Stop
    $changed = $false
    if ([string]$service.StartType -ne 'Automatic') {
        if ($PSCmdlet.ShouldProcess($Name, 'Set service startup type to Automatic')) {
            Set-Service -Name $Name -StartupType Automatic -ErrorAction Stop
            $changed = $true
        }
    }
    $service = Get-Service -Name $Name -ErrorAction Stop
    if ($service.Status -ne 'Running') {
        if ($PSCmdlet.ShouldProcess($Name, 'Start service')) {
            Start-Service -Name $Name -ErrorAction Stop
            $changed = $true
        }
    }

    $status = if ($changed) { 'Changed' } else { 'Unchanged' }
    $service = Get-Service -Name $Name -ErrorAction Stop
    Write-LabLog -Phase $phase -Action 'StartService' -Status $status -Target $Name -Message "StartType=$($service.StartType); Status=$($service.Status)"
    return $changed
}

function Ensure-IisHttpFirewallRule {
    $rules = @(Get-NetFirewallRule -Name 'IIS-WebServerRole-HTTP-In-TCP' -ErrorAction SilentlyContinue)
    if ($rules.Count -eq 0) {
        Write-LabLog -Phase $phase -Action 'EnableFirewallRule' -Status Info -Target 'IIS-WebServerRole-HTTP-In-TCP' -Message 'Firewall rule was not found.'
        return $false
    }

    $changed = $false
    foreach ($rule in @($rules)) {
        if ([string]$rule.Enabled -ne 'True') {
            if ($PSCmdlet.ShouldProcess($rule.Name, 'Enable IIS HTTP inbound firewall rule')) {
                Enable-NetFirewallRule -Name $rule.Name -ErrorAction Stop
                $changed = $true
            }
        }
    }
    $status = if ($changed) { 'Changed' } else { 'Unchanged' }
    Write-LabLog -Phase $phase -Action 'EnableFirewallRule' -Status $status -Target 'IIS-WebServerRole-HTTP-In-TCP'
    return $changed
}

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "Transcript=$log"
    $domain = Get-LabCurrentDomain -Config $config

    if (-not [bool]$config.ADCS.Install) {
        Write-LabLog -Phase $phase -Action 'ConfigureHttpCdp' -Status Info -Target $env:COMPUTERNAME -Message 'ADCS.Install=false'
        $result = New-LabPhaseResult -Phase $phase -Status Skipped -Message 'AD CS installation is disabled in the configuration.'
    }
    else {
        if ($env:COMPUTERNAME -ine [string]$config.ADCS.TargetComputerName) {
            throw "AD CS target is '$($config.ADCS.TargetComputerName)', but this computer is '$env:COMPUTERNAME'."
        }

        $activeCa = Get-ActiveCaName
        if ($activeCa -ine [string]$config.ADCS.CACommonName) {
            throw "Active CA is '$activeCa', but LabConfig expects '$($config.ADCS.CACommonName)'."
        }

        $certEnrollPath = Join-Path $env:windir 'System32\CertSrv\CertEnroll'
        if (-not (Test-Path -LiteralPath $certEnrollPath -PathType Container)) {
            if ($PSCmdlet.ShouldProcess($certEnrollPath, 'Create CertEnroll publication directory')) {
                New-Item -ItemType Directory -Path $certEnrollPath -Force -ErrorAction Stop | Out-Null
                $changed = $true
                Write-LabLog -Phase $phase -Action 'CreateDirectory' -Status Changed -Target $certEnrollPath
            }
        }
        else {
            Write-LabLog -Phase $phase -Action 'CreateDirectory' -Status Unchanged -Target $certEnrollPath
        }

        $changed = (Ensure-WindowsFeatureInstalled -Name @('Web-Server', 'Web-Static-Content', 'Web-Filtering')) -or $changed
        $changed = (Ensure-ServiceRunning -Name 'W3SVC') -or $changed
        $changed = (Ensure-CertEnrollVirtualDirectory -PhysicalPath $certEnrollPath) -or $changed
        $changed = (Ensure-CertEnrollWebConfig -Path $certEnrollPath) -or $changed
        $changed = (Ensure-IisHttpFirewallRule) -or $changed

        $caRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$activeCa"
        $crlFlags = $script:AddToIssuedCertificateFlag -bor $script:AddToFreshestCrlFlag
        $crlUpdate = Set-CaPublicationUrlFlag -RegistryPath $caRegistryPath -PropertyName 'CRLPublicationURLs' -Url $script:CrlHttpUrl -RequiredFlags $crlFlags
        $aiaUpdate = Set-CaPublicationUrlFlag -RegistryPath $caRegistryPath -PropertyName 'CACertPublicationURLs' -Url $script:AiaHttpUrl -RequiredFlags $script:AddToIssuedCertificateFlag
        if ([bool]$crlUpdate.Changed -or [bool]$aiaUpdate.Changed) {
            $changed = $true
            if ($PSCmdlet.ShouldProcess('CertSvc', 'Restart after HTTP CDP/AIA registry update')) {
                Restart-Service -Name CertSvc -Force -ErrorAction Stop
                Write-LabLog -Phase $phase -Action 'RestartService' -Status Changed -Target 'CertSvc' -Message 'Applied HTTP CDP/AIA publication URLs.'
            }
        }
        else {
            Write-LabLog -Phase $phase -Action 'RestartService' -Status Unchanged -Target 'CertSvc' -Message 'HTTP CDP/AIA publication URLs already configured.'
        }
        $changed = (Ensure-ServiceRunning -Name 'CertSvc') -or $changed

        $fqdn = "$($env:COMPUTERNAME).$($domain.DNSRoot)"
        $expectedCaCertPath = Join-Path $certEnrollPath "$fqdn`_$activeCa.crt"
        if (-not (Test-Path -LiteralPath $expectedCaCertPath -PathType Leaf)) {
            if ($PSCmdlet.ShouldProcess($expectedCaCertPath, 'Export CA certificate for HTTP AIA publication')) {
                Invoke-CertUtil -ArgumentList @('-ca.cert', $expectedCaCertPath) -Action '-ca.cert' -RetryCount 12 -RetryDelaySeconds 5 | Out-Null
                $changed = $true
                Write-LabLog -Phase $phase -Action 'ExportCACert' -Status Changed -Target $expectedCaCertPath
            }
        }
        else {
            Write-LabLog -Phase $phase -Action 'ExportCACert' -Status Unchanged -Target $expectedCaCertPath
        }

        if ($PSCmdlet.ShouldProcess($activeCa, 'Publish current CRL')) {
            Invoke-CertUtil -ArgumentList @('-crl') -Action '-crl' -RetryCount 12 -RetryDelaySeconds 5 | Out-Null
            $changed = $true
            Write-LabLog -Phase $phase -Action 'PublishCRL' -Status Changed -Target $activeCa
        }

        $crlFiles = @(Get-ChildItem -LiteralPath $certEnrollPath -Filter '*.crl' -File -ErrorAction Stop)
        $crtFiles = @(Get-ChildItem -LiteralPath $certEnrollPath -Filter '*.crt' -File -ErrorAction Stop)
        if ($crlFiles.Count -eq 0) {
            throw "No CRL files were found in '$certEnrollPath' after publication."
        }
        if ($crtFiles.Count -eq 0) {
            throw "No CA certificate files were found in '$certEnrollPath' after publication."
        }

        $result = New-LabPhaseResult -Phase $phase -Status Succeeded -Changed $changed -Message "HTTP CDP/AIA enabled; BaseUrl=http://$fqdn/CertEnroll; CRLs=$($crlFiles.Count); CA certs=$($crtFiles.Count)"
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
