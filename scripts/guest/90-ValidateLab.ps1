#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'config\LabConfig.psd1'),
    [string]$TimeZoneId,
    [string]$OutputPath,
    [switch]$SkipDcDiag,
    [switch]$ExpectAdcsHttpCdp,
    [switch]$FailOnValidationError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $repositoryRoot 'modules\Lab.ActiveDirectory.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Validation.psm1') -Force -ErrorAction Stop
Assert-LabAdministrator
$config = Import-LabConfig -Path $ConfigPath
$phase = 'Validation'
$log = Start-LabTranscript -Phase $phase
$results = New-Object System.Collections.Generic.List[object]
$validationResults = @()
$summary = $null
$failedResults = @()
$failedNames = @()

function Add-ExpectedResult {
    param([string]$Category, [string]$Name, $Expected, $Actual)
    $results.Add((Test-LabExpectedValue -Category $Category -Name $Name -Expected $Expected -Actual $Actual))
}

function Add-BooleanResult {
    param([string]$Category, [string]$Name, [bool]$Passed, $Expected, $Actual, [string]$Message = '')
    $status = if ($Passed) { 'Passed' } else { 'Failed' }
    $results.Add((New-LabValidationResult -Category $Category -Name $Name -Status $status -Expected $Expected -Actual $Actual -Message $Message))
}

function Write-ValidationProgress {
    param(
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Message
    )

    Write-LabLog -Phase $phase -Action 'Progress' -Status Info -Target $Target -Message "$Message; CompletedChecks=$($results.Count)"
}

function ConvertTo-ValidationLogValue {
    param([AllowNull()]$Value)

    if ($null -eq $Value) {
        return '<null>'
    }

    return ([string]$Value) -replace '\r?\n|\r', ' | '
}

function ConvertFrom-CaPublicationEntry {
    param([Parameter(Mandatory = $true)][string]$Entry)

    if ($Entry -notmatch '^(?<Flags>\d+):(?<Url>.+)$') {
        return [pscustomobject]@{
            Parsed = $false
            Flags  = 0
            Url    = [string]$Entry
        }
    }

    return [pscustomobject]@{
        Parsed = $true
        Flags  = [int]$matches.Flags
        Url    = [string]$matches.Url
    }
}

function Test-CaPublicationUrlFlag {
    param(
        [AllowNull()]$Entries,
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][int]$RequiredFlags
    )

    foreach ($entry in @($Entries)) {
        if ($null -eq $entry) { continue }
        $parsed = ConvertFrom-CaPublicationEntry -Entry ([string]$entry)
        if (-not [bool]$parsed.Parsed) { continue }
        if ([string]$parsed.Url -ieq $Url) {
            $hasFlags = (([int]$parsed.Flags -band $RequiredFlags) -eq $RequiredFlags)
            return [pscustomobject]@{
                Present = $true
                Passed  = $hasFlags
                Actual  = ('Flags=0x{0:X8}; Url={1}' -f [int]$parsed.Flags, [string]$parsed.Url)
            }
        }
    }

    return [pscustomobject]@{
        Present = $false
        Passed  = $false
        Actual  = 'Missing'
    }
}

function Test-HttpDownload {
    param([Parameter(Mandatory = $true)][string]$Url)

    $client = New-Object Net.WebClient
    try {
        $bytes = $client.DownloadData($Url)
        return [pscustomobject]@{
            Passed = ($bytes.Length -gt 0)
            Actual = "Bytes=$($bytes.Length); Url=$Url"
        }
    }
    catch {
        return [pscustomobject]@{
            Passed = $false
            Actual = "$($_.Exception.Message); Url=$Url"
        }
    }
    finally {
        $client.Dispose()
    }
}

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "Transcript=$log"

    Write-ValidationProgress -Target 'Provenance' -Message 'Checking configuration and build metadata'
    $configSha256 = (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256 -ErrorAction Stop).Hash
    $results.Add((New-LabValidationResult -Category 'Provenance' -Name 'LabConfigSHA256' -Status Passed -Expected 'Recorded SHA256' -Actual $configSha256))
    foreach ($metadataName in @('BUILD_COMMIT', 'BUILD_STATUS', 'BUILD_PUBLISHED_AT')) {
        $metadataPath = Join-Path $repositoryRoot $metadataName
        if (Test-Path -LiteralPath $metadataPath -PathType Leaf) {
            $metadataValue = ([string](Get-Content -LiteralPath $metadataPath -Raw)).Trim()
            if ([string]::IsNullOrWhiteSpace($metadataValue)) { $metadataValue = 'Clean' }
            $results.Add((New-LabValidationResult -Category 'Provenance' -Name $metadataName -Status Passed -Expected 'Published from WSL' -Actual $metadataValue))
        }
        else {
            $results.Add((New-LabValidationResult -Category 'Provenance' -Name $metadataName -Status Skipped -Expected 'Published from WSL' -Actual 'Metadata file not supplied'))
        }
    }

    Write-ValidationProgress -Target 'OSAndNetwork' -Message 'Checking hostname, time zone, IP, DNS client, and routes'
    Add-ExpectedResult -Category 'OS' -Name 'Hostname' -Expected ([string]$config.Lab.ComputerName) -Actual $env:COMPUTERNAME
    $expectedTimeZoneId = if ($PSBoundParameters.ContainsKey('TimeZoneId')) { $TimeZoneId } else { [string]$config.Time.WindowsTimeZoneId }
    if ([string]::IsNullOrWhiteSpace($expectedTimeZoneId) -or $expectedTimeZoneId -eq 'Host') {
        throw 'TimeZoneId is required when Time.WindowsTimeZoneId is Host. Run through the host bootstrap or pass -TimeZoneId.'
    }
    Add-ExpectedResult -Category 'OS' -Name 'TimeZone' -Expected $expectedTimeZoneId -Actual ((Get-TimeZone -ErrorAction Stop).Id)

    $adapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.HardwareInterface -and $_.Status -ne 'Disabled' })
    Add-BooleanResult -Category 'Network' -Name 'EnabledHardwareAdapterCount' -Passed ($adapters.Count -eq 1) -Expected 1 -Actual $adapters.Count
    if ($adapters.Count -eq 1) {
        $adapter = $adapters[0]
        $addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)
        $targetAddress = @($addresses | Where-Object { $_.IPAddress -eq [string]$config.Network.DC01.IPAddress -and $_.PrefixLength -eq [int]$config.Network.DC01.PrefixLength })
        Add-BooleanResult -Category 'Network' -Name 'IPv4AddressAndPrefix' -Passed ($targetAddress.Count -eq 1) -Expected "$($config.Network.DC01.IPAddress)/$($config.Network.DC01.PrefixLength)" -Actual (($addresses | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" }) -join ',')

        $dns = @((Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses)
        Add-ExpectedResult -Category 'Network' -Name 'DnsServers' -Expected (@($config.Network.DC01.DnsServers) -join ',') -Actual ($dns -join ',')
        $defaultRoutes = @(Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
        $nextHops = @($defaultRoutes | ForEach-Object { [string]$_.NextHop })
        Add-BooleanResult -Category 'Network' -Name 'NoDefaultGateway' -Passed ($defaultRoutes.Count -eq 0) -Expected 'No default route' -Actual ($nextHops -join ',')
    }

    Write-ValidationProgress -Target 'ActiveDirectoryAndDNS' -Message 'Checking forest, domain controller discovery, DNS zone, and SRV records'
    $domain = Get-LabCurrentDomain -Config $config
    $forest = Get-ADForest -ErrorAction Stop
    Add-ExpectedResult -Category 'ADDS' -Name 'Domain' -Expected ([string]$config.Domain.DnsName) -Actual ([string]$domain.DNSRoot)
    Add-ExpectedResult -Category 'ADDS' -Name 'NetBIOSName' -Expected ([string]$config.Domain.NetBIOSName) -Actual ([string]$domain.NetBIOSName)
    Add-ExpectedResult -Category 'ADDS' -Name 'Forest' -Expected ([string]$config.Domain.DnsName) -Actual ([string]$forest.Name)
    Add-BooleanResult -Category 'ADDS' -Name 'DomainMode' -Passed (-not [string]::IsNullOrWhiteSpace([string]$domain.DomainMode)) -Expected 'Configured functional level' -Actual ([string]$domain.DomainMode)
    Add-BooleanResult -Category 'ADDS' -Name 'ForestMode' -Passed (-not [string]::IsNullOrWhiteSpace([string]$forest.ForestMode)) -Expected 'Configured functional level' -Actual ([string]$forest.ForestMode)

    try {
        $dc = Get-ADDomainController -Discover -DomainName ([string]$domain.DNSRoot) -ErrorAction Stop
        Add-BooleanResult -Category 'ADDS' -Name 'DCDiscovery' -Passed ($null -ne $dc) -Expected 'Discoverable DC' -Actual ([string]$dc.HostName)
    }
    catch {
        Add-BooleanResult -Category 'ADDS' -Name 'DCDiscovery' -Passed $false -Expected 'Discoverable DC' -Actual $_.Exception.Message
    }

    foreach ($expectedZone in @(
        [pscustomobject]@{ ResultName = 'DomainZone'; Name = [string]$config.Domain.DnsName },
        [pscustomobject]@{ ResultName = 'ForestLocatorZone'; Name = "_msdcs.$([string]$forest.RootDomain)" }
    )) {
        $dnsZone = Get-DnsServerZone -Name $expectedZone.Name -ErrorAction SilentlyContinue
        $dnsZoneName = if ($null -eq $dnsZone) { 'Missing' } else { [string]$dnsZone.ZoneName }
        Add-BooleanResult -Category 'DNS' -Name $expectedZone.ResultName -Passed ($null -ne $dnsZone) -Expected $expectedZone.Name -Actual $dnsZoneName
        if ($null -ne $dnsZone) {
            $configurationPassed = (
                [string]$dnsZone.ZoneType -ieq 'Primary' -and
                [bool]$dnsZone.IsDsIntegrated -and
                [string]$dnsZone.DynamicUpdate -ieq 'Secure'
            )
            $actualConfiguration = "ZoneType=$($dnsZone.ZoneType); IsDsIntegrated=$([bool]$dnsZone.IsDsIntegrated); DynamicUpdate=$($dnsZone.DynamicUpdate)"
            Add-BooleanResult -Category 'DNS' -Name "$($expectedZone.ResultName)Configuration" -Passed $configurationPassed -Expected 'ZoneType=Primary; IsDsIntegrated=True; DynamicUpdate=Secure' -Actual $actualConfiguration
        }
    }
    foreach ($recordName in @("_ldap._tcp.dc._msdcs.$($config.Domain.DnsName)", "_kerberos._tcp.$($config.Domain.DnsName)")) {
        try {
            $records = @(Resolve-DnsName -Name $recordName -Type SRV -ErrorAction Stop)
            Add-BooleanResult -Category 'DNS' -Name "SRV:$recordName" -Passed ($records.Count -gt 0) -Expected 'One or more SRV records' -Actual $records.Count
        }
        catch {
            Add-BooleanResult -Category 'DNS' -Name "SRV:$recordName" -Passed $false -Expected 'One or more SRV records' -Actual $_.Exception.Message
        }
    }

    foreach ($suffix in @($config.Domain.UpnSuffixes)) {
        Add-BooleanResult -Category 'ADDS' -Name "UPNSuffix:$suffix" -Passed (@($forest.UPNSuffixes) -icontains [string]$suffix) -Expected 'Present' -Actual (@($forest.UPNSuffixes) -join ',')
    }

    Write-ValidationProgress -Target 'DirectoryObjects' -Message 'Checking OUs, groups, users, memberships, and computer accounts'
    $domainDn = [string]$domain.DistinguishedName
    $rootOu = [string]$config.Organization.RootOU
    $rootOuDn = Get-LabOuDistinguishedName -RootOU $rootOu -DomainDistinguishedName $domainDn
    Add-BooleanResult -Category 'Objects' -Name "OU:$rootOuDn" -Passed ($null -ne (Get-LabADOrganizationalUnitOrNull -Identity $rootOuDn)) -Expected 'Present' -Actual 'Directory lookup'
    foreach ($ouPath in @($config.OrganizationalUnits | ForEach-Object { ,@($_.Path) })) {
        $dn = Get-LabOuDistinguishedName -RootOU $rootOu -RelativePath @($ouPath) -DomainDistinguishedName $domainDn
        Add-BooleanResult -Category 'Objects' -Name "OU:$dn" -Passed ($null -ne (Get-LabADOrganizationalUnitOrNull -Identity $dn)) -Expected 'Present' -Actual 'Directory lookup'
    }

    foreach ($groupConfig in @($config.Groups)) {
        $group = Get-LabADGroupOrNull -Identity ([string]$groupConfig.Name)
        Add-BooleanResult -Category 'Objects' -Name "Group:$($groupConfig.Name)" -Passed ($null -ne $group) -Expected 'Present' -Actual $(if ($null -eq $group) { 'Missing' } else { $group.DistinguishedName })
    }

    foreach ($userConfig in @($config.Users)) {
        $sam = [string]$userConfig.SamAccountName
        $user = Get-LabADUserOrNull -Identity $sam
        Add-BooleanResult -Category 'Objects' -Name "User:$sam" -Passed ($null -ne $user) -Expected 'Present' -Actual $(if ($null -eq $user) { 'Missing' } else { $user.DistinguishedName })
        if ($null -eq $user) { continue }
        $expectedUpn = if ($userConfig.ContainsKey('UserPrincipalName')) { [string]$userConfig.UserPrincipalName } else { "$sam@$($config.Domain.DnsName)" }
        Add-ExpectedResult -Category 'Objects' -Name "UserUPN:$sam" -Expected $expectedUpn -Actual ([string]$user.UserPrincipalName)
        foreach ($groupName in @($userConfig.Groups) + @($userConfig.BuiltInGroups)) {
            if ([string]::IsNullOrWhiteSpace([string]$groupName)) { continue }
            $group = Get-LabADGroupOrNull -Identity ([string]$groupName)
            $member = $false
            if ($null -ne $group) { $member = @((Get-ADGroupMember -Identity $group -ErrorAction Stop) | Where-Object { [string]$_.SID -eq [string]$user.SID }).Count -gt 0 }
            Add-BooleanResult -Category 'Membership' -Name "$groupName/$sam" -Passed $member -Expected 'Member' -Actual $(if ($member) { 'Member' } else { 'Not member' })
        }
        foreach ($groupName in @($userConfig.AbsentFromBuiltInGroups)) {
            $group = Get-LabADGroupOrNull -Identity ([string]$groupName)
            $member = $false
            if ($null -ne $group) { $member = @((Get-ADGroupMember -Identity $group -ErrorAction Stop) | Where-Object { [string]$_.SID -eq [string]$user.SID }).Count -gt 0 }
            Add-BooleanResult -Category 'Membership' -Name "$groupName/$sam" -Passed (-not $member) -Expected 'Not member' -Actual $(if ($member) { 'Member' } else { 'Not member' })
        }
    }

    foreach ($computerConfig in @($config.Computers)) {
        $computer = Get-LabADComputerOrNull -Identity ([string]$computerConfig.Name)
        Add-BooleanResult -Category 'Objects' -Name "Computer:$($computerConfig.Name)" -Passed ($null -ne $computer) -Expected 'Present' -Actual $(if ($null -eq $computer) { 'Missing' } else { $computer.DistinguishedName })
        if ($null -ne $computer) {
            Add-ExpectedResult -Category 'Objects' -Name "ComputerEnabled:$($computerConfig.Name)" -Expected ([bool]$computerConfig.Enabled) -Actual ([bool]$computer.Enabled)
        }
    }

    Write-ValidationProgress -Target 'FeaturesAndServices' -Message 'Checking Windows features, AD CS, and required services'
    foreach ($featureName in @('AD-Domain-Services', 'DNS')) {
        $feature = Get-WindowsFeature -Name $featureName -ErrorAction Stop
        Add-BooleanResult -Category 'Features' -Name $featureName -Passed ([bool]$feature.Installed) -Expected 'Installed' -Actual ([string]$feature.InstallState)
    }
    $adcsFeature = Get-WindowsFeature -Name 'ADCS-Cert-Authority' -ErrorAction Stop
    $expectAdcs = [bool]$config.ADCS.Install
    Add-BooleanResult -Category 'Features' -Name 'ADCS-Cert-Authority' -Passed ([bool]$adcsFeature.Installed -eq $expectAdcs) -Expected $(if ($expectAdcs) { 'Installed' } else { 'Available' }) -Actual ([string]$adcsFeature.InstallState)
    if ($expectAdcs -and $adcsFeature.Installed) {
        $activeCa = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' -Name Active -ErrorAction Stop).Active
        Add-ExpectedResult -Category 'ADCS' -Name 'CACommonName' -Expected ([string]$config.ADCS.CACommonName) -Actual ([string]$activeCa)
        Add-ExpectedResult -Category 'ADCS' -Name 'CertSvc' -Expected 'Running' -Actual ([string](Get-Service CertSvc -ErrorAction Stop).Status)

        if ($ExpectAdcsHttpCdp) {
            Write-ValidationProgress -Target 'ADCSHttpCdp' -Message 'Checking IIS CertEnroll publication and HTTP CDP/AIA settings'

            $webFeature = Get-WindowsFeature -Name 'Web-Server' -ErrorAction Stop
            Add-BooleanResult -Category 'ADCSHttpCdp' -Name 'Web-Server' -Passed ([bool]$webFeature.Installed) -Expected 'Installed' -Actual ([string]$webFeature.InstallState)

            $staticContentFeature = Get-WindowsFeature -Name 'Web-Static-Content' -ErrorAction Stop
            Add-BooleanResult -Category 'ADCSHttpCdp' -Name 'Web-Static-Content' -Passed ([bool]$staticContentFeature.Installed) -Expected 'Installed' -Actual ([string]$staticContentFeature.InstallState)

            $requestFilteringFeature = Get-WindowsFeature -Name 'Web-Filtering' -ErrorAction Stop
            Add-BooleanResult -Category 'ADCSHttpCdp' -Name 'Web-Filtering' -Passed ([bool]$requestFilteringFeature.Installed) -Expected 'Installed' -Actual ([string]$requestFilteringFeature.InstallState)

            $w3svc = Get-Service W3SVC -ErrorAction Stop
            Add-ExpectedResult -Category 'ADCSHttpCdp' -Name 'W3SVC' -Expected 'Running' -Actual ([string]$w3svc.Status)

            $caRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$activeCa"
            $caRegistry = Get-ItemProperty -Path $caRegistryPath -Name CRLPublicationURLs, CACertPublicationURLs -ErrorAction Stop
            $httpCdp = Test-CaPublicationUrlFlag -Entries $caRegistry.CRLPublicationURLs -Url 'http://%1/CertEnroll/%3%8%9.crl' -RequiredFlags 0x00000002
            Add-BooleanResult -Category 'ADCSHttpCdp' -Name 'HTTP CDP in issued certificates' -Passed ([bool]$httpCdp.Passed) -Expected 'http://%1/CertEnroll/%3%8%9.crl with ADDTOCERTCDP' -Actual ([string]$httpCdp.Actual)

            $httpAia = Test-CaPublicationUrlFlag -Entries $caRegistry.CACertPublicationURLs -Url 'http://%1/CertEnroll/%1_%3%4.crt' -RequiredFlags 0x00000002
            Add-BooleanResult -Category 'ADCSHttpCdp' -Name 'HTTP AIA in issued certificates' -Passed ([bool]$httpAia.Passed) -Expected 'http://%1/CertEnroll/%1_%3%4.crt with ADDTOCERTCDP' -Actual ([string]$httpAia.Actual)

            $certEnrollPath = Join-Path $env:windir 'System32\CertSrv\CertEnroll'
            Add-BooleanResult -Category 'ADCSHttpCdp' -Name 'CertEnroll directory' -Passed (Test-Path -LiteralPath $certEnrollPath -PathType Container) -Expected 'Present' -Actual $certEnrollPath

            $webConfigPath = Join-Path $certEnrollPath 'web.config'
            $allowDoubleEscaping = $false
            $allowDoubleEscapingActual = 'Missing'
            if (Test-Path -LiteralPath $webConfigPath -PathType Leaf) {
                try {
                    [xml]$webConfig = Get-Content -LiteralPath $webConfigPath -Raw -ErrorAction Stop
                    $requestFiltering = $webConfig.SelectSingleNode('/configuration/system.webServer/security/requestFiltering')
                    if ($null -ne $requestFiltering -and $null -ne $requestFiltering.Attributes['allowDoubleEscaping']) {
                        $allowDoubleEscapingActual = [string]$requestFiltering.Attributes['allowDoubleEscaping'].Value
                        $allowDoubleEscaping = ($allowDoubleEscapingActual -ieq 'true')
                    }
                }
                catch {
                    $allowDoubleEscapingActual = $_.Exception.Message
                }
            }
            Add-BooleanResult -Category 'ADCSHttpCdp' -Name 'IIS encoded plus handling' -Passed $allowDoubleEscaping -Expected 'requestFiltering allowDoubleEscaping=true' -Actual $allowDoubleEscapingActual

            $crlFile = @(Get-ChildItem -LiteralPath $certEnrollPath -Filter '*.crl' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
            Add-BooleanResult -Category 'ADCSHttpCdp' -Name 'Published CRL file' -Passed ($crlFile.Count -eq 1) -Expected 'At least one .crl file' -Actual $(if ($crlFile.Count -eq 0) { 'Missing' } else { $crlFile[0].FullName })

            $caCertFile = @(Get-ChildItem -LiteralPath $certEnrollPath -Filter '*.crt' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
            Add-BooleanResult -Category 'ADCSHttpCdp' -Name 'Published CA certificate file' -Passed ($caCertFile.Count -eq 1) -Expected 'At least one .crt file' -Actual $(if ($caCertFile.Count -eq 0) { 'Missing' } else { $caCertFile[0].FullName })

            $fqdn = "$($env:COMPUTERNAME).$($domain.DNSRoot)"
            if ($crlFile.Count -eq 1) {
                $crlUrl = "http://$fqdn/CertEnroll/$([Uri]::EscapeDataString($crlFile[0].Name))"
                $download = Test-HttpDownload -Url $crlUrl
                Add-BooleanResult -Category 'ADCSHttpCdp' -Name 'HTTP CRL download' -Passed ([bool]$download.Passed) -Expected 'Download succeeds' -Actual ([string]$download.Actual)
            }
            else {
                $results.Add((New-LabValidationResult -Category 'ADCSHttpCdp' -Name 'HTTP CRL download' -Status Skipped -Expected 'Published CRL file' -Actual 'No CRL file'))
            }

            if ($caCertFile.Count -eq 1) {
                $caCertUrl = "http://$fqdn/CertEnroll/$([Uri]::EscapeDataString($caCertFile[0].Name))"
                $download = Test-HttpDownload -Url $caCertUrl
                Add-BooleanResult -Category 'ADCSHttpCdp' -Name 'HTTP CA certificate download' -Passed ([bool]$download.Passed) -Expected 'Download succeeds' -Actual ([string]$download.Actual)
            }
            else {
                $results.Add((New-LabValidationResult -Category 'ADCSHttpCdp' -Name 'HTTP CA certificate download' -Status Skipped -Expected 'Published CA certificate file' -Actual 'No CA certificate file'))
            }
        }
    }

    Add-ExpectedResult -Category 'Services' -Name 'W32Time' -Expected 'Running' -Actual ([string](Get-Service W32Time -ErrorAction Stop).Status)
    Add-ExpectedResult -Category 'Services' -Name 'WinRM' -Expected 'Running' -Actual ([string](Get-Service WinRM -ErrorAction Stop).Status)
    $adws = Get-Service ADWS -ErrorAction Stop
    Add-ExpectedResult -Category 'Services' -Name 'ADWS' -Expected 'Running' -Actual ([string]$adws.Status)
    Add-ExpectedResult -Category 'Services' -Name 'ADWSStartType' -Expected 'Automatic' -Actual ([string]$adws.StartType)
    $winRmRules = @(Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' -ErrorAction SilentlyContinue | Where-Object Enabled -eq 'True')
    Add-BooleanResult -Category 'Services' -Name 'WinRMFirewall' -Passed ($winRmRules.Count -gt 0) -Expected 'At least one enabled inbound WinRM rule' -Actual $winRmRules.Count
    try {
        Test-WSMan -ComputerName localhost -ErrorAction Stop | Out-Null
        Add-BooleanResult -Category 'Services' -Name 'WinRMListener' -Passed $true -Expected 'Responding' -Actual 'Responding'
    }
    catch {
        Add-BooleanResult -Category 'Services' -Name 'WinRMListener' -Passed $false -Expected 'Responding' -Actual $_.Exception.Message
    }

    Write-ValidationProgress -Target 'AuditingAndEvents' -Message 'Checking audit policy and Security event log access'
    $processAuditPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    $commandLineValue = 0
    $commandLineConfiguration = Get-ItemProperty -Path $processAuditPath -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue
    if ($null -ne $commandLineConfiguration) { $commandLineValue = [int]$commandLineConfiguration.ProcessCreationIncludeCmdLine_Enabled }
    Add-ExpectedResult -Category 'Audit' -Name 'ProcessCommandLine' -Expected 1 -Actual ([int]$commandLineValue)
    $hasCa = $null -ne (Get-Service -Name CertSvc -ErrorAction SilentlyContinue)
    foreach ($subcategory in @($config.Audit.Subcategories)) {
        if ([bool]$subcategory.RequiresADCS -and -not $hasCa) {
            $results.Add((New-LabValidationResult -Category 'Audit' -Name ([string]$subcategory.Name) -Status Skipped -Expected 'AD CS installed' -Actual 'AD CS absent'))
            continue
        }
        $actualPolicy = Get-LabAuditPolicyValue -SubcategoryGuid ([guid]$subcategory.Guid)
        $passed = $actualPolicy.Success -eq [bool]$subcategory.Success -and $actualPolicy.Failure -eq [bool]$subcategory.Failure
        Add-BooleanResult -Category 'Audit' -Name ([string]$subcategory.Name) -Passed $passed -Expected "Success=$([bool]$subcategory.Success);Failure=$([bool]$subcategory.Failure)" -Actual "Success=$($actualPolicy.Success);Failure=$($actualPolicy.Failure)"
    }

    try {
        $securityLog = Get-WinEvent -ListLog Security -ErrorAction Stop
        Add-BooleanResult -Category 'Events' -Name 'SecurityLog' -Passed ($securityLog.IsEnabled) -Expected 'Enabled and readable' -Actual "Enabled=$($securityLog.IsEnabled);Records=$($securityLog.RecordCount)"
    }
    catch {
        Add-BooleanResult -Category 'Events' -Name 'SecurityLog' -Passed $false -Expected 'Enabled and readable' -Actual $_.Exception.Message
    }

    $results.Add((New-LabValidationResult -Category 'ADDS' -Name 'Test-ComputerSecureChannel' -Status Skipped -Expected 'Not used on a DC' -Actual 'Skipped' -Message 'DC health is checked with DC discovery and dcdiag instead.'))

    if (-not $SkipDcDiag) {
        Write-ValidationProgress -Target 'DCDiag' -Message 'Running Advertising and DNS diagnostics; this may take several minutes'
        $dcdiagTimer = [System.Diagnostics.Stopwatch]::StartNew()
        $dcdiagOutput = & dcdiag.exe /test:Advertising /test:DNS 2>&1
        $dcdiagExit = $LASTEXITCODE
        $dcdiagTimer.Stop()
        Add-BooleanResult -Category 'ADDS' -Name 'DCDiag' -Passed ($dcdiagExit -eq 0) -Expected 'ExitCode=0' -Actual "ExitCode=$dcdiagExit" -Message (($dcdiagOutput | Select-Object -Last 10) -join [Environment]::NewLine)
        Write-ValidationProgress -Target 'DCDiag' -Message "Completed; ExitCode=$dcdiagExit; DurationSeconds=$([math]::Round($dcdiagTimer.Elapsed.TotalSeconds, 1))"
    }
    else {
        $results.Add((New-LabValidationResult -Category 'ADDS' -Name 'DCDiag' -Status Skipped -Expected 'ExitCode=0' -Actual 'Skipped by parameter'))
        Write-ValidationProgress -Target 'DCDiag' -Message 'Skipped by -SkipDcDiag'
    }

    Write-ValidationProgress -Target 'Results' -Message 'Exporting validation results to JSON'
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Join-Path $env:ProgramData "ADLabBootstrap\Logs\$(Get-Date -Format 'yyyyMMdd-HHmmss')-validation.json"
    }
    $validationResults = $results.ToArray()
    $summary = Export-LabValidationResults -Results $validationResults -Path $OutputPath
    Write-LabLog -Phase $phase -Action 'ExportJSON' -Status Changed -Target $summary.Path -Message "Passed=$($summary.Passed); Failed=$($summary.Failed); Skipped=$($summary.Skipped)"
    $failedResults = @($validationResults | Where-Object Status -eq 'Failed')
    $failedNames = @($failedResults | ForEach-Object { "$($_.Category)/$($_.Name)" })
    if ($failedResults.Count -gt 0) {
        $failedPreview = @($failedNames | Select-Object -First 10)
        $moreCount = [Math]::Max(0, $failedNames.Count - $failedPreview.Count)
        $moreMessage = if ($moreCount -gt 0) { "; More=$moreCount" } else { '' }
        Write-LabLog -Phase $phase -Action 'FailedChecks' -Status Failed -Target 'Validation' -Message "Count=$($failedResults.Count); Checks=$($failedPreview -join '; ')$moreMessage; JSON=$OutputPath"
        foreach ($failedResult in $failedResults) {
            $failedTarget = "$($failedResult.Category)/$($failedResult.Name)"
            $expectedText = ConvertTo-ValidationLogValue -Value $failedResult.Expected
            $actualText = ConvertTo-ValidationLogValue -Value $failedResult.Actual
            $messageText = ConvertTo-ValidationLogValue -Value $failedResult.Message
            $failedDetail = "Expected=$expectedText; Actual=$actualText; Message=$messageText"
            Write-LabLog -Phase $phase -Action 'FailedCheck' -Status Failed -Target $failedTarget -Message $failedDetail
        }
    }
}
catch {
    Write-LabLog -Phase $phase -Action 'Validate' -Status Failed -Target $env:COMPUTERNAME -Message $_.Exception.Message
    throw
}
finally {
    Stop-LabTranscript
}

$validationResults
$failedMessage = if ($failedNames.Count -eq 0) { '' } else { "; FailedChecks=$($failedNames -join '; ')" }
if ($FailOnValidationError -and $summary.Failed -gt 0) {
    throw "$($summary.Failed) validation check(s) failed: $($failedNames -join '; '). See '$OutputPath'."
}
New-LabPhaseResult -Phase $phase -Status Succeeded -Changed $false -Message "JSON=$OutputPath; Passed=$($summary.Passed); Failed=$($summary.Failed); Skipped=$($summary.Skipped)$failedMessage"
