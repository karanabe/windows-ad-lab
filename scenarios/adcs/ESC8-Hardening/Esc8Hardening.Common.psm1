Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Esc8ScenarioName = 'ESC8-Hardening'
$script:Esc8SiteName = 'Default Web Site'
$script:Esc8CertSrvLocation = "$script:Esc8SiteName/CertSrv"
$script:Esc8HttpsPort = 443
$script:Esc8CertFriendlyName = 'windows-ad-lab ESC8 Hardening HTTPS'
$script:Esc8StateRoot = Join-Path $env:ProgramData "ADLabBootstrap\Scenarios\$script:Esc8ScenarioName"
$script:Esc8StatePath = Join-Path $script:Esc8StateRoot 'state.json'
$script:Esc8KerberosOnlyProvider = 'Negotiate:Kerberos'

function Get-Esc8ScenarioName {
    return $script:Esc8ScenarioName
}

function Get-Esc8StateRoot {
    return $script:Esc8StateRoot
}

function Get-Esc8StatePath {
    return $script:Esc8StatePath
}

function Get-Esc8CertSrvIisPath {
    return "IIS:\Sites\$script:Esc8SiteName\CertSrv"
}

function Import-Esc8IisAdministration {
    Import-Module WebAdministration -ErrorAction Stop
    if ($null -eq ('Microsoft.Web.Administration.ServerManager' -as [type])) {
        $assemblyPath = Join-Path $env:windir 'System32\inetsrv\Microsoft.Web.Administration.dll'
        if (-not (Test-Path -LiteralPath $assemblyPath -PathType Leaf)) {
            throw "Microsoft.Web.Administration.dll was not found at '$assemblyPath'. Install the IIS management scripting tools before configuring Web Enrollment."
        }
        Add-Type -Path $assemblyPath -ErrorAction Stop
    }
    if ($null -eq ('Microsoft.Web.Administration.ServerManager' -as [type])) {
        throw 'Microsoft.Web.Administration.ServerManager is unavailable after loading the IIS administration assembly.'
    }
}

function ConvertTo-Esc8Boolean {
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return $null }
    $valueObject = $Value.PSObject.BaseObject
    if ($valueObject -is [bool]) { return [bool]$valueObject }
    return ([string]$valueObject -ieq 'true')
}

function ConvertTo-Esc8ThumbprintString {
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return '' }
    $valueObject = $Value.PSObject.BaseObject
    if ($valueObject -is [byte[]]) {
        return (($valueObject | ForEach-Object { $_.ToString('X2') }) -join '')
    }
    return (([string]$valueObject) -replace '\s', '').ToUpperInvariant()
}

function ConvertTo-Esc8StringArray {
    param([AllowNull()]$Value)

    $values = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Value) { return $values.ToArray() }
    $valueObject = $Value.PSObject.BaseObject
    if ($valueObject -is [string]) {
        if (-not [string]::IsNullOrWhiteSpace($valueObject)) {
            [void]$values.Add([string]$valueObject)
        }
        return $values.ToArray()
    }
    if ($valueObject -is [System.Collections.IEnumerable]) {
        foreach ($item in $valueObject) {
            if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace([string]$item)) {
                [void]$values.Add([string]$item)
            }
        }
        return $values.ToArray()
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$valueObject)) {
        [void]$values.Add([string]$valueObject)
    }
    return $values.ToArray()
}

function Normalize-Esc8TokenChecking {
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return '' }
    switch -Regex ([string]$Value) {
        '^(0|None)$' { return 'None' }
        '^(1|Allow)$' { return 'Allow' }
        '^(2|Require)$' { return 'Require' }
        default { return [string]$Value }
    }
}

function Test-Esc8SslRequired {
    param([AllowNull()][string]$SslFlags)

    if ([string]::IsNullOrWhiteSpace($SslFlags)) { return $false }
    foreach ($flag in @($SslFlags -split ',')) {
        if ($flag.Trim() -ieq 'Ssl') { return $true }
    }
    return $false
}

function Test-Esc8StringArrayEqual {
    param(
        [AllowNull()][string[]]$Actual,
        [AllowNull()][string[]]$Expected
    )

    $actualValues = @(ConvertTo-Esc8StringArray -Value $Actual | ForEach-Object { [string]$_ })
    $expectedValues = @(ConvertTo-Esc8StringArray -Value $Expected | ForEach-Object { [string]$_ })
    if ($actualValues.Count -ne $expectedValues.Count) { return $false }
    for ($index = 0; $index -lt $expectedValues.Count; $index++) {
        if ([string]$actualValues[$index] -ine [string]$expectedValues[$index]) {
            return $false
        }
    }
    return $true
}

function Get-Esc8AccessSslFlags {
    Import-Esc8IisAdministration
    $property = Get-WebConfigurationProperty `
        -Filter '/system.webServer/security/access' `
        -PSPath 'IIS:\' `
        -Location $script:Esc8CertSrvLocation `
        -Name 'sslFlags' `
        -ErrorAction Stop
    $valueProperty = $property.PSObject.Properties['Value']
    if ($null -ne $valueProperty) {
        return [string]$valueProperty.Value
    }
    return [string]$property
}

function Get-Esc8PropertyValue {
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()]$Default = $null
    )

    if ($null -eq $InputObject) { return $Default }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
}

function Get-Esc8ActiveCaName {
    $caRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
    $active = (Get-ItemProperty -Path $caRoot -Name Active -ErrorAction Stop).Active
    if ([string]::IsNullOrWhiteSpace([string]$active)) {
        throw 'No active local Certification Authority was found.'
    }
    return [string]$active
}

function Get-Esc8HttpsBinding {
    try {
        Import-Esc8IisAdministration
    }
    catch {
        return [pscustomobject]@{
            Exists             = $false
            BindingInformation = ''
            CertificateHash    = ''
            CertificateStore   = ''
        }
    }

    $bindings = @(Get-WebBinding -Name $script:Esc8SiteName -Protocol 'https' -ErrorAction SilentlyContinue | Where-Object {
        $parts = ([string]$_.bindingInformation).Split(':')
        $parts.Count -ge 2 -and [string]$parts[1] -eq [string]$script:Esc8HttpsPort
    } | Sort-Object bindingInformation)
    if ($bindings.Count -eq 0) {
        return [pscustomobject]@{
            Exists             = $false
            BindingInformation = ''
            CertificateHash    = ''
            CertificateStore   = ''
        }
    }

    $binding = $bindings[0]
    $certificateStore = [string]$binding.certificateStoreName
    if ([string]::IsNullOrWhiteSpace($certificateStore)) {
        $certificateStore = 'My'
    }
    return [pscustomobject]@{
        Exists             = $true
        BindingInformation = [string]$binding.bindingInformation
        CertificateHash    = ConvertTo-Esc8ThumbprintString -Value $binding.certificateHash
        CertificateStore   = $certificateStore
    }
}

function Get-Esc8WebEnrollmentState {
    $featureInstalled = $false
    $featureState = 'Unknown'
    $feature = Get-WindowsFeature -Name 'ADCS-Web-Enrollment' -ErrorAction SilentlyContinue
    if ($null -ne $feature) {
        $featureInstalled = [bool]$feature.Installed
        $featureState = [string]$feature.InstallState
    }

    $w3svc = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
    $w3svcStatus = if ($null -eq $w3svc) { 'Missing' } else { [string]$w3svc.Status }
    $w3svcStartType = if ($null -eq $w3svc) { 'Missing' } else { [string]$w3svc.StartType }
    $httpsBinding = Get-Esc8HttpsBinding
    $certSrvExists = $false
    $windowsAuthEnabled = $null
    $anonymousAuthEnabled = $null
    $tokenChecking = ''
    $epaFlags = ''
    $providers = New-Object System.Collections.Generic.List[string]
    $sslFlags = ''
    $iisAvailable = $true
    $iisError = ''

    try {
        Import-Esc8IisAdministration
        $certSrvExists = Test-Path -LiteralPath (Get-Esc8CertSrvIisPath)
        if ($certSrvExists) {
            $manager = New-Object Microsoft.Web.Administration.ServerManager
            try {
                $configuration = $manager.GetApplicationHostConfiguration()
                $windowsSection = $configuration.GetSection('system.webServer/security/authentication/windowsAuthentication', $script:Esc8CertSrvLocation)
                $anonymousSection = $configuration.GetSection('system.webServer/security/authentication/anonymousAuthentication', $script:Esc8CertSrvLocation)
                $windowsAuthEnabled = ConvertTo-Esc8Boolean -Value $windowsSection['enabled']
                $anonymousAuthEnabled = ConvertTo-Esc8Boolean -Value $anonymousSection['enabled']
                $sslFlags = Get-Esc8AccessSslFlags
                $extendedProtection = $windowsSection.GetChildElement('extendedProtection')
                if ($null -ne $extendedProtection) {
                    $tokenChecking = Normalize-Esc8TokenChecking -Value $extendedProtection['tokenChecking']
                    $epaFlags = [string]$extendedProtection['flags']
                }
                $providerCollection = $windowsSection.GetCollection('providers')
                foreach ($provider in $providerCollection) {
                    [void]$providers.Add([string]$provider['value'])
                }
            }
            finally {
                $manager.Dispose()
            }
        }
    }
    catch {
        $iisAvailable = $false
        $iisError = $_.Exception.Message
    }

    $providerValues = [string[]]$providers.ToArray()
    $sslRequired = Test-Esc8SslRequired -SslFlags $sslFlags
    $ntlmProviderPresent = (@($providerValues | Where-Object { [string]$_ -ieq 'NTLM' }).Count -gt 0)
    $kerberosOnly = ($providerValues.Count -eq 1 -and [string]$providerValues[0] -ieq $script:Esc8KerberosOnlyProvider)
    $epaRequired = ([string]$tokenChecking -ieq 'Require')
    $webEnrollmentReady = ($featureInstalled -and $certSrvExists)
    $httpAllowed = ($certSrvExists -and -not $sslRequired)
    $httpsReady = ([bool]$httpsBinding.Exists -and -not [string]::IsNullOrWhiteSpace([string]$httpsBinding.CertificateHash))
    $relayPrerequisitesPresent = (
        $webEnrollmentReady -and
        $windowsAuthEnabled -eq $true -and
        $httpAllowed -and
        $ntlmProviderPresent -and
        -not $epaRequired
    )
    $hardened = (
        $webEnrollmentReady -and
        $windowsAuthEnabled -eq $true -and
        $anonymousAuthEnabled -eq $false -and
        $sslRequired -and
        $httpsReady -and
        $epaRequired -and
        $kerberosOnly
    )

    return [pscustomobject]@{
        FeatureInstalled          = $featureInstalled
        FeatureState              = $featureState
        CertSrvExists             = $certSrvExists
        IisAvailable              = $iisAvailable
        IisError                  = $iisError
        W3SvcStatus               = $w3svcStatus
        W3SvcStartType            = $w3svcStartType
        WindowsAuthentication     = $windowsAuthEnabled
        AnonymousAuthentication   = $anonymousAuthEnabled
        SslFlags                  = $sslFlags
        SslRequired               = $sslRequired
        TokenChecking             = $tokenChecking
        EpaFlags                  = $epaFlags
        EpaRequired               = $epaRequired
        Providers                 = $providerValues
        NtlmProviderPresent       = $ntlmProviderPresent
        KerberosOnlyProvider      = $kerberosOnly
        HttpsBindingExists        = [bool]$httpsBinding.Exists
        HttpsBindingInformation   = [string]$httpsBinding.BindingInformation
        HttpsBindingCertificate   = [string]$httpsBinding.CertificateHash
        HttpsBindingStore         = [string]$httpsBinding.CertificateStore
        HttpsReady                = $httpsReady
        HttpAllowed               = $httpAllowed
        RelayPrerequisitesPresent = $relayPrerequisitesPresent
        Hardened                  = $hardened
    }
}

function Read-Esc8ScenarioState {
    if (-not (Test-Path -LiteralPath $script:Esc8StatePath -PathType Leaf)) {
        return $null
    }
    return (Get-Content -LiteralPath $script:Esc8StatePath -Raw -ErrorAction Stop | ConvertFrom-Json)
}

function Save-Esc8ScenarioState {
    param([Parameter(Mandatory = $true)]$State)

    if (-not (Test-Path -LiteralPath $script:Esc8StateRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $script:Esc8StateRoot -Force -ErrorAction Stop | Out-Null
    }
    $State | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:Esc8StatePath -Encoding UTF8 -ErrorAction Stop
}

function Initialize-Esc8ScenarioState {
    $existing = Read-Esc8ScenarioState
    if ($null -ne $existing) {
        return $existing
    }

    $current = Get-Esc8WebEnrollmentState
    $state = [ordered]@{
        SchemaVersion                         = 1
        ScenarioName                          = $script:Esc8ScenarioName
        CreatedAt                             = (Get-Date).ToString('o')
        UpdatedAt                             = (Get-Date).ToString('o')
        LastStage                             = ''
        WebEnrollmentFeatureInstalledBefore   = [bool]$current.FeatureInstalled
        CertSrvExistsBefore                   = [bool]$current.CertSrvExists
        WindowsAuthenticationEnabledBefore    = $current.WindowsAuthentication
        AnonymousAuthenticationEnabledBefore  = $current.AnonymousAuthentication
        SslFlagsBefore                        = [string]$current.SslFlags
        TokenCheckingBefore                   = [string]$current.TokenChecking
        ProvidersBefore                       = [string[]]@($current.Providers)
        HttpsBindingExistedBefore             = [bool]$current.HttpsBindingExists
        HttpsBindingInformationBefore         = [string]$current.HttpsBindingInformation
        HttpsBindingCertificateHashBefore     = [string]$current.HttpsBindingCertificate
        HttpsBindingCertificateStoreBefore    = [string]$current.HttpsBindingStore
        ScenarioCertificateThumbprint         = ''
    }
    Save-Esc8ScenarioState -State $state
    return (Read-Esc8ScenarioState)
}

function Update-Esc8ScenarioState {
    param(
        [Parameter(Mandatory = $true)]$State,
        [string]$LastStage,
        [string]$ScenarioCertificateThumbprint
    )

    $State | Add-Member -MemberType NoteProperty -Name UpdatedAt -Value (Get-Date).ToString('o') -Force
    if (-not [string]::IsNullOrWhiteSpace($LastStage)) {
        $State | Add-Member -MemberType NoteProperty -Name LastStage -Value $LastStage -Force
    }
    if (-not [string]::IsNullOrWhiteSpace($ScenarioCertificateThumbprint)) {
        $State | Add-Member -MemberType NoteProperty -Name ScenarioCertificateThumbprint -Value $ScenarioCertificateThumbprint -Force
    }
    Save-Esc8ScenarioState -State $State
    return (Read-Esc8ScenarioState)
}

function Ensure-Esc8ServiceRunning {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Name)

    $changed = $false
    $service = Get-Service -Name $Name -ErrorAction Stop
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
    return $changed
}

function Ensure-Esc8WebEnrollmentInstalled {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$CAConfig)

    Import-Module ServerManager -ErrorAction Stop
    $changed = $false
    $feature = Get-WindowsFeature -Name 'ADCS-Web-Enrollment' -ErrorAction Stop
    if (-not [bool]$feature.Installed) {
        if ($PSCmdlet.ShouldProcess('ADCS-Web-Enrollment', 'Install AD CS Web Enrollment role service')) {
            Install-WindowsFeature -Name 'ADCS-Web-Enrollment' -IncludeManagementTools -ErrorAction Stop | Out-Null
            $changed = $true
        }
    }

    Import-Module ADCSDeployment -ErrorAction Stop
    Import-Esc8IisAdministration
    if (-not (Test-Path -LiteralPath (Get-Esc8CertSrvIisPath))) {
        if ($PSCmdlet.ShouldProcess($CAConfig, 'Configure AD CS Web Enrollment for local CA')) {
            Install-AdcsWebEnrollment -Force -ErrorAction Stop | Out-Null
            $changed = $true
        }
    }

    return $changed
}

function Ensure-Esc8HttpsFirewallRule {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    $rules = @(Get-NetFirewallRule -Name 'IIS-WebServerRole-HTTPS-In-TCP' -ErrorAction SilentlyContinue)
    $changed = $false
    foreach ($rule in $rules) {
        if ([string]$rule.Enabled -ne 'True') {
            if ($PSCmdlet.ShouldProcess($rule.Name, 'Enable IIS HTTPS inbound firewall rule')) {
                Enable-NetFirewallRule -Name $rule.Name -ErrorAction Stop
                $changed = $true
            }
        }
    }
    return $changed
}

function Get-Esc8ScenarioCertificate {
    $certificates = @(Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {
        [string]$_.FriendlyName -eq $script:Esc8CertFriendlyName -and $_.NotAfter -gt (Get-Date)
    } | Sort-Object NotAfter -Descending)
    if ($certificates.Count -eq 0) { return $null }
    return $certificates[0]
}

function New-Esc8ScenarioCertificate {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$DomainDnsName)

    $certificate = Get-Esc8ScenarioCertificate
    if ($null -ne $certificate) { return $certificate }

    $dnsNames = New-Object System.Collections.Generic.List[string]
    [void]$dnsNames.Add($env:COMPUTERNAME)
    if (-not [string]::IsNullOrWhiteSpace($DomainDnsName)) {
        [void]$dnsNames.Add("$($env:COMPUTERNAME).$DomainDnsName")
    }

    if ($PSCmdlet.ShouldProcess('Cert:\LocalMachine\My', 'Create scenario HTTPS certificate')) {
        return New-SelfSignedCertificate `
            -DnsName ([string[]]$dnsNames.ToArray()) `
            -CertStoreLocation 'Cert:\LocalMachine\My' `
            -FriendlyName $script:Esc8CertFriendlyName `
            -KeyAlgorithm RSA `
            -KeyLength 2048 `
            -HashAlgorithm SHA256 `
            -NotAfter (Get-Date).AddYears(2) `
            -ErrorAction Stop
    }
    return $null
}

function Ensure-Esc8HttpsBinding {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$DomainDnsName)

    Import-Esc8IisAdministration
    $changed = $false
    $scenarioThumbprint = ''
    $binding = Get-Esc8HttpsBinding
    if ([bool]$binding.Exists -and -not [string]::IsNullOrWhiteSpace([string]$binding.CertificateHash)) {
        return [pscustomobject]@{
            Changed                       = $false
            ScenarioCertificateThumbprint = ''
            BindingCertificateThumbprint  = [string]$binding.CertificateHash
        }
    }

    $certificate = New-Esc8ScenarioCertificate -DomainDnsName $DomainDnsName
    if ($null -ne $certificate) {
        $scenarioThumbprint = [string]$certificate.Thumbprint
    }

    if (-not [bool]$binding.Exists) {
        if ($PSCmdlet.ShouldProcess("$script:Esc8SiteName HTTPS $script:Esc8HttpsPort", 'Create IIS HTTPS binding')) {
            New-WebBinding -Name $script:Esc8SiteName -Protocol 'https' -Port $script:Esc8HttpsPort -IPAddress '*' -ErrorAction Stop | Out-Null
            $changed = $true
        }
        $binding = Get-Esc8HttpsBinding
    }

    if ($null -ne $certificate -and [bool]$binding.Exists) {
        $currentHash = ConvertTo-Esc8ThumbprintString -Value $binding.CertificateHash
        if ($currentHash -ine [string]$certificate.Thumbprint) {
            $webBinding = @(Get-WebBinding -Name $script:Esc8SiteName -Protocol 'https' -ErrorAction Stop | Where-Object {
                [string]$_.bindingInformation -eq [string]$binding.BindingInformation
            })[0]
            if ($PSCmdlet.ShouldProcess($binding.BindingInformation, "Bind HTTPS certificate $($certificate.Thumbprint)")) {
                [void]$webBinding.AddSslCertificate($certificate.Thumbprint, 'My')
                $changed = $true
            }
        }
    }

    $finalBinding = Get-Esc8HttpsBinding
    return [pscustomobject]@{
        Changed                       = $changed
        ScenarioCertificateThumbprint = $scenarioThumbprint
        BindingCertificateThumbprint  = [string]$finalBinding.CertificateHash
    }
}

function Set-Esc8IisSecurityState {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][bool]$RequireSsl,
        [Parameter(Mandatory = $true)][ValidateSet('None', 'Allow', 'Require')][string]$TokenChecking,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Providers,
        [bool]$WindowsAuthenticationEnabled = $true,
        [bool]$AnonymousAuthenticationEnabled = $false
    )

    Import-Esc8IisAdministration
    if (-not (Test-Path -LiteralPath (Get-Esc8CertSrvIisPath))) {
        throw "AD CS Web Enrollment IIS application was not found: $script:Esc8CertSrvLocation"
    }

    $desiredSslFlags = if ($RequireSsl) { 'Ssl' } else { 'None' }
    $current = Get-Esc8WebEnrollmentState
    $requiresChange = (
        [bool]$current.SslRequired -ne $RequireSsl -or
        [string]$current.TokenChecking -ine $TokenChecking -or
        -not (Test-Esc8StringArrayEqual -Actual ([string[]]$current.Providers) -Expected ([string[]]$Providers)) -or
        $current.WindowsAuthentication -ne $WindowsAuthenticationEnabled -or
        $current.AnonymousAuthentication -ne $AnonymousAuthenticationEnabled
    )
    if (-not $requiresChange) { return $false }

    if ($PSCmdlet.ShouldProcess($script:Esc8CertSrvLocation, 'Configure IIS SSL, EPA, and Windows authentication providers')) {
        Set-WebConfigurationProperty `
            -Filter '/system.webServer/security/access' `
            -PSPath 'IIS:\' `
            -Location $script:Esc8CertSrvLocation `
            -Name 'sslFlags' `
            -Value $desiredSslFlags `
            -ErrorAction Stop | Out-Null

        $manager = New-Object Microsoft.Web.Administration.ServerManager
        try {
            $configuration = $manager.GetApplicationHostConfiguration()
            $windowsSection = $configuration.GetSection('system.webServer/security/authentication/windowsAuthentication', $script:Esc8CertSrvLocation)
            $anonymousSection = $configuration.GetSection('system.webServer/security/authentication/anonymousAuthentication', $script:Esc8CertSrvLocation)

            $windowsSection['enabled'] = $WindowsAuthenticationEnabled
            $anonymousSection['enabled'] = $AnonymousAuthenticationEnabled

            $extendedProtection = $windowsSection.GetChildElement('extendedProtection')
            $extendedProtection['tokenChecking'] = $TokenChecking
            $extendedProtection['flags'] = 'None'

            $providerCollection = $windowsSection.GetCollection('providers')
            $existingProviders = New-Object System.Collections.Generic.List[object]
            foreach ($provider in $providerCollection) {
                [void]$existingProviders.Add($provider)
            }
            foreach ($provider in $existingProviders.ToArray()) {
                [void]$providerCollection.Remove($provider)
            }
            foreach ($providerName in @($Providers)) {
                $newProvider = $providerCollection.CreateElement('add')
                $newProvider['value'] = [string]$providerName
                [void]$providerCollection.Add($newProvider)
            }

            [void]$manager.CommitChanges()
        }
        finally {
            $manager.Dispose()
        }
    }

    return $true
}

function Restore-Esc8IisSecurityState {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$State)

    $providers = @(ConvertTo-Esc8StringArray -Value (Get-Esc8PropertyValue -InputObject $State -Name 'ProvidersBefore'))
    if ($providers.Count -eq 0) {
        $providers = @('Negotiate', 'NTLM')
    }
    $tokenChecking = Normalize-Esc8TokenChecking -Value (Get-Esc8PropertyValue -InputObject $State -Name 'TokenCheckingBefore' -Default 'None')
    if (@('None', 'Allow', 'Require') -notcontains $tokenChecking) {
        $tokenChecking = 'None'
    }
    $sslFlags = [string](Get-Esc8PropertyValue -InputObject $State -Name 'SslFlagsBefore' -Default 'None')
    $windowsAuthentication = ConvertTo-Esc8Boolean -Value (Get-Esc8PropertyValue -InputObject $State -Name 'WindowsAuthenticationEnabledBefore' -Default $true)
    $anonymousAuthentication = ConvertTo-Esc8Boolean -Value (Get-Esc8PropertyValue -InputObject $State -Name 'AnonymousAuthenticationEnabledBefore' -Default $false)

    return Set-Esc8IisSecurityState `
        -RequireSsl (Test-Esc8SslRequired -SslFlags $sslFlags) `
        -TokenChecking $tokenChecking `
        -Providers ([string[]]$providers) `
        -WindowsAuthenticationEnabled ([bool]$windowsAuthentication) `
        -AnonymousAuthenticationEnabled ([bool]$anonymousAuthentication)
}

function Restore-Esc8HttpsBinding {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$State)

    Import-Esc8IisAdministration
    $changed = $false
    $existedBefore = [bool](Get-Esc8PropertyValue -InputObject $State -Name 'HttpsBindingExistedBefore' -Default $false)
    $beforeHash = ConvertTo-Esc8ThumbprintString -Value (Get-Esc8PropertyValue -InputObject $State -Name 'HttpsBindingCertificateHashBefore' -Default '')
    $beforeStore = [string](Get-Esc8PropertyValue -InputObject $State -Name 'HttpsBindingCertificateStoreBefore' -Default 'My')
    if ([string]::IsNullOrWhiteSpace($beforeStore)) { $beforeStore = 'My' }
    $scenarioThumbprint = ConvertTo-Esc8ThumbprintString -Value (Get-Esc8PropertyValue -InputObject $State -Name 'ScenarioCertificateThumbprint' -Default '')
    $current = Get-Esc8HttpsBinding

    if ($existedBefore) {
        if ([bool]$current.Exists -and -not [string]::IsNullOrWhiteSpace($beforeHash) -and [string]$current.CertificateHash -ine $beforeHash) {
            $binding = @(Get-WebBinding -Name $script:Esc8SiteName -Protocol 'https' -ErrorAction Stop | Where-Object {
                [string]$_.bindingInformation -eq [string]$current.BindingInformation
            })[0]
            if ($PSCmdlet.ShouldProcess($current.BindingInformation, "Restore HTTPS certificate $beforeHash")) {
                [void]$binding.AddSslCertificate($beforeHash, $beforeStore)
                $changed = $true
            }
        }
        return $changed
    }

    if ([bool]$current.Exists) {
        $currentHash = ConvertTo-Esc8ThumbprintString -Value $current.CertificateHash
        if ([string]::IsNullOrWhiteSpace($scenarioThumbprint) -or $currentHash -ieq $scenarioThumbprint) {
            if ($PSCmdlet.ShouldProcess($current.BindingInformation, 'Remove scenario-created HTTPS binding')) {
                Remove-WebBinding -Name $script:Esc8SiteName -Protocol 'https' -Port $script:Esc8HttpsPort -IPAddress '*' -HostHeader '' -ErrorAction Stop
                $changed = $true
            }
        }
    }
    return $changed
}

function Remove-Esc8ScenarioCertificate {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([AllowNull()]$State)

    $scenarioThumbprint = ConvertTo-Esc8ThumbprintString -Value (Get-Esc8PropertyValue -InputObject $State -Name 'ScenarioCertificateThumbprint' -Default '')
    $certificates = @(Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {
        [string]$_.FriendlyName -eq $script:Esc8CertFriendlyName -or
        (-not [string]::IsNullOrWhiteSpace($scenarioThumbprint) -and [string]$_.Thumbprint -ieq $scenarioThumbprint)
    })
    $removed = 0
    foreach ($certificate in $certificates) {
        if ($PSCmdlet.ShouldProcess($certificate.Thumbprint, 'Remove scenario HTTPS certificate')) {
            Remove-Item -LiteralPath $certificate.PSPath -Force -ErrorAction Stop
            $removed++
        }
    }
    return $removed
}

function Uninstall-Esc8WebEnrollment {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    Import-Module ServerManager -ErrorAction Stop
    Import-Module ADCSDeployment -ErrorAction SilentlyContinue
    $changed = $false
    $feature = Get-WindowsFeature -Name 'ADCS-Web-Enrollment' -ErrorAction SilentlyContinue
    if ($null -ne $feature -and [bool]$feature.Installed) {
        $uninstallCommand = Get-Command -Name Uninstall-AdcsWebEnrollment -ErrorAction SilentlyContinue
        if ($null -ne $uninstallCommand) {
            if ($PSCmdlet.ShouldProcess('AD CS Web Enrollment', 'Uninstall role service configuration')) {
                & $uninstallCommand -Force -ErrorAction Stop | Out-Null
                $changed = $true
            }
        }
        if ($PSCmdlet.ShouldProcess('ADCS-Web-Enrollment', 'Uninstall Windows feature')) {
            Uninstall-WindowsFeature -Name 'ADCS-Web-Enrollment' -ErrorAction Stop | Out-Null
            $changed = $true
        }
    }
    return $changed
}

Export-ModuleMember -Function @(
    'ConvertTo-Esc8StringArray',
    'Get-Esc8ActiveCaName',
    'Get-Esc8PropertyValue',
    'Get-Esc8ScenarioName',
    'Get-Esc8StatePath',
    'Get-Esc8StateRoot',
    'Get-Esc8WebEnrollmentState',
    'Initialize-Esc8ScenarioState',
    'Ensure-Esc8HttpsBinding',
    'Ensure-Esc8HttpsFirewallRule',
    'Ensure-Esc8ServiceRunning',
    'Ensure-Esc8WebEnrollmentInstalled',
    'Read-Esc8ScenarioState',
    'Remove-Esc8ScenarioCertificate',
    'Restore-Esc8HttpsBinding',
    'Restore-Esc8IisSecurityState',
    'Save-Esc8ScenarioState',
    'Set-Esc8IisSecurityState',
    'Uninstall-Esc8WebEnrollment',
    'Update-Esc8ScenarioState'
)
