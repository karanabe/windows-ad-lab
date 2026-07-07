Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-LabAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell session.'
    }
}

function Assert-LabPowerShellDirectClient {
    $command = Get-Command -Name New-PSSession -CommandType Cmdlet -ErrorAction Stop
    if (-not $command.Parameters.ContainsKey('VMName')) {
        throw 'This PowerShell does not support New-PSSession -VMName. Use Windows PowerShell 5.1 or PowerShell 7.2 or newer on the Hyper-V host.'
    }
}

function Assert-LabRdnValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string]$FieldName
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "$FieldName cannot be empty."
    }
    if ($Value -ne $Value.Trim()) {
        throw "$FieldName cannot start or end with whitespace: '$Value'"
    }
    if ($Value -match '[,=+<>#;"\\]') {
        throw "$FieldName contains a DN-special character that this lab intentionally rejects: '$Value'"
    }
}

function Assert-LabConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )

    foreach ($section in @('Lab', 'Domain', 'Organization', 'Time', 'Network', 'OrganizationalUnits', 'Groups', 'PasswordPolicies', 'Users', 'Computers', 'Hosts', 'Audit', 'ADCS')) {
        if (-not $Config.ContainsKey($section)) {
            throw "LabConfig.psd1 is missing required section '$section'."
        }
    }

    $computerName = [string]$Config.Lab.ComputerName
    if ($computerName -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,14}$') {
        throw "Lab.ComputerName must be a valid 1-15 character NetBIOS computer name: '$computerName'"
    }
    if ([string]::IsNullOrWhiteSpace([string]$Config.Lab.VMName)) {
        throw 'Lab.VMName is required.'
    }
    if ([string]::IsNullOrWhiteSpace([string]$Config.Lab.GuestBootstrapPath)) {
        throw 'Lab.GuestBootstrapPath is required.'
    }

    $domainName = [string]$Config.Domain.DnsName
    if ($domainName.Length -gt 253 -or $domainName -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$') {
        throw "Domain.DnsName is not a valid multi-label DNS name: '$domainName'"
    }

    $netbiosName = [string]$Config.Domain.NetBIOSName
    if ($netbiosName -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,14}$') {
        throw "Domain.NetBIOSName must be a valid 1-15 character NetBIOS name: '$netbiosName'"
    }
    $upnSuffixes = @{}
    foreach ($suffix in @($Config.Domain.UpnSuffixes)) {
        $suffixText = [string]$suffix
        if ($suffixText -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$') {
            throw "Domain.UpnSuffixes contains an invalid DNS suffix: '$suffixText'"
        }
        if ($upnSuffixes.ContainsKey($suffixText.ToLowerInvariant())) { throw "Duplicate UPN suffix: '$suffixText'" }
        $upnSuffixes[$suffixText.ToLowerInvariant()] = $true
    }

    Assert-LabRdnValue -Value ([string]$Config.Organization.RootOU) -FieldName 'Organization.RootOU'
    if ([string]::IsNullOrWhiteSpace([string]$Config.Organization.Name)) {
        throw 'Organization.Name is required.'
    }
    if ([string]::IsNullOrWhiteSpace([string]$Config.Time.WindowsTimeZoneId)) {
        throw 'Time.WindowsTimeZoneId is required.'
    }

    if ([string]$Config.Network.SwitchType -ne 'Private') {
        throw "Network.SwitchType must be 'Private' for this isolated lab."
    }
    if ([string]::IsNullOrWhiteSpace([string]$Config.Network.SwitchName)) {
        throw 'Network.SwitchName is required.'
    }

    $ipAddress = $null
    if (-not [Net.IPAddress]::TryParse([string]$Config.Network.DC01.IPAddress, [ref]$ipAddress) -or $ipAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Network.DC01.IPAddress is not a valid IPv4 address: '$($Config.Network.DC01.IPAddress)'"
    }
    $prefixLength = [int]$Config.Network.DC01.PrefixLength
    if ($prefixLength -lt 1 -or $prefixLength -gt 32) {
        throw 'Network.DC01.PrefixLength must be between 1 and 32.'
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$Config.Network.DC01.DefaultGateway)) {
        throw 'Network.DC01.DefaultGateway must be empty for the isolated baseline.'
    }
    if (@($Config.Network.DC01.DnsServers).Count -eq 0) {
        throw 'Network.DC01.DnsServers must contain at least one DNS server.'
    }
    foreach ($dnsServer in @($Config.Network.DC01.DnsServers)) {
        $parsedDns = $null
        if (-not [Net.IPAddress]::TryParse([string]$dnsServer, [ref]$parsedDns)) {
            throw "Network.DC01.DnsServers contains an invalid IP address: '$dnsServer'"
        }
    }
    if ([bool]$Config.Network.FutureEdge.Enabled) {
        throw 'Network.FutureEdge.Enabled must remain false during the DC baseline.'
    }

    $ouPaths = @{}
    foreach ($ou in @($Config.OrganizationalUnits)) {
        $segments = @($ou.Path)
        if ($segments.Count -eq 0) {
            throw 'OrganizationalUnits entries must contain at least one path segment.'
        }
        foreach ($segment in $segments) {
            Assert-LabRdnValue -Value ([string]$segment) -FieldName 'OrganizationalUnits.Path'
        }
        $key = $segments -join '/'
        if ($ouPaths.ContainsKey($key)) { throw "Duplicate OU path: '$key'" }
        $ouPaths[$key] = $true
    }

    $groupNames = @{}
    foreach ($group in @($Config.Groups)) {
        $name = [string]$group.Name
        Assert-LabRdnValue -Value $name -FieldName 'Groups.Name'
        if ($groupNames.ContainsKey($name.ToLowerInvariant())) { throw "Duplicate group name: '$name'" }
        $groupNames[$name.ToLowerInvariant()] = $true
        if (-not $ouPaths.ContainsKey((@($group.OU) -join '/'))) {
            throw "Group '$name' references an undefined OU."
        }
        if (@('Global', 'Universal', 'DomainLocal') -notcontains [string]$group.Scope) {
            throw "Group '$name' has an unsupported scope: '$($group.Scope)'"
        }
        if (@('Security', 'Distribution') -notcontains [string]$group.Category) {
            throw "Group '$name' has an unsupported category: '$($group.Category)'"
        }
    }

    $userNames = @{}
    foreach ($user in @($Config.Users)) {
        $sam = [string]$user.SamAccountName
        if ($sam -notmatch '^[A-Za-z0-9._-]{1,20}$') {
            throw "Invalid Users.SamAccountName: '$sam'"
        }
        if ($userNames.ContainsKey($sam.ToLowerInvariant())) { throw "Duplicate user SamAccountName: '$sam'" }
        $userNames[$sam.ToLowerInvariant()] = $true
        if (-not $ouPaths.ContainsKey((@($user.OU) -join '/'))) {
            throw "User '$sam' references an undefined OU."
        }
        $accountType = [string]$user.AccountType
        if (-not $Config.PasswordPolicies.ContainsKey($accountType)) {
            throw "User '$sam' references undefined password policy '$accountType'."
        }
        $policy = $Config.PasswordPolicies[$accountType]
        if ([bool]$policy.ChangePasswordAtLogon -and [bool]$policy.PasswordNeverExpires) {
            throw "Password policy '$accountType' has incompatible settings."
        }
        if ($user.ContainsKey('UserPrincipalName')) {
            $upn = [string]$user.UserPrincipalName
            $allowedUpnSuffixes = @([string]$Config.Domain.DnsName) + @($Config.Domain.UpnSuffixes | ForEach-Object { [string]$_ })
            $upnSuffix = ($upn -split '@', 2)[-1]
            if ($upn -notmatch '^[^@]+@[^@]+$' -or $allowedUpnSuffixes -inotcontains $upnSuffix) {
                throw "User '$sam' has a UPN suffix that is not configured: '$upn'"
            }
        }
        foreach ($groupName in @($user.Groups)) {
            if (-not $groupNames.ContainsKey(([string]$groupName).ToLowerInvariant())) {
                throw "User '$sam' references undefined group '$groupName'."
            }
        }
        $includedBuiltInGroups = @($user.BuiltInGroups | ForEach-Object { ([string]$_).ToLowerInvariant() })
        foreach ($groupName in @($user.AbsentFromBuiltInGroups)) {
            if ($includedBuiltInGroups -contains ([string]$groupName).ToLowerInvariant()) {
                throw "User '$sam' requires and forbids built-in group '$groupName'."
            }
        }
    }

    $computerNames = @{}
    foreach ($computer in @($Config.Computers)) {
        $name = [string]$computer.Name
        if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,14}$') {
            throw "Invalid Computers.Name: '$name'"
        }
        if ($computerNames.ContainsKey($name.ToLowerInvariant())) { throw "Duplicate computer name: '$name'" }
        $computerNames[$name.ToLowerInvariant()] = $true
        if (-not $ouPaths.ContainsKey((@($computer.OU) -join '/'))) {
            throw "Computer '$name' references an undefined OU."
        }
    }

    foreach ($subcategory in @($Config.Audit.Subcategories)) {
        $guid = [guid]::Empty
        if (-not [guid]::TryParse([string]$subcategory.Guid, [ref]$guid)) {
            throw "Audit subcategory '$($subcategory.Name)' has an invalid GUID."
        }
    }
    $caAuditSubcategories = @($Config.Audit.Subcategories | Where-Object { [bool]$_.RequiresADCS })
    if ($caAuditSubcategories.Count -ne 1) {
        throw 'Audit.Subcategories must contain exactly one entry with RequiresADCS=true.'
    }

    if ([bool]$Config.ADCS.Install) {
        if ([string]$Config.ADCS.TargetComputerName -ine $computerName) {
            throw 'ADCS.TargetComputerName must match Lab.ComputerName for this single-DC bootstrap.'
        }
        if ([string]::IsNullOrWhiteSpace([string]$Config.ADCS.CACommonName)) {
            throw 'ADCS.CACommonName is required when ADCS.Install is true.'
        }
    }

    return $true
}

function Import-LabConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Configuration file not found: $Path"
    }
    $config = Import-PowerShellDataFile -LiteralPath $Path
    Assert-LabConfig -Config $config | Out-Null
    return $config
}

function Get-LabDomainDistinguishedName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )

    return (($DomainName.Split('.') | ForEach-Object { "DC=$_" }) -join ',')
}

function Get-LabOuDistinguishedName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootOU,

        [AllowEmptyCollection()]
        [string[]]$RelativePath = @(),

        [Parameter(Mandatory = $true)]
        [string]$DomainDistinguishedName
    )

    Assert-LabRdnValue -Value $RootOU -FieldName 'RootOU'
    $segments = @($RootOU)
    foreach ($segment in @($RelativePath)) {
        Assert-LabRdnValue -Value ([string]$segment) -FieldName 'OU path segment'
        $segments += [string]$segment
    }

    $rdns = @()
    for ($index = $segments.Count - 1; $index -ge 0; $index--) {
        $rdns += "OU=$($segments[$index])"
    }
    return "$($rdns -join ','),$DomainDistinguishedName"
}

function Get-LabParentOuDistinguishedName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootOU,

        [AllowEmptyCollection()]
        [string[]]$RelativePath = @(),

        [Parameter(Mandatory = $true)]
        [string]$DomainDistinguishedName
    )

    if (@($RelativePath).Count -le 1) {
        return (Get-LabOuDistinguishedName -RootOU $RootOU -DomainDistinguishedName $DomainDistinguishedName)
    }
    $parentPath = @($RelativePath[0..($RelativePath.Count - 2)])
    return (Get-LabOuDistinguishedName -RootOU $RootOU -RelativePath $parentPath -DomainDistinguishedName $DomainDistinguishedName)
}

function Get-LabParentDistinguishedName {
    param([Parameter(Mandatory = $true)][string]$DistinguishedName)
    $index = $DistinguishedName.IndexOf(',')
    if ($index -lt 0) { return '' }
    return $DistinguishedName.Substring($index + 1)
}

function Expand-LabToken {
    param(
        [AllowNull()]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )

    if ($null -eq $Value) { return $null }
    return $Value.Replace('{DOMAIN}', [string]$Config.Domain.DnsName).Replace('{NETBIOS}', [string]$Config.Domain.NetBIOSName)
}

function Start-LabTranscript {
    param([Parameter(Mandatory = $true)][string]$Phase)

    $logRoot = Join-Path $env:ProgramData 'ADLabBootstrap\Logs'
    if (-not (Test-Path -LiteralPath $logRoot)) {
        New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
    }
    $path = Join-Path $logRoot "$(Get-Date -Format 'yyyyMMdd-HHmmss')-$Phase.log"
    try { Start-Transcript -Path $path -Force | Out-Null }
    catch { Write-Warning "Transcript could not be started: $($_.Exception.Message)" }
    return $path
}

function Stop-LabTranscript {
    try { Stop-Transcript | Out-Null } catch { }
}

function Write-LabLog {
    param(
        [Parameter(Mandatory = $true)][string]$Phase,
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $true)][ValidateSet('Changed', 'Unchanged', 'Failed', 'Info')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Target,
        [string]$Message = ''
    )

    $timestamp = (Get-Date).ToString('o')
    Write-Host ("{0} Phase={1} Action={2} Status={3} Target={4} Message={5}" -f $timestamp, $Phase, $Action, $Status, $Target, $Message)
}

function New-LabPhaseResult {
    param(
        [Parameter(Mandatory = $true)][string]$Phase,
        [Parameter(Mandatory = $true)][ValidateSet('Succeeded', 'Skipped')][string]$Status,
        [bool]$Changed = $false,
        [bool]$RebootRequired = $false,
        [string]$Message = ''
    )

    return [pscustomobject]@{
        PSTypeName     = 'ADLab.PhaseResult'
        Timestamp      = (Get-Date).ToString('o')
        Phase          = $Phase
        Status         = $Status
        Changed        = $Changed
        RebootRequired = $RebootRequired
        Message        = $Message
    }
}

function Get-LabCurrentDomain {
    param([Parameter(Mandatory = $true)][hashtable]$Config)

    Import-Module ActiveDirectory -ErrorAction Stop -WarningAction SilentlyContinue
    $domain = Get-ADDomain -Server $env:COMPUTERNAME -ErrorAction Stop
    if ($domain.DNSRoot -ine [string]$Config.Domain.DnsName) {
        throw "Current domain '$($domain.DNSRoot)' does not match configured domain '$($Config.Domain.DnsName)'."
    }
    return $domain
}

Export-ModuleMember -Function @(
    'Assert-LabAdministrator',
    'Assert-LabConfig',
    'Assert-LabPowerShellDirectClient',
    'Assert-LabRdnValue',
    'Expand-LabToken',
    'Get-LabCurrentDomain',
    'Get-LabDomainDistinguishedName',
    'Get-LabOuDistinguishedName',
    'Get-LabParentDistinguishedName',
    'Get-LabParentOuDistinguishedName',
    'Import-LabConfig',
    'New-LabPhaseResult',
    'Start-LabTranscript',
    'Stop-LabTranscript',
    'Write-LabLog'
)
