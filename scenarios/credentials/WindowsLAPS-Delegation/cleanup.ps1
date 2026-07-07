#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$HelpdeskGroupName = 'GG_LAPS_Helpdesk',
    [string]$WorkstationComputerName = 'CLIENT01',
    [string]$ServerComputerName = 'FILE01',
    [string]$ControlServerComputerName = 'WEB01',
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'WindowsLAPS-Delegation'
$script:Marker = 'windows-ad-lab:WindowsLAPS-Delegation'
$script:RootOuName = 'LAB'
$script:Changed = $false
$script:LapsPasswordAttribute = 'msLAPS-Password'
$script:LapsExpirationAttribute = 'msLAPS-PasswordExpirationTime'
$script:LapsSchemaAvailable = $false
$AdServerParameters = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $AdServerParameters['Server'] = $Server
}

Import-Module ActiveDirectory -ErrorAction Stop

function Assert-SimpleRdnValue {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "$Name cannot be empty."
    }
    if ($Value -ne $Value.Trim()) {
        throw "$Name cannot start or end with whitespace: '$Value'"
    }
    if ($Value -match '[,=+<>#;"\\]') {
        throw "$Name contains a DN-special character rejected by this lab: '$Value'"
    }
}

function Assert-SamAccountName {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($Value -notmatch '^[A-Za-z0-9._-]{1,20}$') {
        throw "$Name must be a valid 1-20 character sAMAccountName: '$Value'"
    }
}

function ConvertTo-LdapFilterValue {
    param([Parameter(Mandatory = $true)][string]$Value)

    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace(([string][char]0), '\00')
}

function Get-LapsSchemaAttributeOrNull {
    param([Parameter(Mandatory = $true)][string]$LdapDisplayName)

    $rootDse = Get-ADRootDSE @AdServerParameters -ErrorAction Stop
    $schemaNc = [string]$rootDse.schemaNamingContext
    $escapedName = ConvertTo-LdapFilterValue -Value $LdapDisplayName
    $attributes = @(Get-ADObject -SearchBase $schemaNc -SearchScope OneLevel -LDAPFilter "(lDAPDisplayName=$escapedName)" -Properties lDAPDisplayName @AdServerParameters -ErrorAction Stop)
    if ($attributes.Count -gt 1) {
        throw "Multiple schema attributes were returned for lDAPDisplayName '$LdapDisplayName'."
    }
    if ($attributes.Count -eq 0) {
        return $null
    }
    return $attributes[0]
}

function Test-WindowsLapsSchemaAvailable {
    foreach ($attributeName in @($script:LapsPasswordAttribute, $script:LapsExpirationAttribute)) {
        if ($null -eq (Get-LapsSchemaAttributeOrNull -LdapDisplayName $attributeName)) {
            return $false
        }
    }
    return $true
}

function ConvertTo-SingleAdValue {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)][string]$AttributeName,
        [Parameter(Mandatory = $true)][string]$DistinguishedName
    )

    if ($null -eq $Value) {
        return $null
    }
    $valueObject = $Value.PSObject.BaseObject
    if ($valueObject -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) {
        if ($valueObject.Count -eq 0) { return $null }
        if ($valueObject.Count -gt 1) {
            throw "Attribute '$AttributeName' on '$DistinguishedName' should have one value, found $($valueObject.Count)."
        }
        return $valueObject[0]
    }
    if ($valueObject -is [array] -and -not ($valueObject -is [byte[]])) {
        if ($valueObject.Count -eq 0) { return $null }
        if ($valueObject.Count -gt 1) {
            throw "Attribute '$AttributeName' on '$DistinguishedName' should have one value, found $($valueObject.Count)."
        }
        return $valueObject[0]
    }
    return $valueObject
}

function Ensure-AdDrive {
    if ($null -ne (Get-PSDrive -Name AD -ErrorAction SilentlyContinue)) {
        return
    }

    $driveParameters = @{
        Name        = 'AD'
        PSProvider  = 'ActiveDirectory'
        Root        = ''
        Scope       = 'Script'
        ErrorAction = 'Stop'
    }
    if ($AdServerParameters.ContainsKey('Server')) {
        $driveParameters['Server'] = $AdServerParameters['Server']
    }
    New-PSDrive @driveParameters | Out-Null
}

function Get-AdOrganizationalUnitOrNull {
    param([Parameter(Mandatory = $true)][string]$DistinguishedName)

    try {
        return Get-ADOrganizationalUnit -Identity $DistinguishedName -Properties adminDescription @AdServerParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

function Get-ScenarioGroupOrNull {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)

    $escapedName = ConvertTo-LdapFilterValue -Value $SamAccountName
    $groups = @(Get-ADGroup -LDAPFilter "(sAMAccountName=$escapedName)" -Properties adminDescription, SID @AdServerParameters -ErrorAction Stop)
    if ($groups.Count -gt 1) {
        throw "Multiple groups were returned for sAMAccountName '$SamAccountName'."
    }
    if ($groups.Count -eq 0) {
        return $null
    }
    return $groups[0]
}

function Get-ScenarioComputerOrNull {
    param([Parameter(Mandatory = $true)][string]$ComputerName)

    try {
        $getParameters = @{
            Identity    = $ComputerName
            ErrorAction = 'Stop'
        }
        if ($script:LapsSchemaAvailable) {
            $getParameters['Properties'] = @($script:LapsPasswordAttribute, $script:LapsExpirationAttribute)
        }
        foreach ($key in $AdServerParameters.Keys) {
            $getParameters[$key] = $AdServerParameters[$key]
        }
        return Get-ADComputer @getParameters
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

function Get-ScenarioFileTimeUtc {
    param([Parameter(Mandatory = $true)][string]$IsoUtc)

    return ([DateTimeOffset]::Parse($IsoUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)).UtcDateTime.ToFileTimeUtc()
}

function Get-ScenarioLapsUpdateTimeHex {
    return ('{0:x}' -f (Get-ScenarioFileTimeUtc -IsoUtc '2026-01-01T00:00:00Z'))
}

function Get-ScenarioLapsExpirationFileTime {
    return (Get-ScenarioFileTimeUtc -IsoUtc '2036-01-01T00:00:00Z')
}

function New-ScenarioLapsPasswordJson {
    param([Parameter(Mandatory = $true)][string]$ComputerName)

    $record = [ordered]@{
        n = 'Administrator'
        t = (Get-ScenarioLapsUpdateTimeHex)
        p = "LAB-ONLY-$($ComputerName.ToUpperInvariant())-WINDOWS-LAPS-DELEGATION"
    }
    return ($record | ConvertTo-Json -Compress)
}

function Test-IdentityReferenceMatchesSid {
    param(
        [Parameter(Mandatory = $true)]$IdentityReference,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$Sid
    )

    try {
        $candidate = $IdentityReference.Translate([Security.Principal.SecurityIdentifier])
        return ([string]$candidate.Value -eq [string]$Sid.Value)
    }
    catch {
        return ([string]$IdentityReference -eq [string]$Sid.Value)
    }
}

function Remove-ScenarioPrincipalAces {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    Ensure-AdDrive
    $path = "AD:\$DistinguishedName"
    $acl = Get-Acl -Path $path
    $rulesToRemove = @($acl.Access | Where-Object {
        -not $_.IsInherited -and (Test-IdentityReferenceMatchesSid -IdentityReference $_.IdentityReference -Sid $PrincipalSid)
    })
    if ($rulesToRemove.Count -eq 0) {
        return 0
    }

    if ($PSCmdlet.ShouldProcess($DistinguishedName, 'Remove scenario principal ACEs')) {
        foreach ($rule in $rulesToRemove) {
            [void]$acl.RemoveAccessRuleSpecific($rule)
        }
        Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
        $script:Changed = $true
    }
    return $rulesToRemove.Count
}

function Clear-ScenarioLapsAttributes {
    param([Parameter(Mandatory = $true)]$Computer)

    if (-not $script:LapsSchemaAvailable) {
        return 0
    }

    $expectedPassword = New-ScenarioLapsPasswordJson -ComputerName ([string]$Computer.Name)
    $expectedExpiration = [Int64](Get-ScenarioLapsExpirationFileTime)
    $currentPassword = ConvertTo-SingleAdValue -Value $Computer.($script:LapsPasswordAttribute) -AttributeName $script:LapsPasswordAttribute -DistinguishedName ([string]$Computer.DistinguishedName)
    $currentExpiration = ConvertTo-SingleAdValue -Value $Computer.($script:LapsExpirationAttribute) -AttributeName $script:LapsExpirationAttribute -DistinguishedName ([string]$Computer.DistinguishedName)

    if ($null -ne $currentPassword -and [string]$currentPassword -cne $expectedPassword) {
        throw "Computer '$($Computer.Name)' has a Windows LAPS password value that was not created by this scenario. Refusing to clear '$($Computer.DistinguishedName)'."
    }
    if ($null -ne $currentExpiration -and [Int64]$currentExpiration -ne $expectedExpiration) {
        throw "Computer '$($Computer.Name)' has a Windows LAPS expiration value that was not created by this scenario. Refusing to clear '$($Computer.DistinguishedName)'."
    }
    if ($null -eq $currentPassword -and $null -eq $currentExpiration) {
        return 0
    }

    $attributesToClear = New-Object 'System.Collections.Generic.List[string]'
    if ($null -ne $currentPassword) {
        [void]$attributesToClear.Add($script:LapsPasswordAttribute)
    }
    if ($null -ne $currentExpiration) {
        [void]$attributesToClear.Add($script:LapsExpirationAttribute)
    }

    if ($PSCmdlet.ShouldProcess($Computer.DistinguishedName, 'Clear synthetic Windows LAPS observation attributes')) {
        Set-ADObject -Identity $Computer.DistinguishedName -Clear $attributesToClear.ToArray() @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }
    return $attributesToClear.Count
}

function Remove-ScenarioGroup {
    param([Parameter(Mandatory = $true)]$Group)

    if ([string]$Group.adminDescription -cne $script:Marker) {
        throw "Group '$($Group.SamAccountName)' exists but is not marked for this scenario. Refusing to delete it."
    }

    if ($PSCmdlet.ShouldProcess($Group.DistinguishedName, 'Delete scenario Helpdesk group')) {
        Remove-ADGroup -Identity $Group.DistinguishedName -Confirm:$false @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }
}

Assert-SimpleRdnValue -Value $HelpdeskGroupName -Name 'HelpdeskGroupName'
Assert-SamAccountName -Value $HelpdeskGroupName -Name 'HelpdeskGroupName'

$domain = Get-ADDomain @AdServerParameters -ErrorAction Stop
if ([string]$domain.DNSRoot -ine 'ad.lab.exceeds.test') {
    throw "Current domain '$($domain.DNSRoot)' is not the expected Baseline 06 domain 'ad.lab.exceeds.test'."
}

$domainDn = [string]$domain.DistinguishedName
$rootOuDn = "OU=$script:RootOuName,$domainDn"
$workstationsOuDn = "OU=Workstations,OU=Computers,$rootOuDn"
$serversOuDn = "OU=Servers,OU=Computers,$rootOuDn"
foreach ($ouDn in @($rootOuDn, $workstationsOuDn, $serversOuDn)) {
    if ($null -eq (Get-AdOrganizationalUnitOrNull -DistinguishedName $ouDn)) {
        throw "Required Baseline 06 OU '$ouDn' was not found."
    }
}
$script:LapsSchemaAvailable = Test-WindowsLapsSchemaAvailable

$helpdeskGroup = Get-ScenarioGroupOrNull -SamAccountName $HelpdeskGroupName
$removedAces = 0
if ($null -ne $helpdeskGroup) {
    if ([string]$helpdeskGroup.adminDescription -cne $script:Marker) {
        throw "Group '$HelpdeskGroupName' exists but is not marked for this scenario. Refusing cleanup."
    }
    $helpdeskSid = [Security.Principal.SecurityIdentifier]$helpdeskGroup.SID
    foreach ($targetDn in @($workstationsOuDn, $serversOuDn)) {
        $removedAces += Remove-ScenarioPrincipalAces -DistinguishedName $targetDn -PrincipalSid $helpdeskSid
    }
    foreach ($computerName in @($WorkstationComputerName, $ServerComputerName, $ControlServerComputerName)) {
        $computer = Get-ScenarioComputerOrNull -ComputerName $computerName
        if ($null -ne $computer) {
            $removedAces += Remove-ScenarioPrincipalAces -DistinguishedName ([string]$computer.DistinguishedName) -PrincipalSid $helpdeskSid
        }
    }
}

$clearedAttributes = 0
foreach ($computerName in @($WorkstationComputerName, $ServerComputerName, $ControlServerComputerName)) {
    $computer = Get-ScenarioComputerOrNull -ComputerName $computerName
    if ($null -ne $computer) {
        $clearedAttributes += Clear-ScenarioLapsAttributes -Computer $computer
    }
}

if ($null -ne $helpdeskGroup) {
    Remove-ScenarioGroup -Group $helpdeskGroup
}

if ($WhatIfPreference) {
    Write-Host 'WhatIf: Baseline restored check skipped because no objects were deleted.'
}
else {
    if ($null -ne (Get-ScenarioGroupOrNull -SamAccountName $HelpdeskGroupName)) {
        throw "Cleanup finished but scenario group '$HelpdeskGroupName' still exists."
    }
    foreach ($computerName in @($WorkstationComputerName, $ServerComputerName, $ControlServerComputerName)) {
        $computer = Get-ScenarioComputerOrNull -ComputerName $computerName
        if ($script:LapsSchemaAvailable -and $null -ne $computer) {
            $currentPassword = ConvertTo-SingleAdValue -Value $computer.($script:LapsPasswordAttribute) -AttributeName $script:LapsPasswordAttribute -DistinguishedName ([string]$computer.DistinguishedName)
            $currentExpiration = ConvertTo-SingleAdValue -Value $computer.($script:LapsExpirationAttribute) -AttributeName $script:LapsExpirationAttribute -DistinguishedName ([string]$computer.DistinguishedName)
            if ($null -ne $currentPassword -or $null -ne $currentExpiration) {
                throw "Cleanup finished but synthetic LAPS attributes remain on '$($computer.DistinguishedName)'."
            }
        }
    }
}

[pscustomobject]@{
    Scenario          = $script:ScenarioName
    Changed           = $script:Changed
    Baseline          = '06-ADCS-HTTP-CDP'
    BaselineRestored  = (-not $WhatIfPreference)
    RemovedAces       = $removedAces
    ClearedAttributes = $clearedAttributes
    WindowsLapsSchemaPresent = $script:LapsSchemaAvailable
    RemovedGroup      = $HelpdeskGroupName
}
