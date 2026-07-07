#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$HelpdeskGroupName = 'GG_LAPS_Helpdesk',
    [string]$HelpdeskMemberSamAccountName = 'john.smith',
    [string]$WorkstationComputerName = 'CLIENT01',
    [string]$ServerComputerName = 'FILE01',
    [string]$ControlServerComputerName = 'WEB01',
    [bool]$IncludeFile01Misconfiguration = $true,
    [switch]$UpdateSchemaIfMissing,
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'WindowsLAPS-Delegation'
$script:Marker = 'windows-ad-lab:WindowsLAPS-Delegation'
$script:RootOuName = 'LAB'
$script:Changed = $false
$script:ScenarioDescription = 'LAB ONLY: Windows LAPS delegation observation principal'
$script:LapsPasswordAttribute = 'msLAPS-Password'
$script:LapsExpirationAttribute = 'msLAPS-PasswordExpirationTime'
$AdServerParameters = @{}
$LapsDomainControllerParameters = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $AdServerParameters['Server'] = $Server
    $LapsDomainControllerParameters['DomainController'] = $Server
}

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module LAPS -ErrorAction Stop

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

function Assert-ComputerName {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($Value -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,14}$') {
        throw "$Name must be a valid 1-15 character NetBIOS computer name: '$Value'"
    }
}

function ConvertTo-LdapFilterValue {
    param([Parameter(Mandatory = $true)][string]$Value)

    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace(([string][char]0), '\00')
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

function ConvertTo-GuidValue {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($null -eq $Value) {
        throw "$Context did not contain a GUID value."
    }
    $valueObject = $Value.PSObject.BaseObject
    if ($valueObject -is [Guid]) {
        return [Guid]$valueObject
    }
    if ($valueObject -is [byte[]]) {
        return New-Object -TypeName System.Guid -ArgumentList (, ([byte[]]$valueObject))
    }
    return [Guid]([string]$valueObject)
}

function Get-LapsSchemaAttributeOrNull {
    param([Parameter(Mandatory = $true)][string]$LdapDisplayName)

    $rootDse = Get-ADRootDSE @AdServerParameters -ErrorAction Stop
    $schemaNc = [string]$rootDse.schemaNamingContext
    $escapedName = ConvertTo-LdapFilterValue -Value $LdapDisplayName
    $attributes = @(Get-ADObject -SearchBase $schemaNc -SearchScope OneLevel -LDAPFilter "(lDAPDisplayName=$escapedName)" -Properties lDAPDisplayName, schemaIDGUID, searchFlags @AdServerParameters -ErrorAction Stop)
    if ($attributes.Count -gt 1) {
        throw "Multiple schema attributes were returned for lDAPDisplayName '$LdapDisplayName'."
    }
    if ($attributes.Count -eq 0) {
        return $null
    }
    return $attributes[0]
}

function Assert-WindowsLapsSchema {
    param([switch]$UpdateIfMissing)

    $missingAttributes = New-Object 'System.Collections.Generic.List[string]'
    foreach ($attributeName in @($script:LapsPasswordAttribute, $script:LapsExpirationAttribute)) {
        $attribute = Get-LapsSchemaAttributeOrNull -LdapDisplayName $attributeName
        if ($null -eq $attribute) {
            [void]$missingAttributes.Add($attributeName)
            continue
        }
        [void](ConvertTo-GuidValue -Value $attribute.schemaIDGUID -Context "schemaIDGUID for $attributeName")
    }
    if ($missingAttributes.Count -eq 0) {
        return
    }

    if (-not $UpdateIfMissing) {
        throw "Windows LAPS schema attribute(s) were not found: $($missingAttributes.ToArray() -join ', '). This is not a conflict with other scenarios; the Windows LAPS schema extension is additive and can coexist with them. Rerun with -ScriptParameters @{ UpdateSchemaIfMissing = `$true } only if this lab checkpoint may be changed by Update-LapsADSchema, because cleanup cannot remove AD schema extensions."
    }

    if ($PSCmdlet.ShouldProcess($domain.DNSRoot, "Extend AD schema for Windows LAPS attributes: $($missingAttributes.ToArray() -join ', ')")) {
        Update-LapsADSchema -Confirm:$false -ErrorAction Stop | Out-Null
        $script:Changed = $true
    }

    $stillMissing = New-Object 'System.Collections.Generic.List[string]'
    foreach ($attributeName in @($script:LapsPasswordAttribute, $script:LapsExpirationAttribute)) {
        $attribute = Get-LapsSchemaAttributeOrNull -LdapDisplayName $attributeName
        if ($null -eq $attribute) {
            [void]$stillMissing.Add($attributeName)
            continue
        }
        [void](ConvertTo-GuidValue -Value $attribute.schemaIDGUID -Context "schemaIDGUID for $attributeName")
    }
    if ($stillMissing.Count -gt 0) {
        throw "Windows LAPS schema attribute(s) are still missing after Update-LapsADSchema: $($stillMissing.ToArray() -join ', ')."
    }
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
        return Get-ADOrganizationalUnit -Identity $DistinguishedName -Properties adminDescription, Description @AdServerParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

function Get-ScenarioGroupOrNull {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)

    $escapedName = ConvertTo-LdapFilterValue -Value $SamAccountName
    $groups = @(Get-ADGroup -LDAPFilter "(sAMAccountName=$escapedName)" -Properties adminDescription, Description, Member, SID @AdServerParameters -ErrorAction Stop)
    if ($groups.Count -gt 1) {
        throw "Multiple groups were returned for sAMAccountName '$SamAccountName'."
    }
    if ($groups.Count -eq 0) {
        return $null
    }
    return $groups[0]
}

function Get-ScenarioUserBySamOrNull {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)

    $escapedSam = ConvertTo-LdapFilterValue -Value $SamAccountName
    $users = @(Get-ADUser -LDAPFilter "(sAMAccountName=$escapedSam)" -Properties Enabled @AdServerParameters -ErrorAction Stop)
    if ($users.Count -gt 1) {
        throw "Multiple users were returned for sAMAccountName '$SamAccountName'."
    }
    if ($users.Count -eq 0) {
        return $null
    }
    return $users[0]
}

function Get-ScenarioComputerOrNull {
    param([Parameter(Mandatory = $true)][string]$ComputerName)

    try {
        return Get-ADComputer -Identity $ComputerName -Properties Description, msLAPS-Password, msLAPS-PasswordExpirationTime @AdServerParameters -ErrorAction Stop
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

function Ensure-ScenarioGroup {
    param(
        [Parameter(Mandatory = $true)][string]$GroupName,
        [Parameter(Mandatory = $true)][string]$GroupsOuDn,
        [Parameter(Mandatory = $true)]$HelpdeskMember
    )

    $group = Get-ScenarioGroupOrNull -SamAccountName $GroupName
    if ($null -eq $group) {
        if ($PSCmdlet.ShouldProcess($GroupName, "Create scenario group in $GroupsOuDn")) {
            New-ADGroup `
                -Name $GroupName `
                -SamAccountName $GroupName `
                -GroupScope Global `
                -GroupCategory Security `
                -Path $GroupsOuDn `
                -Description $script:ScenarioDescription `
                -OtherAttributes @{ adminDescription = $script:Marker } `
                @AdServerParameters `
                -ErrorAction Stop | Out-Null
            $script:Changed = $true
        }
        $group = Get-ScenarioGroupOrNull -SamAccountName $GroupName
    }

    if ($null -eq $group) {
        Write-Host "WhatIf: scenario group '$GroupName' was not created, so membership and ACL changes are skipped."
        return $null
    }
    if ([string]$group.adminDescription -cne $script:Marker -or [string]$group.DistinguishedName -ine "CN=$GroupName,$GroupsOuDn") {
        throw "Group '$GroupName' already exists outside this scenario. Refusing to modify it."
    }

    $replace = @{}
    if ([string]$group.Description -cne $script:ScenarioDescription) {
        $replace['description'] = $script:ScenarioDescription
    }
    if ([string]$group.adminDescription -cne $script:Marker) {
        $replace['adminDescription'] = $script:Marker
    }
    if ($replace.Count -gt 0 -and $PSCmdlet.ShouldProcess($group.DistinguishedName, 'Update scenario group metadata')) {
        Set-ADObject -Identity $group.DistinguishedName -Replace $replace @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }

    $group = Get-ScenarioGroupOrNull -SamAccountName $GroupName
    $members = @($group.Member | ForEach-Object { [string]$_ })
    if ($members -notcontains [string]$HelpdeskMember.DistinguishedName) {
        if ($PSCmdlet.ShouldProcess($group.DistinguishedName, "Add member $($HelpdeskMember.SamAccountName)")) {
            Add-ADGroupMember -Identity $group.DistinguishedName -Members $HelpdeskMember.DistinguishedName @AdServerParameters -ErrorAction Stop
            $script:Changed = $true
        }
    }

    return (Get-ScenarioGroupOrNull -SamAccountName $GroupName)
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
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid,
        [Parameter(Mandatory = $true)][string]$ActionName
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

    if ($PSCmdlet.ShouldProcess($DistinguishedName, $ActionName)) {
        foreach ($rule in $rulesToRemove) {
            [void]$acl.RemoveAccessRuleSpecific($rule)
        }
        Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
        $script:Changed = $true
    }
    return $rulesToRemove.Count
}

function Ensure-LapsReadDelegation {
    param(
        [Parameter(Mandatory = $true)][string]$TargetOuDn,
        [Parameter(Mandatory = $true)]$Group,
        [Parameter(Mandatory = $true)][string]$QualifiedPrincipal
    )

    $groupSid = [Security.Principal.SecurityIdentifier]$Group.SID
    [void](Remove-ScenarioPrincipalAces -DistinguishedName $TargetOuDn -PrincipalSid $groupSid -ActionName 'Reset Workstations Windows LAPS delegation ACEs')

    if ($PSCmdlet.ShouldProcess($TargetOuDn, "Grant Windows LAPS read delegation to $QualifiedPrincipal")) {
        Set-LapsADReadPasswordPermission -Identity $TargetOuDn -AllowedPrincipals @($QualifiedPrincipal) @LapsDomainControllerParameters -ErrorAction Stop | Out-Null
        $script:Changed = $true
    }
}

function Ensure-File01Misconfiguration {
    param(
        [Parameter(Mandatory = $true)]$Computer,
        [Parameter(Mandatory = $true)]$Group,
        [Parameter(Mandatory = $true)][bool]$Enabled
    )

    $groupSid = [Security.Principal.SecurityIdentifier]$Group.SID
    if (-not $Enabled) {
        [void](Remove-ScenarioPrincipalAces -DistinguishedName ([string]$Computer.DistinguishedName) -PrincipalSid $groupSid -ActionName 'Remove FILE01 scenario misconfiguration ACE')
        return
    }

    Ensure-AdDrive
    $path = "AD:\$($Computer.DistinguishedName)"
    $acl = Get-Acl -Path $path
    $existing = @($acl.Access | Where-Object {
        -not $_.IsInherited `
            -and [string]$_.AccessControlType -eq 'Allow' `
            -and (($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) `
            -and (Test-IdentityReferenceMatchesSid -IdentityReference $_.IdentityReference -Sid $groupSid)
    })
    if ($existing.Count -gt 0) {
        return
    }

    if ($PSCmdlet.ShouldProcess($Computer.DistinguishedName, "Grant LAB ONLY GenericAll misconfiguration to $($Group.SamAccountName)")) {
        $rule = New-Object `
            -TypeName System.DirectoryServices.ActiveDirectoryAccessRule `
            -ArgumentList $groupSid, ([System.DirectoryServices.ActiveDirectoryRights]::GenericAll), ([System.Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
        Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
        $script:Changed = $true
    }
}

function Ensure-ScenarioLapsAttributes {
    param([Parameter(Mandatory = $true)]$Computer)

    $computerName = [string]$Computer.Name
    $desiredPassword = New-ScenarioLapsPasswordJson -ComputerName $computerName
    $desiredExpiration = [Int64](Get-ScenarioLapsExpirationFileTime)
    $currentPassword = ConvertTo-SingleAdValue -Value $Computer.($script:LapsPasswordAttribute) -AttributeName $script:LapsPasswordAttribute -DistinguishedName ([string]$Computer.DistinguishedName)
    $currentExpiration = ConvertTo-SingleAdValue -Value $Computer.($script:LapsExpirationAttribute) -AttributeName $script:LapsExpirationAttribute -DistinguishedName ([string]$Computer.DistinguishedName)

    if ($null -ne $currentPassword -and [string]$currentPassword -cne $desiredPassword) {
        throw "Computer '$computerName' already has a non-scenario Windows LAPS password value. Refusing to overwrite '$($Computer.DistinguishedName)'."
    }
    if ($null -ne $currentExpiration -and [Int64]$currentExpiration -ne $desiredExpiration) {
        throw "Computer '$computerName' already has a non-scenario Windows LAPS expiration value. Refusing to overwrite '$($Computer.DistinguishedName)'."
    }
    if ([string]$currentPassword -ceq $desiredPassword -and $null -ne $currentExpiration -and [Int64]$currentExpiration -eq $desiredExpiration) {
        return
    }

    if ($PSCmdlet.ShouldProcess($Computer.DistinguishedName, 'Write synthetic Windows LAPS observation attributes')) {
        $replace = @{}
        $replace[$script:LapsPasswordAttribute] = $desiredPassword
        $replace[$script:LapsExpirationAttribute] = $desiredExpiration
        Set-ADObject -Identity $Computer.DistinguishedName -Replace $replace @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }
}

Assert-SimpleRdnValue -Value $HelpdeskGroupName -Name 'HelpdeskGroupName'
Assert-SamAccountName -Value $HelpdeskGroupName -Name 'HelpdeskGroupName'
Assert-SamAccountName -Value $HelpdeskMemberSamAccountName -Name 'HelpdeskMemberSamAccountName'
Assert-ComputerName -Value $WorkstationComputerName -Name 'WorkstationComputerName'
Assert-ComputerName -Value $ServerComputerName -Name 'ServerComputerName'
Assert-ComputerName -Value $ControlServerComputerName -Name 'ControlServerComputerName'
if ($ServerComputerName -ieq $ControlServerComputerName) {
    throw 'ServerComputerName and ControlServerComputerName must be different.'
}

$domain = Get-ADDomain @AdServerParameters -ErrorAction Stop
if ([string]$domain.DNSRoot -ine 'ad.lab.exceeds.test') {
    throw "Current domain '$($domain.DNSRoot)' is not the expected Baseline 06 domain 'ad.lab.exceeds.test'."
}

Assert-WindowsLapsSchema -UpdateIfMissing:$UpdateSchemaIfMissing

$domainDn = [string]$domain.DistinguishedName
$rootOuDn = "OU=$script:RootOuName,$domainDn"
$groupsOuDn = "OU=Groups,$rootOuDn"
$workstationsOuDn = "OU=Workstations,OU=Computers,$rootOuDn"
$serversOuDn = "OU=Servers,OU=Computers,$rootOuDn"
foreach ($ouDn in @($rootOuDn, $groupsOuDn, $workstationsOuDn, $serversOuDn)) {
    if ($null -eq (Get-AdOrganizationalUnitOrNull -DistinguishedName $ouDn)) {
        throw "Required Baseline 06 OU '$ouDn' was not found. Restore 06-ADCS-HTTP-CDP before running this scenario."
    }
}

$helpdeskMember = Get-ScenarioUserBySamOrNull -SamAccountName $HelpdeskMemberSamAccountName
if ($null -eq $helpdeskMember) {
    throw "Helpdesk member '$HelpdeskMemberSamAccountName' was not found in Baseline 06."
}

$workstationComputer = Get-ScenarioComputerOrNull -ComputerName $WorkstationComputerName
$serverComputer = Get-ScenarioComputerOrNull -ComputerName $ServerComputerName
$controlServerComputer = Get-ScenarioComputerOrNull -ComputerName $ControlServerComputerName
foreach ($computer in @($workstationComputer, $serverComputer, $controlServerComputer)) {
    if ($null -eq $computer) {
        throw 'One or more required Baseline 06 computer objects were not found.'
    }
}
if ([string]$workstationComputer.DistinguishedName -notlike "*,$workstationsOuDn") {
    throw "Computer '$WorkstationComputerName' is not under '$workstationsOuDn'."
}
foreach ($computer in @($serverComputer, $controlServerComputer)) {
    if ([string]$computer.DistinguishedName -notlike "*,$serversOuDn") {
        throw "Computer '$($computer.Name)' is not under '$serversOuDn'."
    }
}

$helpdeskGroup = Ensure-ScenarioGroup -GroupName $HelpdeskGroupName -GroupsOuDn $groupsOuDn -HelpdeskMember $helpdeskMember
if ($null -ne $helpdeskGroup) {
    $qualifiedHelpdeskGroup = "$($domain.NetBIOSName)\$HelpdeskGroupName"
    Ensure-LapsReadDelegation -TargetOuDn $workstationsOuDn -Group $helpdeskGroup -QualifiedPrincipal $qualifiedHelpdeskGroup
    Ensure-File01Misconfiguration -Computer $serverComputer -Group $helpdeskGroup -Enabled $IncludeFile01Misconfiguration
}

foreach ($computer in @($workstationComputer, $serverComputer, $controlServerComputer)) {
    Ensure-ScenarioLapsAttributes -Computer $computer
}

[pscustomobject]@{
    Scenario                      = $script:ScenarioName
    Changed                       = $script:Changed
    Baseline                      = '06-ADCS-HTTP-CDP'
    HelpdeskGroup                 = "$($domain.NetBIOSName)\$HelpdeskGroupName"
    HelpdeskMember                = $HelpdeskMemberSamAccountName
    ClientDelegation              = $workstationsOuDn
    ServerDelegation              = 'Not granted to Helpdesk'
    File01MisconfigurationEnabled = $IncludeFile01Misconfiguration
    SchemaUpdateRequested         = [bool]$UpdateSchemaIfMissing
    ObservationValues             = @($WorkstationComputerName, $ServerComputerName, $ControlServerComputerName)
    PasswordValuesLogged          = $false
}
