#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$GmsaName = 'gmsa_web',
    [string]$ReaderGroupName = 'GG_gMSA_Readers',
    [string]$GroupMemberManagerSamAccountName = 'operator01',
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'gMSA-PasswordRetrieval'
$script:Marker = 'windows-ad-lab:gMSA-PasswordRetrieval'
$script:RootOuName = 'LAB'
$script:Changed = $false
$script:MemberAttribute = 'member'
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

function Assert-GmsaName {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Name
    )

    Assert-SimpleRdnValue -Value $Value -Name $Name
    if ($Value -notmatch '^[A-Za-z][A-Za-z0-9_-]{0,18}$') {
        throw "$Name must be 1-19 characters, start with a letter, and contain only letters, digits, underscore, or hyphen: '$Value'"
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

function Get-AdSchemaObjectOrNull {
    param(
        [Parameter(Mandatory = $true)][string]$LdapDisplayName,
        [Parameter(Mandatory = $true)][string]$ObjectClass
    )

    $rootDse = Get-ADRootDSE @AdServerParameters -ErrorAction Stop
    $schemaNc = [string]$rootDse.schemaNamingContext
    $escapedName = ConvertTo-LdapFilterValue -Value $LdapDisplayName
    $escapedClass = ConvertTo-LdapFilterValue -Value $ObjectClass
    $objects = @(Get-ADObject -SearchBase $schemaNc -SearchScope OneLevel -LDAPFilter "(&(objectClass=$escapedClass)(lDAPDisplayName=$escapedName))" -Properties lDAPDisplayName, schemaIDGUID @AdServerParameters -ErrorAction Stop)
    if ($objects.Count -gt 1) {
        throw "Multiple schema objects were returned for lDAPDisplayName '$LdapDisplayName'."
    }
    if ($objects.Count -eq 0) {
        return $null
    }
    return $objects[0]
}

function Get-AdAttributeSchemaGuid {
    param([Parameter(Mandatory = $true)][string]$LdapDisplayName)

    $schemaObject = Get-AdSchemaObjectOrNull -LdapDisplayName $LdapDisplayName -ObjectClass 'attributeSchema'
    if ($null -eq $schemaObject) {
        throw "Required schema attribute '$LdapDisplayName' was not found."
    }
    return (ConvertTo-GuidValue -Value $schemaObject.schemaIDGUID -Context "schemaIDGUID for $LdapDisplayName")
}

function Get-ScenarioUserBySamOrNull {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)

    $escapedSam = ConvertTo-LdapFilterValue -Value $SamAccountName
    $users = @(Get-ADUser -LDAPFilter "(sAMAccountName=$escapedSam)" -Properties SID @AdServerParameters -ErrorAction Stop)
    if ($users.Count -gt 1) {
        throw "Multiple users were returned for sAMAccountName '$SamAccountName'."
    }
    if ($users.Count -eq 0) {
        return $null
    }
    return $users[0]
}

function Get-ScenarioGroupOrNull {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)

    $escapedName = ConvertTo-LdapFilterValue -Value $SamAccountName
    $groups = @(Get-ADGroup -LDAPFilter "(sAMAccountName=$escapedName)" -Properties adminDescription, Member, SID @AdServerParameters -ErrorAction Stop)
    if ($groups.Count -gt 1) {
        throw "Multiple groups were returned for sAMAccountName '$SamAccountName'."
    }
    if ($groups.Count -eq 0) {
        return $null
    }
    return $groups[0]
}

function Get-ScenarioServiceAccountOrNull {
    param([Parameter(Mandatory = $true)][string]$Name)

    try {
        return Get-ADServiceAccount -Identity $Name -Properties adminDescription, MemberOf, SID @AdServerParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

function Get-BuiltinGroupOrNull {
    param([Parameter(Mandatory = $true)][string]$Identity)

    try {
        return Get-ADGroup -Identity $Identity -Properties Member, SID @AdServerParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
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

function Remove-ScenarioMemberWriteAce {
    param(
        [Parameter(Mandatory = $true)][string]$GroupDistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid,
        [Parameter(Mandatory = $true)][Guid]$MemberAttributeGuid
    )

    Ensure-AdDrive
    $path = "AD:\$GroupDistinguishedName"
    $acl = Get-Acl -Path $path -ErrorAction Stop
    $rulesToRemove = @($acl.Access | Where-Object {
        -not $_.IsInherited `
            -and [string]$_.AccessControlType -eq 'Allow' `
            -and (($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -eq [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) `
            -and ([Guid]$_.ObjectType -eq $MemberAttributeGuid) `
            -and (Test-IdentityReferenceMatchesSid -IdentityReference $_.IdentityReference -Sid $PrincipalSid)
    })
    if ($rulesToRemove.Count -eq 0) {
        return 0
    }

    if ($PSCmdlet.ShouldProcess($GroupDistinguishedName, "Remove scenario WriteProperty ACE for $script:MemberAttribute")) {
        foreach ($rule in $rulesToRemove) {
            [void]$acl.RemoveAccessRuleSpecific($rule)
        }
        Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
        $script:Changed = $true
    }
    return $rulesToRemove.Count
}

function Remove-BackupOperatorsMembership {
    param([Parameter(Mandatory = $true)]$Gmsa)

    $backupOperators = Get-BuiltinGroupOrNull -Identity 'Backup Operators'
    if ($null -eq $backupOperators) {
        return $false
    }
    $members = @($backupOperators.Member | ForEach-Object { [string]$_ })
    if ($members -notcontains [string]$Gmsa.DistinguishedName) {
        return $false
    }

    if ($PSCmdlet.ShouldProcess($backupOperators.DistinguishedName, "Remove gMSA $($Gmsa.Name) from Backup Operators")) {
        Remove-ADGroupMember -Identity $backupOperators.DistinguishedName -Members $Gmsa.DistinguishedName -Confirm:$false @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }
    return $true
}

function Remove-ScenarioServiceAccount {
    param([Parameter(Mandatory = $true)]$Gmsa)

    if ([string]$Gmsa.adminDescription -cne $script:Marker) {
        throw "gMSA '$($Gmsa.Name)' exists but is not marked for this scenario. Refusing cleanup."
    }

    [void](Remove-BackupOperatorsMembership -Gmsa $Gmsa)
    if ($PSCmdlet.ShouldProcess($Gmsa.DistinguishedName, 'Delete scenario gMSA')) {
        Remove-ADServiceAccount -Identity $Gmsa.DistinguishedName -Confirm:$false @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }
}

function Remove-ScenarioGroup {
    param([Parameter(Mandatory = $true)]$Group)

    if ([string]$Group.adminDescription -cne $script:Marker) {
        throw "Group '$($Group.SamAccountName)' exists but is not marked for this scenario. Refusing cleanup."
    }

    if ($PSCmdlet.ShouldProcess($Group.DistinguishedName, 'Delete scenario gMSA reader group')) {
        Remove-ADGroup -Identity $Group.DistinguishedName -Confirm:$false @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }
}

function Assert-BaselineRestored {
    param(
        [Parameter(Mandatory = $true)][string]$ServiceAccountName,
        [Parameter(Mandatory = $true)][string]$GroupName
    )

    $currentGmsa = Get-ScenarioServiceAccountOrNull -Name $ServiceAccountName
    $currentGroup = Get-ScenarioGroupOrNull -SamAccountName $GroupName
    if ($null -ne $currentGmsa -or $null -ne $currentGroup) {
        throw "BaselineRestored check failed. Remaining objects: gMSA=$($null -ne $currentGmsa); group=$($null -ne $currentGroup)"
    }
}

Assert-GmsaName -Value $GmsaName -Name 'GmsaName'
Assert-SimpleRdnValue -Value $ReaderGroupName -Name 'ReaderGroupName'
Assert-SamAccountName -Value $ReaderGroupName -Name 'ReaderGroupName'
Assert-SamAccountName -Value $GroupMemberManagerSamAccountName -Name 'GroupMemberManagerSamAccountName'

$domain = Get-ADDomain @AdServerParameters -ErrorAction Stop
if ([string]$domain.DNSRoot -ine 'ad.lab.exceeds.test') {
    throw "Current domain '$($domain.DNSRoot)' is not the expected Baseline 06 domain 'ad.lab.exceeds.test'."
}

$gmsa = Get-ScenarioServiceAccountOrNull -Name $GmsaName
if ($null -ne $gmsa) {
    Remove-ScenarioServiceAccount -Gmsa $gmsa
}

$readerGroup = Get-ScenarioGroupOrNull -SamAccountName $ReaderGroupName
$removedAces = 0
if ($null -ne $readerGroup) {
    if ([string]$readerGroup.adminDescription -cne $script:Marker) {
        throw "Group '$ReaderGroupName' exists but is not marked for this scenario. Refusing cleanup."
    }

    $memberManager = Get-ScenarioUserBySamOrNull -SamAccountName $GroupMemberManagerSamAccountName
    if ($null -ne $memberManager) {
        $memberAttributeGuid = Get-AdAttributeSchemaGuid -LdapDisplayName $script:MemberAttribute
        $removedAces += Remove-ScenarioMemberWriteAce `
            -GroupDistinguishedName ([string]$readerGroup.DistinguishedName) `
            -PrincipalSid ([Security.Principal.SecurityIdentifier]$memberManager.SID) `
            -MemberAttributeGuid $memberAttributeGuid
    }
    Remove-ScenarioGroup -Group $readerGroup
}

$baselineRestored = $true
if (-not $WhatIfPreference) {
    Assert-BaselineRestored -ServiceAccountName $GmsaName -GroupName $ReaderGroupName
}
else {
    $baselineRestored = $false
}

[pscustomobject]@{
    Scenario            = $script:ScenarioName
    Changed             = $script:Changed
    RemovedMemberAces   = $removedAces
    KdsRootKeyPreserved = $true
    BaselineRestored    = $baselineRestored
}
