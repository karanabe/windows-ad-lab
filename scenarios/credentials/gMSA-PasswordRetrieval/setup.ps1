#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$GmsaName = 'gmsa_web',
    [string]$AuthorizedComputerName = 'WEB01',
    [string]$ControlComputerName = 'FILE01',
    [string]$ReaderGroupName = 'GG_gMSA_Readers',
    [string]$ReaderGroupMemberSamAccountName = 'john.smith',
    [string]$GroupMemberManagerSamAccountName = 'operator01',
    [bool]$IncludeReaderGroupMisconfiguration = $true,
    [bool]$IncludeBackupOperatorsMembership = $true,
    [switch]$CreateKdsRootKeyIfMissing,
    [string[]]$ServicePrincipalNames = @(),
    [ValidateRange(1, 365)][int]$ManagedPasswordIntervalDays = 30,
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'gMSA-PasswordRetrieval'
$script:Marker = 'windows-ad-lab:gMSA-PasswordRetrieval'
$script:RootOuName = 'LAB'
$script:ScenarioDescription = 'LAB ONLY: gMSA password retrieval observation principal'
$script:GmsaDescription = 'LAB ONLY: gMSA retrieval permission observation account'
$script:Changed = $false
$script:GmsaMembershipAttribute = 'msDS-GroupMSAMembership'
$script:GmsaManagedPasswordAttribute = 'msDS-ManagedPassword'
$script:GmsaManagedPasswordIntervalAttribute = 'msDS-ManagedPasswordInterval'
$script:MemberAttribute = 'member'
$AdServerParameters = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $AdServerParameters['Server'] = $Server
}

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module Kds -ErrorAction Stop

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

function ConvertTo-StringArray {
    param([AllowNull()]$Value)

    if ($null -eq $Value) {
        return @()
    }
    $valueObject = $Value.PSObject.BaseObject
    if ($valueObject -is [array] -and -not ($valueObject -is [byte[]])) {
        return @($valueObject | ForEach-Object { [string]$_ })
    }
    if ($valueObject -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) {
        return @($valueObject | ForEach-Object { [string]$_ })
    }
    return @([string]$valueObject)
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

function Assert-GmsaSchema {
    foreach ($schemaSpec in @(
        @{ Name = 'msDS-GroupManagedServiceAccount'; Class = 'classSchema' },
        @{ Name = $script:GmsaMembershipAttribute; Class = 'attributeSchema' },
        @{ Name = $script:GmsaManagedPasswordAttribute; Class = 'attributeSchema' },
        @{ Name = $script:GmsaManagedPasswordIntervalAttribute; Class = 'attributeSchema' }
    )) {
        $schemaObject = Get-AdSchemaObjectOrNull -LdapDisplayName ([string]$schemaSpec.Name) -ObjectClass ([string]$schemaSpec.Class)
        if ($null -eq $schemaObject) {
            throw "Required gMSA schema object '$($schemaSpec.Name)' was not found."
        }
        [void](ConvertTo-GuidValue -Value $schemaObject.schemaIDGUID -Context "schemaIDGUID for $($schemaSpec.Name)")
    }
}

function Get-AdAttributeSchemaGuid {
    param([Parameter(Mandatory = $true)][string]$LdapDisplayName)

    $schemaObject = Get-AdSchemaObjectOrNull -LdapDisplayName $LdapDisplayName -ObjectClass 'attributeSchema'
    if ($null -eq $schemaObject) {
        throw "Required schema attribute '$LdapDisplayName' was not found."
    }
    return (ConvertTo-GuidValue -Value $schemaObject.schemaIDGUID -Context "schemaIDGUID for $LdapDisplayName")
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

function Get-ScenarioComputerOrNull {
    param([Parameter(Mandatory = $true)][string]$ComputerName)

    try {
        return Get-ADComputer -Identity $ComputerName -Properties Description, Enabled, SID @AdServerParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

function Get-ScenarioUserBySamOrNull {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)

    $escapedSam = ConvertTo-LdapFilterValue -Value $SamAccountName
    $users = @(Get-ADUser -LDAPFilter "(sAMAccountName=$escapedSam)" -Properties Enabled, SID @AdServerParameters -ErrorAction Stop)
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
    $groups = @(Get-ADGroup -LDAPFilter "(sAMAccountName=$escapedName)" -Properties adminDescription, Description, Member, SID @AdServerParameters -ErrorAction Stop)
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
        return Get-ADServiceAccount `
            -Identity $Name `
            -Properties adminDescription, Description, DisplayName, DNSHostName, Enabled, MemberOf, msDS-GroupMSAMembership, msDS-ManagedPasswordInterval, PrincipalsAllowedToRetrieveManagedPassword, ServicePrincipalName, SID `
            @AdServerParameters `
            -ErrorAction Stop
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

function ConvertTo-RawSecurityDescriptor {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)][string]$AttributeName,
        [Parameter(Mandatory = $true)][string]$DistinguishedName
    )

    $singleValue = ConvertTo-SingleAdValue -Value $Value -AttributeName $AttributeName -DistinguishedName $DistinguishedName
    if ($null -eq $singleValue) {
        return $null
    }
    $valueObject = $singleValue.PSObject.BaseObject
    if ($valueObject -is [System.Security.AccessControl.RawSecurityDescriptor]) {
        return $valueObject
    }
    if ($valueObject -is [System.DirectoryServices.ActiveDirectorySecurity]) {
        $sddl = $valueObject.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
        return New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $sddl
    }
    if ($valueObject -is [byte[]]) {
        return [System.Security.AccessControl.RawSecurityDescriptor]::new([byte[]]$valueObject, 0)
    }
    if ($valueObject -is [string]) {
        return New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList ([string]$valueObject)
    }
    throw "Attribute '$AttributeName' on '$DistinguishedName' returned unsupported value type '$($valueObject.GetType().FullName)'."
}

function Get-DescriptorAllowedSidValues {
    param([AllowNull()][System.Security.AccessControl.RawSecurityDescriptor]$Descriptor)

    if ($null -eq $Descriptor -or $null -eq $Descriptor.DiscretionaryAcl) {
        return @()
    }

    $sids = New-Object 'System.Collections.Generic.List[string]'
    foreach ($ace in $Descriptor.DiscretionaryAcl) {
        if ($ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowed) {
            continue
        }
        if ($null -eq $ace.SecurityIdentifier) {
            continue
        }
        [void]$sids.Add([string]$ace.SecurityIdentifier.Value)
    }
    return [string[]]($sids.ToArray() | Sort-Object -Unique)
}

function Test-SameStringSet {
    param(
        [AllowEmptyCollection()][string[]]$Expected = @(),
        [AllowEmptyCollection()][string[]]$Actual = @()
    )

    $expectedSet = @($Expected | Sort-Object -Unique)
    $actualSet = @($Actual | Sort-Object -Unique)
    if ($expectedSet.Count -ne $actualSet.Count) {
        return $false
    }
    return (@(Compare-Object -ReferenceObject $expectedSet -DifferenceObject $actualSet).Count -eq 0)
}

function Test-GmsaRetrievePrincipals {
    param(
        [Parameter(Mandatory = $true)]$Gmsa,
        [Parameter(Mandatory = $true)][object[]]$AllowedPrincipals
    )

    $descriptor = ConvertTo-RawSecurityDescriptor -Value $Gmsa.($script:GmsaMembershipAttribute) -AttributeName $script:GmsaMembershipAttribute -DistinguishedName ([string]$Gmsa.DistinguishedName)
    $actualSidValues = @(Get-DescriptorAllowedSidValues -Descriptor $descriptor)
    $expectedSidValues = @($AllowedPrincipals | ForEach-Object { [string]([Security.Principal.SecurityIdentifier]$_.SID).Value })
    return (Test-SameStringSet -Expected $expectedSidValues -Actual $actualSidValues)
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

function Ensure-ScenarioGroup {
    param(
        [Parameter(Mandatory = $true)][string]$GroupName,
        [Parameter(Mandatory = $true)][string]$GroupsOuDn,
        [Parameter(Mandatory = $true)]$ReaderGroupMember
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
        Write-Host "WhatIf: scenario group '$GroupName' was not created, so dependent gMSA retrieval-policy changes are skipped."
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
    if ($members -notcontains [string]$ReaderGroupMember.DistinguishedName) {
        if ($PSCmdlet.ShouldProcess($group.DistinguishedName, "Add member $($ReaderGroupMember.SamAccountName)")) {
            Add-ADGroupMember -Identity $group.DistinguishedName -Members $ReaderGroupMember.DistinguishedName @AdServerParameters -ErrorAction Stop
            $script:Changed = $true
        }
    }

    return (Get-ScenarioGroupOrNull -SamAccountName $GroupName)
}

function Ensure-MemberWriteDelegation {
    param(
        [Parameter(Mandatory = $true)]$Group,
        [Parameter(Mandatory = $true)]$MemberManager,
        [Parameter(Mandatory = $true)][Guid]$MemberAttributeGuid
    )

    $managerSid = [Security.Principal.SecurityIdentifier]$MemberManager.SID
    [void](Remove-ScenarioMemberWriteAce -GroupDistinguishedName ([string]$Group.DistinguishedName) -PrincipalSid $managerSid -MemberAttributeGuid $MemberAttributeGuid)

    Ensure-AdDrive
    $path = "AD:\$($Group.DistinguishedName)"
    $acl = Get-Acl -Path $path -ErrorAction Stop
    if ($PSCmdlet.ShouldProcess($Group.DistinguishedName, "Grant WriteProperty on $script:MemberAttribute to $($MemberManager.SamAccountName)")) {
        $rule = New-Object `
            -TypeName System.DirectoryServices.ActiveDirectoryAccessRule `
            -ArgumentList $managerSid, ([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty), ([System.Security.AccessControl.AccessControlType]::Allow), $MemberAttributeGuid
        [void]$acl.AddAccessRule($rule)
        Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
        $script:Changed = $true
    }
}

function Ensure-KdsRootKey {
    param([switch]$CreateIfMissing)

    $rootKeys = @(Get-KdsRootKey -ErrorAction Stop)
    if ($rootKeys.Count -gt 0) {
        return [pscustomobject]@{
            Present = $true
            Created = $false
            Count   = $rootKeys.Count
        }
    }

    if (-not $CreateIfMissing) {
        throw "KDS root key was not found. This is not a conflict with other scenarios; a KDS root key is a forest-wide prerequisite for gMSA password generation. Rerun with -ScriptParameters @{ CreateKdsRootKeyIfMissing = `$true } only if this isolated single-DC lab checkpoint may receive an additive KDS root key. Cleanup intentionally preserves KDS root keys; use checkpoint restore for exact baseline schema/configuration."
    }

    $domainControllers = @(Get-ADDomainController -Filter * @AdServerParameters -ErrorAction Stop)
    if ($domainControllers.Count -ne 1) {
        throw "CreateKdsRootKeyIfMissing is only supported by this scenario in a single-DC lab; found $($domainControllers.Count) domain controllers."
    }

    if ($PSCmdlet.ShouldProcess($domainControllers[0].HostName, 'Create single-DC lab KDS root key with past effective time')) {
        Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) -ErrorAction Stop | Out-Null
        $script:Changed = $true
    }

    $rootKeysAfterCreate = @(Get-KdsRootKey -ErrorAction Stop)
    if ($rootKeysAfterCreate.Count -eq 0 -and -not $WhatIfPreference) {
        throw 'KDS root key is still missing after Add-KdsRootKey.'
    }
    return [pscustomobject]@{
        Present = ($rootKeysAfterCreate.Count -gt 0)
        Created = $true
        Count   = $rootKeysAfterCreate.Count
    }
}

function Ensure-GmsaAccount {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ServiceAccountsOuDn,
        [Parameter(Mandatory = $true)][string]$DnsHostName,
        [Parameter(Mandatory = $true)][string[]]$DesiredServicePrincipalNames,
        [Parameter(Mandatory = $true)][object[]]$AllowedPrincipals,
        [Parameter(Mandatory = $true)][int]$PasswordIntervalDays
    )

    $gmsa = Get-ScenarioServiceAccountOrNull -Name $Name
    if ($null -eq $gmsa) {
        if ($PSCmdlet.ShouldProcess($Name, "Create gMSA in $ServiceAccountsOuDn")) {
            New-ADServiceAccount `
                -Name $Name `
                -SamAccountName "$Name$" `
                -DNSHostName $DnsHostName `
                -Path $ServiceAccountsOuDn `
                -Description $script:GmsaDescription `
                -DisplayName $Name `
                -Enabled $true `
                -ManagedPasswordIntervalInDays $PasswordIntervalDays `
                -ServicePrincipalNames $DesiredServicePrincipalNames `
                -PrincipalsAllowedToRetrieveManagedPassword @($AllowedPrincipals | ForEach-Object { [string]$_.DistinguishedName }) `
                -OtherAttributes @{ adminDescription = $script:Marker } `
                @AdServerParameters `
                -ErrorAction Stop | Out-Null
            $script:Changed = $true
        }
        $gmsa = Get-ScenarioServiceAccountOrNull -Name $Name
    }

    if ($null -eq $gmsa) {
        Write-Host "WhatIf: gMSA '$Name' was not created, so gMSA updates are skipped."
        return $null
    }
    if ([string]$gmsa.adminDescription -cne $script:Marker -or [string]$gmsa.DistinguishedName -ine "CN=$Name,$ServiceAccountsOuDn") {
        throw "gMSA '$Name' already exists outside this scenario. Refusing to modify it."
    }

    $replace = @{}
    if ([string]$gmsa.Description -cne $script:GmsaDescription) {
        $replace['description'] = $script:GmsaDescription
    }
    if ([string]$gmsa.DisplayName -cne $Name) {
        $replace['displayName'] = $Name
    }
    if ([string]$gmsa.adminDescription -cne $script:Marker) {
        $replace['adminDescription'] = $script:Marker
    }
    if ($replace.Count -gt 0 -and $PSCmdlet.ShouldProcess($gmsa.DistinguishedName, 'Update scenario gMSA metadata')) {
        Set-ADObject -Identity $gmsa.DistinguishedName -Replace $replace @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }

    $currentInterval = ConvertTo-SingleAdValue -Value $gmsa.($script:GmsaManagedPasswordIntervalAttribute) -AttributeName $script:GmsaManagedPasswordIntervalAttribute -DistinguishedName ([string]$gmsa.DistinguishedName)
    if ($null -ne $currentInterval -and [int]$currentInterval -ne $PasswordIntervalDays) {
        throw "Scenario gMSA '$Name' has managed password interval '$currentInterval', expected '$PasswordIntervalDays'. This value is set when the gMSA is created; run cleanup and setup again to recreate it."
    }

    $desiredSpns = @($DesiredServicePrincipalNames | Sort-Object -Unique)
    $currentSpns = @(ConvertTo-StringArray -Value $gmsa.ServicePrincipalName | Sort-Object -Unique)
    if (-not (Test-SameStringSet -Expected $desiredSpns -Actual $currentSpns)) {
        if ($PSCmdlet.ShouldProcess($gmsa.DistinguishedName, 'Replace scenario gMSA SPNs')) {
            Set-ADServiceAccount -Identity $gmsa.DistinguishedName -ServicePrincipalNames @{ Replace = $desiredSpns } @AdServerParameters -ErrorAction Stop
            $script:Changed = $true
        }
    }

    $gmsa = Get-ScenarioServiceAccountOrNull -Name $Name
    if ($null -ne $gmsa -and -not (Test-GmsaRetrievePrincipals -Gmsa $gmsa -AllowedPrincipals $AllowedPrincipals)) {
        if ($PSCmdlet.ShouldProcess($gmsa.DistinguishedName, 'Set PrincipalsAllowedToRetrieveManagedPassword')) {
            Set-ADServiceAccount `
                -Identity $gmsa.DistinguishedName `
                -PrincipalsAllowedToRetrieveManagedPassword @($AllowedPrincipals | ForEach-Object { [string]$_.DistinguishedName }) `
                @AdServerParameters `
                -ErrorAction Stop
            $script:Changed = $true
        }
    }

    return (Get-ScenarioServiceAccountOrNull -Name $Name)
}

function Set-BackupOperatorsMembership {
    param(
        [Parameter(Mandatory = $true)]$Gmsa,
        [Parameter(Mandatory = $true)][bool]$Enabled
    )

    $backupOperators = Get-BuiltinGroupOrNull -Identity 'Backup Operators'
    if ($null -eq $backupOperators) {
        throw "Built-in group 'Backup Operators' was not found."
    }

    $members = @($backupOperators.Member | ForEach-Object { [string]$_ })
    $isMember = ($members -contains [string]$Gmsa.DistinguishedName)
    if ($Enabled -and -not $isMember) {
        if ($PSCmdlet.ShouldProcess($backupOperators.DistinguishedName, "Add gMSA $($Gmsa.Name) to Backup Operators")) {
            Add-ADGroupMember -Identity $backupOperators.DistinguishedName -Members $Gmsa.DistinguishedName @AdServerParameters -ErrorAction Stop
            $script:Changed = $true
        }
    }
    elseif (-not $Enabled -and $isMember) {
        if ($PSCmdlet.ShouldProcess($backupOperators.DistinguishedName, "Remove gMSA $($Gmsa.Name) from Backup Operators")) {
            Remove-ADGroupMember -Identity $backupOperators.DistinguishedName -Members $Gmsa.DistinguishedName -Confirm:$false @AdServerParameters -ErrorAction Stop
            $script:Changed = $true
        }
    }
}

Assert-GmsaName -Value $GmsaName -Name 'GmsaName'
Assert-ComputerName -Value $AuthorizedComputerName -Name 'AuthorizedComputerName'
Assert-ComputerName -Value $ControlComputerName -Name 'ControlComputerName'
if ($AuthorizedComputerName -ieq $ControlComputerName) {
    throw 'AuthorizedComputerName and ControlComputerName must be different.'
}
Assert-SimpleRdnValue -Value $ReaderGroupName -Name 'ReaderGroupName'
Assert-SamAccountName -Value $ReaderGroupName -Name 'ReaderGroupName'
Assert-SamAccountName -Value $ReaderGroupMemberSamAccountName -Name 'ReaderGroupMemberSamAccountName'
Assert-SamAccountName -Value $GroupMemberManagerSamAccountName -Name 'GroupMemberManagerSamAccountName'
if ($ReaderGroupMemberSamAccountName -ieq $GroupMemberManagerSamAccountName) {
    throw 'ReaderGroupMemberSamAccountName and GroupMemberManagerSamAccountName must be different.'
}

$domain = Get-ADDomain @AdServerParameters -ErrorAction Stop
if ([string]$domain.DNSRoot -ine 'ad.lab.exceeds.test') {
    throw "Current domain '$($domain.DNSRoot)' is not the expected Baseline 06 domain 'ad.lab.exceeds.test'."
}

Assert-GmsaSchema
$kdsState = Ensure-KdsRootKey -CreateIfMissing:$CreateKdsRootKeyIfMissing

$domainDn = [string]$domain.DistinguishedName
$rootOuDn = "OU=$script:RootOuName,$domainDn"
$groupsOuDn = "OU=Groups,$rootOuDn"
$serviceAccountsOuDn = "OU=Service Accounts,$rootOuDn"
$serversOuDn = "OU=Servers,OU=Computers,$rootOuDn"
foreach ($ouDn in @($rootOuDn, $groupsOuDn, $serviceAccountsOuDn, $serversOuDn)) {
    if ($null -eq (Get-AdOrganizationalUnitOrNull -DistinguishedName $ouDn)) {
        throw "Required Baseline 06 OU '$ouDn' was not found. Restore 06-ADCS-HTTP-CDP before running this scenario."
    }
}

$authorizedComputer = Get-ScenarioComputerOrNull -ComputerName $AuthorizedComputerName
$controlComputer = Get-ScenarioComputerOrNull -ComputerName $ControlComputerName
foreach ($computerSpec in @(
    @{ Name = $AuthorizedComputerName; Computer = $authorizedComputer },
    @{ Name = $ControlComputerName; Computer = $controlComputer }
)) {
    if ($null -eq $computerSpec.Computer) {
        throw "Required Baseline 06 computer '$($computerSpec.Name)' was not found."
    }
    if ([string]$computerSpec.Computer.DistinguishedName -notlike "*,$serversOuDn") {
        throw "Computer '$($computerSpec.Name)' is not under '$serversOuDn'."
    }
}

$readerMember = Get-ScenarioUserBySamOrNull -SamAccountName $ReaderGroupMemberSamAccountName
if ($null -eq $readerMember) {
    throw "Reader group member '$ReaderGroupMemberSamAccountName' was not found in Baseline 06."
}
$memberManager = Get-ScenarioUserBySamOrNull -SamAccountName $GroupMemberManagerSamAccountName
if ($null -eq $memberManager) {
    throw "Group member manager '$GroupMemberManagerSamAccountName' was not found in Baseline 06."
}

$readerGroup = Ensure-ScenarioGroup -GroupName $ReaderGroupName -GroupsOuDn $groupsOuDn -ReaderGroupMember $readerMember
$memberAttributeGuid = Get-AdAttributeSchemaGuid -LdapDisplayName $script:MemberAttribute
if ($null -ne $readerGroup) {
    Ensure-MemberWriteDelegation -Group $readerGroup -MemberManager $memberManager -MemberAttributeGuid $memberAttributeGuid
}

$desiredSpns = @($ServicePrincipalNames | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { [string]$_ })
if ($desiredSpns.Count -eq 0) {
    $desiredSpns = @(
        "HTTP/$AuthorizedComputerName",
        "HTTP/$AuthorizedComputerName.$($domain.DNSRoot)"
    )
}
$desiredSpns = [string[]]($desiredSpns | Sort-Object -Unique)

$allowedPrincipals = New-Object 'System.Collections.Generic.List[object]'
[void]$allowedPrincipals.Add($authorizedComputer)
if ($IncludeReaderGroupMisconfiguration -and $null -ne $readerGroup) {
    [void]$allowedPrincipals.Add($readerGroup)
}

$gmsa = Ensure-GmsaAccount `
    -Name $GmsaName `
    -ServiceAccountsOuDn $serviceAccountsOuDn `
    -DnsHostName "$GmsaName.$($domain.DNSRoot)" `
    -DesiredServicePrincipalNames $desiredSpns `
    -AllowedPrincipals $allowedPrincipals.ToArray() `
    -PasswordIntervalDays $ManagedPasswordIntervalDays

if ($null -ne $gmsa) {
    Set-BackupOperatorsMembership -Gmsa $gmsa -Enabled $IncludeBackupOperatorsMembership
}

[pscustomobject]@{
    Scenario                                = $script:ScenarioName
    Changed                                 = $script:Changed
    Baseline                                = '06-ADCS-HTTP-CDP'
    Gmsa                                    = "$($domain.NetBIOSName)\$GmsaName$"
    AuthorizedComputer                      = "$($domain.NetBIOSName)\$AuthorizedComputerName$"
    ControlComputer                         = "$($domain.NetBIOSName)\$ControlComputerName$"
    ReaderGroup                             = "$($domain.NetBIOSName)\$ReaderGroupName"
    ReaderGroupMember                       = $ReaderGroupMemberSamAccountName
    GroupMemberManager                      = $GroupMemberManagerSamAccountName
    ReaderGroupMisconfigurationEnabled      = $IncludeReaderGroupMisconfiguration
    BackupOperatorsOverprivilegeEnabled     = $IncludeBackupOperatorsMembership
    KdsRootKeyPresent                       = [bool]$kdsState.Present
    KdsRootKeyCreated                       = [bool]$kdsState.Created
    KdsRootKeyCount                         = [int]$kdsState.Count
    ManagedPasswordIntervalDays             = $ManagedPasswordIntervalDays
    ManagedPasswordValueLogged              = $false
}
