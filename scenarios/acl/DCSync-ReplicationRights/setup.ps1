#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$DelegatedUserSamAccountName = 'svc_backup',
    [string]$ControlUserSamAccountName = 'operator01',
    [string]$RightsGroupName = 'GG_DCSync_Ops',
    [string]$ReaderGroupName = 'GG_DCSync_Readers',
    [bool]$IncludeFilteredSetRight = $true,
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'DCSync-ReplicationRights'
$script:Marker = 'windows-ad-lab:DCSync-ReplicationRights'
$script:RootOuName = 'LAB'
$script:ScenarioDescription = 'LAB ONLY: DCSync replication rights observation group'
$script:Changed = $false
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

function ConvertTo-StringArray {
    param([AllowNull()]$Value)

    if ($null -eq $Value) {
        return @()
    }
    $valueObject = $Value.PSObject.BaseObject
    if ($valueObject -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) {
        return @($valueObject | ForEach-Object { [string]$_ })
    }
    if ($valueObject -is [array] -and -not ($valueObject -is [byte[]])) {
        return @($valueObject | ForEach-Object { [string]$_ })
    }
    return @([string]$valueObject)
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

function Get-DcsyncReplicationRightSpecs {
    param([bool]$IncludeFilteredSet)

    $rights = @(
        [pscustomobject]@{
            Name        = 'DS-Replication-Get-Changes'
            DisplayName = 'Replicating Directory Changes'
            Guid        = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        },
        [pscustomobject]@{
            Name        = 'DS-Replication-Get-Changes-All'
            DisplayName = 'Replicating Directory Changes All'
            Guid        = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
        }
    )
    if ($IncludeFilteredSet) {
        $rights += [pscustomobject]@{
            Name        = 'DS-Replication-Get-Changes-In-Filtered-Set'
            DisplayName = 'Replicating Directory Changes In Filtered Set'
            Guid        = [guid]'89e95b76-444d-4c62-991a-0facbeda640c'
        }
    }
    return $rights
}

function Assert-DcsyncControlAccessRights {
    param([bool]$IncludeFilteredSet)

    $rootDse = Get-ADRootDSE @AdServerParameters -ErrorAction Stop
    $extendedRightsContainer = "CN=Extended-Rights,$($rootDse.configurationNamingContext)"
    foreach ($right in @(Get-DcsyncReplicationRightSpecs -IncludeFilteredSet $IncludeFilteredSet)) {
        $escapedGuid = ConvertTo-LdapFilterValue -Value ([string]$right.Guid)
        $objects = @(Get-ADObject `
                -SearchBase $extendedRightsContainer `
                -SearchScope OneLevel `
                -LDAPFilter "(&(objectClass=controlAccessRight)(rightsGuid=$escapedGuid))" `
                -Properties cn, displayName, rightsGuid `
                @AdServerParameters `
                -ErrorAction Stop)
        if ($objects.Count -ne 1) {
            throw "Expected one controlAccessRight for '$($right.Name)' with rightsGuid '$($right.Guid)', found $($objects.Count)."
        }
        if ([string]$objects[0].cn -cne [string]$right.Name) {
            throw "ControlAccessRight '$($right.Guid)' has CN '$($objects[0].cn)', expected '$($right.Name)'."
        }
    }
}

function Get-ScenarioUserBySamOrNull {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)

    $escapedSam = ConvertTo-LdapFilterValue -Value $SamAccountName
    $users = @(Get-ADUser -LDAPFilter "(sAMAccountName=$escapedSam)" -Properties Enabled, SID, MemberOf @AdServerParameters -ErrorAction Stop)
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

function Ensure-ScenarioGroup {
    param(
        [Parameter(Mandatory = $true)][string]$GroupName,
        [Parameter(Mandatory = $true)][string]$GroupsOuDn
    )

    Assert-SimpleRdnValue -Value $GroupName -Name 'GroupName'
    Assert-SamAccountName -Value $GroupName -Name 'GroupName'

    $group = Get-ScenarioGroupOrNull -SamAccountName $GroupName
    if ($null -eq $group) {
        if ($PSCmdlet.ShouldProcess("CN=$GroupName,$GroupsOuDn", 'Create DCSync scenario group')) {
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
        throw "Scenario group '$GroupName' was not found after creation."
    }
    if ([string]$group.DistinguishedName -ine "CN=$GroupName,$GroupsOuDn") {
        throw "Group '$GroupName' exists outside the scenario OU: $($group.DistinguishedName). Refusing to reuse it."
    }
    if ([string]$group.adminDescription -cne $script:Marker) {
        throw "Group '$GroupName' exists but is not scenario-marked. Refusing to modify it."
    }

    $replace = @{}
    if ([string]$group.Description -cne $script:ScenarioDescription) {
        $replace['description'] = $script:ScenarioDescription
    }
    if ($replace.Count -gt 0 -and $PSCmdlet.ShouldProcess($group.DistinguishedName, 'Update DCSync scenario group metadata')) {
        Set-ADGroup -Identity $group.DistinguishedName -Replace $replace @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
        $group = Get-ScenarioGroupOrNull -SamAccountName $GroupName
    }

    return $group
}

function Ensure-GroupMember {
    param(
        [Parameter(Mandatory = $true)]$Group,
        [Parameter(Mandatory = $true)][string]$MemberDistinguishedName,
        [Parameter(Mandatory = $true)][string]$MemberLabel
    )

    $members = @(ConvertTo-StringArray -Value $Group.Member)
    if ($members -icontains $MemberDistinguishedName) {
        return $false
    }

    if ($PSCmdlet.ShouldProcess($Group.DistinguishedName, "Add member $MemberLabel")) {
        Add-ADGroupMember -Identity $Group.DistinguishedName -Members $MemberDistinguishedName @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }
    return $true
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

function Test-DcsyncRightAce {
    param(
        [Parameter(Mandatory = $true)]$AccessRule,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid,
        [Parameter(Mandatory = $true)][Guid]$RightGuid
    )

    if ($AccessRule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }
    if (-not (Test-IdentityReferenceMatchesSid -IdentityReference $AccessRule.IdentityReference -Sid $PrincipalSid)) { return $false }
    if (($AccessRule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) { return $false }
    return ($AccessRule.ObjectType -eq $RightGuid)
}

function Ensure-DcsyncRightAce {
    param(
        [Parameter(Mandatory = $true)][string]$DomainDistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid,
        [Parameter(Mandatory = $true)]$Right
    )

    Ensure-AdDrive
    $rightGuid = [guid]$Right.Guid
    $path = "AD:\$DomainDistinguishedName"
    $acl = Get-Acl -Path $path -ErrorAction Stop
    $existingRules = @($acl.Access | Where-Object {
        -not $_.IsInherited -and (Test-DcsyncRightAce -AccessRule $_ -PrincipalSid $PrincipalSid -RightGuid $rightGuid)
    })
    if ($existingRules.Count -gt 0) {
        return $false
    }

    $rule = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @(
        $PrincipalSid,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $rightGuid
    )
    if ($PSCmdlet.ShouldProcess($DomainDistinguishedName, "Grant $($Right.Name) to $RightsGroupName")) {
        $acl.AddAccessRule($rule)
        Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
        $script:Changed = $true
    }
    return $true
}

Assert-SamAccountName -Value $DelegatedUserSamAccountName -Name 'DelegatedUserSamAccountName'
Assert-SamAccountName -Value $ControlUserSamAccountName -Name 'ControlUserSamAccountName'
Assert-SamAccountName -Value $RightsGroupName -Name 'RightsGroupName'
Assert-SamAccountName -Value $ReaderGroupName -Name 'ReaderGroupName'
Assert-SimpleRdnValue -Value $RightsGroupName -Name 'RightsGroupName'
Assert-SimpleRdnValue -Value $ReaderGroupName -Name 'ReaderGroupName'
if ($DelegatedUserSamAccountName -ieq $ControlUserSamAccountName) {
    throw 'DelegatedUserSamAccountName and ControlUserSamAccountName must be different.'
}
if ($RightsGroupName -ieq $ReaderGroupName) {
    throw 'RightsGroupName and ReaderGroupName must be different.'
}

$domain = Get-ADDomain @AdServerParameters -ErrorAction Stop
if ([string]$domain.DNSRoot -ine 'ad.lab.exceeds.test') {
    throw "Current domain '$($domain.DNSRoot)' is not the expected Baseline 06 domain 'ad.lab.exceeds.test'."
}

$domainDn = [string]$domain.DistinguishedName
$rootOuDn = "OU=$script:RootOuName,$domainDn"
$groupsOuDn = "OU=Groups,$rootOuDn"
if ($null -eq (Get-ADOrganizationalUnit -Identity $rootOuDn @AdServerParameters -ErrorAction SilentlyContinue)) {
    throw "Baseline root OU '$rootOuDn' was not found. Restore 06-ADCS-HTTP-CDP before running this scenario."
}
if ($null -eq (Get-ADOrganizationalUnit -Identity $groupsOuDn @AdServerParameters -ErrorAction SilentlyContinue)) {
    throw "Baseline groups OU '$groupsOuDn' was not found. Restore 06-ADCS-HTTP-CDP before running this scenario."
}

Assert-DcsyncControlAccessRights -IncludeFilteredSet $IncludeFilteredSetRight

$delegatedUser = Get-ScenarioUserBySamOrNull -SamAccountName $DelegatedUserSamAccountName
$controlUser = Get-ScenarioUserBySamOrNull -SamAccountName $ControlUserSamAccountName
foreach ($requiredObject in @(
        @{ Name = $DelegatedUserSamAccountName; Object = $delegatedUser; Type = 'user' },
        @{ Name = $ControlUserSamAccountName; Object = $controlUser; Type = 'user' }
    )) {
    if ($null -eq $requiredObject.Object) {
        throw "Required baseline $($requiredObject.Type) '$($requiredObject.Name)' was not found. Restore 06-ADCS-HTTP-CDP before running this scenario."
    }
}

$rightsGroup = Ensure-ScenarioGroup -GroupName $RightsGroupName -GroupsOuDn $groupsOuDn
$readerGroup = Ensure-ScenarioGroup -GroupName $ReaderGroupName -GroupsOuDn $groupsOuDn

$delegatedUserMembershipChanged = Ensure-GroupMember -Group $readerGroup -MemberDistinguishedName ([string]$delegatedUser.DistinguishedName) -MemberLabel $DelegatedUserSamAccountName
$readerGroup = Get-ScenarioGroupOrNull -SamAccountName $ReaderGroupName
$readerNestedMembershipChanged = Ensure-GroupMember -Group $rightsGroup -MemberDistinguishedName ([string]$readerGroup.DistinguishedName) -MemberLabel $ReaderGroupName
$rightsGroup = Get-ScenarioGroupOrNull -SamAccountName $RightsGroupName

$aceChanges = New-Object 'System.Collections.Generic.List[object]'
foreach ($right in @(Get-DcsyncReplicationRightSpecs -IncludeFilteredSet $IncludeFilteredSetRight)) {
    $changed = Ensure-DcsyncRightAce -DomainDistinguishedName $domainDn -PrincipalSid $rightsGroup.SID -Right $right
    [void]$aceChanges.Add([pscustomobject]@{
            Name    = [string]$right.Name
            Guid    = [string]$right.Guid
            Changed = [bool]$changed
        })
}

[pscustomobject]@{
    Scenario                         = $script:ScenarioName
    Changed                          = $script:Changed
    Baseline                         = '06-ADCS-HTTP-CDP'
    Domain                           = $domainDn
    DelegatedUser                    = $delegatedUser.DistinguishedName
    ControlUser                      = $controlUser.DistinguishedName
    ReaderGroup                      = $readerGroup.DistinguishedName
    RightsGroup                      = $rightsGroup.DistinguishedName
    DelegatedUserMembershipChanged   = $delegatedUserMembershipChanged
    ReaderNestedMembershipChanged    = $readerNestedMembershipChanged
    IncludeFilteredSetRight          = $IncludeFilteredSetRight
    ReplicationRightChanges          = [object[]]$aceChanges.ToArray()
    CredentialReplicationExecuted    = $false
}
