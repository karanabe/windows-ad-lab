#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$DelegatedUserSamAccountName = 'svc_backup',
    [string]$RightsGroupName = 'GG_DCSync_Ops',
    [string]$ReaderGroupName = 'GG_DCSync_Readers',
    [bool]$IncludeFilteredSetRight = $true,
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'DCSync-ReplicationRights'
$script:Marker = 'windows-ad-lab:DCSync-ReplicationRights'
$script:Changed = $false
$AdServerParameters = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $AdServerParameters['Server'] = $Server
}

Import-Module ActiveDirectory -ErrorAction Stop

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
            Name = 'DS-Replication-Get-Changes'
            Guid = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        },
        [pscustomobject]@{
            Name = 'DS-Replication-Get-Changes-All'
            Guid = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
        }
    )
    if ($IncludeFilteredSet) {
        $rights += [pscustomobject]@{
            Name = 'DS-Replication-Get-Changes-In-Filtered-Set'
            Guid = [guid]'89e95b76-444d-4c62-991a-0facbeda640c'
        }
    }
    return $rights
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

function Assert-ScenarioGroupMarker {
    param(
        [AllowNull()]$Group,
        [Parameter(Mandatory = $true)][string]$GroupName
    )

    if ($null -eq $Group) {
        return
    }
    if ([string]$Group.adminDescription -cne $script:Marker) {
        throw "Group '$GroupName' exists but is not scenario-marked. Refusing cleanup."
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

function Remove-DcsyncRightAces {
    param(
        [Parameter(Mandatory = $true)][string]$DomainDistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    Ensure-AdDrive
    $path = "AD:\$DomainDistinguishedName"
    $acl = Get-Acl -Path $path -ErrorAction Stop
    $rulesToRemove = New-Object 'System.Collections.Generic.List[object]'
    foreach ($right in @(Get-DcsyncReplicationRightSpecs -IncludeFilteredSet $IncludeFilteredSetRight)) {
        foreach ($rule in @($acl.Access | Where-Object {
                    -not $_.IsInherited -and (Test-DcsyncRightAce -AccessRule $_ -PrincipalSid $PrincipalSid -RightGuid ([guid]$right.Guid))
                })) {
            [void]$rulesToRemove.Add($rule)
        }
    }
    if ($rulesToRemove.Count -eq 0) {
        return 0
    }

    if ($PSCmdlet.ShouldProcess($DomainDistinguishedName, "Remove scenario DCSync replication ACEs for $RightsGroupName")) {
        foreach ($rule in $rulesToRemove.ToArray()) {
            [void]$acl.RemoveAccessRuleSpecific($rule)
        }
        Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
        $script:Changed = $true
    }
    return $rulesToRemove.Count
}

function Get-DcsyncRightAceCount {
    param(
        [Parameter(Mandatory = $true)][string]$DomainDistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    Ensure-AdDrive
    $acl = Get-Acl -Path "AD:\$DomainDistinguishedName" -ErrorAction Stop
    $count = 0
    foreach ($right in @(Get-DcsyncReplicationRightSpecs -IncludeFilteredSet $IncludeFilteredSetRight)) {
        $count += @($acl.Access | Where-Object {
                -not $_.IsInherited -and (Test-DcsyncRightAce -AccessRule $_ -PrincipalSid $PrincipalSid -RightGuid ([guid]$right.Guid))
            }).Count
    }
    return $count
}

function Remove-GroupMemberIfPresent {
    param(
        [Parameter(Mandatory = $true)]$Group,
        [Parameter(Mandatory = $true)][string]$MemberDistinguishedName,
        [Parameter(Mandatory = $true)][string]$MemberLabel
    )

    $members = @(ConvertTo-StringArray -Value $Group.Member)
    if (-not ($members -icontains $MemberDistinguishedName)) {
        return $false
    }

    if ($PSCmdlet.ShouldProcess($Group.DistinguishedName, "Remove member $MemberLabel")) {
        Remove-ADGroupMember -Identity $Group.DistinguishedName -Members $MemberDistinguishedName -Confirm:$false @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }
    return $true
}

function Remove-ScenarioGroup {
    param(
        [AllowNull()]$Group,
        [Parameter(Mandatory = $true)][string]$GroupName
    )

    if ($null -eq $Group) {
        return $false
    }
    Assert-ScenarioGroupMarker -Group $Group -GroupName $GroupName
    if ($PSCmdlet.ShouldProcess($Group.DistinguishedName, 'Remove DCSync scenario group')) {
        Remove-ADGroup -Identity $Group.DistinguishedName -Confirm:$false @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }
    return $true
}

function Assert-BaselineRestored {
    param(
        [Parameter(Mandatory = $true)][string]$DomainDistinguishedName,
        [AllowNull()][Security.Principal.SecurityIdentifier]$RightsGroupSid
    )

    $currentRightsGroup = Get-ScenarioGroupOrNull -SamAccountName $RightsGroupName
    $currentReaderGroup = Get-ScenarioGroupOrNull -SamAccountName $ReaderGroupName
    if ($null -ne $currentRightsGroup -or $null -ne $currentReaderGroup) {
        throw "Cleanup finished but scenario groups remain. RightsGroupPresent=$($null -ne $currentRightsGroup); ReaderGroupPresent=$($null -ne $currentReaderGroup)"
    }
    if ($null -ne $RightsGroupSid) {
        $remainingAceCount = Get-DcsyncRightAceCount -DomainDistinguishedName $DomainDistinguishedName -PrincipalSid $RightsGroupSid
        if ($remainingAceCount -gt 0) {
            throw "Cleanup finished but domain root still has $remainingAceCount scenario DCSync ACE(s)."
        }
    }
}

Assert-SamAccountName -Value $DelegatedUserSamAccountName -Name 'DelegatedUserSamAccountName'
Assert-SamAccountName -Value $RightsGroupName -Name 'RightsGroupName'
Assert-SamAccountName -Value $ReaderGroupName -Name 'ReaderGroupName'
if ($RightsGroupName -ieq $ReaderGroupName) {
    throw 'RightsGroupName and ReaderGroupName must be different.'
}

$domain = Get-ADDomain @AdServerParameters -ErrorAction Stop
if ([string]$domain.DNSRoot -ine 'ad.lab.exceeds.test') {
    throw "Current domain '$($domain.DNSRoot)' is not the expected Baseline 06 domain 'ad.lab.exceeds.test'."
}
$domainDn = [string]$domain.DistinguishedName

$delegatedUser = Get-ScenarioUserBySamOrNull -SamAccountName $DelegatedUserSamAccountName
$rightsGroup = Get-ScenarioGroupOrNull -SamAccountName $RightsGroupName
$readerGroup = Get-ScenarioGroupOrNull -SamAccountName $ReaderGroupName
Assert-ScenarioGroupMarker -Group $rightsGroup -GroupName $RightsGroupName
Assert-ScenarioGroupMarker -Group $readerGroup -GroupName $ReaderGroupName

$rightsGroupSid = if ($null -eq $rightsGroup) { $null } else { $rightsGroup.SID }
$removedAceCount = 0
if ($null -ne $rightsGroup) {
    $removedAceCount = Remove-DcsyncRightAces -DomainDistinguishedName $domainDn -PrincipalSid $rightsGroup.SID
}

$delegatedUserMembershipRemoved = $false
if ($null -ne $readerGroup -and $null -ne $delegatedUser) {
    $delegatedUserMembershipRemoved = Remove-GroupMemberIfPresent -Group $readerGroup -MemberDistinguishedName ([string]$delegatedUser.DistinguishedName) -MemberLabel $DelegatedUserSamAccountName
    $readerGroup = Get-ScenarioGroupOrNull -SamAccountName $ReaderGroupName
}

$readerNestedMembershipRemoved = $false
if ($null -ne $rightsGroup -and $null -ne $readerGroup) {
    $readerNestedMembershipRemoved = Remove-GroupMemberIfPresent -Group $rightsGroup -MemberDistinguishedName ([string]$readerGroup.DistinguishedName) -MemberLabel $ReaderGroupName
    $rightsGroup = Get-ScenarioGroupOrNull -SamAccountName $RightsGroupName
}

$readerGroupRemoved = Remove-ScenarioGroup -Group $readerGroup -GroupName $ReaderGroupName
$rightsGroup = Get-ScenarioGroupOrNull -SamAccountName $RightsGroupName
$rightsGroupRemoved = Remove-ScenarioGroup -Group $rightsGroup -GroupName $RightsGroupName

if ($WhatIfPreference) {
    Write-Host 'WhatIf: Baseline restored check skipped because no objects were changed.'
}
else {
    Assert-BaselineRestored -DomainDistinguishedName $domainDn -RightsGroupSid $rightsGroupSid
}

[pscustomobject]@{
    Scenario                         = $script:ScenarioName
    Changed                          = $script:Changed
    Baseline                         = '06-ADCS-HTTP-CDP'
    BaselineRestored                 = (-not $WhatIfPreference)
    Domain                           = $domainDn
    RightsGroupAcesRemoved           = $removedAceCount
    DelegatedUserMembershipRemoved   = $delegatedUserMembershipRemoved
    ReaderNestedMembershipRemoved    = $readerNestedMembershipRemoved
    ReaderGroupRemoved               = $readerGroupRemoved
    RightsGroupRemoved               = $rightsGroupRemoved
}
