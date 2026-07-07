#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$DelegatedUserSamAccountName = 'svc_backup',
    [string]$ControlUserSamAccountName = 'operator01',
    [string]$RightsGroupName = 'GG_DCSync_Ops',
    [string]$ReaderGroupName = 'GG_DCSync_Readers',
    [bool]$ExpectFilteredSetRight = $true,
    [string]$OutputPath,
    [string]$Server,
    [switch]$IncludeAcl,
    [switch]$PassThru,
    [switch]$FailOnValidationError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'DCSync-ReplicationRights'
$script:Marker = 'windows-ad-lab:DCSync-ReplicationRights'
$script:PrivilegedGroupSamAccountNames = @(
    'Administrators',
    'Account Operators',
    'Backup Operators',
    'Domain Admins',
    'Enterprise Admins',
    'Server Operators'
)
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

function New-ValidationResult {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('Passed', 'Failed', 'Skipped')][string]$Status,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [string]$Message = ''
    )

    return [pscustomobject]@{
        Name     = $Name
        Status   = $Status
        Expected = $Expected
        Actual   = $Actual
        Message  = $Message
    }
}

function Add-ValidationResult {
    param(
        [AllowEmptyCollection()][System.Collections.Generic.List[object]]$Results,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [string]$Message = ''
    )

    $status = if ($Passed) { 'Passed' } else { 'Failed' }
    [void]$Results.Add((New-ValidationResult -Name $Name -Status $status -Expected $Expected -Actual $Actual -Message $Message))
}

function Add-SkippedResult {
    param(
        [AllowEmptyCollection()][System.Collections.Generic.List[object]]$Results,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [string]$Message = ''
    )

    [void]$Results.Add((New-ValidationResult -Name $Name -Status Skipped -Expected $Expected -Actual $Actual -Message $Message))
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

function Get-DcsyncRightAceCount {
    param(
        [Parameter(Mandatory = $true)][string]$DomainDistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid,
        [Parameter(Mandatory = $true)][Guid]$RightGuid
    )

    Ensure-AdDrive
    $acl = Get-Acl -Path "AD:\$DomainDistinguishedName" -ErrorAction Stop
    return @($acl.Access | Where-Object {
            -not $_.IsInherited -and (Test-DcsyncRightAce -AccessRule $_ -PrincipalSid $PrincipalSid -RightGuid $RightGuid)
        }).Count
}

function Format-Ace {
    param([Parameter(Mandatory = $true)]$AccessRule)

    return '{0};{1};{2};ObjectType={3};Inherited={4}' -f
        $AccessRule.IdentityReference,
        $AccessRule.AccessControlType,
        $AccessRule.ActiveDirectoryRights,
        $AccessRule.ObjectType,
        $AccessRule.IsInherited
}

function Get-PrincipalAceSummary {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    Ensure-AdDrive
    $acl = Get-Acl -Path "AD:\$DistinguishedName" -ErrorAction Stop
    return [string[]]@($acl.Access | Where-Object {
            -not $_.IsInherited -and (Test-IdentityReferenceMatchesSid -IdentityReference $_.IdentityReference -Sid $PrincipalSid)
        } | ForEach-Object { Format-Ace -AccessRule $_ })
}

function Test-GroupContainsMemberDn {
    param(
        [AllowNull()]$Group,
        [AllowNull()][string]$MemberDistinguishedName
    )

    if ($null -eq $Group -or [string]::IsNullOrWhiteSpace($MemberDistinguishedName)) {
        return $false
    }
    $members = @(ConvertTo-StringArray -Value $Group.Member)
    return ($members -icontains $MemberDistinguishedName)
}

function Get-PrincipalGroupSamAccountNames {
    param([Parameter(Mandatory = $true)]$Principal)

    $groups = @(Get-ADPrincipalGroupMembership -Identity $Principal.DistinguishedName @AdServerParameters -ErrorAction Stop)
    return [string[]]@($groups | ForEach-Object { [string]$_.SamAccountName } | Sort-Object -Unique)
}

function Get-PrivilegedGroupMatches {
    param([string[]]$GroupSamAccountNames)

    return [string[]]@($GroupSamAccountNames | Where-Object { $script:PrivilegedGroupSamAccountNames -icontains $_ } | Sort-Object -Unique)
}

Assert-SamAccountName -Value $DelegatedUserSamAccountName -Name 'DelegatedUserSamAccountName'
Assert-SamAccountName -Value $ControlUserSamAccountName -Name 'ControlUserSamAccountName'
Assert-SamAccountName -Value $RightsGroupName -Name 'RightsGroupName'
Assert-SamAccountName -Value $ReaderGroupName -Name 'ReaderGroupName'
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

$results = New-Object 'System.Collections.Generic.List[object]'
$delegatedUser = Get-ScenarioUserBySamOrNull -SamAccountName $DelegatedUserSamAccountName
$controlUser = Get-ScenarioUserBySamOrNull -SamAccountName $ControlUserSamAccountName
$rightsGroup = Get-ScenarioGroupOrNull -SamAccountName $RightsGroupName
$readerGroup = Get-ScenarioGroupOrNull -SamAccountName $ReaderGroupName

Add-ValidationResult -Results $results -Name 'Delegated user exists' -Passed ($null -ne $delegatedUser) -Expected $DelegatedUserSamAccountName -Actual $(if ($null -eq $delegatedUser) { '<missing>' } else { $delegatedUser.DistinguishedName })
Add-ValidationResult -Results $results -Name 'Control user exists' -Passed ($null -ne $controlUser) -Expected $ControlUserSamAccountName -Actual $(if ($null -eq $controlUser) { '<missing>' } else { $controlUser.DistinguishedName })
Add-ValidationResult -Results $results -Name 'DCSync rights group exists' -Passed ($null -ne $rightsGroup) -Expected $RightsGroupName -Actual $(if ($null -eq $rightsGroup) { '<missing>' } else { $rightsGroup.DistinguishedName })
Add-ValidationResult -Results $results -Name 'DCSync reader group exists' -Passed ($null -ne $readerGroup) -Expected $ReaderGroupName -Actual $(if ($null -eq $readerGroup) { '<missing>' } else { $readerGroup.DistinguishedName })

if ($null -ne $rightsGroup) {
    Add-ValidationResult -Results $results -Name 'DCSync rights group marker' -Passed ([string]$rightsGroup.adminDescription -ceq $script:Marker) -Expected $script:Marker -Actual ([string]$rightsGroup.adminDescription)
}
else {
    Add-SkippedResult -Results $results -Name 'DCSync rights group marker' -Expected $script:Marker -Actual '<missing>'
}
if ($null -ne $readerGroup) {
    Add-ValidationResult -Results $results -Name 'DCSync reader group marker' -Passed ([string]$readerGroup.adminDescription -ceq $script:Marker) -Expected $script:Marker -Actual ([string]$readerGroup.adminDescription)
}
else {
    Add-SkippedResult -Results $results -Name 'DCSync reader group marker' -Expected $script:Marker -Actual '<missing>'
}

if ($null -ne $delegatedUser -and $null -ne $readerGroup) {
    Add-ValidationResult `
        -Results $results `
        -Name 'Delegated user is member of reader group' `
        -Passed (Test-GroupContainsMemberDn -Group $readerGroup -MemberDistinguishedName ([string]$delegatedUser.DistinguishedName)) `
        -Expected $delegatedUser.DistinguishedName `
        -Actual (@(ConvertTo-StringArray -Value $readerGroup.Member) -join '; ')
}
else {
    Add-SkippedResult -Results $results -Name 'Delegated user is member of reader group' -Expected 'User and reader group present' -Actual 'Missing dependency'
}

if ($null -ne $readerGroup -and $null -ne $rightsGroup) {
    Add-ValidationResult `
        -Results $results `
        -Name 'Reader group is nested into rights group' `
        -Passed (Test-GroupContainsMemberDn -Group $rightsGroup -MemberDistinguishedName ([string]$readerGroup.DistinguishedName)) `
        -Expected $readerGroup.DistinguishedName `
        -Actual (@(ConvertTo-StringArray -Value $rightsGroup.Member) -join '; ')
}
else {
    Add-SkippedResult -Results $results -Name 'Reader group is nested into rights group' -Expected 'Reader and rights group present' -Actual 'Missing dependency'
}

if ($null -ne $delegatedUser) {
    $delegatedUserGroupNames = @(Get-PrincipalGroupSamAccountNames -Principal $delegatedUser)
    $privilegedMatches = @(Get-PrivilegedGroupMatches -GroupSamAccountNames $delegatedUserGroupNames)
    Add-ValidationResult `
        -Results $results `
        -Name 'Delegated user is not a privileged admin' `
        -Passed ($privilegedMatches.Count -eq 0) `
        -Expected 'No Domain Admins, Enterprise Admins, Administrators, Account Operators, Backup Operators, or Server Operators membership' `
        -Actual $(if ($privilegedMatches.Count -eq 0) { ($delegatedUserGroupNames -join '; ') } else { ($privilegedMatches -join '; ') }) `
        -Message 'DCSync viability in this scenario comes from domain root replication ACEs, not admin group membership.'
}
else {
    Add-SkippedResult -Results $results -Name 'Delegated user is not a privileged admin' -Expected 'Delegated user present' -Actual '<missing>'
}

if ($null -ne $rightsGroup) {
    foreach ($right in @(Get-DcsyncReplicationRightSpecs -IncludeFilteredSet $ExpectFilteredSetRight)) {
        $aceCount = Get-DcsyncRightAceCount -DomainDistinguishedName $domainDn -PrincipalSid $rightsGroup.SID -RightGuid ([guid]$right.Guid)
        Add-ValidationResult `
            -Results $results `
            -Name "Rights group has $($right.DisplayName)" `
            -Passed ($aceCount -eq 1) `
            -Expected 'One explicit domain root ExtendedRight ACE' `
            -Actual "Count=$aceCount;RightGuid=$($right.Guid)"
    }
}
else {
    Add-SkippedResult -Results $results -Name 'Rights group DCSync ACEs' -Expected 'Rights group present' -Actual '<missing>'
}

if ($null -ne $delegatedUser) {
    $directAceCount = 0
    foreach ($right in @(Get-DcsyncReplicationRightSpecs -IncludeFilteredSet $ExpectFilteredSetRight)) {
        $directAceCount += Get-DcsyncRightAceCount -DomainDistinguishedName $domainDn -PrincipalSid $delegatedUser.SID -RightGuid ([guid]$right.Guid)
    }
    Add-ValidationResult `
        -Results $results `
        -Name 'Delegated user has no direct domain root DCSync ACE' `
        -Passed ($directAceCount -eq 0) `
        -Expected '0 direct DCSync ACEs' `
        -Actual "Count=$directAceCount" `
        -Message 'The effective path should be through nested groups.'
}
else {
    Add-SkippedResult -Results $results -Name 'Delegated user has no direct domain root DCSync ACE' -Expected 'Delegated user present' -Actual '<missing>'
}

if ($null -ne $controlUser) {
    $controlAceCount = 0
    foreach ($right in @(Get-DcsyncReplicationRightSpecs -IncludeFilteredSet $ExpectFilteredSetRight)) {
        $controlAceCount += Get-DcsyncRightAceCount -DomainDistinguishedName $domainDn -PrincipalSid $controlUser.SID -RightGuid ([guid]$right.Guid)
    }
    $controlUserIsReader = ($null -ne $readerGroup -and (Test-GroupContainsMemberDn -Group $readerGroup -MemberDistinguishedName ([string]$controlUser.DistinguishedName)))
    $controlUserIsRightsMember = ($null -ne $rightsGroup -and (Test-GroupContainsMemberDn -Group $rightsGroup -MemberDistinguishedName ([string]$controlUser.DistinguishedName)))
    Add-ValidationResult `
        -Results $results `
        -Name 'Control user remains outside DCSync path' `
        -Passed ($controlAceCount -eq 0 -and -not $controlUserIsReader -and -not $controlUserIsRightsMember) `
        -Expected 'No direct ACE and no scenario group membership' `
        -Actual "DirectAceCount=$controlAceCount;ReaderMember=$controlUserIsReader;RightsMember=$controlUserIsRightsMember"
}
else {
    Add-SkippedResult -Results $results -Name 'Control user remains outside DCSync path' -Expected 'Control user present' -Actual '<missing>'
}

Add-ValidationResult `
    -Results $results `
    -Name 'Credential replication is not automated' `
    -Passed $true `
    -Expected 'No DCSync execution, password hash dump, or external offensive tool invocation' `
    -Actual 'Static ACL validation only'

if ($IncludeAcl -and $null -ne $rightsGroup) {
    $aceSummaries = @(Get-PrincipalAceSummary -DistinguishedName $domainDn -PrincipalSid $rightsGroup.SID)
    Add-ValidationResult -Results $results -Name 'Rights group explicit domain root ACE summary' -Passed ($aceSummaries.Count -gt 0) -Expected 'At least one explicit ACE' -Actual ($aceSummaries -join ' | ')
}

$resultRows = $results.ToArray()
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $parent = Split-Path -Parent $OutputPath
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $resultRows | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
}

$failed = @($resultRows | Where-Object Status -eq 'Failed')
if ($FailOnValidationError -and $failed.Count -gt 0) {
    $failedNames = @($failed | ForEach-Object { $_.Name })
    throw "$script:ScenarioName validation failed: $($failedNames -join '; ')"
}

if ($PassThru) {
    return $resultRows
}

$resultRows | Format-Table -AutoSize
