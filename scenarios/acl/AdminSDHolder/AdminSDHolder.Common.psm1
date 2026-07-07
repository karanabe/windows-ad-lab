Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:AdminSdHolderScenarioName = 'AdminSDHolder'
$script:AdminSdHolderMarker = 'windows-ad-lab:AdminSDHolder'
$script:AdminSdHolderStateRoot = Join-Path $env:ProgramData "ADLabBootstrap\Scenarios\$script:AdminSdHolderScenarioName"
$script:AdminSdHolderStatePath = Join-Path $script:AdminSdHolderStateRoot 'state.json'
$script:AdminSdHolderResetPasswordRightGuid = [guid]'00299570-246d-11d0-a768-00aa006e0529'
$script:AdminSdHolderDescription = 'LAB ONLY: AdminSDHolder reset password delegation observation group'
$script:AdminSdHolderPrivilegedGroupSamAccountNames = @(
    'Administrators',
    'Account Operators',
    'Backup Operators',
    'Domain Admins',
    'Enterprise Admins',
    'Server Operators'
)

function Get-AdminSdHolderScenarioName {
    return $script:AdminSdHolderScenarioName
}

function Get-AdminSdHolderMarker {
    return $script:AdminSdHolderMarker
}

function Get-AdminSdHolderStateRoot {
    return $script:AdminSdHolderStateRoot
}

function Get-AdminSdHolderStatePath {
    return $script:AdminSdHolderStatePath
}

function Get-AdminSdHolderResetPasswordRightGuid {
    return $script:AdminSdHolderResetPasswordRightGuid
}

function Get-AdminSdHolderPropertyValue {
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

function Assert-AdminSdHolderSamAccountName {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($Value -notmatch '^[A-Za-z0-9._-]{1,20}$') {
        throw "$Name must be a valid 1-20 character sAMAccountName: '$Value'"
    }
}

function Assert-AdminSdHolderRdnValue {
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

function ConvertTo-AdminSdHolderLdapFilterValue {
    param([Parameter(Mandatory = $true)][string]$Value)

    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace(([string][char]0), '\00')
}

function ConvertTo-AdminSdHolderStringArray {
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

function Get-AdminSdHolderAdServerParameters {
    param([string]$Server)

    $parameters = @{}
    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $parameters['Server'] = $Server
    }
    return $parameters
}

function Ensure-AdminSdHolderAdDrive {
    param([string]$Server)

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
    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $driveParameters['Server'] = $Server
    }
    New-PSDrive @driveParameters | Out-Null
}

function Get-AdminSdHolderDistinguishedName {
    param([Parameter(Mandatory = $true)][string]$DomainDistinguishedName)

    return "CN=AdminSDHolder,CN=System,$DomainDistinguishedName"
}

function Get-AdminSdHolderUserOrNull {
    param(
        [Parameter(Mandatory = $true)][string]$SamAccountName,
        [string]$Server
    )

    $adParameters = Get-AdminSdHolderAdServerParameters -Server $Server
    $escapedSam = ConvertTo-AdminSdHolderLdapFilterValue -Value $SamAccountName
    $users = @(Get-ADUser -LDAPFilter "(sAMAccountName=$escapedSam)" -Properties Enabled, SID, MemberOf, adminCount @adParameters -ErrorAction Stop)
    if ($users.Count -gt 1) {
        throw "Multiple users were returned for sAMAccountName '$SamAccountName'."
    }
    if ($users.Count -eq 0) {
        return $null
    }
    return $users[0]
}

function Get-AdminSdHolderGroupOrNull {
    param(
        [Parameter(Mandatory = $true)][string]$SamAccountName,
        [string]$Server
    )

    $adParameters = Get-AdminSdHolderAdServerParameters -Server $Server
    $escapedName = ConvertTo-AdminSdHolderLdapFilterValue -Value $SamAccountName
    $groups = @(Get-ADGroup -LDAPFilter "(sAMAccountName=$escapedName)" -Properties adminDescription, Description, Member, SID @adParameters -ErrorAction Stop)
    if ($groups.Count -gt 1) {
        throw "Multiple groups were returned for sAMAccountName '$SamAccountName'."
    }
    if ($groups.Count -eq 0) {
        return $null
    }
    return $groups[0]
}

function Get-AdminSdHolderObjectOrNull {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [string]$Server
    )

    $adParameters = Get-AdminSdHolderAdServerParameters -Server $Server
    try {
        return Get-ADObject -Identity $DistinguishedName -Properties adminDescription @adParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

function Get-AdminSdHolderAdminCountObjects {
    param(
        [Parameter(Mandatory = $true)][string]$DomainDistinguishedName,
        [string]$Server
    )

    $adParameters = Get-AdminSdHolderAdServerParameters -Server $Server
    return @(Get-ADObject `
            -SearchBase $DomainDistinguishedName `
            -LDAPFilter '(adminCount=1)' `
            -Properties adminCount, objectClass, sAMAccountName `
            @adParameters `
            -ErrorAction Stop)
}

function Test-AdminSdHolderGroupContainsMemberDn {
    param(
        [AllowNull()]$Group,
        [AllowNull()][string]$MemberDistinguishedName
    )

    if ($null -eq $Group -or [string]::IsNullOrWhiteSpace($MemberDistinguishedName)) {
        return $false
    }
    $members = @(ConvertTo-AdminSdHolderStringArray -Value $Group.Member)
    return ($members -icontains $MemberDistinguishedName)
}

function Get-AdminSdHolderPrincipalGroupSamAccountNames {
    param(
        [Parameter(Mandatory = $true)]$Principal,
        [string]$Server
    )

    $adParameters = Get-AdminSdHolderAdServerParameters -Server $Server
    $groups = @(Get-ADPrincipalGroupMembership -Identity $Principal.DistinguishedName @adParameters -ErrorAction Stop)
    return [string[]]@($groups | ForEach-Object { [string]$_.SamAccountName } | Sort-Object -Unique)
}

function Get-AdminSdHolderPrivilegedGroupMatches {
    param([string[]]$GroupSamAccountNames)

    return [string[]]@($GroupSamAccountNames | Where-Object { $script:AdminSdHolderPrivilegedGroupSamAccountNames -icontains $_ } | Sort-Object -Unique)
}

function Assert-AdminSdHolderResetPasswordRight {
    param([string]$Server)

    $adParameters = Get-AdminSdHolderAdServerParameters -Server $Server
    $rootDse = Get-ADRootDSE @adParameters -ErrorAction Stop
    $extendedRightsContainer = "CN=Extended-Rights,$($rootDse.configurationNamingContext)"
    $escapedGuid = ConvertTo-AdminSdHolderLdapFilterValue -Value ([string]$script:AdminSdHolderResetPasswordRightGuid)
    $objects = @(Get-ADObject `
            -SearchBase $extendedRightsContainer `
            -SearchScope OneLevel `
            -LDAPFilter "(&(objectClass=controlAccessRight)(rightsGuid=$escapedGuid))" `
            -Properties cn, displayName, rightsGuid `
            @adParameters `
            -ErrorAction Stop)
    if ($objects.Count -ne 1) {
        throw "Expected one Reset Password controlAccessRight with rightsGuid '$script:AdminSdHolderResetPasswordRightGuid', found $($objects.Count)."
    }
}

function Test-AdminSdHolderIdentityReferenceMatchesSid {
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

function Test-AdminSdHolderResetPasswordAce {
    param(
        [Parameter(Mandatory = $true)]$AccessRule,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    if ($AccessRule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }
    if ($AccessRule.IsInherited) { return $false }
    if (-not (Test-AdminSdHolderIdentityReferenceMatchesSid -IdentityReference $AccessRule.IdentityReference -Sid $PrincipalSid)) { return $false }
    if (($AccessRule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) { return $false }
    return ($AccessRule.ObjectType -eq $script:AdminSdHolderResetPasswordRightGuid)
}

function Get-AdminSdHolderAcl {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [string]$Server
    )

    Ensure-AdminSdHolderAdDrive -Server $Server
    return Get-Acl -Path "AD:\$DistinguishedName" -ErrorAction Stop
}

function Get-AdminSdHolderResetPasswordAceCount {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid,
        [string]$Server
    )

    $acl = Get-AdminSdHolderAcl -DistinguishedName $DistinguishedName -Server $Server
    return @($acl.Access | Where-Object {
            Test-AdminSdHolderResetPasswordAce -AccessRule $_ -PrincipalSid $PrincipalSid
        }).Count
}

function Format-AdminSdHolderAce {
    param([Parameter(Mandatory = $true)]$AccessRule)

    return '{0};{1};{2};ObjectType={3};Inherited={4}' -f
        $AccessRule.IdentityReference,
        $AccessRule.AccessControlType,
        $AccessRule.ActiveDirectoryRights,
        $AccessRule.ObjectType,
        $AccessRule.IsInherited
}

function Get-AdminSdHolderPrincipalAceSummary {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid,
        [string]$Server
    )

    $acl = Get-AdminSdHolderAcl -DistinguishedName $DistinguishedName -Server $Server
    return [string[]]@($acl.Access | Where-Object {
            -not $_.IsInherited -and (Test-AdminSdHolderIdentityReferenceMatchesSid -IdentityReference $_.IdentityReference -Sid $PrincipalSid)
        } | ForEach-Object { Format-AdminSdHolderAce -AccessRule $_ })
}

function Ensure-AdminSdHolderScenarioGroup {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$GroupName,
        [Parameter(Mandatory = $true)][string]$GroupsOuDistinguishedName,
        [string]$Server
    )

    Assert-AdminSdHolderSamAccountName -Value $GroupName -Name 'DelegateGroupName'
    Assert-AdminSdHolderRdnValue -Value $GroupName -Name 'DelegateGroupName'
    $adParameters = Get-AdminSdHolderAdServerParameters -Server $Server
    $group = Get-AdminSdHolderGroupOrNull -SamAccountName $GroupName -Server $Server
    if ($null -eq $group) {
        if ($PSCmdlet.ShouldProcess("CN=$GroupName,$GroupsOuDistinguishedName", 'Create AdminSDHolder scenario group')) {
            New-ADGroup `
                -Name $GroupName `
                -SamAccountName $GroupName `
                -GroupScope Global `
                -GroupCategory Security `
                -Path $GroupsOuDistinguishedName `
                -Description $script:AdminSdHolderDescription `
                -OtherAttributes @{ adminDescription = $script:AdminSdHolderMarker } `
                @adParameters `
                -ErrorAction Stop | Out-Null
        }
        $group = Get-AdminSdHolderGroupOrNull -SamAccountName $GroupName -Server $Server
    }

    if ($null -eq $group) {
        throw "Scenario group '$GroupName' was not found after creation."
    }
    if ([string]$group.DistinguishedName -ine "CN=$GroupName,$GroupsOuDistinguishedName") {
        throw "Group '$GroupName' exists outside the scenario OU: $($group.DistinguishedName). Refusing to reuse it."
    }
    if ([string]$group.adminDescription -cne $script:AdminSdHolderMarker) {
        throw "Group '$GroupName' exists but is not scenario-marked. Refusing to modify it."
    }
    if ([string]$group.Description -cne $script:AdminSdHolderDescription) {
        if ($PSCmdlet.ShouldProcess($group.DistinguishedName, 'Update AdminSDHolder scenario group metadata')) {
            Set-ADGroup -Identity $group.DistinguishedName -Replace @{ description = $script:AdminSdHolderDescription } @adParameters -ErrorAction Stop
            $group = Get-AdminSdHolderGroupOrNull -SamAccountName $GroupName -Server $Server
        }
    }

    return $group
}

function Ensure-AdminSdHolderGroupMember {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]$Group,
        [Parameter(Mandatory = $true)][string]$MemberDistinguishedName,
        [Parameter(Mandatory = $true)][string]$MemberLabel,
        [string]$Server
    )

    if (Test-AdminSdHolderGroupContainsMemberDn -Group $Group -MemberDistinguishedName $MemberDistinguishedName) {
        return $false
    }

    $adParameters = Get-AdminSdHolderAdServerParameters -Server $Server
    if ($PSCmdlet.ShouldProcess($Group.DistinguishedName, "Add member $MemberLabel")) {
        Add-ADGroupMember -Identity $Group.DistinguishedName -Members $MemberDistinguishedName @adParameters -ErrorAction Stop
        return $true
    }
    return $false
}

function Ensure-AdminSdHolderResetPasswordAce {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$AdminSdHolderDistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid,
        [Parameter(Mandatory = $true)][string]$PrincipalLabel,
        [string]$Server
    )

    $acl = Get-AdminSdHolderAcl -DistinguishedName $AdminSdHolderDistinguishedName -Server $Server
    $existingRules = @($acl.Access | Where-Object {
            Test-AdminSdHolderResetPasswordAce -AccessRule $_ -PrincipalSid $PrincipalSid
        })
    if ($existingRules.Count -gt 0) {
        return $false
    }

    $rule = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @(
        $PrincipalSid,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $script:AdminSdHolderResetPasswordRightGuid
    )
    if ($PSCmdlet.ShouldProcess($AdminSdHolderDistinguishedName, "Grant Reset Password to $PrincipalLabel on AdminSDHolder")) {
        $acl.AddAccessRule($rule)
        Set-Acl -Path "AD:\$AdminSdHolderDistinguishedName" -AclObject $acl -ErrorAction Stop
        return $true
    }
    return $false
}

function Remove-AdminSdHolderResetPasswordAces {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid,
        [Parameter(Mandatory = $true)][string]$TargetLabel,
        [string]$Server
    )

    $acl = Get-AdminSdHolderAcl -DistinguishedName $DistinguishedName -Server $Server
    $rulesToRemove = @($acl.Access | Where-Object {
            Test-AdminSdHolderResetPasswordAce -AccessRule $_ -PrincipalSid $PrincipalSid
        })
    if ($rulesToRemove.Count -eq 0) {
        return 0
    }

    if ($PSCmdlet.ShouldProcess($DistinguishedName, "Remove AdminSDHolder scenario Reset Password ACEs from $TargetLabel")) {
        foreach ($rule in $rulesToRemove) {
            [void]$acl.RemoveAccessRuleSpecific($rule)
        }
        Set-Acl -Path "AD:\$DistinguishedName" -AclObject $acl -ErrorAction Stop
    }
    return $rulesToRemove.Count
}

function Remove-AdminSdHolderGroupMemberIfPresent {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]$Group,
        [Parameter(Mandatory = $true)][string]$MemberDistinguishedName,
        [Parameter(Mandatory = $true)][string]$MemberLabel,
        [string]$Server
    )

    if (-not (Test-AdminSdHolderGroupContainsMemberDn -Group $Group -MemberDistinguishedName $MemberDistinguishedName)) {
        return $false
    }

    $adParameters = Get-AdminSdHolderAdServerParameters -Server $Server
    if ($PSCmdlet.ShouldProcess($Group.DistinguishedName, "Remove member $MemberLabel")) {
        Remove-ADGroupMember -Identity $Group.DistinguishedName -Members $MemberDistinguishedName -Confirm:$false @adParameters -ErrorAction Stop
        return $true
    }
    return $false
}

function Remove-AdminSdHolderScenarioGroup {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [AllowNull()]$Group,
        [Parameter(Mandatory = $true)][string]$GroupName,
        [string]$Server
    )

    if ($null -eq $Group) {
        return $false
    }
    if ([string]$Group.adminDescription -cne $script:AdminSdHolderMarker) {
        throw "Group '$GroupName' exists but is not scenario-marked. Refusing cleanup."
    }

    $adParameters = Get-AdminSdHolderAdServerParameters -Server $Server
    if ($PSCmdlet.ShouldProcess($Group.DistinguishedName, 'Remove AdminSDHolder scenario group')) {
        Remove-ADGroup -Identity $Group.DistinguishedName -Confirm:$false @adParameters -ErrorAction Stop
        return $true
    }
    return $false
}

function Invoke-AdminSdHolderSdProp {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [ValidateRange(0, 120)][int]$PostTriggerWaitSeconds = 15,
        [string]$Server
    )

    $rootDsePath = if ([string]::IsNullOrWhiteSpace($Server)) { 'LDAP://RootDSE' } else { "LDAP://$Server/RootDSE" }
    if ($PSCmdlet.ShouldProcess($rootDsePath, 'Trigger SDProp with RunProtectAdminGroupsTask')) {
        $rootDse = [ADSI]$rootDsePath
        $rootDse.Put('RunProtectAdminGroupsTask', '1')
        $rootDse.SetInfo()
        if ($PostTriggerWaitSeconds -gt 0) {
            Start-Sleep -Seconds $PostTriggerWaitSeconds
        }
        return $true
    }
    return $false
}

function Wait-AdminSdHolderResetPasswordAce {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid,
        [Parameter(Mandatory = $true)][bool]$ExpectedPresent,
        [ValidateRange(1, 300)][int]$TimeoutSeconds = 90,
        [string]$Server
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $count = Get-AdminSdHolderResetPasswordAceCount -DistinguishedName $DistinguishedName -PrincipalSid $PrincipalSid -Server $Server
        if ($ExpectedPresent -and $count -gt 0) {
            return $true
        }
        if (-not $ExpectedPresent -and $count -eq 0) {
            return $true
        }
        Start-Sleep -Seconds 3
    } while ((Get-Date) -lt $deadline)

    return $false
}

function Read-AdminSdHolderScenarioState {
    if (-not (Test-Path -LiteralPath $script:AdminSdHolderStatePath -PathType Leaf)) {
        return $null
    }
    return (Get-Content -LiteralPath $script:AdminSdHolderStatePath -Raw -ErrorAction Stop | ConvertFrom-Json)
}

function Save-AdminSdHolderScenarioState {
    param([Parameter(Mandatory = $true)]$State)

    if (-not (Test-Path -LiteralPath $script:AdminSdHolderStateRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $script:AdminSdHolderStateRoot -Force -ErrorAction Stop | Out-Null
    }
    $State | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:AdminSdHolderStatePath -Encoding UTF8 -ErrorAction Stop
}

function Save-AdminSdHolderCurrentState {
    param(
        [Parameter(Mandatory = $true)][string]$DomainDistinguishedName,
        [Parameter(Mandatory = $true)][string]$AdminSdHolderDistinguishedName,
        [Parameter(Mandatory = $true)]$DelegateGroup,
        [Parameter(Mandatory = $true)][string]$DelegateMemberSamAccountName,
        [Parameter(Mandatory = $true)][string]$ProtectedUserSamAccountName
    )

    $existing = Read-AdminSdHolderScenarioState
    $createdAt = if ($null -eq $existing) {
        (Get-Date).ToString('o')
    }
    else {
        [string](Get-AdminSdHolderPropertyValue -InputObject $existing -Name 'CreatedAt' -Default (Get-Date).ToString('o'))
    }

    $state = [ordered]@{
        SchemaVersion                    = 1
        ScenarioName                     = $script:AdminSdHolderScenarioName
        Marker                           = $script:AdminSdHolderMarker
        CreatedAt                        = $createdAt
        UpdatedAt                        = (Get-Date).ToString('o')
        DomainDistinguishedName          = $DomainDistinguishedName
        AdminSdHolderDistinguishedName   = $AdminSdHolderDistinguishedName
        DelegateGroupName                = [string]$DelegateGroup.SamAccountName
        DelegateGroupDistinguishedName   = [string]$DelegateGroup.DistinguishedName
        DelegateGroupSid                 = [string]$DelegateGroup.SID.Value
        DelegateMemberSamAccountName     = $DelegateMemberSamAccountName
        ProtectedUserSamAccountName      = $ProtectedUserSamAccountName
        ResetPasswordControlAccessGuid   = [string]$script:AdminSdHolderResetPasswordRightGuid
    }
    Save-AdminSdHolderScenarioState -State $state
    return (Read-AdminSdHolderScenarioState)
}

function Remove-AdminSdHolderScenarioState {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if (-not (Test-Path -LiteralPath $script:AdminSdHolderStateRoot -PathType Container)) {
        return $false
    }
    if ($PSCmdlet.ShouldProcess($script:AdminSdHolderStateRoot, 'Remove AdminSDHolder scenario state directory')) {
        Remove-Item -LiteralPath $script:AdminSdHolderStateRoot -Recurse -Force -ErrorAction Stop
        return $true
    }
    return $false
}

function Get-AdminSdHolderScenarioPosture {
    param(
        [string]$DelegateMemberSamAccountName = 'john.smith',
        [string]$DelegateGroupName = 'GG_AdminSD_Resetters',
        [string]$ProtectedUserSamAccountName = 'yagami_adm',
        [string]$Server,
        [switch]$IncludeAcl
    )

    Import-Module ActiveDirectory -ErrorAction Stop
    Assert-AdminSdHolderSamAccountName -Value $DelegateMemberSamAccountName -Name 'DelegateMemberSamAccountName'
    Assert-AdminSdHolderSamAccountName -Value $DelegateGroupName -Name 'DelegateGroupName'
    Assert-AdminSdHolderSamAccountName -Value $ProtectedUserSamAccountName -Name 'ProtectedUserSamAccountName'

    $adParameters = Get-AdminSdHolderAdServerParameters -Server $Server
    $domain = Get-ADDomain @adParameters -ErrorAction Stop
    $domainDn = [string]$domain.DistinguishedName
    $adminSdHolderDn = Get-AdminSdHolderDistinguishedName -DomainDistinguishedName $domainDn
    $adminSdHolder = Get-AdminSdHolderObjectOrNull -DistinguishedName $adminSdHolderDn -Server $Server
    $delegateMember = Get-AdminSdHolderUserOrNull -SamAccountName $DelegateMemberSamAccountName -Server $Server
    $delegateGroup = Get-AdminSdHolderGroupOrNull -SamAccountName $DelegateGroupName -Server $Server
    $protectedUser = Get-AdminSdHolderUserOrNull -SamAccountName $ProtectedUserSamAccountName -Server $Server
    $delegateGroupSid = if ($null -eq $delegateGroup) { $null } else { [Security.Principal.SecurityIdentifier]$delegateGroup.SID }
    $adminSdHolderAceCount = 0
    $protectedUserAceCount = 0
    $protectedUserAccessRulesProtected = $false
    $adminCountObjectsWithScenarioAce = @()
    $adminSdHolderAceSummary = @()
    $protectedUserAceSummary = @()

    if ($null -ne $delegateGroupSid -and $null -ne $adminSdHolder) {
        $adminSdHolderAceCount = Get-AdminSdHolderResetPasswordAceCount -DistinguishedName $adminSdHolderDn -PrincipalSid $delegateGroupSid -Server $Server
        if ($IncludeAcl) {
            $adminSdHolderAceSummary = @(Get-AdminSdHolderPrincipalAceSummary -DistinguishedName $adminSdHolderDn -PrincipalSid $delegateGroupSid -Server $Server)
        }
    }

    if ($null -ne $protectedUser) {
        $protectedAcl = Get-AdminSdHolderAcl -DistinguishedName ([string]$protectedUser.DistinguishedName) -Server $Server
        $protectedUserAccessRulesProtected = [bool]$protectedAcl.AreAccessRulesProtected
        if ($null -ne $delegateGroupSid) {
            $protectedUserAceCount = @($protectedAcl.Access | Where-Object {
                    Test-AdminSdHolderResetPasswordAce -AccessRule $_ -PrincipalSid $delegateGroupSid
                }).Count
            if ($IncludeAcl) {
                $protectedUserAceSummary = [string[]]@($protectedAcl.Access | Where-Object {
                        -not $_.IsInherited -and (Test-AdminSdHolderIdentityReferenceMatchesSid -IdentityReference $_.IdentityReference -Sid $delegateGroupSid)
                    } | ForEach-Object { Format-AdminSdHolderAce -AccessRule $_ })
            }
        }
    }

    $adminCountObjects = @(Get-AdminSdHolderAdminCountObjects -DomainDistinguishedName $domainDn -Server $Server)
    if ($null -ne $delegateGroupSid) {
        $matches = New-Object 'System.Collections.Generic.List[string]'
        foreach ($protectedObject in $adminCountObjects) {
            $count = Get-AdminSdHolderResetPasswordAceCount -DistinguishedName ([string]$protectedObject.DistinguishedName) -PrincipalSid $delegateGroupSid -Server $Server
            if ($count -gt 0) {
                [void]$matches.Add("$($protectedObject.DistinguishedName) ($count)")
            }
        }
        $adminCountObjectsWithScenarioAce = [string[]]$matches.ToArray()
    }

    $delegateMemberGroupNames = @()
    if ($null -ne $delegateMember) {
        $delegateMemberGroupNames = @(Get-AdminSdHolderPrincipalGroupSamAccountNames -Principal $delegateMember -Server $Server)
    }

    $protectedUserGroupNames = @()
    if ($null -ne $protectedUser) {
        $protectedUserGroupNames = @(Get-AdminSdHolderPrincipalGroupSamAccountNames -Principal $protectedUser -Server $Server)
    }

    return [pscustomobject]@{
        DomainDistinguishedName                  = $domainDn
        AdminSdHolderDistinguishedName           = $adminSdHolderDn
        AdminSdHolderExists                      = ($null -ne $adminSdHolder)
        DelegateMemberExists                     = ($null -ne $delegateMember)
        DelegateMemberDistinguishedName          = if ($null -eq $delegateMember) { '' } else { [string]$delegateMember.DistinguishedName }
        DelegateGroupExists                      = ($null -ne $delegateGroup)
        DelegateGroupDistinguishedName           = if ($null -eq $delegateGroup) { '' } else { [string]$delegateGroup.DistinguishedName }
        DelegateGroupMarker                      = if ($null -eq $delegateGroup) { '' } else { [string]$delegateGroup.adminDescription }
        DelegateGroupSid                         = if ($null -eq $delegateGroupSid) { '' } else { [string]$delegateGroupSid.Value }
        DelegateMembershipPresent                = ($null -ne $delegateMember -and $null -ne $delegateGroup -and (Test-AdminSdHolderGroupContainsMemberDn -Group $delegateGroup -MemberDistinguishedName ([string]$delegateMember.DistinguishedName)))
        DelegateMemberGroupSamAccountNames       = [string[]]$delegateMemberGroupNames
        DelegateMemberPrivilegedGroupMatches     = [string[]](Get-AdminSdHolderPrivilegedGroupMatches -GroupSamAccountNames $delegateMemberGroupNames)
        ProtectedUserExists                      = ($null -ne $protectedUser)
        ProtectedUserDistinguishedName           = if ($null -eq $protectedUser) { '' } else { [string]$protectedUser.DistinguishedName }
        ProtectedUserAdminCount                  = if ($null -eq $protectedUser) { '' } else { [string]$protectedUser.adminCount }
        ProtectedUserAccessRulesProtected        = $protectedUserAccessRulesProtected
        ProtectedUserGroupSamAccountNames        = [string[]]$protectedUserGroupNames
        AdminSdHolderResetPasswordAceCount       = [int]$adminSdHolderAceCount
        ProtectedUserResetPasswordAceCount       = [int]$protectedUserAceCount
        AdminCountObjectCount                    = [int]$adminCountObjects.Count
        AdminCountObjectsWithScenarioAce         = [string[]]$adminCountObjectsWithScenarioAce
        AdminSdHolderAceSummary                  = [string[]]$adminSdHolderAceSummary
        ProtectedUserAceSummary                  = [string[]]$protectedUserAceSummary
        ResetPasswordControlAccessGuid           = [string]$script:AdminSdHolderResetPasswordRightGuid
        PasswordResetExecuted                    = $false
    }
}

function Set-AdminSdHolderScenario {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$DelegateMemberSamAccountName = 'john.smith',
        [string]$DelegateGroupName = 'GG_AdminSD_Resetters',
        [string]$ProtectedUserSamAccountName = 'yagami_adm',
        [Parameter(Mandatory = $true)][string]$GroupsOuDistinguishedName,
        [bool]$RequireDelegateMemberNonPrivileged = $false,
        [bool]$TriggerSdProp = $true,
        [ValidateRange(0, 120)][int]$PostSdPropWaitSeconds = 15,
        [ValidateRange(1, 300)][int]$PropagationTimeoutSeconds = 90,
        [string]$Server
    )

    Import-Module ActiveDirectory -ErrorAction Stop
    Assert-AdminSdHolderSamAccountName -Value $DelegateMemberSamAccountName -Name 'DelegateMemberSamAccountName'
    Assert-AdminSdHolderSamAccountName -Value $DelegateGroupName -Name 'DelegateGroupName'
    Assert-AdminSdHolderRdnValue -Value $DelegateGroupName -Name 'DelegateGroupName'
    Assert-AdminSdHolderSamAccountName -Value $ProtectedUserSamAccountName -Name 'ProtectedUserSamAccountName'
    Assert-AdminSdHolderResetPasswordRight -Server $Server

    $adParameters = Get-AdminSdHolderAdServerParameters -Server $Server
    $domain = Get-ADDomain @adParameters -ErrorAction Stop
    $domainDn = [string]$domain.DistinguishedName
    $adminSdHolderDn = Get-AdminSdHolderDistinguishedName -DomainDistinguishedName $domainDn
    $adminSdHolder = Get-AdminSdHolderObjectOrNull -DistinguishedName $adminSdHolderDn -Server $Server
    if ($null -eq $adminSdHolder) {
        throw "AdminSDHolder container '$adminSdHolderDn' was not found."
    }
    if ($null -eq (Get-ADOrganizationalUnit -Identity $GroupsOuDistinguishedName @adParameters -ErrorAction SilentlyContinue)) {
        throw "Scenario groups OU '$GroupsOuDistinguishedName' was not found. Restore 06-ADCS-HTTP-CDP before running this scenario."
    }

    $delegateMember = Get-AdminSdHolderUserOrNull -SamAccountName $DelegateMemberSamAccountName -Server $Server
    if ($null -eq $delegateMember) {
        throw "Required baseline user '$DelegateMemberSamAccountName' was not found. Restore 06-ADCS-HTTP-CDP before running this scenario."
    }
    $delegateMemberGroups = @(Get-AdminSdHolderPrincipalGroupSamAccountNames -Principal $delegateMember -Server $Server)
    $delegateMemberPrivilegedMatches = @(Get-AdminSdHolderPrivilegedGroupMatches -GroupSamAccountNames $delegateMemberGroups)
    if ($RequireDelegateMemberNonPrivileged -and $delegateMemberPrivilegedMatches.Count -gt 0) {
        throw "Delegate member '$DelegateMemberSamAccountName' is already privileged through: $($delegateMemberPrivilegedMatches -join ', '). Restore 06-ADCS-HTTP-CDP before running this scenario."
    }
    $protectedUser = Get-AdminSdHolderUserOrNull -SamAccountName $ProtectedUserSamAccountName -Server $Server
    if ($null -eq $protectedUser) {
        throw "Required protected user '$ProtectedUserSamAccountName' was not found. Restore 06-ADCS-HTTP-CDP before running this scenario."
    }
    $protectedUserGroups = @(Get-AdminSdHolderPrincipalGroupSamAccountNames -Principal $protectedUser -Server $Server)
    if ($protectedUserGroups -notcontains 'Domain Admins') {
        throw "Protected user '$ProtectedUserSamAccountName' is not a Domain Admin. The default scenario target must be a protected account."
    }

    $changed = $false
    $delegateGroup = Ensure-AdminSdHolderScenarioGroup `
        -GroupName $DelegateGroupName `
        -GroupsOuDistinguishedName $GroupsOuDistinguishedName `
        -Server $Server `
        -WhatIf:$WhatIfPreference
    $delegateMembershipChanged = Ensure-AdminSdHolderGroupMember `
        -Group $delegateGroup `
        -MemberDistinguishedName ([string]$delegateMember.DistinguishedName) `
        -MemberLabel $DelegateMemberSamAccountName `
        -Server $Server `
        -WhatIf:$WhatIfPreference
    if ($delegateMembershipChanged) { $changed = $true }

    $delegateGroup = Get-AdminSdHolderGroupOrNull -SamAccountName $DelegateGroupName -Server $Server
    $adminSdHolderAceChanged = Ensure-AdminSdHolderResetPasswordAce `
        -AdminSdHolderDistinguishedName $adminSdHolderDn `
        -PrincipalSid $delegateGroup.SID `
        -PrincipalLabel $DelegateGroupName `
        -Server $Server `
        -WhatIf:$WhatIfPreference
    if ($adminSdHolderAceChanged) { $changed = $true }

    if (-not $WhatIfPreference) {
        Save-AdminSdHolderCurrentState `
            -DomainDistinguishedName $domainDn `
            -AdminSdHolderDistinguishedName $adminSdHolderDn `
            -DelegateGroup $delegateGroup `
            -DelegateMemberSamAccountName $DelegateMemberSamAccountName `
            -ProtectedUserSamAccountName $ProtectedUserSamAccountName | Out-Null
    }

    $sdPropTriggered = $false
    $protectedUserAceObserved = $false
    if ($TriggerSdProp) {
        $sdPropTriggered = Invoke-AdminSdHolderSdProp -PostTriggerWaitSeconds $PostSdPropWaitSeconds -Server $Server -WhatIf:$WhatIfPreference
        if ($sdPropTriggered) { $changed = $true }
        if (-not $WhatIfPreference) {
            $protectedUserAceObserved = Wait-AdminSdHolderResetPasswordAce `
                -DistinguishedName ([string]$protectedUser.DistinguishedName) `
                -PrincipalSid $delegateGroup.SID `
                -ExpectedPresent $true `
                -TimeoutSeconds $PropagationTimeoutSeconds `
                -Server $Server
            if (-not $protectedUserAceObserved) {
                throw "SDProp did not stamp the scenario Reset Password ACE on '$($protectedUser.DistinguishedName)' within $PropagationTimeoutSeconds seconds."
            }
        }
    }

    $posture = Get-AdminSdHolderScenarioPosture `
        -DelegateMemberSamAccountName $DelegateMemberSamAccountName `
        -DelegateGroupName $DelegateGroupName `
        -ProtectedUserSamAccountName $ProtectedUserSamAccountName `
        -Server $Server

    return [pscustomobject]@{
        Scenario                         = $script:AdminSdHolderScenarioName
        Changed                          = $changed
        Baseline                         = '06-ADCS-HTTP-CDP'
        Domain                           = $domainDn
        AdminSdHolder                    = $adminSdHolderDn
        DelegateMember                   = $delegateMember.DistinguishedName
        DelegateGroup                    = $delegateGroup.DistinguishedName
        ProtectedUser                    = $protectedUser.DistinguishedName
        DelegateMembershipChanged        = $delegateMembershipChanged
        DelegateMemberPrivilegedGroups   = [string[]]$delegateMemberPrivilegedMatches
        AdminSdHolderAceChanged          = $adminSdHolderAceChanged
        TriggerSdProp                    = $TriggerSdProp
        SdPropTriggered                  = $sdPropTriggered
        ProtectedUserAceObserved         = $protectedUserAceObserved
        AdminSdHolderAceCount            = $posture.AdminSdHolderResetPasswordAceCount
        ProtectedUserAceCount            = $posture.ProtectedUserResetPasswordAceCount
        AdminCountObjectsWithScenarioAce = [string[]]$posture.AdminCountObjectsWithScenarioAce
        StatePath                        = $script:AdminSdHolderStatePath
        PasswordResetExecuted            = $false
    }
}

function Clear-AdminSdHolderScenario {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [string]$DelegateMemberSamAccountName = 'john.smith',
        [string]$DelegateGroupName = 'GG_AdminSD_Resetters',
        [bool]$TriggerSdProp = $true,
        [ValidateRange(0, 120)][int]$PostSdPropWaitSeconds = 15,
        [ValidateRange(1, 300)][int]$PropagationTimeoutSeconds = 90,
        [string]$Server
    )

    Import-Module ActiveDirectory -ErrorAction Stop
    Assert-AdminSdHolderSamAccountName -Value $DelegateMemberSamAccountName -Name 'DelegateMemberSamAccountName'
    Assert-AdminSdHolderSamAccountName -Value $DelegateGroupName -Name 'DelegateGroupName'

    $state = Read-AdminSdHolderScenarioState
    $effectiveGroupName = $DelegateGroupName
    if ($null -ne $state) {
        $stateScenarioName = [string](Get-AdminSdHolderPropertyValue -InputObject $state -Name 'ScenarioName' -Default '')
        if ($stateScenarioName -ne $script:AdminSdHolderScenarioName) {
            throw "State file '$script:AdminSdHolderStatePath' belongs to '$stateScenarioName', not '$script:AdminSdHolderScenarioName'."
        }
        $stateGroupName = [string](Get-AdminSdHolderPropertyValue -InputObject $state -Name 'DelegateGroupName' -Default '')
        if (-not [string]::IsNullOrWhiteSpace($stateGroupName)) {
            $effectiveGroupName = $stateGroupName
        }
    }

    $adParameters = Get-AdminSdHolderAdServerParameters -Server $Server
    $domain = Get-ADDomain @adParameters -ErrorAction Stop
    $domainDn = [string]$domain.DistinguishedName
    $adminSdHolderDn = Get-AdminSdHolderDistinguishedName -DomainDistinguishedName $domainDn
    $delegateMember = Get-AdminSdHolderUserOrNull -SamAccountName $DelegateMemberSamAccountName -Server $Server
    $delegateGroup = Get-AdminSdHolderGroupOrNull -SamAccountName $effectiveGroupName -Server $Server
    if ($null -ne $delegateGroup -and [string]$delegateGroup.adminDescription -cne $script:AdminSdHolderMarker) {
        throw "Group '$effectiveGroupName' exists but is not scenario-marked. Refusing cleanup."
    }

    $delegateGroupSid = $null
    if ($null -ne $delegateGroup) {
        $delegateGroupSid = [Security.Principal.SecurityIdentifier]$delegateGroup.SID
    }
    elseif ($null -ne $state) {
        $stateSid = [string](Get-AdminSdHolderPropertyValue -InputObject $state -Name 'DelegateGroupSid' -Default '')
        if (-not [string]::IsNullOrWhiteSpace($stateSid)) {
            $delegateGroupSid = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList $stateSid
        }
    }

    $changed = $false
    $sdPropTriggered = $false
    $adminSdHolderAcesRemoved = 0
    $protectedObjectAcesRemoved = 0
    if ($null -ne $delegateGroupSid) {
        $adminSdHolderAcesRemoved = Remove-AdminSdHolderResetPasswordAces `
            -DistinguishedName $adminSdHolderDn `
            -PrincipalSid $delegateGroupSid `
            -TargetLabel 'AdminSDHolder' `
            -Server $Server `
            -WhatIf:$WhatIfPreference
        if ($adminSdHolderAcesRemoved -gt 0) { $changed = $true }

        foreach ($protectedObject in @(Get-AdminSdHolderAdminCountObjects -DomainDistinguishedName $domainDn -Server $Server)) {
            $removed = Remove-AdminSdHolderResetPasswordAces `
                -DistinguishedName ([string]$protectedObject.DistinguishedName) `
                -PrincipalSid $delegateGroupSid `
                -TargetLabel ([string]$protectedObject.DistinguishedName) `
                -Server $Server `
                -WhatIf:$WhatIfPreference
            $protectedObjectAcesRemoved += $removed
            if ($removed -gt 0) { $changed = $true }
        }

        if ($TriggerSdProp) {
            $sdPropTriggered = Invoke-AdminSdHolderSdProp -PostTriggerWaitSeconds $PostSdPropWaitSeconds -Server $Server -WhatIf:$WhatIfPreference
            if ($sdPropTriggered) { $changed = $true }
            if (-not $WhatIfPreference) {
                [void](Wait-AdminSdHolderResetPasswordAce `
                        -DistinguishedName $adminSdHolderDn `
                        -PrincipalSid $delegateGroupSid `
                        -ExpectedPresent $false `
                        -TimeoutSeconds $PropagationTimeoutSeconds `
                        -Server $Server)
            }
        }
    }
    $delegateMembershipRemoved = $false
    if ($null -ne $delegateGroup -and $null -ne $delegateMember) {
        $delegateMembershipRemoved = Remove-AdminSdHolderGroupMemberIfPresent `
            -Group $delegateGroup `
            -MemberDistinguishedName ([string]$delegateMember.DistinguishedName) `
            -MemberLabel $DelegateMemberSamAccountName `
            -Server $Server `
            -WhatIf:$WhatIfPreference
        if ($delegateMembershipRemoved) { $changed = $true }
        $delegateGroup = Get-AdminSdHolderGroupOrNull -SamAccountName $effectiveGroupName -Server $Server
    }

    $delegateGroupRemoved = Remove-AdminSdHolderScenarioGroup -Group $delegateGroup -GroupName $effectiveGroupName -Server $Server -WhatIf:$WhatIfPreference
    if ($delegateGroupRemoved) { $changed = $true }

    $stateRemoved = Remove-AdminSdHolderScenarioState -WhatIf:$WhatIfPreference
    if ($stateRemoved) { $changed = $true }

    $baselineRestored = $false
    if (-not $WhatIfPreference) {
        $remainingGroup = Get-AdminSdHolderGroupOrNull -SamAccountName $effectiveGroupName -Server $Server
        $remainingAdminSdHolderAceCount = 0
        $remainingProtectedObjectAceCount = 0
        if ($null -ne $delegateGroupSid) {
            $remainingAdminSdHolderAceCount = Get-AdminSdHolderResetPasswordAceCount -DistinguishedName $adminSdHolderDn -PrincipalSid $delegateGroupSid -Server $Server
            foreach ($protectedObject in @(Get-AdminSdHolderAdminCountObjects -DomainDistinguishedName $domainDn -Server $Server)) {
                $remainingProtectedObjectAceCount += Get-AdminSdHolderResetPasswordAceCount -DistinguishedName ([string]$protectedObject.DistinguishedName) -PrincipalSid $delegateGroupSid -Server $Server
            }
        }
        if ($null -ne $remainingGroup -or $remainingAdminSdHolderAceCount -gt 0 -or $remainingProtectedObjectAceCount -gt 0) {
            throw "Cleanup finished but scenario residue remains. GroupPresent=$($null -ne $remainingGroup); AdminSDHolderAceCount=$remainingAdminSdHolderAceCount; ProtectedObjectAceCount=$remainingProtectedObjectAceCount"
        }
        $baselineRestored = $true
    }

    return [pscustomobject]@{
        Scenario                     = $script:AdminSdHolderScenarioName
        Changed                      = $changed
        Baseline                     = '06-ADCS-HTTP-CDP'
        BaselineRestored             = $baselineRestored
        Domain                       = $domainDn
        DelegateGroupName            = $effectiveGroupName
        DelegateGroupSid             = if ($null -eq $delegateGroupSid) { '' } else { [string]$delegateGroupSid.Value }
        AdminSdHolderAcesRemoved     = $adminSdHolderAcesRemoved
        ProtectedObjectAcesRemoved   = $protectedObjectAcesRemoved
        SdPropTriggered              = $sdPropTriggered
        DelegateMembershipRemoved    = $delegateMembershipRemoved
        DelegateGroupRemoved         = $delegateGroupRemoved
        StateRemoved                 = $stateRemoved
        PasswordResetExecuted        = $false
    }
}

Export-ModuleMember -Function @(
    'Clear-AdminSdHolderScenario',
    'Get-AdminSdHolderMarker',
    'Get-AdminSdHolderResetPasswordRightGuid',
    'Get-AdminSdHolderScenarioName',
    'Get-AdminSdHolderScenarioPosture',
    'Get-AdminSdHolderStatePath',
    'Get-AdminSdHolderStateRoot',
    'Read-AdminSdHolderScenarioState',
    'Set-AdminSdHolderScenario'
)
