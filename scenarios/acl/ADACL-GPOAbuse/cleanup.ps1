#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$HelpdeskUserSamAccountName = 'john.smith',
    [string]$WorkstationAdminsGroupName = 'GG_GPO_WS_Admins',
    [string]$GpoName = 'GPO-Workstation-Baseline',
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'ADACL-GPOAbuse'
$script:Marker = 'windows-ad-lab:ADACL-GPOAbuse'
$script:RootOuName = 'LAB'
$script:Changed = $false
$AdServerParameters = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $AdServerParameters['Server'] = $Server
}

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

function Assert-SamAccountName {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($Value -notmatch '^[A-Za-z0-9._-]{1,20}$') {
        throw "$Name must be a valid 1-20 character sAMAccountName: '$Value'"
    }
}

function Assert-GpoDisplayName {
    param([Parameter(Mandatory = $true)][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw 'GpoName cannot be empty.'
    }
    if ($Value -ne $Value.Trim()) {
        throw "GpoName cannot start or end with whitespace: '$Value'"
    }
    if ($Value -match '[\\/]') {
        throw "GpoName cannot contain a path separator: '$Value'"
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

function Get-SchemaAttributeGuid {
    param([Parameter(Mandatory = $true)][string]$LdapDisplayName)

    $rootDse = Get-ADRootDSE @AdServerParameters -ErrorAction Stop
    $schemaNc = [string]$rootDse.schemaNamingContext
    $escapedName = ConvertTo-LdapFilterValue -Value $LdapDisplayName
    $attributes = @(Get-ADObject -SearchBase $schemaNc -SearchScope OneLevel -LDAPFilter "(lDAPDisplayName=$escapedName)" -Properties lDAPDisplayName, schemaIDGUID @AdServerParameters -ErrorAction Stop)
    if ($attributes.Count -ne 1) {
        throw "Expected one schema attribute named '$LdapDisplayName', found $($attributes.Count)."
    }
    return (ConvertTo-GuidValue -Value $attributes[0].schemaIDGUID -Context "schemaIDGUID for $LdapDisplayName")
}

function Get-AdOrganizationalUnitOrNull {
    param([Parameter(Mandatory = $true)][string]$DistinguishedName)

    try {
        return Get-ADOrganizationalUnit -Identity $DistinguishedName -Properties gPLink @AdServerParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
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

function Get-ScenarioGpoByNameOrNull {
    param([Parameter(Mandatory = $true)][string]$Name)

    $gpos = @(Get-GPO -All @GpParameters -ErrorAction Stop | Where-Object { [string]$_.DisplayName -ceq $Name })
    if ($gpos.Count -gt 1) {
        throw "Multiple GPOs named '$Name' were returned. Refusing to choose one."
    }
    if ($gpos.Count -eq 0) {
        return $null
    }
    return $gpos[0]
}

function Get-GpoContainerDistinguishedName {
    param(
        [Parameter(Mandatory = $true)]$Gpo,
        [Parameter(Mandatory = $true)][string]$DomainDistinguishedName
    )

    $gpoGuid = [string]$Gpo.Id
    return "CN={$gpoGuid},CN=Policies,CN=System,$DomainDistinguishedName"
}

function Get-GpoContainerOrNull {
    param([Parameter(Mandatory = $true)][string]$DistinguishedName)

    try {
        return Get-ADObject -Identity $DistinguishedName -Properties adminDescription, displayName, gPCFileSysPath @AdServerParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

function Get-GpoSysvolPath {
    param([Parameter(Mandatory = $true)]$Gpo)

    $gpoGuid = [string]$Gpo.Id
    return (Join-Path $env:SystemRoot "SYSVOL\domain\Policies\{$gpoGuid}")
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

function Test-MemberWriteAce {
    param(
        [Parameter(Mandatory = $true)]$AccessRule,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid,
        [Parameter(Mandatory = $true)][Guid]$MemberAttributeGuid
    )

    if ($AccessRule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }
    if (-not (Test-IdentityReferenceMatchesSid -IdentityReference $AccessRule.IdentityReference -Sid $PrincipalSid)) { return $false }
    if (($AccessRule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -ne [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) { return $false }
    return ($AccessRule.ObjectType -eq $MemberAttributeGuid)
}

function Test-GpoGenericWriteAce {
    param(
        [Parameter(Mandatory = $true)]$AccessRule,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    if ($AccessRule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }
    if (-not (Test-IdentityReferenceMatchesSid -IdentityReference $AccessRule.IdentityReference -Sid $PrincipalSid)) { return $false }
    return (($AccessRule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)
}

function Test-FileModifyAce {
    param(
        [Parameter(Mandatory = $true)]$AccessRule,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    if ($AccessRule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }
    if (-not (Test-IdentityReferenceMatchesSid -IdentityReference $AccessRule.IdentityReference -Sid $PrincipalSid)) { return $false }
    return (($AccessRule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Modify) -eq [System.Security.AccessControl.FileSystemRights]::Modify)
}

function Remove-MemberWriteAce {
    param(
        [Parameter(Mandatory = $true)][string]$GroupDistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid,
        [Parameter(Mandatory = $true)][Guid]$MemberAttributeGuid
    )

    Ensure-AdDrive
    $path = "AD:\$GroupDistinguishedName"
    $acl = Get-Acl -Path $path -ErrorAction Stop
    $rulesToRemove = @($acl.Access | Where-Object { -not $_.IsInherited -and (Test-MemberWriteAce -AccessRule $_ -PrincipalSid $PrincipalSid -MemberAttributeGuid $MemberAttributeGuid) })
    if ($rulesToRemove.Count -eq 0) {
        return 0
    }

    if ($PSCmdlet.ShouldProcess($GroupDistinguishedName, 'Remove scenario WriteMembers ACE')) {
        foreach ($rule in $rulesToRemove) {
            [void]$acl.RemoveAccessRuleSpecific($rule)
        }
        Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
        $script:Changed = $true
    }
    return $rulesToRemove.Count
}

function Remove-GpoGenericWriteAce {
    param(
        [Parameter(Mandatory = $true)][string]$GpoDistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    Ensure-AdDrive
    $path = "AD:\$GpoDistinguishedName"
    $acl = Get-Acl -Path $path -ErrorAction Stop
    $rulesToRemove = @($acl.Access | Where-Object { -not $_.IsInherited -and (Test-GpoGenericWriteAce -AccessRule $_ -PrincipalSid $PrincipalSid) })
    if ($rulesToRemove.Count -eq 0) {
        return 0
    }

    if ($PSCmdlet.ShouldProcess($GpoDistinguishedName, 'Remove scenario GenericWrite ACE from GPO AD object')) {
        foreach ($rule in $rulesToRemove) {
            [void]$acl.RemoveAccessRuleSpecific($rule)
        }
        Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
        $script:Changed = $true
    }
    return $rulesToRemove.Count
}

function Remove-GpoSysvolModifyAce {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Container)) {
        return 0
    }
    $acl = Get-Acl -LiteralPath $LiteralPath -ErrorAction Stop
    $rulesToRemove = @($acl.Access | Where-Object { -not $_.IsInherited -and (Test-FileModifyAce -AccessRule $_ -PrincipalSid $PrincipalSid) })
    if ($rulesToRemove.Count -eq 0) {
        return 0
    }

    if ($PSCmdlet.ShouldProcess($LiteralPath, 'Remove scenario Modify ACE from GPO SYSVOL folder')) {
        foreach ($rule in $rulesToRemove) {
            [void]$acl.RemoveAccessRuleSpecific($rule)
        }
        Set-Acl -LiteralPath $LiteralPath -AclObject $acl -ErrorAction Stop
        $script:Changed = $true
    }
    return $rulesToRemove.Count
}

function Get-GpoLinkState {
    param(
        [Parameter(Mandatory = $true)][string]$TargetOuDistinguishedName,
        [Parameter(Mandatory = $true)][string]$GpoDistinguishedName
    )

    $ou = Get-ADOrganizationalUnit -Identity $TargetOuDistinguishedName -Properties gPLink @AdServerParameters -ErrorAction Stop
    $rawValue = ConvertTo-SingleAdValue -Value $ou.gPLink -AttributeName 'gPLink' -DistinguishedName $TargetOuDistinguishedName
    $linkValue = if ($null -eq $rawValue) { '' } else { [string]$rawValue }
    $escapedLink = [regex]::Escape("LDAP://$GpoDistinguishedName")
    $match = [regex]::Match($linkValue, "\[$escapedLink;([0-3])\]", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $match.Success) {
        return [pscustomobject]@{
            Linked = $false
            Enabled = $false
            Option = $null
            Raw = $linkValue
        }
    }
    $option = [int]$match.Groups[1].Value
    return [pscustomobject]@{
        Linked = $true
        Enabled = (($option -band 1) -eq 0)
        Option = $option
        Raw = $linkValue
    }
}

function Remove-ScenarioGpoLink {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$TargetOuDistinguishedName,
        [Parameter(Mandatory = $true)][string]$GpoDistinguishedName
    )

    $state = Get-GpoLinkState -TargetOuDistinguishedName $TargetOuDistinguishedName -GpoDistinguishedName $GpoDistinguishedName
    if (-not $state.Linked) {
        return $false
    }

    if ($PSCmdlet.ShouldProcess($TargetOuDistinguishedName, "Remove GPO link for $Name")) {
        Remove-GPLink -Name $Name -Target $TargetOuDistinguishedName @GpParameters -ErrorAction Stop | Out-Null
        $script:Changed = $true
    }
    return $true
}

function Remove-ScenarioGpo {
    param(
        [Parameter(Mandatory = $true)]$Gpo,
        [Parameter(Mandatory = $true)][string]$GpoDistinguishedName
    )

    $container = Get-GpoContainerOrNull -DistinguishedName $GpoDistinguishedName
    if ($null -eq $container) {
        return $false
    }
    if ([string]$container.adminDescription -cne $script:Marker) {
        throw "GPO '$($Gpo.DisplayName)' exists but is not marked for this scenario. Refusing to delete it."
    }

    if ($PSCmdlet.ShouldProcess($Gpo.DisplayName, 'Delete scenario GPO')) {
        Remove-GPO -Name ([string]$Gpo.DisplayName) -Confirm:$false @GpParameters -ErrorAction Stop | Out-Null
        $script:Changed = $true
    }
    return $true
}

function Remove-ScenarioGroup {
    param([Parameter(Mandatory = $true)]$Group)

    if ([string]$Group.adminDescription -cne $script:Marker) {
        throw "Group '$($Group.SamAccountName)' exists but is not marked for this scenario. Refusing to delete it."
    }

    if ($PSCmdlet.ShouldProcess($Group.DistinguishedName, 'Delete scenario Workstation Admins group')) {
        Remove-ADGroup -Identity $Group.DistinguishedName -Confirm:$false @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }
}

Assert-SamAccountName -Value $HelpdeskUserSamAccountName -Name 'HelpdeskUserSamAccountName'
Assert-SamAccountName -Value $WorkstationAdminsGroupName -Name 'WorkstationAdminsGroupName'
Assert-GpoDisplayName -Value $GpoName

$domain = Get-ADDomain @AdServerParameters -ErrorAction Stop
if ([string]$domain.DNSRoot -ine 'ad.lab.exceeds.test') {
    throw "Current domain '$($domain.DNSRoot)' is not the expected Baseline 06 domain 'ad.lab.exceeds.test'."
}
$GpParameters = @{ Domain = [string]$domain.DNSRoot }
if ($AdServerParameters.ContainsKey('Server')) {
    $GpParameters['Server'] = [string]$AdServerParameters['Server']
}

$domainDn = [string]$domain.DistinguishedName
$rootOuDn = "OU=$script:RootOuName,$domainDn"
$workstationsOuDn = "OU=Workstations,OU=Computers,$rootOuDn"
if ($null -eq (Get-AdOrganizationalUnitOrNull -DistinguishedName $workstationsOuDn)) {
    throw "Required Baseline 06 OU '$workstationsOuDn' was not found."
}

$memberWriteAcesRemoved = 0
$gpoGenericWriteAcesRemoved = 0
$gpoSysvolModifyAcesRemoved = 0
$gpoLinkRemoved = $false
$gpoRemoved = $false
$groupRemoved = $false
$gpoDn = $null

$helpdeskUser = Get-ScenarioUserBySamOrNull -SamAccountName $HelpdeskUserSamAccountName
$workstationAdminsGroup = Get-ScenarioGroupOrNull -SamAccountName $WorkstationAdminsGroupName
if ($null -ne $workstationAdminsGroup) {
    if ([string]$workstationAdminsGroup.adminDescription -cne $script:Marker) {
        throw "Group '$WorkstationAdminsGroupName' exists but is not marked for this scenario. Refusing cleanup."
    }
    if ($null -ne $helpdeskUser) {
        $memberAttributeGuid = Get-SchemaAttributeGuid -LdapDisplayName 'member'
        $memberWriteAcesRemoved = Remove-MemberWriteAce -GroupDistinguishedName ([string]$workstationAdminsGroup.DistinguishedName) -PrincipalSid $helpdeskUser.SID -MemberAttributeGuid $memberAttributeGuid
    }
}

$gpo = Get-ScenarioGpoByNameOrNull -Name $GpoName
if ($null -ne $gpo) {
    $gpoDn = Get-GpoContainerDistinguishedName -Gpo $gpo -DomainDistinguishedName $domainDn
    $container = Get-GpoContainerOrNull -DistinguishedName $gpoDn
    if ($null -ne $container -and [string]$container.adminDescription -cne $script:Marker) {
        throw "GPO '$GpoName' exists but is not marked for this scenario. Refusing cleanup."
    }
    if ($null -ne $workstationAdminsGroup) {
        $gpoGenericWriteAcesRemoved = Remove-GpoGenericWriteAce -GpoDistinguishedName $gpoDn -PrincipalSid $workstationAdminsGroup.SID
        $gpoSysvolModifyAcesRemoved = Remove-GpoSysvolModifyAce -LiteralPath (Get-GpoSysvolPath -Gpo $gpo) -PrincipalSid $workstationAdminsGroup.SID
    }
    $gpoLinkRemoved = Remove-ScenarioGpoLink -Name $GpoName -TargetOuDistinguishedName $workstationsOuDn -GpoDistinguishedName $gpoDn
    $gpoRemoved = Remove-ScenarioGpo -Gpo $gpo -GpoDistinguishedName $gpoDn
}

if ($null -ne $workstationAdminsGroup) {
    Remove-ScenarioGroup -Group $workstationAdminsGroup
    $groupRemoved = $true
}

if ($WhatIfPreference) {
    Write-Host 'WhatIf: Baseline restored check skipped because no objects were deleted.'
}
else {
    if ($null -ne (Get-ScenarioGroupOrNull -SamAccountName $WorkstationAdminsGroupName)) {
        throw "Cleanup finished but scenario group '$WorkstationAdminsGroupName' still exists."
    }
    if ($null -ne (Get-ScenarioGpoByNameOrNull -Name $GpoName)) {
        throw "Cleanup finished but scenario GPO '$GpoName' still exists."
    }
    if (-not [string]::IsNullOrWhiteSpace($gpoDn)) {
        $linkState = Get-GpoLinkState -TargetOuDistinguishedName $workstationsOuDn -GpoDistinguishedName $gpoDn
        if ($linkState.Linked) {
            throw "Cleanup finished but '$GpoName' is still linked to '$workstationsOuDn'."
        }
    }
}

[pscustomobject]@{
    Scenario                   = $script:ScenarioName
    Changed                    = $script:Changed
    Baseline                   = '06-ADCS-HTTP-CDP'
    BaselineRestored           = (-not $WhatIfPreference)
    WorkstationAdminsGroup     = $WorkstationAdminsGroupName
    GroupRemoved               = $groupRemoved
    MemberWriteAcesRemoved     = $memberWriteAcesRemoved
    Gpo                        = $GpoName
    GpoRemoved                 = $gpoRemoved
    GpoLinkRemoved             = $gpoLinkRemoved
    GpoGenericWriteAcesRemoved = $gpoGenericWriteAcesRemoved
    GpoSysvolModifyAcesRemoved = $gpoSysvolModifyAcesRemoved
}
