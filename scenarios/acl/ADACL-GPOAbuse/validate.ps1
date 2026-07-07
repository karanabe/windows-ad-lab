#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$HelpdeskUserSamAccountName = 'john.smith',
    [string]$WorkstationAdminsGroupName = 'GG_GPO_WS_Admins',
    [string]$GpoName = 'GPO-Workstation-Baseline',
    [string]$TargetComputerName = 'CLIENT01',
    [string]$RegistryKey = 'HKLM\Software\Policies\ExceedsLab\Scenario07',
    [string]$RegistryValueName = 'Marker',
    [string]$RegistryValue = 'ADACL-GPOAbuse',
    [string]$OutputPath,
    [string]$Server,
    [switch]$IncludeAcl,
    [switch]$PassThru,
    [switch]$FailOnValidationError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'ADACL-GPOAbuse'
$script:Marker = 'windows-ad-lab:ADACL-GPOAbuse'
$script:RootOuName = 'LAB'
$script:WriteMembersEdgeName = 'WriteMembers'
$AdServerParameters = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $AdServerParameters['Server'] = $Server
}

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

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

function Get-ScenarioComputerOrNull {
    param([Parameter(Mandatory = $true)][string]$ComputerName)

    try {
        return Get-ADComputer -Identity $ComputerName -Properties Description, Enabled, SID @AdServerParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
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
        return Get-ADObject -Identity $DistinguishedName -Properties adminDescription, displayName, gPCFileSysPath, gPCMachineExtensionNames, versionNumber @AdServerParameters -ErrorAction Stop
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

function Get-MemberWriteAceCount {
    param(
        [Parameter(Mandatory = $true)][string]$GroupDistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid,
        [Parameter(Mandatory = $true)][Guid]$MemberAttributeGuid
    )

    Ensure-AdDrive
    $acl = Get-Acl -Path "AD:\$GroupDistinguishedName" -ErrorAction Stop
    return @($acl.Access | Where-Object { -not $_.IsInherited -and (Test-MemberWriteAce -AccessRule $_ -PrincipalSid $PrincipalSid -MemberAttributeGuid $MemberAttributeGuid) }).Count
}

function Get-GpoGenericWriteAceCount {
    param(
        [Parameter(Mandatory = $true)][string]$GpoDistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    Ensure-AdDrive
    $acl = Get-Acl -Path "AD:\$GpoDistinguishedName" -ErrorAction Stop
    return @($acl.Access | Where-Object { -not $_.IsInherited -and (Test-GpoGenericWriteAce -AccessRule $_ -PrincipalSid $PrincipalSid) }).Count
}

function Get-GpoSysvolModifyAceCount {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Container)) {
        return 0
    }
    $acl = Get-Acl -LiteralPath $LiteralPath -ErrorAction Stop
    return @($acl.Access | Where-Object { -not $_.IsInherited -and (Test-FileModifyAce -AccessRule $_ -PrincipalSid $PrincipalSid) }).Count
}

function Format-AdAce {
    param([Parameter(Mandatory = $true)]$AccessRule)

    return '{0};{1};{2};ObjectType={3};Inherited={4}' -f
        $AccessRule.IdentityReference,
        $AccessRule.AccessControlType,
        $AccessRule.ActiveDirectoryRights,
        $AccessRule.ObjectType,
        $AccessRule.IsInherited
}

function Format-FileAce {
    param([Parameter(Mandatory = $true)]$AccessRule)

    return '{0};{1};{2};Inheritance={3};Inherited={4}' -f
        $AccessRule.IdentityReference,
        $AccessRule.AccessControlType,
        $AccessRule.FileSystemRights,
        $AccessRule.InheritanceFlags,
        $AccessRule.IsInherited
}

function Get-PrincipalAdAceSummary {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    Ensure-AdDrive
    $acl = Get-Acl -Path "AD:\$DistinguishedName" -ErrorAction Stop
    return [string[]]@($acl.Access | Where-Object {
        -not $_.IsInherited -and (Test-IdentityReferenceMatchesSid -IdentityReference $_.IdentityReference -Sid $PrincipalSid)
    } | ForEach-Object { Format-AdAce -AccessRule $_ })
}

function Get-PrincipalFileAceSummary {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Container)) {
        return @()
    }
    $acl = Get-Acl -LiteralPath $LiteralPath -ErrorAction Stop
    return [string[]]@($acl.Access | Where-Object {
        -not $_.IsInherited -and (Test-IdentityReferenceMatchesSid -IdentityReference $_.IdentityReference -Sid $PrincipalSid)
    } | ForEach-Object { Format-FileAce -AccessRule $_ })
}

function Get-GpoRegistryValueOrNull {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$ValueName
    )

    try {
        return Get-GPRegistryValue -Name $Name -Key $Key -ValueName $ValueName @GpParameters -ErrorAction Stop
    }
    catch {
        return $null
    }
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

function Get-ObjectPropertyValueOrNull {
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory = $true)][string]$PropertyName
    )

    if ($null -eq $InputObject) {
        return $null
    }
    $properties = @($InputObject.PSObject.Properties.Match($PropertyName))
    if ($properties.Count -eq 0) {
        return $null
    }
    return $properties[0].Value
}

function Get-GpoPermissionSummary {
    param([Parameter(Mandatory = $true)][string]$Name)

    $permissions = @(Get-GPPermission -Name $Name -All @GpParameters -ErrorAction Stop)
    $summaries = New-Object 'System.Collections.Generic.List[string]'
    foreach ($permission in $permissions) {
        $trustee = Get-ObjectPropertyValueOrNull -InputObject $permission -PropertyName 'Trustee'
        $trusteeName = Get-ObjectPropertyValueOrNull -InputObject $trustee -PropertyName 'Name'
        $trusteeSid = Get-ObjectPropertyValueOrNull -InputObject $trustee -PropertyName 'Sid'
        $permissionName = Get-ObjectPropertyValueOrNull -InputObject $permission -PropertyName 'Permission'
        [void]$summaries.Add(('{0};{1};{2}' -f $trusteeName, $trusteeSid, $permissionName))
    }
    return [string[]]$summaries.ToArray()
}

function Test-GpoSecurityFilteringAllowsDefaultComputers {
    param([Parameter(Mandatory = $true)][string]$Name)

    $summaries = @(Get-GpoPermissionSummary -Name $Name)
    foreach ($summary in $summaries) {
        if ($summary -imatch '(^|\\)(Authenticated Users|Domain Computers);' -and $summary -imatch ';GpoApply$') {
            return $true
        }
    }
    return $false
}

$domain = Get-ADDomain @AdServerParameters -ErrorAction Stop
if ([string]$domain.DNSRoot -ine 'ad.lab.exceeds.test') {
    throw "Current domain '$($domain.DNSRoot)' is not the expected Baseline 06 domain 'ad.lab.exceeds.test'."
}
$GpParameters = @{ Domain = [string]$domain.DNSRoot }
if ($AdServerParameters.ContainsKey('Server')) {
    $GpParameters['Server'] = [string]$AdServerParameters['Server']
}

$results = New-Object 'System.Collections.Generic.List[object]'
$domainDn = [string]$domain.DistinguishedName
$rootOuDn = "OU=$script:RootOuName,$domainDn"
$workstationsOuDn = "OU=Workstations,OU=Computers,$rootOuDn"
$groupsOuDn = "OU=Groups,$rootOuDn"
$helpdeskUser = Get-ScenarioUserBySamOrNull -SamAccountName $HelpdeskUserSamAccountName
$workstationAdminsGroup = Get-ScenarioGroupOrNull -SamAccountName $WorkstationAdminsGroupName
$targetComputer = Get-ScenarioComputerOrNull -ComputerName $TargetComputerName
$workstationsOu = Get-AdOrganizationalUnitOrNull -DistinguishedName $workstationsOuDn
$groupsOu = Get-AdOrganizationalUnitOrNull -DistinguishedName $groupsOuDn
$gpo = Get-ScenarioGpoByNameOrNull -Name $GpoName

Add-ValidationResult -Results $results -Name 'Helpdesk user exists' -Passed ($null -ne $helpdeskUser) -Expected $HelpdeskUserSamAccountName -Actual $(if ($null -eq $helpdeskUser) { '<missing>' } else { $helpdeskUser.DistinguishedName })
Add-ValidationResult -Results $results -Name 'Workstation Admins scenario group exists' -Passed ($null -ne $workstationAdminsGroup) -Expected $WorkstationAdminsGroupName -Actual $(if ($null -eq $workstationAdminsGroup) { '<missing>' } else { $workstationAdminsGroup.DistinguishedName })
Add-ValidationResult -Results $results -Name 'Target computer exists' -Passed ($null -ne $targetComputer) -Expected $TargetComputerName -Actual $(if ($null -eq $targetComputer) { '<missing>' } else { $targetComputer.DistinguishedName })
Add-ValidationResult -Results $results -Name 'Target Workstations OU exists' -Passed ($null -ne $workstationsOu) -Expected $workstationsOuDn -Actual $(if ($null -eq $workstationsOu) { '<missing>' } else { $workstationsOu.DistinguishedName })
Add-ValidationResult -Results $results -Name 'Groups OU exists' -Passed ($null -ne $groupsOu) -Expected $groupsOuDn -Actual $(if ($null -eq $groupsOu) { '<missing>' } else { $groupsOu.DistinguishedName })
Add-ValidationResult -Results $results -Name 'Scenario GPO exists' -Passed ($null -ne $gpo) -Expected $GpoName -Actual $(if ($null -eq $gpo) { '<missing>' } else { [string]$gpo.Id })

if ($null -ne $workstationAdminsGroup) {
    Add-ValidationResult -Results $results -Name 'Workstation Admins group is scenario-marked' -Passed ([string]$workstationAdminsGroup.adminDescription -ceq $script:Marker) -Expected $script:Marker -Actual ([string]$workstationAdminsGroup.adminDescription)
}

if ($null -ne $targetComputer) {
    Add-ValidationResult -Results $results -Name 'Target computer is in linked OU scope' -Passed ([string]$targetComputer.DistinguishedName -ilike "*,$workstationsOuDn") -Expected $workstationsOuDn -Actual ([string]$targetComputer.DistinguishedName) -Message 'GPO application still depends on normal computer-side policy processing.'
}

if ($null -ne $helpdeskUser -and $null -ne $workstationAdminsGroup) {
    $memberAttributeGuid = Get-SchemaAttributeGuid -LdapDisplayName 'member'
    $writeMembersAceCount = Get-MemberWriteAceCount -GroupDistinguishedName ([string]$workstationAdminsGroup.DistinguishedName) -PrincipalSid $helpdeskUser.SID -MemberAttributeGuid $memberAttributeGuid
    $groupMembers = @(ConvertTo-StringArray -Value $workstationAdminsGroup.Member)
    Add-ValidationResult -Results $results -Name 'WriteMembers edge exists' -Passed ($writeMembersAceCount -gt 0) -Expected "$HelpdeskUserSamAccountName can write member on $WorkstationAdminsGroupName" -Actual "Count=$writeMembersAceCount" -Message 'This is the first AD ACL edge in the chain.'
    Add-ValidationResult -Results $results -Name 'Helpdesk user is not pre-seeded into Workstation Admins' -Passed (-not ($groupMembers -icontains [string]$helpdeskUser.DistinguishedName)) -Expected 'No direct membership before exercising WriteMembers' -Actual ($groupMembers -join '; ')
}
else {
    Add-SkippedResult -Results $results -Name 'WriteMembers checks' -Expected 'Helpdesk user and Workstation Admins group present' -Actual 'One or more objects are missing'
}

if ($null -ne $gpo) {
    $gpoDn = Get-GpoContainerDistinguishedName -Gpo $gpo -DomainDistinguishedName $domainDn
    $gpoContainer = Get-GpoContainerOrNull -DistinguishedName $gpoDn
    $gpoSysvolPath = Get-GpoSysvolPath -Gpo $gpo
    $registryValueObject = Get-GpoRegistryValueOrNull -Name $GpoName -Key $RegistryKey -ValueName $RegistryValueName
    $registryPolPath = Join-Path $gpoSysvolPath 'Machine\registry.pol'
    $linkState = if ($null -ne $workstationsOu) { Get-GpoLinkState -TargetOuDistinguishedName $workstationsOuDn -GpoDistinguishedName $gpoDn } else { $null }

    Add-ValidationResult -Results $results -Name 'GPO container is scenario-marked' -Passed ($null -ne $gpoContainer -and [string]$gpoContainer.adminDescription -ceq $script:Marker) -Expected $script:Marker -Actual $(if ($null -eq $gpoContainer) { '<missing>' } else { [string]$gpoContainer.adminDescription })
    Add-ValidationResult -Results $results -Name 'GPO is linked to Workstations OU' -Passed ($null -ne $linkState -and [bool]$linkState.Linked) -Expected $workstationsOuDn -Actual $(if ($null -eq $linkState) { '<missing OU>' } else { $linkState.Raw })
    Add-ValidationResult -Results $results -Name 'GPO link is enabled' -Passed ($null -ne $linkState -and [bool]$linkState.Enabled) -Expected 'Enabled link option' -Actual $(if ($null -eq $linkState) { '<missing OU>' } else { "Option=$($linkState.Option)" })
    Add-ValidationResult -Results $results -Name 'GPO registry policy marker exists' -Passed ($null -ne $registryValueObject -and [string]$registryValueObject.Value -ceq $RegistryValue) -Expected "$RegistryKey\\$RegistryValueName=$RegistryValue" -Actual $(if ($null -eq $registryValueObject) { '<missing>' } else { "$($registryValueObject.KeyPath)\\$($registryValueObject.ValueName)=$($registryValueObject.Value)" }) -Message 'The marker is harmless and represents GPO content changed through the GroupPolicy module.'
    Add-ValidationResult -Results $results -Name 'GPO SYSVOL registry.pol exists' -Passed (Test-Path -LiteralPath $registryPolPath -PathType Leaf) -Expected $registryPolPath -Actual $(if (Test-Path -LiteralPath $registryPolPath -PathType Leaf) { 'Present' } else { '<missing>' })
    Add-ValidationResult -Results $results -Name 'GPO has no WMI filter' -Passed ([string]::IsNullOrWhiteSpace([string](Get-ObjectPropertyValueOrNull -InputObject $gpo -PropertyName 'WmiFilter'))) -Expected 'No WMI filter' -Actual ([string](Get-ObjectPropertyValueOrNull -InputObject $gpo -PropertyName 'WmiFilter'))

    if ($null -ne $workstationAdminsGroup) {
        $gpoGenericWriteAceCount = Get-GpoGenericWriteAceCount -GpoDistinguishedName $gpoDn -PrincipalSid $workstationAdminsGroup.SID
        $gpoSysvolModifyAceCount = Get-GpoSysvolModifyAceCount -LiteralPath $gpoSysvolPath -PrincipalSid $workstationAdminsGroup.SID
        Add-ValidationResult -Results $results -Name 'Workstation Admins has GPO AD GenericWrite' -Passed ($gpoGenericWriteAceCount -gt 0) -Expected 'GenericWrite on groupPolicyContainer' -Actual "Count=$gpoGenericWriteAceCount" -Message 'This is the AD object side of GPO editability.'
        Add-ValidationResult -Results $results -Name 'Workstation Admins has GPO SYSVOL Modify' -Passed ($gpoSysvolModifyAceCount -gt 0) -Expected 'Modify on GPO SYSVOL folder' -Actual "Count=$gpoSysvolModifyAceCount" -Message 'This is the file-system side of GPO editability.'
    }
    else {
        Add-SkippedResult -Results $results -Name 'GPO ACL checks' -Expected 'Workstation Admins group present' -Actual '<missing group>'
    }

    try {
        $defaultApply = Test-GpoSecurityFilteringAllowsDefaultComputers -Name $GpoName
        $permissionSummary = @(Get-GpoPermissionSummary -Name $GpoName)
        Add-ValidationResult -Results $results -Name 'Security filtering permits default computer scope' -Passed $defaultApply -Expected 'Authenticated Users or Domain Computers has GpoApply' -Actual ($permissionSummary -join ' | ')
    }
    catch {
        Add-SkippedResult -Results $results -Name 'Security filtering permits default computer scope' -Expected 'Get-GPPermission succeeds' -Actual $_.Exception.Message
    }

    if ($IncludeAcl -and $null -ne $workstationAdminsGroup) {
        $gpoAdAces = @(Get-PrincipalAdAceSummary -DistinguishedName $gpoDn -PrincipalSid $workstationAdminsGroup.SID)
        $gpoFileAces = @(Get-PrincipalFileAceSummary -LiteralPath $gpoSysvolPath -PrincipalSid $workstationAdminsGroup.SID)
        Add-ValidationResult -Results $results -Name 'Workstation Admins GPO AD ACE summary' -Passed ($gpoAdAces.Count -gt 0) -Expected 'At least one explicit AD ACE' -Actual ($gpoAdAces -join ' | ')
        Add-ValidationResult -Results $results -Name 'Workstation Admins GPO SYSVOL ACE summary' -Passed ($gpoFileAces.Count -gt 0) -Expected 'At least one explicit file ACE' -Actual ($gpoFileAces -join ' | ')
    }
}
else {
    Add-SkippedResult -Results $results -Name 'GPO checks' -Expected 'Scenario GPO present' -Actual '<missing GPO>'
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
