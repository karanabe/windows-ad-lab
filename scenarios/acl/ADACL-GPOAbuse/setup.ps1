#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$HelpdeskUserSamAccountName = 'john.smith',
    [string]$WorkstationAdminsGroupName = 'GG_GPO_WS_Admins',
    [string]$GpoName = 'GPO-Workstation-Baseline',
    [string]$TargetComputerName = 'CLIENT01',
    [string]$RegistryKey = 'HKLM\Software\Policies\ExceedsLab\Scenario07',
    [string]$RegistryValueName = 'Marker',
    [string]$RegistryValue = 'ADACL-GPOAbuse',
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'ADACL-GPOAbuse'
$script:Marker = 'windows-ad-lab:ADACL-GPOAbuse'
$script:RootOuName = 'LAB'
$script:Changed = $false
$script:WriteMembersEdgeName = 'WriteMembers'
$AdServerParameters = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $AdServerParameters['Server'] = $Server
}

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

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

function Get-GpoContainer {
    param([Parameter(Mandatory = $true)][string]$DistinguishedName)

    return Get-ADObject -Identity $DistinguishedName -Properties adminDescription, displayName, gPCFileSysPath, gPCMachineExtensionNames, versionNumber @AdServerParameters -ErrorAction Stop
}

function Get-GpoSysvolPath {
    param([Parameter(Mandatory = $true)]$Gpo)

    $gpoGuid = [string]$Gpo.Id
    return (Join-Path $env:SystemRoot "SYSVOL\domain\Policies\{$gpoGuid}")
}

function Wait-ScenarioSysvolPath {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    for ($attempt = 0; $attempt -lt 12; $attempt++) {
        if (Test-Path -LiteralPath $LiteralPath -PathType Container) {
            return
        }
        Start-Sleep -Seconds 2
    }
    throw "GPO SYSVOL path was not created within the expected time: $LiteralPath"
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

function Ensure-ScenarioGroup {
    param(
        [Parameter(Mandatory = $true)][string]$GroupName,
        [Parameter(Mandatory = $true)][string]$GroupsOuDn
    )

    $group = Get-ScenarioGroupOrNull -SamAccountName $GroupName
    if ($null -eq $group) {
        if ($PSCmdlet.ShouldProcess($GroupName, "Create scenario group in $GroupsOuDn")) {
            New-ADGroup -Name $GroupName -SamAccountName $GroupName -GroupScope Global -GroupCategory Security -Path $GroupsOuDn -Description 'LAB ONLY: AD ACL to GPO abuse path group' @AdServerParameters -ErrorAction Stop | Out-Null
            $group = Get-ScenarioGroupOrNull -SamAccountName $GroupName
            Set-ADObject -Identity $group.DistinguishedName -Replace @{ adminDescription = $script:Marker } @AdServerParameters -ErrorAction Stop
            $script:Changed = $true
        }
        return (Get-ScenarioGroupOrNull -SamAccountName $GroupName)
    }

    if ([string]$group.adminDescription -cne $script:Marker) {
        throw "Group '$GroupName' already exists but is not marked for this scenario. Refusing to reuse it."
    }
    return $group
}

function Ensure-MemberWriteAce {
    param(
        [Parameter(Mandatory = $true)][string]$GroupDistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid,
        [Parameter(Mandatory = $true)][Guid]$MemberAttributeGuid
    )

    Ensure-AdDrive
    $path = "AD:\$GroupDistinguishedName"
    $acl = Get-Acl -Path $path -ErrorAction Stop
    $existingRules = @($acl.Access | Where-Object { -not $_.IsInherited -and (Test-MemberWriteAce -AccessRule $_ -PrincipalSid $PrincipalSid -MemberAttributeGuid $MemberAttributeGuid) })
    if ($existingRules.Count -gt 0) {
        return $false
    }

    $rule = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @(
        $PrincipalSid,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $MemberAttributeGuid
    )
    if ($PSCmdlet.ShouldProcess($GroupDistinguishedName, "Grant $script:WriteMembersEdgeName on member attribute")) {
        $acl.AddAccessRule($rule)
        Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
        $script:Changed = $true
    }
    return $true
}

function Ensure-ScenarioGpo {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$DomainDistinguishedName
    )

    $created = $false
    $gpo = Get-ScenarioGpoByNameOrNull -Name $Name
    if ($null -eq $gpo) {
        if ($PSCmdlet.ShouldProcess($Name, 'Create scenario GPO')) {
            New-GPO -Name $Name -Comment $script:Marker @GpParameters -ErrorAction Stop | Out-Null
            $script:Changed = $true
            $created = $true
        }
        $gpo = Get-ScenarioGpoByNameOrNull -Name $Name
        if ($null -eq $gpo) {
            return $null
        }
    }

    $gpoDn = Get-GpoContainerDistinguishedName -Gpo $gpo -DomainDistinguishedName $DomainDistinguishedName
    $container = Get-GpoContainer -DistinguishedName $gpoDn
    if ([string]$container.adminDescription -ne $script:Marker) {
        if (-not $created) {
            throw "GPO '$Name' already exists but is not marked for this scenario. Refusing to reuse it."
        }
        if ($PSCmdlet.ShouldProcess($gpoDn, 'Mark scenario GPO container')) {
            Set-ADObject -Identity $gpoDn -Replace @{ adminDescription = $script:Marker } @AdServerParameters -ErrorAction Stop
            $script:Changed = $true
        }
    }

    return (Get-ScenarioGpoByNameOrNull -Name $Name)
}

function Ensure-GpoGenericWriteAce {
    param(
        [Parameter(Mandatory = $true)][string]$GpoDistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    Ensure-AdDrive
    $path = "AD:\$GpoDistinguishedName"
    $acl = Get-Acl -Path $path -ErrorAction Stop
    $existingRules = @($acl.Access | Where-Object { -not $_.IsInherited -and (Test-GpoGenericWriteAce -AccessRule $_ -PrincipalSid $PrincipalSid) })
    if ($existingRules.Count -gt 0) {
        return $false
    }

    $rule = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @(
        $PrincipalSid,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    if ($PSCmdlet.ShouldProcess($GpoDistinguishedName, 'Grant GenericWrite on GPO AD object')) {
        $acl.AddAccessRule($rule)
        Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
        $script:Changed = $true
    }
    return $true
}

function Ensure-GpoSysvolModifyAce {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    Wait-ScenarioSysvolPath -LiteralPath $LiteralPath
    $acl = Get-Acl -LiteralPath $LiteralPath -ErrorAction Stop
    $existingRules = @($acl.Access | Where-Object { -not $_.IsInherited -and (Test-FileModifyAce -AccessRule $_ -PrincipalSid $PrincipalSid) })
    if ($existingRules.Count -gt 0) {
        return $false
    }

    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
        $PrincipalSid,
        [System.Security.AccessControl.FileSystemRights]::Modify,
        $inheritanceFlags,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    if ($PSCmdlet.ShouldProcess($LiteralPath, 'Grant Modify on GPO SYSVOL folder')) {
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $LiteralPath -AclObject $acl -ErrorAction Stop
        $script:Changed = $true
    }
    return $true
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

function Ensure-GpoRegistryMarker {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$ValueName,
        [Parameter(Mandatory = $true)][string]$Value
    )

    $current = Get-GpoRegistryValueOrNull -Name $Name -Key $Key -ValueName $ValueName
    if ($null -ne $current) {
        if ([string]$current.Value -cne $Value) {
            throw "GPO '$Name' already has registry policy '$Key\\$ValueName' with value '$($current.Value)'. Refusing to replace a non-scenario value."
        }
        return $false
    }

    if ($PSCmdlet.ShouldProcess($Name, "Set registry policy marker $Key\\$ValueName")) {
        Set-GPRegistryValue -Name $Name -Key $Key -ValueName $ValueName -Type String -Value $Value @GpParameters -ErrorAction Stop | Out-Null
        $script:Changed = $true
    }
    return $true
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

function Ensure-GpoLink {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$TargetOuDistinguishedName,
        [Parameter(Mandatory = $true)][string]$GpoDistinguishedName
    )

    $state = Get-GpoLinkState -TargetOuDistinguishedName $TargetOuDistinguishedName -GpoDistinguishedName $GpoDistinguishedName
    if ($state.Linked -and $state.Enabled) {
        return $false
    }

    if ($state.Linked) {
        if ($PSCmdlet.ShouldProcess($TargetOuDistinguishedName, "Enable GPO link for $Name")) {
            Set-GPLink -Name $Name -Target $TargetOuDistinguishedName -LinkEnabled Yes @GpParameters -ErrorAction Stop | Out-Null
            $script:Changed = $true
        }
        return $true
    }

    if ($PSCmdlet.ShouldProcess($TargetOuDistinguishedName, "Link GPO $Name")) {
        New-GPLink -Name $Name -Target $TargetOuDistinguishedName -LinkEnabled Yes @GpParameters -ErrorAction Stop | Out-Null
        $script:Changed = $true
    }
    return $true
}

Assert-SamAccountName -Value $HelpdeskUserSamAccountName -Name 'HelpdeskUserSamAccountName'
Assert-SamAccountName -Value $WorkstationAdminsGroupName -Name 'WorkstationAdminsGroupName'
Assert-GpoDisplayName -Value $GpoName
Assert-ComputerName -Value $TargetComputerName -Name 'TargetComputerName'
if ([string]::IsNullOrWhiteSpace($RegistryKey) -or $RegistryKey -notmatch '^HKLM\\') {
    throw "RegistryKey must be an HKLM policy path, for example HKLM\Software\Policies\ExceedsLab\Scenario07."
}
if ([string]::IsNullOrWhiteSpace($RegistryValueName)) {
    throw 'RegistryValueName cannot be empty.'
}

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
$groupsOuDn = "OU=Groups,$rootOuDn"
$workstationsOuDn = "OU=Workstations,OU=Computers,$rootOuDn"
foreach ($ouDn in @($rootOuDn, $groupsOuDn, $workstationsOuDn)) {
    if ($null -eq (Get-AdOrganizationalUnitOrNull -DistinguishedName $ouDn)) {
        throw "Required Baseline 06 OU '$ouDn' was not found. Restore 06-ADCS-HTTP-CDP before running this scenario."
    }
}

$helpdeskUser = Get-ScenarioUserBySamOrNull -SamAccountName $HelpdeskUserSamAccountName
$targetComputer = Get-ScenarioComputerOrNull -ComputerName $TargetComputerName
foreach ($requiredObject in @(
    @{ Name = $HelpdeskUserSamAccountName; Object = $helpdeskUser; Type = 'user' },
    @{ Name = $TargetComputerName; Object = $targetComputer; Type = 'computer' }
)) {
    if ($null -eq $requiredObject.Object) {
        throw "Required baseline $($requiredObject.Type) '$($requiredObject.Name)' was not found. Restore 06-ADCS-HTTP-CDP before running this scenario."
    }
}
if ([string]$targetComputer.DistinguishedName -inotlike "*,$workstationsOuDn") {
    throw "Target computer '$TargetComputerName' is not under '$workstationsOuDn'. Current DN: $($targetComputer.DistinguishedName)"
}

$memberAttributeGuid = Get-SchemaAttributeGuid -LdapDisplayName 'member'
$workstationAdminsGroup = Ensure-ScenarioGroup -GroupName $WorkstationAdminsGroupName -GroupsOuDn $groupsOuDn
if ($null -eq $workstationAdminsGroup) {
    throw "Scenario group '$WorkstationAdminsGroupName' was not available after creation."
}
$writeMembersAceChanged = Ensure-MemberWriteAce -GroupDistinguishedName ([string]$workstationAdminsGroup.DistinguishedName) -PrincipalSid $helpdeskUser.SID -MemberAttributeGuid $memberAttributeGuid

$gpo = Ensure-ScenarioGpo -Name $GpoName -DomainDistinguishedName $domainDn
if ($null -eq $gpo) {
    throw "Scenario GPO '$GpoName' was not available after creation."
}
$gpoDn = Get-GpoContainerDistinguishedName -Gpo $gpo -DomainDistinguishedName $domainDn
$gpoContainer = Get-GpoContainer -DistinguishedName $gpoDn
$gpoSysvolPath = Get-GpoSysvolPath -Gpo $gpo
$gpoAdAceChanged = Ensure-GpoGenericWriteAce -GpoDistinguishedName $gpoDn -PrincipalSid $workstationAdminsGroup.SID
$gpoSysvolAceChanged = Ensure-GpoSysvolModifyAce -LiteralPath $gpoSysvolPath -PrincipalSid $workstationAdminsGroup.SID
$registryMarkerChanged = Ensure-GpoRegistryMarker -Name $GpoName -Key $RegistryKey -ValueName $RegistryValueName -Value $RegistryValue
$gpoLinkChanged = Ensure-GpoLink -Name $GpoName -TargetOuDistinguishedName $workstationsOuDn -GpoDistinguishedName $gpoDn
$linkState = Get-GpoLinkState -TargetOuDistinguishedName $workstationsOuDn -GpoDistinguishedName $gpoDn
$gpo = Get-ScenarioGpoByNameOrNull -Name $GpoName
$gpoContainer = Get-GpoContainer -DistinguishedName $gpoDn

[pscustomobject]@{
    Scenario                    = $script:ScenarioName
    Changed                     = $script:Changed
    Baseline                    = '06-ADCS-HTTP-CDP'
    HelpdeskUser                = $helpdeskUser.DistinguishedName
    WorkstationAdminsGroup      = $workstationAdminsGroup.DistinguishedName
    WriteMembersEdge            = $script:WriteMembersEdgeName
    WriteMembersAceChanged      = $writeMembersAceChanged
    Gpo                         = $GpoName
    GpoId                       = [string]$gpo.Id
    GpoContainer                = $gpoDn
    GpoSysvolPath               = $gpoSysvolPath
    GpoAdGenericWriteChanged    = $gpoAdAceChanged
    GpoSysvolModifyChanged      = $gpoSysvolAceChanged
    RegistryMarkerChanged       = $registryMarkerChanged
    RegistryPolicy              = "$RegistryKey\\$RegistryValueName"
    TargetOu                    = $workstationsOuDn
    TargetComputer              = $targetComputer.DistinguishedName
    GpoLinkChanged              = $gpoLinkChanged
    GpoLinkEnabled              = [bool]$linkState.Enabled
    GpoVersionNumber            = $gpoContainer.versionNumber
    AutomatedEndpointExecution  = $false
}
