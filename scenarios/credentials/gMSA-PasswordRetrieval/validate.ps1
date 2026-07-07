#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$GmsaName = 'gmsa_web',
    [string]$AuthorizedComputerName = 'WEB01',
    [string]$ControlComputerName = 'FILE01',
    [string]$ReaderGroupName = 'GG_gMSA_Readers',
    [string]$ReaderGroupMemberSamAccountName = 'john.smith',
    [string]$GroupMemberManagerSamAccountName = 'operator01',
    [bool]$ExpectReaderGroupMisconfiguration = $true,
    [bool]$ExpectBackupOperatorsMembership = $true,
    [ValidateRange(1, 365)][int]$ManagedPasswordIntervalDays = 30,
    [string[]]$ServicePrincipalNames = @(),
    [string]$Server,
    [switch]$IncludeAcl,
    [switch]$PassThru,
    [switch]$FailOnValidationError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'gMSA-PasswordRetrieval'
$script:Marker = 'windows-ad-lab:gMSA-PasswordRetrieval'
$script:RootOuName = 'LAB'
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
        return [Guid]::Empty
    }
    return (ConvertTo-GuidValue -Value $schemaObject.schemaIDGUID -Context "schemaIDGUID for $LdapDisplayName")
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

function Get-GmsaRetrieveAllowedSidValues {
    param([AllowNull()]$Gmsa)

    if ($null -eq $Gmsa) {
        return @()
    }
    $descriptor = ConvertTo-RawSecurityDescriptor -Value $Gmsa.($script:GmsaMembershipAttribute) -AttributeName $script:GmsaMembershipAttribute -DistinguishedName ([string]$Gmsa.DistinguishedName)
    return @(Get-DescriptorAllowedSidValues -Descriptor $descriptor)
}

function Test-GmsaRetrievePrincipalSid {
    param(
        [AllowNull()]$Gmsa,
        [AllowNull()]$Principal
    )

    if ($null -eq $Gmsa -or $null -eq $Principal) {
        return $false
    }
    $allowedSidValues = @(Get-GmsaRetrieveAllowedSidValues -Gmsa $Gmsa)
    return ($allowedSidValues -contains [string]([Security.Principal.SecurityIdentifier]$Principal.SID).Value)
}

function Format-RetrievePolicySummary {
    param([AllowNull()]$Gmsa)

    if ($null -eq $Gmsa) {
        return '<missing gMSA>'
    }
    $propertyValues = ConvertTo-StringArray -Value $Gmsa.PrincipalsAllowedToRetrieveManagedPassword
    if ($propertyValues.Count -eq 0) {
        $propertySummary = '<empty>'
    }
    else {
        $propertySummary = (($propertyValues | Sort-Object -Unique) -join '; ')
    }
    $sidValues = @(Get-GmsaRetrieveAllowedSidValues -Gmsa $Gmsa)
    if ($sidValues.Count -eq 0) {
        $sidSummary = '<none>'
    }
    else {
        $sidSummary = (($sidValues | Sort-Object -Unique) -join '; ')
    }
    return "PrincipalsAllowedToRetrieveManagedPassword=$propertySummary;msDS-GroupMSAMembership SIDs=$sidSummary"
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

function Get-MemberWriteAceCount {
    param(
        [Parameter(Mandatory = $true)][string]$GroupDistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid,
        [Parameter(Mandatory = $true)][Guid]$MemberAttributeGuid
    )

    Ensure-AdDrive
    $acl = Get-Acl -Path "AD:\$GroupDistinguishedName" -ErrorAction Stop
    $matches = @($acl.Access | Where-Object {
        [string]$_.AccessControlType -eq 'Allow' `
            -and (($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -eq [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) `
            -and ([Guid]$_.ObjectType -eq $MemberAttributeGuid) `
            -and (Test-IdentityReferenceMatchesSid -IdentityReference $_.IdentityReference -Sid $PrincipalSid)
    })
    return $matches.Count
}

function Get-AclSummaryRows {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    Ensure-AdDrive
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $acl = Get-Acl -Path "AD:\$DistinguishedName" -ErrorAction Stop
    foreach ($rule in @($acl.Access | Where-Object { Test-IdentityReferenceMatchesSid -IdentityReference $_.IdentityReference -Sid $PrincipalSid })) {
        [void]$rows.Add([pscustomobject]@{
            Target      = $DistinguishedName
            Identity    = [string]$rule.IdentityReference
            Type        = [string]$rule.AccessControlType
            Rights      = [string]$rule.ActiveDirectoryRights
            Inherited   = [bool]$rule.IsInherited
            ObjectType  = [string]$rule.ObjectType
            InheritedBy = [string]$rule.InheritedObjectType
        })
    }
    return $rows.ToArray()
}

function Add-RetrieveAccessResult {
    param(
        [AllowEmptyCollection()][System.Collections.Generic.List[object]]$Results,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()]$Gmsa,
        [AllowNull()]$Principal,
        [Parameter(Mandatory = $true)][bool]$Expected
    )

    if ($null -eq $Gmsa -or $null -eq $Principal) {
        Add-SkippedResult -Results $Results -Name $Name -Expected "Retrieve allowed=$Expected" -Actual '<missing gMSA or principal>'
        return
    }

    $actual = Test-GmsaRetrievePrincipalSid -Gmsa $Gmsa -Principal $Principal
    Add-ValidationResult `
        -Results $Results `
        -Name $Name `
        -Passed ($actual -eq $Expected) `
        -Expected "Retrieve allowed=$Expected" `
        -Actual "Retrieve allowed=$actual;$(Format-RetrievePolicySummary -Gmsa $Gmsa)"
}

$results = New-Object 'System.Collections.Generic.List[object]'
$domain = Get-ADDomain @AdServerParameters -ErrorAction Stop
$domainDn = [string]$domain.DistinguishedName
$rootOuDn = "OU=$script:RootOuName,$domainDn"
$groupsOuDn = "OU=Groups,$rootOuDn"
$serviceAccountsOuDn = "OU=Service Accounts,$rootOuDn"
$serversOuDn = "OU=Servers,OU=Computers,$rootOuDn"

Add-ValidationResult -Results $results -Name 'Expected domain' -Passed ([string]$domain.DNSRoot -ieq 'ad.lab.exceeds.test') -Expected 'ad.lab.exceeds.test' -Actual ([string]$domain.DNSRoot)

$kdsRootKeys = @(Get-KdsRootKey -ErrorAction Stop)
Add-ValidationResult -Results $results -Name 'KDS root key present' -Passed ($kdsRootKeys.Count -gt 0) -Expected 'At least one KDS root key' -Actual "Count=$($kdsRootKeys.Count)"

foreach ($schemaSpec in @(
    @{ Name = 'msDS-GroupManagedServiceAccount'; Class = 'classSchema' },
    @{ Name = $script:GmsaMembershipAttribute; Class = 'attributeSchema' },
    @{ Name = $script:GmsaManagedPasswordAttribute; Class = 'attributeSchema' },
    @{ Name = $script:GmsaManagedPasswordIntervalAttribute; Class = 'attributeSchema' }
)) {
    $schemaObject = Get-AdSchemaObjectOrNull -LdapDisplayName ([string]$schemaSpec.Name) -ObjectClass ([string]$schemaSpec.Class)
    if ($null -eq $schemaObject) {
        $schemaActual = '<missing>'
    }
    else {
        $schemaGuid = ConvertTo-GuidValue -Value $schemaObject.schemaIDGUID -Context "schemaIDGUID for $($schemaSpec.Name)"
        $schemaActual = "Guid=$schemaGuid"
    }
    Add-ValidationResult -Results $results -Name "gMSA schema: $($schemaSpec.Name)" -Passed ($null -ne $schemaObject) -Expected 'Schema object exists' -Actual $schemaActual
}

$desiredSpns = @($ServicePrincipalNames | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { [string]$_ })
if ($desiredSpns.Count -eq 0) {
    $desiredSpns = @(
        "HTTP/$AuthorizedComputerName",
        "HTTP/$AuthorizedComputerName.$($domain.DNSRoot)"
    )
}
$desiredSpns = [string[]]($desiredSpns | Sort-Object -Unique)

$gmsa = Get-ScenarioServiceAccountOrNull -Name $GmsaName
$authorizedComputer = Get-ScenarioComputerOrNull -ComputerName $AuthorizedComputerName
$controlComputer = Get-ScenarioComputerOrNull -ComputerName $ControlComputerName
$readerGroup = Get-ScenarioGroupOrNull -SamAccountName $ReaderGroupName
$readerMember = Get-ScenarioUserBySamOrNull -SamAccountName $ReaderGroupMemberSamAccountName
$memberManager = Get-ScenarioUserBySamOrNull -SamAccountName $GroupMemberManagerSamAccountName
$backupOperators = Get-BuiltinGroupOrNull -Identity 'Backup Operators'

$gmsaActual = if ($null -eq $gmsa) { '<missing>' } else { [string]$gmsa.DistinguishedName }
Add-ValidationResult -Results $results -Name 'gMSA exists' -Passed ($null -ne $gmsa) -Expected "$GmsaName$" -Actual $gmsaActual
if ($null -eq $gmsa) {
    Add-SkippedResult -Results $results -Name 'gMSA marker' -Expected $script:Marker -Actual '<missing gMSA>'
    Add-SkippedResult -Results $results -Name 'gMSA OU' -Expected $serviceAccountsOuDn -Actual '<missing gMSA>'
    Add-SkippedResult -Results $results -Name 'gMSA SPNs' -Expected ($desiredSpns -join '; ') -Actual '<missing gMSA>'
    Add-SkippedResult -Results $results -Name 'gMSA managed password interval' -Expected $ManagedPasswordIntervalDays -Actual '<missing gMSA>'
}
else {
    Add-ValidationResult -Results $results -Name 'gMSA marker' -Passed ([string]$gmsa.adminDescription -ceq $script:Marker) -Expected $script:Marker -Actual ([string]$gmsa.adminDescription)
    Add-ValidationResult -Results $results -Name 'gMSA OU' -Passed ([string]$gmsa.DistinguishedName -ieq "CN=$GmsaName,$serviceAccountsOuDn") -Expected "CN=$GmsaName,$serviceAccountsOuDn" -Actual ([string]$gmsa.DistinguishedName)
    $currentSpns = @(ConvertTo-StringArray -Value $gmsa.ServicePrincipalName | Sort-Object -Unique)
    Add-ValidationResult -Results $results -Name 'gMSA SPNs' -Passed (Test-SameStringSet -Expected $desiredSpns -Actual $currentSpns) -Expected ($desiredSpns -join '; ') -Actual ($currentSpns -join '; ')
    $currentInterval = ConvertTo-SingleAdValue -Value $gmsa.($script:GmsaManagedPasswordIntervalAttribute) -AttributeName $script:GmsaManagedPasswordIntervalAttribute -DistinguishedName ([string]$gmsa.DistinguishedName)
    $intervalActual = if ($null -eq $currentInterval) { '<not set>' } else { [int]$currentInterval }
    Add-ValidationResult -Results $results -Name 'gMSA managed password interval' -Passed ($null -ne $currentInterval -and [int]$currentInterval -eq $ManagedPasswordIntervalDays) -Expected $ManagedPasswordIntervalDays -Actual $intervalActual
}

foreach ($computerSpec in @(
    @{ Name = $AuthorizedComputerName; Computer = $authorizedComputer },
    @{ Name = $ControlComputerName; Computer = $controlComputer }
)) {
    $computerActual = if ($null -eq $computerSpec.Computer) { '<missing>' } else { [string]$computerSpec.Computer.DistinguishedName }
    Add-ValidationResult -Results $results -Name "Computer exists: $($computerSpec.Name)" -Passed ($null -ne $computerSpec.Computer) -Expected ([string]$computerSpec.Name) -Actual $computerActual
    if ($null -ne $computerSpec.Computer) {
        Add-ValidationResult -Results $results -Name "Computer OU: $($computerSpec.Name)" -Passed ([string]$computerSpec.Computer.DistinguishedName -like "*,$serversOuDn") -Expected $serversOuDn -Actual ([string]$computerSpec.Computer.DistinguishedName)
    }
}

$readerGroupActual = if ($null -eq $readerGroup) { '<missing>' } else { [string]$readerGroup.DistinguishedName }
Add-ValidationResult -Results $results -Name 'Reader group exists' -Passed ($null -ne $readerGroup) -Expected "$($domain.NetBIOSName)\$ReaderGroupName" -Actual $readerGroupActual
if ($null -eq $readerGroup) {
    Add-SkippedResult -Results $results -Name 'Reader group marker' -Expected $script:Marker -Actual '<missing group>'
    Add-SkippedResult -Results $results -Name 'Reader group membership' -Expected $ReaderGroupMemberSamAccountName -Actual '<missing group>'
    Add-SkippedResult -Results $results -Name 'Group member manager delegation' -Expected $GroupMemberManagerSamAccountName -Actual '<missing group>'
}
else {
    Add-ValidationResult -Results $results -Name 'Reader group marker' -Passed ([string]$readerGroup.adminDescription -ceq $script:Marker) -Expected $script:Marker -Actual ([string]$readerGroup.adminDescription)
    $readerMemberDn = if ($null -eq $readerMember) { '<missing user>' } else { [string]$readerMember.DistinguishedName }
    $readerMembers = @($readerGroup.Member | ForEach-Object { [string]$_ })
    Add-ValidationResult -Results $results -Name 'Reader group membership' -Passed ($readerMembers -contains $readerMemberDn) -Expected $readerMemberDn -Actual (($readerMembers | Sort-Object) -join '; ')
    if ($null -eq $memberManager) {
        Add-SkippedResult -Results $results -Name 'Group member manager delegation' -Expected $GroupMemberManagerSamAccountName -Actual '<missing manager user>'
    }
    else {
        $memberAttributeGuid = Get-AdAttributeSchemaGuid -LdapDisplayName $script:MemberAttribute
        $managerSid = [Security.Principal.SecurityIdentifier]$memberManager.SID
        $memberWriteAceCount = Get-MemberWriteAceCount -GroupDistinguishedName ([string]$readerGroup.DistinguishedName) -PrincipalSid $managerSid -MemberAttributeGuid $memberAttributeGuid
        Add-ValidationResult -Results $results -Name 'Group member manager delegation' -Passed ($memberWriteAceCount -gt 0) -Expected "WriteProperty on $script:MemberAttribute" -Actual "AceCount=$memberWriteAceCount"
        if ($IncludeAcl) {
            Get-AclSummaryRows -DistinguishedName ([string]$readerGroup.DistinguishedName) -PrincipalSid $managerSid | Format-Table -AutoSize | Out-Host
        }
    }
}

Add-RetrieveAccessResult `
    -Results $results `
    -Name 'Authorized computer can retrieve gMSA password' `
    -Gmsa $gmsa `
    -Principal $authorizedComputer `
    -Expected $true
Add-RetrieveAccessResult `
    -Results $results `
    -Name 'Control computer cannot retrieve gMSA password' `
    -Gmsa $gmsa `
    -Principal $controlComputer `
    -Expected $false
Add-RetrieveAccessResult `
    -Results $results `
    -Name 'Reader group can retrieve gMSA password' `
    -Gmsa $gmsa `
    -Principal $readerGroup `
    -Expected $ExpectReaderGroupMisconfiguration

if ($null -eq $backupOperators -or $null -eq $gmsa) {
    Add-SkippedResult -Results $results -Name 'Backup Operators overprivilege' -Expected $ExpectBackupOperatorsMembership -Actual '<missing Backup Operators group or gMSA>'
}
else {
    $backupMembers = @($backupOperators.Member | ForEach-Object { [string]$_ })
    $isBackupOperator = ($backupMembers -contains [string]$gmsa.DistinguishedName)
    Add-ValidationResult `
        -Results $results `
        -Name 'Backup Operators overprivilege' `
        -Passed ($isBackupOperator -eq $ExpectBackupOperatorsMembership) `
        -Expected "gMSA member=$ExpectBackupOperatorsMembership" `
        -Actual "gMSA member=$isBackupOperator"
}

$resultRows = @($results.ToArray())
if ($PassThru) {
    return $resultRows
}

$resultRows | Format-Table -AutoSize
$failed = @($resultRows | Where-Object Status -eq 'Failed')
if ($FailOnValidationError -and $failed.Count -gt 0) {
    $failedNames = @($failed | ForEach-Object { [string]$_.Name })
    throw "$script:ScenarioName validation failed: $($failedNames -join '; ')"
}
