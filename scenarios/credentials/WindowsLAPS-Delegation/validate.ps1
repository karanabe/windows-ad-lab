#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$HelpdeskGroupName = 'GG_LAPS_Helpdesk',
    [string]$HelpdeskMemberSamAccountName = 'john.smith',
    [string]$WorkstationComputerName = 'CLIENT01',
    [string]$ServerComputerName = 'FILE01',
    [string]$ControlServerComputerName = 'WEB01',
    [bool]$ExpectFile01Misconfiguration = $true,
    [string]$Server,
    [switch]$IncludeAcl,
    [switch]$PassThru,
    [switch]$FailOnValidationError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'WindowsLAPS-Delegation'
$script:Marker = 'windows-ad-lab:WindowsLAPS-Delegation'
$script:RootOuName = 'LAB'
$script:LapsPasswordAttribute = 'msLAPS-Password'
$script:LapsExpirationAttribute = 'msLAPS-PasswordExpirationTime'
$script:LapsPasswordSchemaGuid = [Guid]::Empty
$script:LapsEncryptedPasswordRightsGuid = [Guid]'f3531ec6-6330-4f8e-8d39-7a671fbac605'
$AdServerParameters = @{}
$LapsDomainControllerParameters = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $AdServerParameters['Server'] = $Server
    $LapsDomainControllerParameters['DomainController'] = $Server
}

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module LAPS -ErrorAction Stop

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

function Get-LapsSchemaAttributeOrNull {
    param([Parameter(Mandatory = $true)][string]$LdapDisplayName)

    $rootDse = Get-ADRootDSE @AdServerParameters -ErrorAction Stop
    $schemaNc = [string]$rootDse.schemaNamingContext
    $escapedName = ConvertTo-LdapFilterValue -Value $LdapDisplayName
    $attributes = @(Get-ADObject -SearchBase $schemaNc -SearchScope OneLevel -LDAPFilter "(lDAPDisplayName=$escapedName)" -Properties lDAPDisplayName, schemaIDGUID, searchFlags @AdServerParameters -ErrorAction Stop)
    if ($attributes.Count -gt 1) {
        throw "Multiple schema attributes were returned for lDAPDisplayName '$LdapDisplayName'."
    }
    if ($attributes.Count -eq 0) {
        return $null
    }
    return $attributes[0]
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

function Get-ScenarioUserBySamOrNull {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)

    $escapedSam = ConvertTo-LdapFilterValue -Value $SamAccountName
    $users = @(Get-ADUser -LDAPFilter "(sAMAccountName=$escapedSam)" -Properties Enabled @AdServerParameters -ErrorAction Stop)
    if ($users.Count -gt 1) {
        throw "Multiple users were returned for sAMAccountName '$SamAccountName'."
    }
    if ($users.Count -eq 0) {
        return $null
    }
    return $users[0]
}

function Get-ScenarioComputerOrNull {
    param([Parameter(Mandatory = $true)][string]$ComputerName)

    try {
        return Get-ADComputer -Identity $ComputerName -Properties Description, msLAPS-Password, msLAPS-PasswordExpirationTime @AdServerParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

function Get-ScenarioFileTimeUtc {
    param([Parameter(Mandatory = $true)][string]$IsoUtc)

    return ([DateTimeOffset]::Parse($IsoUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)).UtcDateTime.ToFileTimeUtc()
}

function Get-ScenarioLapsUpdateTimeHex {
    return ('{0:x}' -f (Get-ScenarioFileTimeUtc -IsoUtc '2026-01-01T00:00:00Z'))
}

function Get-ScenarioLapsExpirationFileTime {
    return (Get-ScenarioFileTimeUtc -IsoUtc '2036-01-01T00:00:00Z')
}

function New-ScenarioLapsPasswordJson {
    param([Parameter(Mandatory = $true)][string]$ComputerName)

    $record = [ordered]@{
        n = 'Administrator'
        t = (Get-ScenarioLapsUpdateTimeHex)
        p = "LAB-ONLY-$($ComputerName.ToUpperInvariant())-WINDOWS-LAPS-DELEGATION"
    }
    return ($record | ConvertTo-Json -Compress)
}

function ConvertTo-LapsPasswordSummary {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)][string]$DistinguishedName
    )

    $singleValue = ConvertTo-SingleAdValue -Value $Value -AttributeName $script:LapsPasswordAttribute -DistinguishedName $DistinguishedName
    if ($null -eq $singleValue) {
        return '<not set>'
    }
    try {
        $record = ([string]$singleValue | ConvertFrom-Json)
        $hasPassword = ($record.PSObject.Properties.Name -contains 'p' -and -not [string]::IsNullOrEmpty([string]$record.p))
        return "Account=$($record.n);UpdateTimeHex=$($record.t);PasswordPresent=$hasPassword"
    }
    catch {
        return 'Present but not parseable as Windows LAPS JSON'
    }
}

function Get-LapsExtendedRightHolders {
    param(
        [Parameter(Mandatory = $true)][string]$Identity,
        [switch]$IncludeComputers
    )

    $findParameters = @{
        Identity    = @($Identity)
        ErrorAction = 'Stop'
    }
    foreach ($key in $LapsDomainControllerParameters.Keys) {
        $findParameters[$key] = $LapsDomainControllerParameters[$key]
    }
    if ($IncludeComputers) {
        $findParameters['IncludeComputers'] = $true
    }
    return @(Find-LapsADExtendedRights @findParameters)
}

function Get-LapsExtendedRightHoldersForOu {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][string]$Name,
        [switch]$IncludeComputers
    )

    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($identity in @($DistinguishedName, $Name)) {
        foreach ($row in @(Get-LapsExtendedRightHolders -Identity $identity -IncludeComputers:$IncludeComputers)) {
            [void]$rows.Add($row)
        }
        if ($rows.Count -gt 0) {
            break
        }
    }
    return $rows.ToArray()
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

function Test-HolderMatchesPrincipal {
    param(
        [AllowNull()]$Holder,
        [Parameter(Mandatory = $true)][string]$QualifiedPrincipal,
        [Parameter(Mandatory = $true)][string]$SamAccountName,
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    if ($null -eq $Holder) {
        return $false
    }
    $holderValues = New-Object 'System.Collections.Generic.List[string]'
    [void]$holderValues.Add([string]$Holder)
    foreach ($propertyName in @('Name', 'SamAccountName', 'SID', 'SecurityIdentifier', 'DistinguishedName', 'NTAccount')) {
        $property = $Holder.PSObject.Properties[$propertyName]
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            [void]$holderValues.Add([string]$property.Value)
        }
    }

    foreach ($holderText in @($holderValues.ToArray())) {
        if ($holderText -ieq $QualifiedPrincipal) { return $true }
        if ($holderText -ieq $SamAccountName) { return $true }
        if ($holderText -ieq $DistinguishedName) { return $true }
        if ($holderText -ieq [string]$PrincipalSid.Value) { return $true }
        if ($holderText -like "*\$SamAccountName") { return $true }
    }
    return $false
}

function Test-LapsHolderContainsPrincipal {
    param(
        [AllowNull()]$RightsRows,
        [Parameter(Mandatory = $true)][string]$ObjectDn,
        [Parameter(Mandatory = $true)][string]$QualifiedPrincipal,
        [Parameter(Mandatory = $true)][string]$SamAccountName,
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid,
        [switch]$AllowSingleRowFallback
    )

    $rightsRowsArray = @($RightsRows)
    $matchingRows = @($rightsRowsArray | Where-Object { [string]$_.ObjectDN -ieq $ObjectDn })
    if ($matchingRows.Count -eq 0 -and $AllowSingleRowFallback -and $rightsRowsArray.Count -eq 1) {
        $matchingRows = $rightsRowsArray
    }

    foreach ($row in @($matchingRows)) {
        foreach ($holder in @(ConvertTo-StringArray -Value $row.ExtendedRightHolders)) {
            if (Test-HolderMatchesPrincipal -Holder $holder -QualifiedPrincipal $QualifiedPrincipal -SamAccountName $SamAccountName -DistinguishedName $DistinguishedName -PrincipalSid $PrincipalSid) {
                return $true
            }
        }
    }
    return $false
}

function Format-HoldersForObject {
    param(
        [AllowNull()]$RightsRows,
        [Parameter(Mandatory = $true)][string]$ObjectDn,
        [switch]$AllowSingleRowFallback
    )

    $holders = New-Object 'System.Collections.Generic.List[string]'
    $rightsRowsArray = @($RightsRows)
    $matchingRows = @($rightsRowsArray | Where-Object { [string]$_.ObjectDN -ieq $ObjectDn })
    if ($matchingRows.Count -eq 0 -and $AllowSingleRowFallback -and $rightsRowsArray.Count -eq 1) {
        $matchingRows = $rightsRowsArray
    }
    foreach ($row in @($matchingRows)) {
        foreach ($holder in @(ConvertTo-StringArray -Value $row.ExtendedRightHolders)) {
            [void]$holders.Add([string]$holder)
        }
    }
    if ($holders.Count -eq 0) {
        return '<none>'
    }
    return (($holders.ToArray() | Sort-Object -Unique) -join '; ')
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

function Test-Right {
    param(
        [Parameter(Mandatory = $true)][System.DirectoryServices.ActiveDirectoryRights]$Rights,
        [Parameter(Mandatory = $true)][System.DirectoryServices.ActiveDirectoryRights]$Right
    )

    return (($Rights -band $Right) -eq $Right)
}

function Test-LapsReadCapableAce {
    param(
        [Parameter(Mandatory = $true)]$AccessRule,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    if ([string]$AccessRule.AccessControlType -ne 'Allow') {
        return $false
    }
    if (-not (Test-IdentityReferenceMatchesSid -IdentityReference $AccessRule.IdentityReference -Sid $PrincipalSid)) {
        return $false
    }

    $rights = $AccessRule.ActiveDirectoryRights
    if (Test-Right -Rights $rights -Right ([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)) { return $true }

    $objectType = [Guid]$AccessRule.ObjectType
    $appliesToAllProperties = ($objectType -eq [Guid]::Empty)
    $appliesToLapsPassword = ($objectType -eq $script:LapsPasswordSchemaGuid)
    $appliesToEncryptedLapsPassword = ($objectType -eq $script:LapsEncryptedPasswordRightsGuid)
    $appliesToRelevantLapsRight = ($appliesToAllProperties -or $appliesToLapsPassword -or $appliesToEncryptedLapsPassword)

    if ((Test-Right -Rights $rights -Right ([System.DirectoryServices.ActiveDirectoryRights]::ReadProperty)) -and $appliesToRelevantLapsRight) { return $true }
    if ((Test-Right -Rights $rights -Right ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)) -and $appliesToRelevantLapsRight) { return $true }
    return $false
}

function Get-LapsReadCapableAceCount {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    Ensure-AdDrive
    $acl = Get-Acl -Path "AD:\$DistinguishedName"
    $matches = @($acl.Access | Where-Object { Test-LapsReadCapableAce -AccessRule $_ -PrincipalSid $PrincipalSid })
    return $matches.Count
}

function Get-GenericAllAceCount {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    Ensure-AdDrive
    $acl = Get-Acl -Path "AD:\$DistinguishedName"
    $matches = @($acl.Access | Where-Object {
        [string]$_.AccessControlType -eq 'Allow' `
            -and (Test-Right -Rights $_.ActiveDirectoryRights -Right ([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)) `
            -and (Test-IdentityReferenceMatchesSid -IdentityReference $_.IdentityReference -Sid $PrincipalSid)
    })
    return $matches.Count
}

function Get-ExplicitGenericAllAceCount {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    Ensure-AdDrive
    $acl = Get-Acl -Path "AD:\$DistinguishedName"
    $matches = @($acl.Access | Where-Object {
        -not $_.IsInherited `
            -and [string]$_.AccessControlType -eq 'Allow' `
            -and (Test-Right -Rights $_.ActiveDirectoryRights -Right ([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)) `
            -and (Test-IdentityReferenceMatchesSid -IdentityReference $_.IdentityReference -Sid $PrincipalSid)
    })
    return $matches.Count
}

function ConvertTo-YesNo {
    param([Parameter(Mandatory = $true)][bool]$Value)

    if ($Value) {
        return 'Yes'
    }
    return 'No'
}

function Format-ScenarioEffectiveAccess {
    param(
        [Parameter(Mandatory = $true)][bool]$GenericAll,
        [Parameter(Mandatory = $true)][bool]$ReadLapsPassword
    )

    return "GenericAll=$(ConvertTo-YesNo -Value $GenericAll);Read LAPS Password=$(ConvertTo-YesNo -Value $ReadLapsPassword)"
}

function Add-EffectiveHelpdeskAccessResult {
    param(
        [AllowEmptyCollection()][System.Collections.Generic.List[object]]$Results,
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [AllowNull()]$Computer,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid,
        [Parameter(Mandatory = $true)][bool]$ExpectedGenericAll,
        [Parameter(Mandatory = $true)][bool]$ExpectedReadLapsPassword
    )

    if ($null -eq $Computer) {
        Add-SkippedResult -Results $Results -Name "Effective Helpdesk access: $ComputerName" -Expected (Format-ScenarioEffectiveAccess -GenericAll $ExpectedGenericAll -ReadLapsPassword $ExpectedReadLapsPassword) -Actual '<missing computer>'
        return
    }

    $genericAllAceCount = Get-GenericAllAceCount -DistinguishedName ([string]$Computer.DistinguishedName) -PrincipalSid $PrincipalSid
    $lapsReadAceCount = Get-LapsReadCapableAceCount -DistinguishedName ([string]$Computer.DistinguishedName) -PrincipalSid $PrincipalSid
    $actualGenericAll = ($genericAllAceCount -gt 0)
    $actualReadLapsPassword = ($lapsReadAceCount -gt 0)
    $expected = Format-ScenarioEffectiveAccess -GenericAll $ExpectedGenericAll -ReadLapsPassword $ExpectedReadLapsPassword
    $actual = "$(Format-ScenarioEffectiveAccess -GenericAll $actualGenericAll -ReadLapsPassword $actualReadLapsPassword);GenericAllAceCount=$genericAllAceCount;LapsReadAceCount=$lapsReadAceCount"

    Add-ValidationResult `
        -Results $Results `
        -Name "Effective Helpdesk access: $ComputerName" `
        -Passed ($actualGenericAll -eq $ExpectedGenericAll -and $actualReadLapsPassword -eq $ExpectedReadLapsPassword) `
        -Expected $expected `
        -Actual $actual
}

function Get-AclSummaryRows {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    Ensure-AdDrive
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $acl = Get-Acl -Path "AD:\$DistinguishedName"
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

$results = New-Object 'System.Collections.Generic.List[object]'
$domain = Get-ADDomain @AdServerParameters -ErrorAction Stop
$domainDn = [string]$domain.DistinguishedName
$rootOuDn = "OU=$script:RootOuName,$domainDn"
$groupsOuDn = "OU=Groups,$rootOuDn"
$workstationsOuDn = "OU=Workstations,OU=Computers,$rootOuDn"
$serversOuDn = "OU=Servers,OU=Computers,$rootOuDn"
$qualifiedHelpdeskGroup = "$($domain.NetBIOSName)\$HelpdeskGroupName"

Add-ValidationResult -Results $results -Name 'Expected domain' -Passed ([string]$domain.DNSRoot -ieq 'ad.lab.exceeds.test') -Expected 'ad.lab.exceeds.test' -Actual ([string]$domain.DNSRoot)

foreach ($attributeName in @($script:LapsPasswordAttribute, $script:LapsExpirationAttribute)) {
    $attribute = Get-LapsSchemaAttributeOrNull -LdapDisplayName $attributeName
    if ($null -eq $attribute) {
        $schemaActual = '<missing>'
    }
    else {
        $schemaGuid = ConvertTo-GuidValue -Value $attribute.schemaIDGUID -Context "schemaIDGUID for $attributeName"
        if ($attributeName -ieq $script:LapsPasswordAttribute) {
            $script:LapsPasswordSchemaGuid = $schemaGuid
        }
        $schemaActual = "Guid=$schemaGuid;SearchFlags=$($attribute.searchFlags)"
    }
    Add-ValidationResult -Results $results -Name "Windows LAPS schema: $attributeName" -Passed ($null -ne $attribute) -Expected 'Schema attribute exists' -Actual $schemaActual
}
$schemaFailures = @($results.ToArray() | Where-Object { [string]$_.Name -like 'Windows LAPS schema:*' -and [string]$_.Status -eq 'Failed' })
if ($schemaFailures.Count -gt 0) {
    $resultRows = @($results.ToArray())
    if ($PassThru) {
        return $resultRows
    }
    $resultRows | Format-Table -AutoSize
    if ($FailOnValidationError) {
        $failedNames = @($schemaFailures | ForEach-Object { [string]$_.Name })
        throw "$script:ScenarioName validation failed: $($failedNames -join '; ')"
    }
    return
}

$helpdeskGroup = Get-ScenarioGroupOrNull -SamAccountName $HelpdeskGroupName
$helpdeskMember = Get-ScenarioUserBySamOrNull -SamAccountName $HelpdeskMemberSamAccountName
$helpdeskGroupActual = if ($null -eq $helpdeskGroup) { '<missing>' } else { [string]$helpdeskGroup.DistinguishedName }
Add-ValidationResult -Results $results -Name 'Helpdesk group exists' -Passed ($null -ne $helpdeskGroup) -Expected $qualifiedHelpdeskGroup -Actual $helpdeskGroupActual
if ($null -eq $helpdeskGroup) {
    Add-SkippedResult -Results $results -Name 'Helpdesk group marker' -Expected $script:Marker -Actual '<missing group>'
    Add-SkippedResult -Results $results -Name 'Helpdesk membership' -Expected $HelpdeskMemberSamAccountName -Actual '<missing group>'
}
else {
    Add-ValidationResult -Results $results -Name 'Helpdesk group marker' -Passed ([string]$helpdeskGroup.adminDescription -ceq $script:Marker) -Expected $script:Marker -Actual ([string]$helpdeskGroup.adminDescription)
    $memberDn = if ($null -eq $helpdeskMember) { '<missing user>' } else { [string]$helpdeskMember.DistinguishedName }
    $members = @($helpdeskGroup.Member | ForEach-Object { [string]$_ })
    Add-ValidationResult -Results $results -Name 'Helpdesk membership' -Passed ($members -contains $memberDn) -Expected $memberDn -Actual (($members | Sort-Object) -join '; ')
}

$workstationComputer = Get-ScenarioComputerOrNull -ComputerName $WorkstationComputerName
$serverComputer = Get-ScenarioComputerOrNull -ComputerName $ServerComputerName
$controlServerComputer = Get-ScenarioComputerOrNull -ComputerName $ControlServerComputerName
foreach ($spec in @(
    @{ Name = $WorkstationComputerName; Computer = $workstationComputer; ExpectedParent = $workstationsOuDn },
    @{ Name = $ServerComputerName; Computer = $serverComputer; ExpectedParent = $serversOuDn },
    @{ Name = $ControlServerComputerName; Computer = $controlServerComputer; ExpectedParent = $serversOuDn }
)) {
    $computer = $spec.Computer
    $computerActual = if ($null -eq $computer) { '<missing>' } else { [string]$computer.DistinguishedName }
    Add-ValidationResult -Results $results -Name "Computer exists: $($spec.Name)" -Passed ($null -ne $computer) -Expected ([string]$spec.Name) -Actual $computerActual
    if ($null -ne $computer) {
        Add-ValidationResult -Results $results -Name "Computer OU: $($spec.Name)" -Passed ([string]$computer.DistinguishedName -like "*,$($spec.ExpectedParent)") -Expected ([string]$spec.ExpectedParent) -Actual ([string]$computer.DistinguishedName)
        $expectedPassword = New-ScenarioLapsPasswordJson -ComputerName ([string]$computer.Name)
        $currentPassword = ConvertTo-SingleAdValue -Value $computer.($script:LapsPasswordAttribute) -AttributeName $script:LapsPasswordAttribute -DistinguishedName ([string]$computer.DistinguishedName)
        Add-ValidationResult -Results $results -Name "Synthetic LAPS password value: $($spec.Name)" -Passed ([string]$currentPassword -ceq $expectedPassword) -Expected 'Scenario JSON value with redacted password' -Actual (ConvertTo-LapsPasswordSummary -Value $computer.($script:LapsPasswordAttribute) -DistinguishedName ([string]$computer.DistinguishedName))
        $expectedExpiration = [Int64](Get-ScenarioLapsExpirationFileTime)
        $currentExpiration = ConvertTo-SingleAdValue -Value $computer.($script:LapsExpirationAttribute) -AttributeName $script:LapsExpirationAttribute -DistinguishedName ([string]$computer.DistinguishedName)
        $expirationActual = if ($null -eq $currentExpiration) { '<not set>' } else { [Int64]$currentExpiration }
        Add-ValidationResult -Results $results -Name "Synthetic LAPS expiration value: $($spec.Name)" -Passed ($null -ne $currentExpiration -and [Int64]$currentExpiration -eq $expectedExpiration) -Expected $expectedExpiration -Actual $expirationActual
    }
}

if ($null -eq $helpdeskGroup) {
    Add-SkippedResult -Results $results -Name 'Workstations OU LAPS read holder' -Expected $qualifiedHelpdeskGroup -Actual '<missing group>'
    Add-SkippedResult -Results $results -Name 'Servers OU LAPS read holder absent' -Expected 'Helpdesk absent' -Actual '<missing group>'
    Add-SkippedResult -Results $results -Name 'FILE01 explicit misconfiguration' -Expected $ExpectFile01Misconfiguration -Actual '<missing group>'
}
else {
    $helpdeskSid = [Security.Principal.SecurityIdentifier]$helpdeskGroup.SID
    $workstationRights = @(Get-LapsExtendedRightHoldersForOu -DistinguishedName $workstationsOuDn -Name 'Workstations')
    $serverRights = @(Get-LapsExtendedRightHoldersForOu -DistinguishedName $serversOuDn -Name 'Servers' -IncludeComputers)
    $workstationFindHolder = Test-LapsHolderContainsPrincipal -RightsRows $workstationRights -ObjectDn $workstationsOuDn -QualifiedPrincipal $qualifiedHelpdeskGroup -SamAccountName $HelpdeskGroupName -DistinguishedName ([string]$helpdeskGroup.DistinguishedName) -PrincipalSid $helpdeskSid -AllowSingleRowFallback
    $workstationAclCount = Get-LapsReadCapableAceCount -DistinguishedName $workstationsOuDn -PrincipalSid $helpdeskSid
    $serverFindHolder = Test-LapsHolderContainsPrincipal -RightsRows $serverRights -ObjectDn $serversOuDn -QualifiedPrincipal $qualifiedHelpdeskGroup -SamAccountName $HelpdeskGroupName -DistinguishedName ([string]$helpdeskGroup.DistinguishedName) -PrincipalSid $helpdeskSid
    $serverAclCount = Get-LapsReadCapableAceCount -DistinguishedName $serversOuDn -PrincipalSid $helpdeskSid
    Add-ValidationResult `
        -Results $results `
        -Name 'Workstations OU LAPS read holder' `
        -Passed ($workstationFindHolder -or $workstationAclCount -gt 0) `
        -Expected $qualifiedHelpdeskGroup `
        -Actual "Find-LapsADExtendedRights=$(Format-HoldersForObject -RightsRows $workstationRights -ObjectDn $workstationsOuDn -AllowSingleRowFallback);AclMatchCount=$workstationAclCount"
    Add-ValidationResult `
        -Results $results `
        -Name 'Servers OU LAPS read holder absent' `
        -Passed ((-not $serverFindHolder) -and $serverAclCount -eq 0) `
        -Expected 'Helpdesk not delegated at Servers OU' `
        -Actual "Find-LapsADExtendedRights=$(Format-HoldersForObject -RightsRows $serverRights -ObjectDn $serversOuDn);AclMatchCount=$serverAclCount"
    if ($null -ne $serverComputer) {
        $file01GenericAllCount = Get-ExplicitGenericAllAceCount -DistinguishedName ([string]$serverComputer.DistinguishedName) -PrincipalSid $helpdeskSid
        Add-ValidationResult `
            -Results $results `
            -Name 'FILE01 explicit misconfiguration' `
            -Passed (($file01GenericAllCount -gt 0) -eq $ExpectFile01Misconfiguration) `
            -Expected "Explicit Helpdesk GenericAll present=$ExpectFile01Misconfiguration" `
            -Actual "Count=$file01GenericAllCount"
    }
    if ($null -ne $controlServerComputer) {
        $web01GenericAllCount = Get-ExplicitGenericAllAceCount -DistinguishedName ([string]$controlServerComputer.DistinguishedName) -PrincipalSid $helpdeskSid
        Add-ValidationResult -Results $results -Name 'WEB01 explicit misconfiguration absent' -Passed ($web01GenericAllCount -eq 0) -Expected 'No explicit Helpdesk GenericAll' -Actual "Count=$web01GenericAllCount"
    }

    foreach ($accessSpec in @(
        @{ Name = $WorkstationComputerName; Computer = $workstationComputer; ExpectedGenericAll = $false; ExpectedReadLapsPassword = $true },
        @{ Name = $ServerComputerName; Computer = $serverComputer; ExpectedGenericAll = $ExpectFile01Misconfiguration; ExpectedReadLapsPassword = $ExpectFile01Misconfiguration },
        @{ Name = $ControlServerComputerName; Computer = $controlServerComputer; ExpectedGenericAll = $false; ExpectedReadLapsPassword = $false }
    )) {
        Add-EffectiveHelpdeskAccessResult `
            -Results $results `
            -ComputerName ([string]$accessSpec.Name) `
            -Computer $accessSpec.Computer `
            -PrincipalSid $helpdeskSid `
            -ExpectedGenericAll ([bool]$accessSpec.ExpectedGenericAll) `
            -ExpectedReadLapsPassword ([bool]$accessSpec.ExpectedReadLapsPassword)
    }

    if ($IncludeAcl) {
        foreach ($computer in @($workstationComputer, $serverComputer, $controlServerComputer)) {
            if ($null -ne $computer) {
                Get-AclSummaryRows -DistinguishedName ([string]$computer.DistinguishedName) -PrincipalSid $helpdeskSid | Format-Table -AutoSize | Out-Host
            }
        }
    }
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
