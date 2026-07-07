#Requires -Version 5.1

[CmdletBinding()]
param(
    [datetime]$StartTime = (Get-Date).AddHours(-24),
    [datetime]$EndTime = (Get-Date),
    [ValidateRange(1, 5000)][int]$MaxEventsPerQuery = 500,
    [string]$ComputerName = $env:COMPUTERNAME,
    [string]$Server,
    [switch]$SkipCurrentState
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'WindowsLAPS-Delegation'
$script:HelpdeskGroupName = 'GG_LAPS_Helpdesk'
$script:HelpdeskMemberSamAccountName = 'john.smith'
$script:WorkstationComputerName = 'CLIENT01'
$script:ServerComputerName = 'FILE01'
$script:ControlServerComputerName = 'WEB01'
$script:Marker = 'windows-ad-lab:WindowsLAPS-Delegation'
$script:RootOuName = 'LAB'
$script:LapsPasswordAttribute = 'msLAPS-Password'
$script:LapsExpirationAttribute = 'msLAPS-PasswordExpirationTime'
$script:LapsPasswordSchemaGuid = [guid]::Empty
$script:LapsEncryptedPasswordRightsGuid = [guid]'f3531ec6-6330-4f8e-8d39-7a671fbac605'
$script:FindingPatterns = @(
    'WindowsLAPS-Delegation',
    'WindowsLAPS-Delegation',
    'windows-ad-lab:WindowsLAPS-Delegation',
    'GG_LAPS_Helpdesk',
    'john.smith',
    'CLIENT01',
    'FILE01',
    'WEB01',
    'msLAPS-Password',
    'msLAPS-PasswordExpirationTime',
    'f3531ec6-6330-4f8e-8d39-7a671fbac605',
    'Set-LapsADReadPasswordPermission',
    'Update-LapsADSchema',
    'Find-LapsADExtendedRights',
    'GenericAll',
    'Read LAPS Password',
    'nTSecurityDescriptor',
    'Set-ADObject',
    'Set-Acl'
)
$script:SecurityGroupManagementEventIds = @(
    4727, # A security-enabled global group was created.
    4728, # A member was added to a security-enabled global group.
    4729, # A member was removed from a security-enabled global group.
    4730, # A security-enabled global group was deleted.
    4737  # A security-enabled global group was changed.
)
$script:ComputerAccountChangeEventIds = @(
    4742  # A computer account was changed.
)
$script:DirectoryServiceChangeEventIds = @(
    5136, # A directory service object was modified.
    5137, # A directory service object was created.
    5141  # A directory service object was deleted.
)
$script:DirectoryServiceAccessEventIds = @(
    4662  # An operation was performed on an object.
)
$script:ObjectPermissionChangeEventIds = @(
    4670  # Permissions on an object were changed.
)
$script:ProcessCreationEventIds = @(
    4688  # A new process was created.
)
$script:PowerShellOperationalEventIds = @(
    4103, # PowerShell module logging captured command invocation details.
    4104  # PowerShell script block logging captured executed script content.
)
$script:SysmonEventIds = @(
    1,  # Sysmon process creation.
    11, # Sysmon file create.
    13  # Sysmon registry value set.
)

if ($EndTime -lt $StartTime) {
    throw 'EndTime must be greater than or equal to StartTime.'
}

$findings = New-Object 'System.Collections.Generic.List[object]'

function ConvertTo-AuditMessageSummary {
    param([AllowNull()][string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return ''
    }
    $summary = ($Message -replace '\s+', ' ').Trim()
    if ($summary.Length -gt 900) {
        return "$($summary.Substring(0, 900))..."
    }
    return $summary
}

function Test-AuditTextContainsAny {
    param(
        [AllowNull()][string]$Text,
        [AllowEmptyCollection()][string[]]$Patterns
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }
    foreach ($pattern in @($Patterns)) {
        if ([string]::IsNullOrWhiteSpace($pattern)) {
            continue
        }
        if ($Text.IndexOf($pattern, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }
    return $false
}

function Add-AuditFinding {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Found', 'Warning')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Check,
        [Parameter(Mandatory = $true)][string]$Signal,
        [AllowNull()][object]$Data = $null
    )

    [void]$findings.Add([pscustomobject]@{
            Timestamp = (Get-Date).ToString('o')
            Scenario  = $script:ScenarioName
            Status    = $Status
            Source    = $Source
            Check     = $Check
            Signal    = $Signal
            Data      = $Data
        })
}

function Add-EventLogMatches {
    param(
        [Parameter(Mandatory = $true)][string]$LogName,
        [AllowEmptyCollection()][int[]]$EventId = @(),
        [Parameter(Mandatory = $true)][string]$Check,
        [AllowEmptyCollection()][string[]]$Patterns = $script:FindingPatterns
    )

    $filter = @{
        LogName   = $LogName
        StartTime = $StartTime
        EndTime   = $EndTime
    }
    if (@($EventId).Count -gt 0) {
        $filter['Id'] = $EventId
    }

    $parameters = @{
        FilterHashtable = $filter
        MaxEvents       = $MaxEventsPerQuery
        ErrorAction     = 'Stop'
    }
    if (-not [string]::IsNullOrWhiteSpace($ComputerName) -and $ComputerName -ine $env:COMPUTERNAME) {
        $parameters['ComputerName'] = $ComputerName
    }

    try {
        $events = @(Get-WinEvent @parameters)
    }
    catch {
        if ($_.Exception.Message -like '*No events were found*') {
            return
        }
        Add-AuditFinding -Status Warning -Source 'EventLog' -Check $Check -Signal "Unable to query $LogName" -Data $_.Exception.Message
        return
    }

    foreach ($event in $events) {
        $message = [string]$event.Message
        if (-not (Test-AuditTextContainsAny -Text $message -Patterns $Patterns)) {
            continue
        }
        Add-AuditFinding -Status Found -Source 'EventLog' -Check $Check -Signal "$LogName/$($event.Id)" -Data ([pscustomobject]@{
                TimeCreated  = if ($null -eq $event.TimeCreated) { '' } else { $event.TimeCreated.ToString('o') }
                LogName      = $LogName
                EventId      = [int]$event.Id
                RecordId     = [long]$event.RecordId
                ProviderName = [string]$event.ProviderName
                MachineName  = [string]$event.MachineName
                UserId       = if ($null -eq $event.UserId) { '' } else { [string]$event.UserId }
                Message      = ConvertTo-AuditMessageSummary -Message $message
            })
    }
}

function Get-AdServerParameters {
    $parameters = @{}
    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $parameters['Server'] = $Server
    }
    return $parameters
}

function ConvertTo-LdapFilterValue {
    param([Parameter(Mandatory = $true)][string]$Value)

    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace(([string][char]0), '\00')
}

function ConvertTo-AuditStringArray {
    param([AllowNull()]$Value)

    if ($null -eq $Value) {
        return @()
    }
    $valueObject = $Value.PSObject.BaseObject
    if ($valueObject -is [string]) {
        return [string[]]@([string]$valueObject)
    }
    if ($valueObject -is [byte[]]) {
        return [string[]]@([Convert]::ToBase64String([byte[]]$valueObject))
    }
    if ($valueObject -is [System.Collections.IEnumerable]) {
        $values = New-Object 'System.Collections.Generic.List[string]'
        foreach ($item in $valueObject) {
            if ($null -ne $item) {
                [void]$values.Add([string]$item)
            }
        }
        return [string[]]$values.ToArray()
    }
    return [string[]]@([string]$valueObject)
}

function ConvertTo-AuditSingleValue {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)][string]$AttributeName,
        [Parameter(Mandatory = $true)][string]$DistinguishedName
    )

    if ($null -eq $Value) {
        return $null
    }
    $valueObject = $Value.PSObject.BaseObject
    if ($valueObject -is [string] -or $valueObject -is [byte[]]) {
        return $valueObject
    }
    if ($valueObject -is [System.Collections.IEnumerable]) {
        $values = @($valueObject)
        if ($values.Count -eq 0) { return $null }
        if ($values.Count -gt 1) {
            throw "Attribute '$AttributeName' on '$DistinguishedName' should have one value, found $($values.Count)."
        }
        return $values[0]
    }
    return $valueObject
}

function ConvertTo-AuditGuid {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($null -eq $Value) {
        throw "$Context did not contain a GUID value."
    }
    $valueObject = $Value.PSObject.BaseObject
    if ($valueObject -is [guid]) {
        return [guid]$valueObject
    }
    if ($valueObject -is [byte[]]) {
        return New-Object -TypeName System.Guid -ArgumentList (, ([byte[]]$valueObject))
    }
    return [guid]([string]$valueObject)
}

function Ensure-AuditAdDrive {
    param([hashtable]$AdParameters)

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
    if ($AdParameters.ContainsKey('Server')) {
        $driveParameters['Server'] = $AdParameters['Server']
    }
    New-PSDrive @driveParameters | Out-Null
}

function Test-AuditIdentityReferenceMatchesSid {
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

function Get-LapsSchemaAttributeOrNull {
    param(
        [Parameter(Mandatory = $true)][string]$LdapDisplayName,
        [hashtable]$AdParameters
    )

    $rootDse = Get-ADRootDSE @AdParameters -ErrorAction Stop
    $schemaNc = [string]$rootDse.schemaNamingContext
    $escapedName = ConvertTo-LdapFilterValue -Value $LdapDisplayName
    $attributes = @(Get-ADObject -SearchBase $schemaNc -SearchScope OneLevel -LDAPFilter "(lDAPDisplayName=$escapedName)" -Properties lDAPDisplayName, schemaIDGUID, searchFlags @AdParameters -ErrorAction Stop)
    if ($attributes.Count -gt 1) {
        throw "Multiple schema attributes were returned for lDAPDisplayName '$LdapDisplayName'."
    }
    if ($attributes.Count -eq 0) {
        return $null
    }
    return $attributes[0]
}

function Get-AdOrganizationalUnitOrNull {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [hashtable]$AdParameters
    )

    try {
        return Get-ADOrganizationalUnit -Identity $DistinguishedName -Properties adminDescription, Description @AdParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

function Get-ScenarioGroupOrNull {
    param(
        [Parameter(Mandatory = $true)][string]$SamAccountName,
        [hashtable]$AdParameters
    )

    $escapedName = ConvertTo-LdapFilterValue -Value $SamAccountName
    $groups = @(Get-ADGroup -LDAPFilter "(sAMAccountName=$escapedName)" -Properties adminDescription, Description, Member, SID @AdParameters -ErrorAction Stop)
    if ($groups.Count -gt 1) {
        throw "Multiple groups were returned for sAMAccountName '$SamAccountName'."
    }
    if ($groups.Count -eq 0) {
        return $null
    }
    return $groups[0]
}

function Get-ScenarioUserBySamOrNull {
    param(
        [Parameter(Mandatory = $true)][string]$SamAccountName,
        [hashtable]$AdParameters
    )

    $escapedSam = ConvertTo-LdapFilterValue -Value $SamAccountName
    $users = @(Get-ADUser -LDAPFilter "(sAMAccountName=$escapedSam)" -Properties Enabled @AdParameters -ErrorAction Stop)
    if ($users.Count -gt 1) {
        throw "Multiple users were returned for sAMAccountName '$SamAccountName'."
    }
    if ($users.Count -eq 0) {
        return $null
    }
    return $users[0]
}

function Get-ScenarioComputerOrNull {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [hashtable]$AdParameters
    )

    try {
        return Get-ADComputer -Identity $Name -Properties Description, msLAPS-Password, msLAPS-PasswordExpirationTime, whenChanged, whenCreated @AdParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

function Test-LapsReadCapableAce {
    param(
        [Parameter(Mandatory = $true)]$AccessRule,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    if ([string]$AccessRule.AccessControlType -ne 'Allow') {
        return $false
    }
    if (-not (Test-AuditIdentityReferenceMatchesSid -IdentityReference $AccessRule.IdentityReference -Sid $PrincipalSid)) {
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

    $acl = Get-Acl -Path "AD:\$DistinguishedName" -ErrorAction Stop
    return @($acl.Access | Where-Object { Test-LapsReadCapableAce -AccessRule $_ -PrincipalSid $PrincipalSid }).Count
}

function Get-ExplicitGenericAllAceCount {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    $acl = Get-Acl -Path "AD:\$DistinguishedName" -ErrorAction Stop
    return @($acl.Access | Where-Object {
            -not $_.IsInherited `
                -and [string]$_.AccessControlType -eq 'Allow' `
                -and (Test-Right -Rights $_.ActiveDirectoryRights -Right ([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)) `
                -and (Test-AuditIdentityReferenceMatchesSid -IdentityReference $_.IdentityReference -Sid $PrincipalSid)
        }).Count
}

function New-ComputerLapsState {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()]$Computer
    )

    $passwordPresent = $false
    $expirationPresent = $false
    if ($null -ne $Computer) {
        $passwordValue = ConvertTo-AuditSingleValue -Value $Computer.($script:LapsPasswordAttribute) -AttributeName $script:LapsPasswordAttribute -DistinguishedName ([string]$Computer.DistinguishedName)
        $expirationValue = ConvertTo-AuditSingleValue -Value $Computer.($script:LapsExpirationAttribute) -AttributeName $script:LapsExpirationAttribute -DistinguishedName ([string]$Computer.DistinguishedName)
        $passwordPresent = ($null -ne $passwordValue -and -not [string]::IsNullOrEmpty([string]$passwordValue))
        $expirationPresent = ($null -ne $expirationValue -and -not [string]::IsNullOrEmpty([string]$expirationValue))
    }

    return [pscustomobject]@{
        Name                         = $Name
        Exists                       = ($null -ne $Computer)
        DistinguishedName            = if ($null -eq $Computer) { '' } else { [string]$Computer.DistinguishedName }
        LapsPasswordPresent          = $passwordPresent
        LapsPasswordValueRead        = $false
        LapsExpirationPresent        = $expirationPresent
        WhenCreated                  = if ($null -eq $Computer -or $null -eq $Computer.whenCreated) { '' } else { $Computer.whenCreated.ToString('o') }
        WhenChanged                  = if ($null -eq $Computer -or $null -eq $Computer.whenChanged) { '' } else { $Computer.whenChanged.ToString('o') }
    }
}

function Get-ScenarioCurrentState {
    $adParameters = Get-AdServerParameters
    Import-Module ActiveDirectory -ErrorAction Stop
    Ensure-AuditAdDrive -AdParameters $adParameters

    $domain = Get-ADDomain @adParameters -ErrorAction Stop
    $domainDn = [string]$domain.DistinguishedName
    $rootOuDn = "OU=$script:RootOuName,$domainDn"
    $groupsOuDn = "OU=Groups,$rootOuDn"
    $workstationsOuDn = "OU=Workstations,OU=Computers,$rootOuDn"
    $serversOuDn = "OU=Servers,OU=Computers,$rootOuDn"
    $workstationsOu = Get-AdOrganizationalUnitOrNull -DistinguishedName $workstationsOuDn -AdParameters $adParameters
    $serversOu = Get-AdOrganizationalUnitOrNull -DistinguishedName $serversOuDn -AdParameters $adParameters
    $helpdeskGroup = Get-ScenarioGroupOrNull -SamAccountName $script:HelpdeskGroupName -AdParameters $adParameters
    $helpdeskMember = Get-ScenarioUserBySamOrNull -SamAccountName $script:HelpdeskMemberSamAccountName -AdParameters $adParameters
    $workstationComputer = Get-ScenarioComputerOrNull -Name $script:WorkstationComputerName -AdParameters $adParameters
    $serverComputer = Get-ScenarioComputerOrNull -Name $script:ServerComputerName -AdParameters $adParameters
    $controlServerComputer = Get-ScenarioComputerOrNull -Name $script:ControlServerComputerName -AdParameters $adParameters

    $schemaAttribute = Get-LapsSchemaAttributeOrNull -LdapDisplayName $script:LapsPasswordAttribute -AdParameters $adParameters
    if ($null -ne $schemaAttribute) {
        $script:LapsPasswordSchemaGuid = ConvertTo-AuditGuid -Value $schemaAttribute.schemaIDGUID -Context "schemaIDGUID for $script:LapsPasswordAttribute"
    }

    $members = if ($null -eq $helpdeskGroup) { @() } else { ConvertTo-AuditStringArray -Value $helpdeskGroup.Member }
    $memberDn = if ($null -eq $helpdeskMember) { '' } else { [string]$helpdeskMember.DistinguishedName }
    $groupSid = if ($null -eq $helpdeskGroup) { $null } else { [Security.Principal.SecurityIdentifier]$helpdeskGroup.SID }
    $workstationsLapsAceCount = 0
    $serversLapsAceCount = 0
    $file01GenericAllAceCount = 0
    $web01GenericAllAceCount = 0

    if ($null -ne $groupSid -and $null -ne $workstationsOu) {
        $workstationsLapsAceCount = Get-LapsReadCapableAceCount -DistinguishedName $workstationsOuDn -PrincipalSid $groupSid
    }
    if ($null -ne $groupSid -and $null -ne $serversOu) {
        $serversLapsAceCount = Get-LapsReadCapableAceCount -DistinguishedName $serversOuDn -PrincipalSid $groupSid
    }
    if ($null -ne $groupSid -and $null -ne $serverComputer) {
        $file01GenericAllAceCount = Get-ExplicitGenericAllAceCount -DistinguishedName ([string]$serverComputer.DistinguishedName) -PrincipalSid $groupSid
    }
    if ($null -ne $groupSid -and $null -ne $controlServerComputer) {
        $web01GenericAllAceCount = Get-ExplicitGenericAllAceCount -DistinguishedName ([string]$controlServerComputer.DistinguishedName) -PrincipalSid $groupSid
    }

    return [pscustomobject]@{
        DomainDistinguishedName             = $domainDn
        GroupsOuDn                          = $groupsOuDn
        WorkstationsOuDn                    = $workstationsOuDn
        ServersOuDn                         = $serversOuDn
        WorkstationsOuExists                = ($null -ne $workstationsOu)
        ServersOuExists                     = ($null -ne $serversOu)
        LapsPasswordSchemaPresent           = ($null -ne $schemaAttribute)
        LapsPasswordSchemaGuid              = [string]$script:LapsPasswordSchemaGuid
        HelpdeskGroupExists                 = ($null -ne $helpdeskGroup)
        HelpdeskGroupDn                     = if ($null -eq $helpdeskGroup) { '' } else { [string]$helpdeskGroup.DistinguishedName }
        HelpdeskGroupMarker                 = if ($null -eq $helpdeskGroup) { '' } else { [string]$helpdeskGroup.adminDescription }
        HelpdeskMemberExists                = ($null -ne $helpdeskMember)
        HelpdeskGroupContainsMember         = ($null -ne $helpdeskGroup -and -not [string]::IsNullOrWhiteSpace($memberDn) -and $members -contains $memberDn)
        WorkstationsOuLapsReadAceCount      = [int]$workstationsLapsAceCount
        ServersOuLapsReadAceCount           = [int]$serversLapsAceCount
        File01ExplicitGenericAllAceCount    = [int]$file01GenericAllAceCount
        Web01ExplicitGenericAllAceCount     = [int]$web01GenericAllAceCount
        Computers                           = [object[]]@(
            (New-ComputerLapsState -Name $script:WorkstationComputerName -Computer $workstationComputer),
            (New-ComputerLapsState -Name $script:ServerComputerName -Computer $serverComputer),
            (New-ComputerLapsState -Name $script:ControlServerComputerName -Computer $controlServerComputer)
        )
        LapsPasswordValuesLogged            = $false
        LapsPasswordRetrievalExecutedByScript = $false
    }
}

Add-EventLogMatches -LogName 'Security' -EventId $script:SecurityGroupManagementEventIds -Check 'Security group management'
Add-EventLogMatches -LogName 'Security' -EventId $script:ComputerAccountChangeEventIds -Check 'Computer account changes'
Add-EventLogMatches -LogName 'Security' -EventId $script:DirectoryServiceChangeEventIds -Check 'Directory service changes'
Add-EventLogMatches -LogName 'Security' -EventId $script:DirectoryServiceAccessEventIds -Check 'Windows LAPS password read auditing'
Add-EventLogMatches -LogName 'Security' -EventId $script:ObjectPermissionChangeEventIds -Check 'Object permission changes'
Add-EventLogMatches -LogName 'Security' -EventId $script:ProcessCreationEventIds -Check 'Process creation'
Add-EventLogMatches -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId $script:PowerShellOperationalEventIds -Check 'PowerShell operational logging'
Add-EventLogMatches -LogName 'Microsoft-Windows-Sysmon/Operational' -EventId $script:SysmonEventIds -Check 'Optional Sysmon EDR-style telemetry'

$currentState = $null
if (-not $SkipCurrentState) {
    try {
        $currentState = Get-ScenarioCurrentState
    }
    catch {
        Add-AuditFinding -Status Warning -Source 'LDAP' -Check 'Current Windows LAPS delegation posture' -Signal 'Unable to collect current state' -Data $_.Exception.Message
    }
}

[pscustomobject]@{
    PSTypeName   = 'ADLab.ScenarioAudit'
    Timestamp    = (Get-Date).ToString('o')
    Scenario     = $script:ScenarioName
    ComputerName = $ComputerName
    WindowStart  = $StartTime.ToString('o')
    WindowEnd    = $EndTime.ToString('o')
    FindingCount = [int]$findings.Count
    Findings     = [object[]]$findings.ToArray()
    CurrentState = $currentState
}
