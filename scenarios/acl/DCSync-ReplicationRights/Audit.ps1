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

$script:ScenarioName = 'DCSync-ReplicationRights'
$script:FindingPatterns = @(
    'DCSync-ReplicationRights',
    'DCSync-ReplicationRights',
    'windows-ad-lab:DCSync-ReplicationRights',
    'GG_DCSync_Readers',
    'GG_DCSync_Ops',
    'svc_backup',
    'operator01',
    'DS-Replication-Get-Changes',
    'DS-Replication-Get-Changes-All',
    'DS-Replication-Get-Changes-In-Filtered-Set',
    'Replicating Directory Changes',
    'Replicating Directory Changes All',
    'Replicating Directory Changes In Filtered Set',
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
    '89e95b76-444d-4c62-991a-0facbeda640c',
    'nTSecurityDescriptor',
    'ExtendedRight',
    'DCSync',
    'DRSUAPI',
    'IDL_DRSGetNCChanges',
    'GetNCChanges',
    'credential replication'
)
$script:SecurityGroupManagementEventIds = @(
    4727, # A security-enabled global group was created.
    4728, # A member was added to a security-enabled global group.
    4729, # A member was removed from a security-enabled global group.
    4730, # A security-enabled global group was deleted.
    4737  # A security-enabled global group was changed.
)
$script:DirectoryServiceChangeEventIds = @(
    5136, # A directory service object was modified.
    5137, # A directory service object was created.
    5141  # A directory service object was deleted.
)
$script:DirectoryServiceAccessEventIds = @(
    4662  # An operation was performed on an object.
)
$script:ProcessCreationEventIds = @(
    4688  # A new process was created.
)
$script:PowerShellOperationalEventIds = @(
    4103, # PowerShell module logging captured command invocation details.
    4104  # PowerShell script block logging captured executed script content.
)
$script:SysmonEventIds = @(
    1, # Sysmon process creation.
    3  # Sysmon network connection.
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

function ConvertTo-AuditStringArray {
    param([AllowNull()]$Value)

    if ($null -eq $Value) {
        return @()
    }
    $valueObject = $Value.PSObject.BaseObject
    if ($valueObject -is [array] -and -not ($valueObject -is [byte[]])) {
        return [string[]]@($valueObject | ForEach-Object { [string]$_ })
    }
    return [string[]]@([string]$valueObject)
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

function Get-DcsyncRightSpecs {
    return @(
        [pscustomobject]@{
            Name        = 'DS-Replication-Get-Changes'
            DisplayName = 'Replicating Directory Changes'
            Guid        = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        },
        [pscustomobject]@{
            Name        = 'DS-Replication-Get-Changes-All'
            DisplayName = 'Replicating Directory Changes All'
            Guid        = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
        },
        [pscustomobject]@{
            Name        = 'DS-Replication-Get-Changes-In-Filtered-Set'
            DisplayName = 'Replicating Directory Changes In Filtered Set'
            Guid        = [guid]'89e95b76-444d-4c62-991a-0facbeda640c'
        }
    )
}

function Get-DcsyncAceCount {
    param(
        [Parameter(Mandatory = $true)]$Acl,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid,
        [Parameter(Mandatory = $true)][guid]$RightGuid
    )

    return @($Acl.Access | Where-Object {
            -not $_.IsInherited -and
            $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            (Test-AuditIdentityReferenceMatchesSid -IdentityReference $_.IdentityReference -Sid $PrincipalSid) -and
            (($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -eq [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -and
            $_.ObjectType -eq $RightGuid
        }).Count
}

function Get-ScenarioCurrentState {
    $adParameters = Get-AdServerParameters
    Import-Module ActiveDirectory -ErrorAction Stop
    Ensure-AuditAdDrive -AdParameters $adParameters

    $domain = Get-ADDomain @adParameters -ErrorAction Stop
    $domainDn = [string]$domain.DistinguishedName
    $delegatedUser = Get-ADUser -Identity 'svc_backup' -Properties SID, memberOf @adParameters -ErrorAction SilentlyContinue
    $controlUser = Get-ADUser -Identity 'operator01' -Properties SID, memberOf @adParameters -ErrorAction SilentlyContinue
    $readerGroup = Get-ADGroup -Identity 'GG_DCSync_Readers' -Properties adminDescription, member, SID @adParameters -ErrorAction SilentlyContinue
    $rightsGroup = Get-ADGroup -Identity 'GG_DCSync_Ops' -Properties adminDescription, member, SID @adParameters -ErrorAction SilentlyContinue
    $domainAcl = Get-Acl -Path "AD:\$domainDn" -ErrorAction Stop
    $readerMembers = if ($null -eq $readerGroup) { @() } else { ConvertTo-AuditStringArray -Value $readerGroup.member }
    $rightsMembers = if ($null -eq $rightsGroup) { @() } else { ConvertTo-AuditStringArray -Value $rightsGroup.member }
    $rightResults = New-Object 'System.Collections.Generic.List[object]'
    $directDelegatedResults = New-Object 'System.Collections.Generic.List[object]'

    foreach ($right in @(Get-DcsyncRightSpecs)) {
        $rightsGroupAceCount = 0
        $delegatedUserAceCount = 0
        if ($null -ne $rightsGroup) {
            $rightsGroupAceCount = Get-DcsyncAceCount -Acl $domainAcl -PrincipalSid ([Security.Principal.SecurityIdentifier]$rightsGroup.SID) -RightGuid ([guid]$right.Guid)
        }
        if ($null -ne $delegatedUser) {
            $delegatedUserAceCount = Get-DcsyncAceCount -Acl $domainAcl -PrincipalSid ([Security.Principal.SecurityIdentifier]$delegatedUser.SID) -RightGuid ([guid]$right.Guid)
        }
        [void]$rightResults.Add([pscustomobject]@{
                Name               = [string]$right.Name
                Guid               = [string]$right.Guid
                RightsGroupAceCount = [int]$rightsGroupAceCount
            })
        [void]$directDelegatedResults.Add([pscustomobject]@{
                Name                  = [string]$right.Name
                Guid                  = [string]$right.Guid
                DelegatedUserAceCount = [int]$delegatedUserAceCount
            })
    }

    return [pscustomobject]@{
        DomainDistinguishedName          = $domainDn
        DelegatedUserExists              = ($null -ne $delegatedUser)
        ControlUserExists                = ($null -ne $controlUser)
        ReaderGroupExists                = ($null -ne $readerGroup)
        ReaderGroupMarker                = if ($null -eq $readerGroup) { '' } else { [string]$readerGroup.adminDescription }
        RightsGroupExists                = ($null -ne $rightsGroup)
        RightsGroupMarker                = if ($null -eq $rightsGroup) { '' } else { [string]$rightsGroup.adminDescription }
        DelegatedUserInReaderGroup       = ($null -ne $delegatedUser -and $readerMembers -icontains [string]$delegatedUser.DistinguishedName)
        ReaderGroupNestedIntoRightsGroup = ($null -ne $readerGroup -and $rightsMembers -icontains [string]$readerGroup.DistinguishedName)
        RightsGroupReplicationAces       = [object[]]$rightResults.ToArray()
        DelegatedUserDirectAces          = [object[]]$directDelegatedResults.ToArray()
        CredentialReplicationExecuted    = $false
    }
}

Add-EventLogMatches -LogName 'Security' -EventId $script:SecurityGroupManagementEventIds -Check 'Security group management'
Add-EventLogMatches -LogName 'Security' -EventId $script:DirectoryServiceChangeEventIds -Check 'Directory service changes'
Add-EventLogMatches -LogName 'Security' -EventId $script:DirectoryServiceAccessEventIds -Check 'Directory replication control access'
Add-EventLogMatches -LogName 'Security' -EventId $script:ProcessCreationEventIds -Check 'Process creation'
Add-EventLogMatches -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId $script:PowerShellOperationalEventIds -Check 'PowerShell operational logging'
Add-EventLogMatches -LogName 'Microsoft-Windows-Sysmon/Operational' -EventId $script:SysmonEventIds -Check 'Optional Sysmon EDR-style telemetry'

$currentState = $null
if (-not $SkipCurrentState) {
    try {
        $currentState = Get-ScenarioCurrentState
    }
    catch {
        Add-AuditFinding -Status Warning -Source 'LDAP' -Check 'Current DCSync rights posture' -Signal 'Unable to collect current state' -Data $_.Exception.Message
    }
}

[pscustomobject]@{
    PSTypeName        = 'ADLab.ScenarioAudit'
    Timestamp         = (Get-Date).ToString('o')
    Scenario          = $script:ScenarioName
    ComputerName      = $ComputerName
    WindowStart       = $StartTime.ToString('o')
    WindowEnd         = $EndTime.ToString('o')
    FindingCount      = [int]$findings.Count
    Findings          = [object[]]$findings.ToArray()
    CurrentState      = $currentState
}
