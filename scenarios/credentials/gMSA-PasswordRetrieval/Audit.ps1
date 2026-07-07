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

$script:ScenarioName = 'gMSA-PasswordRetrieval'
$script:FindingPatterns = @(
    'gMSA-PasswordRetrieval',
    'gMSA-PasswordRetrieval',
    'windows-ad-lab:gMSA-PasswordRetrieval',
    'gmsa_web',
    'gmsa_web$',
    'GG_gMSA_Readers',
    'john.smith',
    'operator01',
    'WEB01',
    'FILE01',
    'Backup Operators',
    'msDS-GroupMSAMembership',
    'msDS-ManagedPassword',
    'PrincipalsAllowedToRetrieveManagedPassword',
    'servicePrincipalName',
    'Add-KdsRootKey',
    'New-ADServiceAccount',
    'Set-ADServiceAccount',
    'nTSecurityDescriptor',
    'WriteProperty'
)
$script:SecurityGroupManagementEventIds = @(
    4727, # A security-enabled global group was created.
    4728, # A member was added to a security-enabled global group.
    4729, # A member was removed from a security-enabled global group.
    4730, # A security-enabled global group was deleted.
    4732, # A member was added to a security-enabled local group.
    4733, # A member was removed from a security-enabled local group.
    4737  # A security-enabled global group was changed.
)
$script:ComputerAccountLifecycleEventIds = @(
    4741, # A computer account was created.
    4743  # A computer account was deleted.
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
    13 # Sysmon registry value set.
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

function Get-AuditSchemaAttributeGuid {
    param(
        [Parameter(Mandatory = $true)][string]$LdapDisplayName,
        [hashtable]$AdParameters
    )

    $rootDse = Get-ADRootDSE @AdParameters -ErrorAction Stop
    $schemaNc = [string]$rootDse.schemaNamingContext
    $objects = @(Get-ADObject -SearchBase $schemaNc -SearchScope OneLevel -LDAPFilter "(lDAPDisplayName=$LdapDisplayName)" -Properties schemaIDGUID @AdParameters -ErrorAction Stop)
    if ($objects.Count -ne 1) {
        throw "Expected one schema attribute '$LdapDisplayName', found $($objects.Count)."
    }
    return ConvertTo-AuditGuid -Value $objects[0].schemaIDGUID -Context "schemaIDGUID for $LdapDisplayName"
}

function Get-ScenarioCurrentState {
    $adParameters = Get-AdServerParameters
    Import-Module ActiveDirectory -ErrorAction Stop
    Ensure-AuditAdDrive -AdParameters $adParameters

    $domain = Get-ADDomain @adParameters -ErrorAction Stop
    $readerGroup = Get-ADGroup -Identity 'GG_gMSA_Readers' -Properties adminDescription, member, SID @adParameters -ErrorAction SilentlyContinue
    $readerMember = Get-ADUser -Identity 'john.smith' -Properties SID @adParameters -ErrorAction SilentlyContinue
    $memberManager = Get-ADUser -Identity 'operator01' -Properties SID @adParameters -ErrorAction SilentlyContinue
    $authorizedComputer = Get-ADComputer -Identity 'WEB01' -Properties SID @adParameters -ErrorAction SilentlyContinue
    $controlComputer = Get-ADComputer -Identity 'FILE01' -Properties SID @adParameters -ErrorAction SilentlyContinue
    $gmsa = Get-ADServiceAccount `
        -Identity 'gmsa_web' `
        -Properties adminDescription, ServicePrincipalName, PrincipalsAllowedToRetrieveManagedPassword, msDS-GroupMSAMembership, msDS-ManagedPasswordInterval, MemberOf, SID `
        @adParameters `
        -ErrorAction SilentlyContinue
    $backupOperators = Get-ADGroup -Identity 'Backup Operators' -Properties member, SID @adParameters -ErrorAction SilentlyContinue
    $managerMemberWriteAceCount = 0

    if ($null -ne $readerGroup -and $null -ne $memberManager) {
        $memberGuid = Get-AuditSchemaAttributeGuid -LdapDisplayName 'member' -AdParameters $adParameters
        $managerSid = [Security.Principal.SecurityIdentifier]$memberManager.SID
        $groupAcl = Get-Acl -Path "AD:\$($readerGroup.DistinguishedName)" -ErrorAction Stop
        $managerMemberWriteAceCount = @($groupAcl.Access | Where-Object {
                -not $_.IsInherited -and
                $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                (Test-AuditIdentityReferenceMatchesSid -IdentityReference $_.IdentityReference -Sid $managerSid) -and
                (($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -eq [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -and
                $_.ObjectType -eq $memberGuid
            }).Count
    }

    $readerMembers = if ($null -eq $readerGroup) { @() } else { ConvertTo-AuditStringArray -Value $readerGroup.member }
    $retrievalPrincipals = if ($null -eq $gmsa) { @() } else { ConvertTo-AuditStringArray -Value $gmsa.PrincipalsAllowedToRetrieveManagedPassword }
    $spns = if ($null -eq $gmsa) { @() } else { ConvertTo-AuditStringArray -Value $gmsa.ServicePrincipalName }
    $backupMembers = if ($null -eq $backupOperators) { @() } else { ConvertTo-AuditStringArray -Value $backupOperators.member }
    $kdsRootKeyCount = $null
    $kdsRootKeyError = ''
    try {
        Import-Module Kds -ErrorAction Stop
        $kdsRootKeyCount = @(Get-KdsRootKey -ErrorAction Stop).Count
    }
    catch {
        $kdsRootKeyError = $_.Exception.Message
    }

    return [pscustomobject]@{
        DomainDistinguishedName          = [string]$domain.DistinguishedName
        GmsaExists                       = ($null -ne $gmsa)
        GmsaDistinguishedName            = if ($null -eq $gmsa) { '' } else { [string]$gmsa.DistinguishedName }
        GmsaMarker                       = if ($null -eq $gmsa) { '' } else { [string]$gmsa.adminDescription }
        GmsaServicePrincipalNames        = [string[]]$spns
        RetrievalPrincipals              = [string[]]$retrievalPrincipals
        AuthorizedComputerExists         = ($null -ne $authorizedComputer)
        ControlComputerExists            = ($null -ne $controlComputer)
        ReaderGroupExists                = ($null -ne $readerGroup)
        ReaderGroupMarker                = if ($null -eq $readerGroup) { '' } else { [string]$readerGroup.adminDescription }
        ReaderGroupContainsMember        = ($null -ne $readerMember -and $readerMembers -icontains [string]$readerMember.DistinguishedName)
        ReaderGroupCanRetrievePassword   = ($null -ne $readerGroup -and @($retrievalPrincipals | Where-Object { $_ -imatch 'GG_gMSA_Readers' -or $_ -ieq [string]$readerGroup.DistinguishedName }).Count -gt 0)
        ManagerMemberWriteAceCount       = [int]$managerMemberWriteAceCount
        BackupOperatorsContainsGmsa      = ($null -ne $gmsa -and $backupMembers -icontains [string]$gmsa.DistinguishedName)
        ManagedPasswordIntervalDays      = if ($null -eq $gmsa) { '' } else { [string]$gmsa.'msDS-ManagedPasswordInterval' }
        ManagedPasswordValueRead         = $false
        KdsRootKeyCount                  = $kdsRootKeyCount
        KdsRootKeyError                  = $kdsRootKeyError
    }
}

Add-EventLogMatches -LogName 'Security' -EventId $script:SecurityGroupManagementEventIds -Check 'Security group management'
Add-EventLogMatches -LogName 'Security' -EventId $script:ComputerAccountLifecycleEventIds -Check 'gMSA account lifecycle'
Add-EventLogMatches -LogName 'Security' -EventId $script:DirectoryServiceChangeEventIds -Check 'Directory service changes'
Add-EventLogMatches -LogName 'Security' -EventId $script:DirectoryServiceAccessEventIds -Check 'Managed password read auditing'
Add-EventLogMatches -LogName 'Security' -EventId $script:ProcessCreationEventIds -Check 'Process creation'
Add-EventLogMatches -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId $script:PowerShellOperationalEventIds -Check 'PowerShell operational logging'
Add-EventLogMatches -LogName 'Microsoft-Windows-Sysmon/Operational' -EventId $script:SysmonEventIds -Check 'Optional Sysmon EDR-style telemetry'

$currentState = $null
if (-not $SkipCurrentState) {
    try {
        $currentState = Get-ScenarioCurrentState
    }
    catch {
        Add-AuditFinding -Status Warning -Source 'LDAP' -Check 'Current gMSA posture' -Signal 'Unable to collect current state' -Data $_.Exception.Message
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
