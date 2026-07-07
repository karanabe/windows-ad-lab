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

$script:ScenarioName = 'ADACL-GPOAbuse'
$script:FindingPatterns = @(
    'ADACL-GPOAbuse',
    'ADACL-GPOAbuse',
    'windows-ad-lab:ADACL-GPOAbuse',
    'GG_GPO_WS_Admins',
    'GPO-Workstation-Baseline',
    'john.smith',
    'CLIENT01',
    'gPLink',
    'groupPolicyContainer',
    'gPCFileSysPath',
    'gPCMachineExtensionNames',
    'nTSecurityDescriptor',
    'registry.pol',
    'Set-GPRegistryValue',
    'New-GPLink',
    'GenericWrite',
    'WriteMembers'
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
$script:ObjectAccessAndPermissionEventIds = @(
    4663, # An attempt was made to access an object.
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
    Import-Module GroupPolicy -ErrorAction Stop
    Ensure-AuditAdDrive -AdParameters $adParameters

    $domain = Get-ADDomain @adParameters -ErrorAction Stop
    $domainDn = [string]$domain.DistinguishedName
    $group = Get-ADGroup -Identity 'GG_GPO_WS_Admins' -Properties adminDescription, member, SID @adParameters -ErrorAction SilentlyContinue
    $helpdeskUser = Get-ADUser -Identity 'john.smith' -Properties SID @adParameters -ErrorAction SilentlyContinue
    $workstationsOuDn = "OU=Workstations,OU=Computers,OU=LAB,$domainDn"
    $workstationsOu = Get-ADOrganizationalUnit -Identity $workstationsOuDn -Properties gPLink @adParameters -ErrorAction SilentlyContinue
    $memberWriteAceCount = 0
    $gpoGenericWriteAceCount = 0
    $sysvolModifyAceCount = 0
    $gpoContainerDn = ''
    $gpoGuid = ''
    $sysvolPath = ''
    $registryPolPath = ''
    $gpoMarker = ''
    $gpoVersionNumber = ''
    $gpoLinkPresent = $false
    $registryPolExists = $false
    $gpo = $null

    if ($null -ne $group -and $null -ne $helpdeskUser) {
        $memberGuid = Get-AuditSchemaAttributeGuid -LdapDisplayName 'member' -AdParameters $adParameters
        $helpdeskSid = [Security.Principal.SecurityIdentifier]$helpdeskUser.SID
        $groupAcl = Get-Acl -Path "AD:\$($group.DistinguishedName)" -ErrorAction Stop
        $memberWriteAceCount = @($groupAcl.Access | Where-Object {
                -not $_.IsInherited -and
                $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                (Test-AuditIdentityReferenceMatchesSid -IdentityReference $_.IdentityReference -Sid $helpdeskSid) -and
                (($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -eq [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -and
                $_.ObjectType -eq $memberGuid
            }).Count
    }

    $gpos = @(Get-GPO -All -ErrorAction Stop | Where-Object { [string]$_.DisplayName -ceq 'GPO-Workstation-Baseline' })
    if ($gpos.Count -eq 1) {
        $gpo = $gpos[0]
        $gpoGuid = [string]$gpo.Id
        $gpoContainerDn = "CN={$gpoGuid},CN=Policies,CN=System,$domainDn"
        $gpoContainer = Get-ADObject -Identity $gpoContainerDn -Properties adminDescription, displayName, gPCFileSysPath, versionNumber @adParameters -ErrorAction Stop
        $gpoMarker = [string]$gpoContainer.adminDescription
        $gpoVersionNumber = [string]$gpoContainer.versionNumber
        if ($null -ne $group) {
            $groupSid = [Security.Principal.SecurityIdentifier]$group.SID
            $gpoAcl = Get-Acl -Path "AD:\$gpoContainerDn" -ErrorAction Stop
            $gpoGenericWriteAceCount = @($gpoAcl.Access | Where-Object {
                    -not $_.IsInherited -and
                    $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                    (Test-AuditIdentityReferenceMatchesSid -IdentityReference $_.IdentityReference -Sid $groupSid) -and
                    (($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)
                }).Count
            $sysvolPath = Join-Path $env:SystemRoot "SYSVOL\domain\Policies\{$gpoGuid}"
            if (Test-Path -LiteralPath $sysvolPath -PathType Container) {
                $sysvolAcl = Get-Acl -LiteralPath $sysvolPath -ErrorAction Stop
                $sysvolModifyAceCount = @($sysvolAcl.Access | Where-Object {
                        -not $_.IsInherited -and
                        $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                        (Test-AuditIdentityReferenceMatchesSid -IdentityReference $_.IdentityReference -Sid $groupSid) -and
                        (($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Modify) -eq [System.Security.AccessControl.FileSystemRights]::Modify)
                    }).Count
            }
            $registryPolPath = Join-Path $sysvolPath 'Machine\registry.pol'
            $registryPolExists = Test-Path -LiteralPath $registryPolPath -PathType Leaf
        }
        if ($null -ne $workstationsOu) {
            $gpoLinkPresent = ([string]$workstationsOu.gPLink).IndexOf("{$gpoGuid}", [StringComparison]::OrdinalIgnoreCase) -ge 0
        }
    }

    return [pscustomobject]@{
        DomainDistinguishedName       = $domainDn
        ScenarioGroupExists           = ($null -ne $group)
        ScenarioGroupMarker           = if ($null -eq $group) { '' } else { [string]$group.adminDescription }
        HelpdeskUserExists            = ($null -ne $helpdeskUser)
        HelpdeskMemberWriteAceCount   = [int]$memberWriteAceCount
        GpoExists                     = ($null -ne $gpo)
        GpoGuid                       = $gpoGuid
        GpoContainerDistinguishedName = $gpoContainerDn
        GpoMarker                     = $gpoMarker
        GpoVersionNumber              = $gpoVersionNumber
        GpoGenericWriteAceCount       = [int]$gpoGenericWriteAceCount
        WorkstationsOuDistinguishedName = $workstationsOuDn
        GpoLinkPresent                = $gpoLinkPresent
        SysvolPath                    = $sysvolPath
        SysvolModifyAceCount          = [int]$sysvolModifyAceCount
        RegistryPolPath               = $registryPolPath
        RegistryPolExists             = $registryPolExists
        AutomatedEndpointExecution    = $false
    }
}

Add-EventLogMatches -LogName 'Security' -EventId $script:SecurityGroupManagementEventIds -Check 'Security group management'
Add-EventLogMatches -LogName 'Security' -EventId $script:DirectoryServiceChangeEventIds -Check 'Directory service changes'
Add-EventLogMatches -LogName 'Security' -EventId $script:ObjectAccessAndPermissionEventIds -Check 'SYSVOL object access and permission changes'
Add-EventLogMatches -LogName 'Security' -EventId $script:ProcessCreationEventIds -Check 'Process creation'
Add-EventLogMatches -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId $script:PowerShellOperationalEventIds -Check 'PowerShell operational logging'
Add-EventLogMatches -LogName 'Microsoft-Windows-Sysmon/Operational' -EventId $script:SysmonEventIds -Check 'Optional Sysmon EDR-style telemetry'

$currentState = $null
if (-not $SkipCurrentState) {
    try {
        $currentState = Get-ScenarioCurrentState
    }
    catch {
        Add-AuditFinding -Status Warning -Source 'LDAP' -Check 'Current AD/GPO/SYSVOL posture' -Signal 'Unable to collect current state' -Data $_.Exception.Message
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
