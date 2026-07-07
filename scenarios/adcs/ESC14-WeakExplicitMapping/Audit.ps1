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

$script:ScenarioName = 'ESC14-WeakExplicitMapping'
$script:ControlPrincipal = 'alice.brown'
$script:TargetUser = 'operator01'
$script:FindingPatterns = @(
    'ESC14-WeakExplicitMapping',
    'ESC14-WeakExplicitMapping',
    'altSecurityIdentities',
    'X509:<RFC822>',
    'alice.brown',
    'operator01',
    'WriteProperty',
    'nTSecurityDescriptor',
    'Set-ADUser',
    'Set-Acl'
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

function ConvertTo-AuditStringArray {
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return @() }
    $valueObject = $Value.PSObject.BaseObject
    if ($valueObject -is [string]) {
        if ([string]::IsNullOrWhiteSpace($valueObject)) { return @() }
        return [string[]]@([string]$valueObject)
    }
    if ($valueObject -is [System.Collections.IEnumerable] -and -not ($valueObject -is [string])) {
        $values = New-Object 'System.Collections.Generic.List[string]'
        foreach ($item in $valueObject) {
            if ($null -ne $item) { [void]$values.Add([string]$item) }
        }
        return [string[]]$values.ToArray()
    }
    return [string[]]@([string]$valueObject)
}

function Get-ScenarioCurrentState {
    $adParameters = @{}
    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $adParameters['Server'] = $Server
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    $control = Get-ADUser -Identity $script:ControlPrincipal -Properties UserPrincipalName, mail @adParameters -ErrorAction SilentlyContinue
    $target = Get-ADUser -Identity $script:TargetUser -Properties altSecurityIdentities @adParameters -ErrorAction SilentlyContinue
    $mappings = @()
    if ($null -ne $target) {
        $mappings = @(ConvertTo-AuditStringArray -Value $target.altSecurityIdentities)
    }
    return [pscustomobject]@{
        ControlPrincipal                   = $script:ControlPrincipal
        ControlPrincipalExists             = ($null -ne $control)
        TargetUser                         = $script:TargetUser
        TargetUserExists                   = ($null -ne $target)
        AltSecurityIdentities              = [string[]]$mappings
        WeakRfc822Present                  = [bool](@($mappings | Where-Object { $_ -like 'X509:<RFC822>*' }).Count -gt 0)
        CertificateRequestExecutedByScript = $false
        PrivateKeyMaterialRead             = $false
    }
}

Add-EventLogMatches -LogName 'Security' -EventId $script:DirectoryServiceChangeEventIds -Check 'Directory service changes'
Add-EventLogMatches -LogName 'Security' -EventId $script:DirectoryServiceAccessEventIds -Check 'Directory service access'
Add-EventLogMatches -LogName 'Security' -EventId $script:ObjectPermissionChangeEventIds -Check 'Target user permission changes'
Add-EventLogMatches -LogName 'Security' -EventId $script:ProcessCreationEventIds -Check 'Process creation'
Add-EventLogMatches -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId $script:PowerShellOperationalEventIds -Check 'PowerShell operational logging'
Add-EventLogMatches -LogName 'Microsoft-Windows-Sysmon/Operational' -EventId $script:SysmonEventIds -Check 'Optional Sysmon EDR-style telemetry'

$currentState = $null
if (-not $SkipCurrentState) {
    try {
        $currentState = Get-ScenarioCurrentState
    }
    catch {
        Add-AuditFinding -Status Warning -Source 'LDAP' -Check 'Current ESC14 mapping posture' -Signal 'Unable to collect current state' -Data $_.Exception.Message
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
