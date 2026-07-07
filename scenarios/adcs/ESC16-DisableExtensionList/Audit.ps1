#Requires -Version 5.1

[CmdletBinding()]
param(
    [datetime]$StartTime = (Get-Date).AddHours(-24),
    [datetime]$EndTime = (Get-Date),
    [ValidateRange(1, 5000)][int]$MaxEventsPerQuery = 500,
    [string]$ComputerName = $env:COMPUTERNAME,
    [switch]$SkipCurrentState
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'ESC16-DisableExtensionList'
$script:FindingPatterns = @(
    'ESC16-DisableExtensionList',
    'ESC16',
    'DisableExtensionList',
    '1.3.6.1.4.1.311.25.2',
    'szOID_NTDS_CA_SECURITY_EXT',
    'PolicyModules',
    'Set-Esc16SidSecurityExtensionDisabled',
    'CertSvc',
    'state.json'
)
$script:RegistryAuditEventIds = @(
    4657, # A registry value was modified.
    4663  # An attempt was made to access an object.
)
$script:ProcessCreationEventIds = @(
    4688  # A new process was created.
)
$script:CertificationServicesEventIds = @(
    4891, # A configuration entry changed in Certificate Services.
    4892  # A Certificate Services property changed.
)
$script:SystemServiceControlEventIds = @(
    7035, # The Service Control Manager sent a control to a service.
    7036  # A service entered a new state.
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

function Get-ScenarioCurrentState {
    Import-Module (Join-Path $PSScriptRoot 'Esc16DisableExtensionList.Common.psm1') -Force -DisableNameChecking -ErrorAction Stop
    $state = Get-Esc16DisableExtensionListState
    return [pscustomobject]@{
        ActiveCaName                       = [string]$state.ActiveCaName
        PolicyModulePath                   = [string]$state.PolicyModulePath
        DisableExtensionList               = [string[]]$state.DisableExtensionList
        SidSecurityExtensionDisabled       = [bool]$state.SidSecurityExtensionDisabled
        Hardened                           = [bool]$state.Hardened
        Vulnerable                         = [bool]$state.Vulnerable
        CertificateRequestExecutedByScript = $false
        PrivateKeyMaterialRead             = $false
    }
}

Add-EventLogMatches -LogName 'Security' -EventId $script:RegistryAuditEventIds -Check 'Registry audit for DisableExtensionList'
Add-EventLogMatches -LogName 'Security' -EventId $script:ProcessCreationEventIds -Check 'Process creation'
Add-EventLogMatches -LogName 'Security' -EventId $script:CertificationServicesEventIds -Check 'Certification Services audit events'
Add-EventLogMatches -LogName 'System' -EventId $script:SystemServiceControlEventIds -Check 'CertSvc service control events'
Add-EventLogMatches -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId $script:PowerShellOperationalEventIds -Check 'PowerShell operational logging'
Add-EventLogMatches -LogName 'Microsoft-Windows-Sysmon/Operational' -EventId $script:SysmonEventIds -Check 'Optional Sysmon EDR-style telemetry'

$currentState = $null
if (-not $SkipCurrentState) {
    try {
        $currentState = Get-ScenarioCurrentState
    }
    catch {
        Add-AuditFinding -Status Warning -Source 'CARegistry' -Check 'Current ESC16 DisableExtensionList posture' -Signal 'Unable to collect current state' -Data $_.Exception.Message
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
