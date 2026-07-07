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

$script:ScenarioName = 'ESC11-RpcEnrollment'
$script:FindingPatterns = @(
    'ESC11-RpcEnrollment',
    'ESC11',
    'InterfaceFlags',
    'CA\InterfaceFlags',
    'IF_ENFORCEENCRYPTICERTREQUEST',
    'IF_NORPCICERTREQUEST',
    '0x00000200',
    '0x00000008',
    'CertSvc',
    'Certification Authority',
    'Set-Esc11PacketPrivacyRequirement',
    'Set-Esc11InterfaceFlags',
    'Restart-Esc11CertSvc',
    'MS-ICPR',
    'ICertRequest',
    'RPC_C_AUTHN_LEVEL_PKT_PRIVACY',
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
    4886, # Certificate Services received a certificate request.
    4887, # Certificate Services approved a certificate request and issued a certificate.
    4888, # Certificate Services denied a certificate request.
    4889, # Certificate Services set the status of a certificate request to pending.
    4890, # Certificate Services manager settings for a certificate request changed.
    4891, # A configuration entry changed in Certificate Services.
    4892, # A Certificate Services property changed.
    4893, # Certificate Services archived a key.
    4894, # Certificate Services imported and archived a key.
    4895, # Certificate Services published the CA certificate to Active Directory.
    4896, # One or more rows were deleted from the certificate database.
    4897, # Role separation was enabled in Certificate Services.
    4898, # Certificate Services loaded a template.
    4899  # A Certificate Services template was updated.
)
$script:SystemServiceControlEventIds = @(
    7035, # The Service Control Manager sent a control to a service.
    7036, # A service entered a new state.
    7040  # The start type of a service changed.
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

function Get-ScenarioCurrentState {
    Import-Module (Join-Path $PSScriptRoot 'Esc11RpcEnrollment.Common.psm1') -Force -DisableNameChecking -ErrorAction Stop
    return Get-Esc11RpcEnrollmentState
}

Add-EventLogMatches -LogName 'Security' -EventId $script:RegistryAuditEventIds -Check 'Registry audit for CA InterfaceFlags'
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
        Add-AuditFinding -Status Warning -Source 'CARegistry' -Check 'Current ESC11 posture' -Signal 'Unable to collect current state' -Data $_.Exception.Message
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
    LdapObjectsChanged = $false
}
