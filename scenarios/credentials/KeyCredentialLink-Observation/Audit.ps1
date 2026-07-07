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

$script:ScenarioName = 'KeyCredentialLink-Observation'
$script:ScenarioOuName = 'KeyCredentialLink-Lab'
$script:SampleSamAccountName = 'kcl.sample'
$script:ControlSamAccountName = 'kcl.control'
$script:Marker = 'windows-ad-lab:KeyCredentialLink-Observation'
$script:RootOuName = 'LAB'
$script:KeyCredentialAttribute = 'msDS-KeyCredentialLink'
$script:FindingPatterns = @(
    'KeyCredentialLink-Observation',
    'KeyCredentialLink-Observation',
    'windows-ad-lab:KeyCredentialLink-Observation',
    'KeyCredentialLink-Lab',
    'kcl.sample',
    'kcl.control',
    'KCL Sample User',
    'KCL Control User',
    'msDS-KeyCredentialLink',
    '5b47d60f-6090-40b2-9f37-2a4de88f3063',
    'KEYCREDENTIALLINK_BLOB',
    'KeyCredential',
    'DeviceId',
    'KeyMaterial',
    'Set-ADObject',
    'New-ADUser',
    'New-ADOrganizationalUnit'
)
$script:UserAccountManagementEventIds = @(
    4720, # A user account was created.
    4722, # A user account was enabled.
    4725, # A user account was disabled.
    4726  # A user account was deleted.
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

function Get-AdOrganizationalUnitOrNull {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [hashtable]$AdParameters
    )

    try {
        return Get-ADOrganizationalUnit -Identity $DistinguishedName -Properties adminDescription, Description, ProtectedFromAccidentalDeletion @AdParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

function Get-ScenarioUserBySamOrNull {
    param(
        [Parameter(Mandatory = $true)][string]$SamAccountName,
        [hashtable]$AdParameters
    )

    $escapedSam = ConvertTo-LdapFilterValue -Value $SamAccountName
    $users = @(Get-ADUser -LDAPFilter "(sAMAccountName=$escapedSam)" -Properties adminDescription, Description, DisplayName, Department, Enabled, msDS-KeyCredentialLink, UserPrincipalName, whenChanged, whenCreated @AdParameters -ErrorAction Stop)
    if ($users.Count -gt 1) {
        throw "Multiple users were returned for sAMAccountName '$SamAccountName'."
    }
    if ($users.Count -eq 0) {
        return $null
    }
    return $users[0]
}

function New-UserState {
    param(
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$SamAccountName,
        [AllowNull()]$User
    )

    $keyCredentialCount = 0
    if ($null -ne $User) {
        $keyCredentialCount = @(ConvertTo-AuditStringArray -Value $User.($script:KeyCredentialAttribute)).Count
    }
    return [pscustomobject]@{
        Role                         = $Role
        SamAccountName               = $SamAccountName
        Exists                       = ($null -ne $User)
        DistinguishedName            = if ($null -eq $User) { '' } else { [string]$User.DistinguishedName }
        Enabled                      = if ($null -eq $User) { $null } else { [bool]$User.Enabled }
        Marker                       = if ($null -eq $User) { '' } else { [string]$User.adminDescription }
        Department                   = if ($null -eq $User) { '' } else { [string]$User.Department }
        KeyCredentialLinkValueCount  = [int]$keyCredentialCount
        KeyCredentialLinkValuesRead  = $false
        WhenCreated                  = if ($null -eq $User -or $null -eq $User.whenCreated) { '' } else { $User.whenCreated.ToString('o') }
        WhenChanged                  = if ($null -eq $User -or $null -eq $User.whenChanged) { '' } else { $User.whenChanged.ToString('o') }
    }
}

function Get-ScenarioCurrentState {
    $adParameters = Get-AdServerParameters
    Import-Module ActiveDirectory -ErrorAction Stop

    $domain = Get-ADDomain @adParameters -ErrorAction Stop
    $domainDn = [string]$domain.DistinguishedName
    $scenarioOuDn = "OU=$script:ScenarioOuName,OU=$script:RootOuName,$domainDn"
    $scenarioOu = Get-AdOrganizationalUnitOrNull -DistinguishedName $scenarioOuDn -AdParameters $adParameters
    $sampleUser = Get-ScenarioUserBySamOrNull -SamAccountName $script:SampleSamAccountName -AdParameters $adParameters
    $controlUser = Get-ScenarioUserBySamOrNull -SamAccountName $script:ControlSamAccountName -AdParameters $adParameters

    return [pscustomobject]@{
        DomainDistinguishedName = $domainDn
        ScenarioOuDn            = $scenarioOuDn
        ScenarioOuExists        = ($null -ne $scenarioOu)
        ScenarioOuMarker        = if ($null -eq $scenarioOu) { '' } else { [string]$scenarioOu.adminDescription }
        ScenarioOuProtected     = if ($null -eq $scenarioOu) { $null } else { [bool]$scenarioOu.ProtectedFromAccidentalDeletion }
        Users                   = [object[]]@(
            (New-UserState -Role 'Sample' -SamAccountName $script:SampleSamAccountName -User $sampleUser),
            (New-UserState -Role 'Control' -SamAccountName $script:ControlSamAccountName -User $controlUser)
        )
        AuthenticationExecutedByScript = $false
        KeyCredentialValuesLogged      = $false
    }
}

Add-EventLogMatches -LogName 'Security' -EventId $script:UserAccountManagementEventIds -Check 'User account management'
Add-EventLogMatches -LogName 'Security' -EventId $script:DirectoryServiceChangeEventIds -Check 'Directory service changes'
Add-EventLogMatches -LogName 'Security' -EventId $script:DirectoryServiceAccessEventIds -Check 'Directory service access'
Add-EventLogMatches -LogName 'Security' -EventId $script:ProcessCreationEventIds -Check 'Process creation'
Add-EventLogMatches -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId $script:PowerShellOperationalEventIds -Check 'PowerShell operational logging'
Add-EventLogMatches -LogName 'Microsoft-Windows-Sysmon/Operational' -EventId $script:SysmonEventIds -Check 'Optional Sysmon EDR-style telemetry'

$currentState = $null
if (-not $SkipCurrentState) {
    try {
        $currentState = Get-ScenarioCurrentState
    }
    catch {
        Add-AuditFinding -Status Warning -Source 'LDAP' -Check 'Current KeyCredentialLink posture' -Signal 'Unable to collect current state' -Data $_.Exception.Message
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
