#Requires -Version 5.1

[CmdletBinding()]
param(
    [datetime]$StartTime = (Get-Date).AddHours(-24),
    [datetime]$EndTime = (Get-Date),
    [ValidateRange(1, 5000)][int]$MaxEventsPerQuery = 500,
    [string]$ComputerName = $env:COMPUTERNAME,
    [string]$Server,
    [ValidateSet('All', 'SetupAudit', 'AbuseDetection')][string]$Mode = 'All',
    [string]$DelegateMemberSamAccountName = 'john.smith',
    [string]$DelegateGroupName = 'GG_AdminSD_Resetters',
    [string]$ProtectedUserSamAccountName = 'yagami_adm',
    [switch]$SkipCurrentState
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'AdminSDHolder'
$script:Marker = 'windows-ad-lab:AdminSDHolder'
$script:ResetPasswordRightGuid = '00299570-246d-11d0-a768-00aa006e0529'
$script:DirectoryServiceAccessSubcategoryGuid = [guid]'0CCE923B-69AE-11D9-BED3-505054503030'
$script:SetupAuditPatterns = @(
    'AdminSDHolder',
    'AdminSDHolder',
    $script:Marker,
    $DelegateGroupName,
    $DelegateMemberSamAccountName,
    'setup.ps1',
    'cleanup.ps1',
    'RunProtectAdminGroupsTask',
    'nTSecurityDescriptor',
    $script:ResetPasswordRightGuid,
    'SDProp',
    'Set-Acl'
)
$script:SecurityGroupManagementEventIds = @(
    4727, # A security-enabled global group was created.
    4728, # A member was added to a security-enabled global group.
    4729, # A member was removed from a security-enabled global group.
    4730, # A security-enabled global group was deleted.
    4737  # A security-enabled global group was changed.
)
$script:PasswordResetEventIds = @(
    4724  # An attempt was made to reset an account password.
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
    1 # Sysmon process creation.
)

if ($EndTime -lt $StartTime) {
    throw 'EndTime must be greater than or equal to StartTime.'
}
foreach ($samAccountName in @($DelegateMemberSamAccountName, $DelegateGroupName, $ProtectedUserSamAccountName)) {
    if ($samAccountName -notmatch '^[A-Za-z0-9._-]{1,20}$') {
        throw "Audit account parameters must be valid 1-20 character sAMAccountName values: '$samAccountName'"
    }
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

function Test-AuditEvidenceClassIncluded {
    param([Parameter(Mandatory = $true)][ValidateSet('SetupAudit', 'AbuseDetection', 'TelemetryGap', 'CollectionWarning')][string]$EvidenceClass)

    if ($Mode -eq 'All') {
        return $true
    }
    if ($EvidenceClass -eq 'CollectionWarning') {
        return $true
    }
    if ($Mode -eq 'AbuseDetection' -and $EvidenceClass -eq 'TelemetryGap') {
        return $true
    }
    return ($EvidenceClass -eq $Mode)
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

function ConvertTo-AuditEventData {
    param([Parameter(Mandatory = $true)]$Event)

    $map = @{}
    try {
        $xml = [xml]$Event.ToXml()
        $index = 0
        foreach ($data in @($xml.Event.EventData.Data)) {
            $name = [string]$data.GetAttribute('Name')
            if ([string]::IsNullOrWhiteSpace($name)) {
                $name = "Data$index"
            }
            $value = [string]$data.InnerText
            if ($map.ContainsKey($name)) {
                $map[$name] = "$($map[$name]); $value"
            }
            else {
                $map[$name] = $value
            }
            $index++
        }
    }
    catch {
        $map['ParseError'] = $_.Exception.Message
    }

    $selected = [ordered]@{}
    foreach ($name in @(
            'TargetUserName',
            'TargetDomainName',
            'SubjectUserName',
            'SubjectDomainName',
            'ObjectDN',
            'ObjectName',
            'ObjectType',
            'AttributeLDAPDisplayName',
            'AttributeValue',
            'OperationType',
            'ProcessName',
            'CommandLine',
            'Properties',
            'AccessMask',
            'Status',
            'FailureCode',
            'IpAddress',
            'IpPort'
        )) {
        $selected[$name] = if ($map.ContainsKey($name)) { [string]$map[$name] } else { '' }
    }
    $selected['Raw'] = $map
    return [pscustomobject]$selected
}

function ConvertTo-AuditEventSearchText {
    param(
        [AllowNull()][string]$Message,
        [AllowNull()]$EventData
    )

    $parts = New-Object 'System.Collections.Generic.List[string]'
    if (-not [string]::IsNullOrWhiteSpace($Message)) {
        [void]$parts.Add($Message)
    }
    if ($null -ne $EventData) {
        foreach ($property in @($EventData.PSObject.Properties)) {
            if ($property.Name -eq 'Raw') {
                continue
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
                [void]$parts.Add([string]$property.Value)
            }
        }
    }
    return ($parts.ToArray() -join "`n")
}

function Test-AuditEventIsSelfObservation {
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }
    foreach ($selfPattern in @(
            'Audit.ps1',
            'ADLab.ScenarioAudit',
            'ConvertTo-AuditEventData',
            'Add-EventLogMatches',
            'SetupAuditFindingCount',
            'AbuseDetectionFindingCount',
            'TelemetryGapCount'
        )) {
        if ($Text.IndexOf($selfPattern, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }
    return $false
}

function Add-AuditFinding {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Found', 'Warning')][string]$Status,
        [Parameter(Mandatory = $true)][ValidateSet('SetupAudit', 'AbuseDetection', 'TelemetryGap', 'CollectionWarning')][string]$EvidenceClass,
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Check,
        [Parameter(Mandatory = $true)][string]$Signal,
        [AllowNull()][object]$Data = $null
    )

    if (-not (Test-AuditEvidenceClassIncluded -EvidenceClass $EvidenceClass)) {
        return
    }

    [void]$findings.Add([pscustomobject]@{
            Timestamp     = (Get-Date).ToString('o')
            Scenario      = $script:ScenarioName
            Status        = $Status
            EvidenceClass = $EvidenceClass
            Source        = $Source
            Check         = $Check
            Signal        = $Signal
            Data          = $Data
        })
}

function Add-EventLogMatches {
    param(
        [Parameter(Mandatory = $true)][string]$LogName,
        [AllowEmptyCollection()][int[]]$EventId = @(),
        [Parameter(Mandatory = $true)][string]$Check,
        [Parameter(Mandatory = $true)][ValidateSet('SetupAudit', 'AbuseDetection')][string]$EvidenceClass,
        [AllowEmptyCollection()][string[]]$Patterns,
        [scriptblock]$Predicate,
        [switch]$RequirePredicate
    )

    if (-not (Test-AuditEvidenceClassIncluded -EvidenceClass $EvidenceClass)) {
        return
    }

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
        Add-AuditFinding -Status Warning -EvidenceClass CollectionWarning -Source 'EventLog' -Check $Check -Signal "Unable to query $LogName" -Data $_.Exception.Message
        return
    }

    foreach ($event in $events) {
        $message = [string]$event.Message
        $eventData = ConvertTo-AuditEventData -Event $event
        $searchText = ConvertTo-AuditEventSearchText -Message $message -EventData $eventData
        if (Test-AuditEventIsSelfObservation -Text $searchText) {
            continue
        }
        $matched = Test-AuditTextContainsAny -Text $searchText -Patterns $Patterns
        if ($null -ne $Predicate) {
            $predicateMatched = [bool](& $Predicate $event $eventData $message)
            if ($RequirePredicate) {
                $matched = $predicateMatched
            }
            else {
                $matched = ($matched -or $predicateMatched)
            }
        }
        if (-not $matched) {
            continue
        }
        Add-AuditFinding -Status Found -EvidenceClass $EvidenceClass -Source 'EventLog' -Check $Check -Signal "$LogName/$($event.Id)" -Data ([pscustomobject]@{
                TimeCreated  = if ($null -eq $event.TimeCreated) { '' } else { $event.TimeCreated.ToString('o') }
                LogName      = $LogName
                EventId      = [int]$event.Id
                RecordId     = [long]$event.RecordId
                ProviderName = [string]$event.ProviderName
                MachineName  = [string]$event.MachineName
                UserId       = if ($null -eq $event.UserId) { '' } else { [string]$event.UserId }
                EventData    = $eventData
                Message      = ConvertTo-AuditMessageSummary -Message $message
            })
    }
}

function Get-ScenarioCurrentState {
    param(
        [string]$DelegateMember,
        [string]$DelegateGroup,
        [string]$ProtectedUser
    )

    Import-Module (Join-Path $PSScriptRoot 'AdminSDHolder.Common.psm1') -Force -DisableNameChecking -ErrorAction Stop
    return Get-AdminSdHolderScenarioPosture `
        -DelegateMemberSamAccountName $DelegateMember `
        -DelegateGroupName $DelegateGroup `
        -ProtectedUserSamAccountName $ProtectedUser `
        -Server $Server `
        -IncludeAcl
}

function Add-AdminSdHolderPostureFindings {
    param([AllowNull()]$CurrentState)

    if ($null -eq $CurrentState) {
        return
    }
    if ([bool]$CurrentState.DelegateGroupExists) {
        Add-AuditFinding -Status Found -EvidenceClass SetupAudit -Source 'LDAP' -Check 'Current setup posture' -Signal 'Delegate group exists' -Data ([pscustomobject]@{
                DelegateGroup = $CurrentState.DelegateGroupDistinguishedName
                Marker        = $CurrentState.DelegateGroupMarker
                Sid           = $CurrentState.DelegateGroupSid
            })
    }
    if ([bool]$CurrentState.DelegateMembershipPresent) {
        Add-AuditFinding -Status Found -EvidenceClass SetupAudit -Source 'LDAP' -Check 'Current setup posture' -Signal 'Delegate member is in scenario group' -Data ([pscustomobject]@{
                DelegateMember = $CurrentState.DelegateMemberDistinguishedName
                DelegateGroup  = $CurrentState.DelegateGroupDistinguishedName
            })
    }
    if ([int]$CurrentState.AdminSdHolderResetPasswordAceCount -gt 0) {
        Add-AuditFinding -Status Found -EvidenceClass SetupAudit -Source 'LDAP' -Check 'Current setup posture' -Signal 'AdminSDHolder Reset Password ACE present' -Data ([pscustomobject]@{
                AdminSdHolder = $CurrentState.AdminSdHolderDistinguishedName
                Count         = [int]$CurrentState.AdminSdHolderResetPasswordAceCount
                RightGuid     = $CurrentState.ResetPasswordControlAccessGuid
                AceSummary    = [string[]]@($CurrentState.AdminSdHolderAceSummary)
            })
    }
    if ([int]$CurrentState.ProtectedUserResetPasswordAceCount -gt 0) {
        Add-AuditFinding -Status Found -EvidenceClass SetupAudit -Source 'LDAP' -Check 'Current setup posture' -Signal 'Protected user Reset Password ACE present' -Data ([pscustomobject]@{
                ProtectedUser = $CurrentState.ProtectedUserDistinguishedName
                Count         = [int]$CurrentState.ProtectedUserResetPasswordAceCount
                RightGuid     = $CurrentState.ResetPasswordControlAccessGuid
                AceSummary    = [string[]]@($CurrentState.ProtectedUserAceSummary)
            })
    }
    if (@($CurrentState.AdminCountObjectsWithScenarioAce).Count -gt 0) {
        Add-AuditFinding -Status Found -EvidenceClass SetupAudit -Source 'LDAP' -Check 'Current setup posture' -Signal 'Scenario ACE propagated to adminCount objects' -Data ([pscustomobject]@{
                Count   = @($CurrentState.AdminCountObjectsWithScenarioAce).Count
                Objects = [string[]]@($CurrentState.AdminCountObjectsWithScenarioAce)
            })
    }
}

function Add-DirectoryServiceAccessTelemetryFinding {
    if (-not (Test-AuditEvidenceClassIncluded -EvidenceClass TelemetryGap)) {
        return
    }

    try {
        $repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        Import-Module (Join-Path $repositoryRoot 'modules\Lab.Validation.psm1') -Force -ErrorAction Stop
        $policy = Get-LabAuditPolicyValue -SubcategoryGuid $script:DirectoryServiceAccessSubcategoryGuid
        if (-not [bool]$policy.Success) {
            Add-AuditFinding -Status Warning -EvidenceClass TelemetryGap -Source 'AuditPolicy' -Check 'Directory Service Access telemetry' -Signal '4662 may be absent because Directory Service Access success auditing is disabled' -Data ([pscustomobject]@{
                    Subcategory = 'Directory Service Access'
                    Guid        = [string]$script:DirectoryServiceAccessSubcategoryGuid
                    Success     = [bool]$policy.Success
                    Failure     = [bool]$policy.Failure
                    Note        = '4662 also requires an SACL on AdminSDHolder or the protected object.'
                })
        }
    }
    catch {
        Add-AuditFinding -Status Warning -EvidenceClass CollectionWarning -Source 'AuditPolicy' -Check 'Directory Service Access telemetry' -Signal 'Unable to query audit policy' -Data $_.Exception.Message
    }
}

$protectedAccountPredicate = {
    param($Event, $EventData, $Message)

    if ($Event.Id -eq 4724) {
        return ([string]$EventData.TargetUserName -ieq $ProtectedUserSamAccountName)
    }
    return $false
}

$resetPasswordControlAccessPredicate = {
    param($Event, $EventData, $Message)

    if ($Event.Id -ne 4662) {
        return $false
    }
    $text = ConvertTo-AuditEventSearchText -Message $Message -EventData $EventData
    return (Test-AuditTextContainsAny -Text $text -Patterns @($script:ResetPasswordRightGuid, 'Reset Password'))
}

$manualPasswordResetCommandPredicate = {
    param($Event, $EventData, $Message)

    $text = ConvertTo-AuditEventSearchText -Message $Message -EventData $EventData
    if (-not (Test-AuditTextContainsAny -Text $text -Patterns @('Set-ADAccountPassword'))) {
        return $false
    }
    foreach ($selfPattern in @(
            'ADLab.ScenarioAudit',
            'manualPasswordResetCommandPredicate',
            'Protected account password reset attempts',
            'Manual password reset PowerShell logging',
            'ConvertTo-AuditEventData'
        )) {
        if ($text.IndexOf($selfPattern, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $false
        }
    }
    return $true
}

Add-EventLogMatches -LogName 'Security' -EventId $script:SecurityGroupManagementEventIds -Check 'Setup group management' -EvidenceClass SetupAudit -Patterns $script:SetupAuditPatterns
Add-EventLogMatches -LogName 'Security' -EventId $script:DirectoryServiceChangeEventIds -Check 'Setup directory service changes' -EvidenceClass SetupAudit -Patterns $script:SetupAuditPatterns
Add-EventLogMatches -LogName 'Security' -EventId $script:ObjectPermissionChangeEventIds -Check 'Setup object permission changes' -EvidenceClass SetupAudit -Patterns $script:SetupAuditPatterns
Add-EventLogMatches -LogName 'Security' -EventId $script:ProcessCreationEventIds -Check 'Setup process creation' -EvidenceClass SetupAudit -Patterns $script:SetupAuditPatterns
Add-EventLogMatches -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId $script:PowerShellOperationalEventIds -Check 'Setup PowerShell operational logging' -EvidenceClass SetupAudit -Patterns $script:SetupAuditPatterns
Add-EventLogMatches -LogName 'Microsoft-Windows-Sysmon/Operational' -EventId $script:SysmonEventIds -Check 'Setup optional Sysmon telemetry' -EvidenceClass SetupAudit -Patterns $script:SetupAuditPatterns

Add-EventLogMatches -LogName 'Security' -EventId $script:PasswordResetEventIds -Check 'Protected account password reset attempts' -EvidenceClass AbuseDetection -Patterns @() -Predicate $protectedAccountPredicate -RequirePredicate
Add-EventLogMatches -LogName 'Security' -EventId $script:DirectoryServiceAccessEventIds -Check 'Reset Password control access' -EvidenceClass AbuseDetection -Patterns @() -Predicate $resetPasswordControlAccessPredicate -RequirePredicate
Add-EventLogMatches -LogName 'Security' -EventId $script:ProcessCreationEventIds -Check 'Manual password reset process creation' -EvidenceClass AbuseDetection -Patterns @() -Predicate $manualPasswordResetCommandPredicate -RequirePredicate
Add-EventLogMatches -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId $script:PowerShellOperationalEventIds -Check 'Manual password reset PowerShell logging' -EvidenceClass AbuseDetection -Patterns @() -Predicate $manualPasswordResetCommandPredicate -RequirePredicate
Add-EventLogMatches -LogName 'Microsoft-Windows-Sysmon/Operational' -EventId $script:SysmonEventIds -Check 'Manual password reset optional Sysmon telemetry' -EvidenceClass AbuseDetection -Patterns @() -Predicate $manualPasswordResetCommandPredicate -RequirePredicate

Add-DirectoryServiceAccessTelemetryFinding

$currentState = $null
if (-not $SkipCurrentState) {
    try {
        $currentState = Get-ScenarioCurrentState `
            -DelegateMember $DelegateMemberSamAccountName `
            -DelegateGroup $DelegateGroupName `
            -ProtectedUser $ProtectedUserSamAccountName
        Add-AdminSdHolderPostureFindings -CurrentState $currentState
    }
    catch {
        Add-AuditFinding -Status Warning -EvidenceClass CollectionWarning -Source 'LDAP' -Check 'Current AdminSDHolder posture' -Signal 'Unable to collect current state' -Data $_.Exception.Message
    }
}

$setupAuditFindingCount = @($findings.ToArray() | Where-Object EvidenceClass -eq 'SetupAudit').Count
$abuseDetectionFindingCount = @($findings.ToArray() | Where-Object EvidenceClass -eq 'AbuseDetection').Count
$telemetryGapCount = @($findings.ToArray() | Where-Object EvidenceClass -eq 'TelemetryGap').Count
$collectionWarningCount = @($findings.ToArray() | Where-Object EvidenceClass -eq 'CollectionWarning').Count
$evidenceFindingCount = $setupAuditFindingCount + $abuseDetectionFindingCount
$assessment = switch ($Mode) {
    'AbuseDetection' {
        if ($abuseDetectionFindingCount -gt 0) { 'AbuseEvidenceFound' }
        elseif ($telemetryGapCount -gt 0 -or $collectionWarningCount -gt 0) { 'NoAbuseEvidenceFoundWithWarnings' }
        else { 'NoAbuseEvidenceFound' }
    }
    'SetupAudit' {
        if ($setupAuditFindingCount -gt 0) { 'SetupEvidenceFound' }
        elseif ($collectionWarningCount -gt 0) { 'NoSetupEvidenceFoundWithWarnings' }
        else { 'NoSetupEvidenceFound' }
    }
    default {
        if ($abuseDetectionFindingCount -gt 0) { 'AbuseEvidenceFound' }
        elseif ($setupAuditFindingCount -gt 0) { 'SetupEvidenceFoundOnly' }
        elseif ($telemetryGapCount -gt 0 -or $collectionWarningCount -gt 0) { 'NoEvidenceFoundWithWarnings' }
        else { 'NoEvidenceFound' }
    }
}

[pscustomobject]@{
    PSTypeName                      = 'ADLab.ScenarioAudit'
    Timestamp                       = (Get-Date).ToString('o')
    Scenario                        = $script:ScenarioName
    Mode                            = $Mode
    Assessment                      = $assessment
    AbuseDetected                   = [bool]($abuseDetectionFindingCount -gt 0)
    SetupAuditEvidenceFound         = [bool]($setupAuditFindingCount -gt 0)
    ComputerName                    = $ComputerName
    WindowStart                     = $StartTime.ToString('o')
    WindowEnd                       = $EndTime.ToString('o')
    FindingCount                    = [int]$findings.Count
    EvidenceFindingCount            = [int]$evidenceFindingCount
    SetupAuditFindingCount          = [int]$setupAuditFindingCount
    AbuseDetectionFindingCount      = [int]$abuseDetectionFindingCount
    TelemetryGapCount               = [int]$telemetryGapCount
    CollectionWarningCount          = [int]$collectionWarningCount
    Findings                        = [object[]]$findings.ToArray()
    CurrentState                    = $currentState
    PasswordResetExecutedByScenario = $false
}
