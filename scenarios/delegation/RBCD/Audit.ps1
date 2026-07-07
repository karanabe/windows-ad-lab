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

$script:ScenarioName = 'RBCD'
$script:ResourceComputerName = 'FILE01'
$script:DelegatingComputerName = 'WEB01'
$script:ControlComputerName = 'CLIENT01'
$script:DelegatedWriterSamAccountName = 'svc_web'
$script:Marker = 'windows-ad-lab:RBCD'
$script:RbcdAttribute = 'msDS-AllowedToActOnBehalfOfOtherIdentity'
$script:RbcdAttributeGuid = [guid]'3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'
$script:RbcdAccessMask = 0x000F01FF # Full control mask used inside the RBCD security descriptor.
$script:FindingPatterns = @(
    'RBCD',
    'windows-ad-lab:RBCD',
    'msDS-AllowedToActOnBehalfOfOtherIdentity',
    '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79',
    'FILE01',
    'WEB01',
    'CLIENT01',
    'svc_web',
    'PrincipalsAllowedToDelegateToAccount',
    'S4U2Self',
    'S4U2Proxy',
    'resource-based constrained delegation',
    'nTSecurityDescriptor',
    'WriteProperty',
    'Set-ADComputer',
    'Set-Acl'
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
$script:KerberosServiceTicketEventIds = @(
    4769  # A Kerberos service ticket was requested.
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

function ConvertTo-LdapFilterValue {
    param([Parameter(Mandatory = $true)][string]$Value)

    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace(([string][char]0), '\00')
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
    if ($valueObject -is [string] -or $valueObject -is [byte[]] -or $valueObject -is [System.Security.AccessControl.RawSecurityDescriptor]) {
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

function Get-ScenarioComputerOrNull {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [hashtable]$AdParameters
    )

    try {
        return Get-ADComputer -Identity $Name -Properties Description, Enabled, ServicePrincipalName, msDS-AllowedToActOnBehalfOfOtherIdentity, PrincipalsAllowedToDelegateToAccount, SID, whenChanged, whenCreated @AdParameters -ErrorAction Stop
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
    $users = @(Get-ADUser -LDAPFilter "(sAMAccountName=$escapedSam)" -Properties Enabled, adminDescription, SID @AdParameters -ErrorAction Stop)
    if ($users.Count -gt 1) {
        throw "Multiple users were returned for sAMAccountName '$SamAccountName'."
    }
    if ($users.Count -eq 0) {
        return $null
    }
    return $users[0]
}

function ConvertTo-RbcdRawSecurityDescriptor {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)][string]$DistinguishedName
    )

    $singleValue = ConvertTo-AuditSingleValue -Value $Value -AttributeName $script:RbcdAttribute -DistinguishedName $DistinguishedName
    if ($null -eq $singleValue) {
        return $null
    }
    $valueObject = $singleValue.PSObject.BaseObject
    if ($valueObject -is [System.Security.AccessControl.RawSecurityDescriptor]) {
        return $valueObject
    }
    if ($valueObject -is [System.DirectoryServices.ActiveDirectorySecurity]) {
        $sddl = $valueObject.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
        return New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $sddl
    }
    if ($valueObject -is [byte[]]) {
        return [System.Security.AccessControl.RawSecurityDescriptor]::new([byte[]]$valueObject, 0)
    }
    if ($valueObject -is [string]) {
        return New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList ([string]$valueObject)
    }
    throw "Attribute '$script:RbcdAttribute' on '$DistinguishedName' returned unsupported value type '$($valueObject.GetType().FullName)'."
}

function Get-RbcdAllowedSidValues {
    param([AllowNull()][System.Security.AccessControl.RawSecurityDescriptor]$Descriptor)

    if ($null -eq $Descriptor -or $null -eq $Descriptor.DiscretionaryAcl) {
        return @()
    }

    $sids = New-Object 'System.Collections.Generic.List[string]'
    foreach ($ace in $Descriptor.DiscretionaryAcl) {
        if ($ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowed) {
            continue
        }
        if ($null -eq $ace.SecurityIdentifier) {
            continue
        }
        [void]$sids.Add([string]$ace.SecurityIdentifier.Value)
    }
    return [string[]]($sids.ToArray() | Sort-Object -Unique)
}

function Test-RbcdDescriptorHasScenarioAccessMask {
    param(
        [AllowNull()][System.Security.AccessControl.RawSecurityDescriptor]$Descriptor,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$ExpectedSid
    )

    if ($null -eq $Descriptor -or $null -eq $Descriptor.DiscretionaryAcl) {
        return $false
    }
    $matchingAces = @($Descriptor.DiscretionaryAcl | Where-Object {
            $_.AceType -eq [System.Security.AccessControl.AceType]::AccessAllowed -and
            $null -ne $_.SecurityIdentifier -and
            [string]$_.SecurityIdentifier.Value -eq [string]$ExpectedSid.Value
        })
    if ($matchingAces.Count -eq 0) {
        return $false
    }
    return (@($matchingAces | Where-Object { [int]$_.AccessMask -eq [int]$script:RbcdAccessMask }).Count -gt 0)
}

function Test-RbcdWriteAce {
    param(
        [Parameter(Mandatory = $true)]$AccessRule,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    if ($AccessRule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }
    if (-not (Test-AuditIdentityReferenceMatchesSid -IdentityReference $AccessRule.IdentityReference -Sid $PrincipalSid)) { return $false }
    if (($AccessRule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -ne [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) { return $false }
    return ($AccessRule.ObjectType -eq $script:RbcdAttributeGuid)
}

function Get-RbcdWriteAceCount {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    $acl = Get-Acl -Path "AD:\$DistinguishedName" -ErrorAction Stop
    return @($acl.Access | Where-Object { -not $_.IsInherited -and (Test-RbcdWriteAce -AccessRule $_ -PrincipalSid $PrincipalSid) }).Count
}

function Get-ScenarioCurrentState {
    $adParameters = Get-AdServerParameters
    Import-Module ActiveDirectory -ErrorAction Stop
    Ensure-AuditAdDrive -AdParameters $adParameters

    $domain = Get-ADDomain @adParameters -ErrorAction Stop
    $resourceComputer = Get-ScenarioComputerOrNull -Name $script:ResourceComputerName -AdParameters $adParameters
    $delegatingComputer = Get-ScenarioComputerOrNull -Name $script:DelegatingComputerName -AdParameters $adParameters
    $controlComputer = Get-ScenarioComputerOrNull -Name $script:ControlComputerName -AdParameters $adParameters
    $writer = Get-ScenarioUserBySamOrNull -SamAccountName $script:DelegatedWriterSamAccountName -AdParameters $adParameters

    $descriptor = $null
    $allowedSids = @()
    $resourceDn = ''
    $descriptorPresent = $false
    $delegatingAllowed = $false
    $controlAllowed = $false
    $delegatingAccessMaskMatches = $false
    $writerAceCount = 0

    if ($null -ne $resourceComputer) {
        $resourceDn = [string]$resourceComputer.DistinguishedName
        $descriptor = ConvertTo-RbcdRawSecurityDescriptor -Value $resourceComputer.($script:RbcdAttribute) -DistinguishedName $resourceDn
        $descriptorPresent = ($null -ne $descriptor)
        $allowedSids = @(Get-RbcdAllowedSidValues -Descriptor $descriptor)
    }
    if ($null -ne $delegatingComputer) {
        $delegatingSid = [string]$delegatingComputer.SID.Value
        $delegatingAllowed = ($allowedSids -contains $delegatingSid)
        $delegatingAccessMaskMatches = Test-RbcdDescriptorHasScenarioAccessMask -Descriptor $descriptor -ExpectedSid ([Security.Principal.SecurityIdentifier]$delegatingComputer.SID)
    }
    if ($null -ne $controlComputer) {
        $controlAllowed = ($allowedSids -contains [string]$controlComputer.SID.Value)
    }
    if ($null -ne $resourceComputer -and $null -ne $writer) {
        $writerAceCount = Get-RbcdWriteAceCount -DistinguishedName $resourceDn -PrincipalSid ([Security.Principal.SecurityIdentifier]$writer.SID)
    }

    return [pscustomobject]@{
        DomainDistinguishedName            = [string]$domain.DistinguishedName
        ResourceComputerName               = $script:ResourceComputerName
        ResourceComputerExists             = ($null -ne $resourceComputer)
        ResourceComputerDistinguishedName  = $resourceDn
        DelegatingComputerName             = $script:DelegatingComputerName
        DelegatingComputerExists           = ($null -ne $delegatingComputer)
        ControlComputerName                = $script:ControlComputerName
        ControlComputerExists              = ($null -ne $controlComputer)
        DelegatedWriterSamAccountName      = $script:DelegatedWriterSamAccountName
        DelegatedWriterExists              = ($null -ne $writer)
        RbcdAttributePresent               = $descriptorPresent
        RbcdAllowedSidValues               = [string[]]$allowedSids
        DelegatingComputerAllowed          = $delegatingAllowed
        DelegatingComputerAccessMaskMatches = $delegatingAccessMaskMatches
        ControlComputerAllowed             = $controlAllowed
        DelegatedWriterRbcdWriteAceCount   = [int]$writerAceCount
        KerberosS4uExecutedByScript        = $false
    }
}

Add-EventLogMatches -LogName 'Security' -EventId $script:ComputerAccountChangeEventIds -Check 'Computer account changes'
Add-EventLogMatches -LogName 'Security' -EventId $script:DirectoryServiceChangeEventIds -Check 'Directory service changes'
Add-EventLogMatches -LogName 'Security' -EventId $script:DirectoryServiceAccessEventIds -Check 'Directory service access'
Add-EventLogMatches -LogName 'Security' -EventId $script:ObjectPermissionChangeEventIds -Check 'Computer object permission changes'
Add-EventLogMatches -LogName 'Security' -EventId $script:KerberosServiceTicketEventIds -Check 'Kerberos service ticket events'
Add-EventLogMatches -LogName 'Security' -EventId $script:ProcessCreationEventIds -Check 'Process creation'
Add-EventLogMatches -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId $script:PowerShellOperationalEventIds -Check 'PowerShell operational logging'
Add-EventLogMatches -LogName 'Microsoft-Windows-Sysmon/Operational' -EventId $script:SysmonEventIds -Check 'Optional Sysmon EDR-style telemetry'

$currentState = $null
if (-not $SkipCurrentState) {
    try {
        $currentState = Get-ScenarioCurrentState
    }
    catch {
        Add-AuditFinding -Status Warning -Source 'LDAP' -Check 'Current RBCD posture' -Signal 'Unable to collect current state' -Data $_.Exception.Message
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
