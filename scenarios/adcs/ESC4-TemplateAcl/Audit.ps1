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

$script:ScenarioName = 'ESC4-TemplateAcl'
$script:TemplateName = 'ESC4LabUser'
$script:ControlPrincipal = 'alice.brown'
$script:TemplateMarker = 'windows-ad-lab:ESC4-TemplateAcl'
$script:ClientAuthenticationOid = '1.3.6.1.5.5.7.3.2'
$script:EnrolleeSuppliesSubjectFlag = 0x00000001 # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT.
$script:PendAllRequestsFlag = 0x00000002 # CT_FLAG_PEND_ALL_REQUESTS.
$script:FindingPatterns = @(
    'ESC4-TemplateAcl',
    'ESC4-TemplateAcl',
    'windows-ad-lab:ESC4-TemplateAcl',
    'ESC4LabUser',
    'ESC4 Lab Template ACL',
    'alice.brown',
    'GenericAll',
    'Certificate Templates',
    'pKICertificateTemplate',
    'nTSecurityDescriptor',
    'certificateTemplates',
    'New-ADObject',
    'Set-ADObject',
    'Set-Acl',
    'Add-CATemplate',
    'certreq',
    'certutil'
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
$script:CertificationServicesEventIds = @(
    4886, # Certificate Services received a certificate request.
    4887, # Certificate Services approved a certificate request and issued a certificate.
    4888, # Certificate Services denied a certificate request.
    4889, # Certificate Services set the status of a certificate request to pending.
    4890, # Certificate Services manager settings for a certificate request changed.
    4891, # A configuration entry changed in Certificate Services.
    4892, # A Certificate Services property changed.
    4898, # Certificate Services loaded a template.
    4899  # A Certificate Services template was updated.
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

function ConvertTo-AuditInt32 {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)][string]$AttributeName,
        [Parameter(Mandatory = $true)][string]$DistinguishedName
    )

    $singleValue = ConvertTo-AuditSingleValue -Value $Value -AttributeName $AttributeName -DistinguishedName $DistinguishedName
    if ($null -eq $singleValue -or [string]::IsNullOrWhiteSpace([string]$singleValue)) {
        return 0
    }
    return [int]$singleValue
}

function ConvertTo-LdapFilterValue {
    param([Parameter(Mandatory = $true)][string]$Value)

    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace(([string][char]0), '\00')
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

function Get-LabAdcsPaths {
    param([hashtable]$AdParameters)

    $rootDse = Get-ADRootDSE @AdParameters -ErrorAction Stop
    $configNc = [string]$rootDse.configurationNamingContext
    return [pscustomobject]@{
        ConfigurationNamingContext = $configNc
        TemplateContainer          = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNc"
        EnrollmentServices         = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNc"
    }
}

function Get-CertificateTemplateOrNull {
    param(
        [Parameter(Mandatory = $true)][string]$TemplateName,
        [Parameter(Mandatory = $true)]$Paths,
        [hashtable]$AdParameters
    )

    $properties = @(
        'adminDescription',
        'displayName',
        'flags',
        'msPKI-Certificate-Application-Policy',
        'msPKI-Certificate-Name-Flag',
        'msPKI-Cert-Template-OID',
        'msPKI-Enrollment-Flag',
        'msPKI-RA-Signature',
        'pKIExtendedKeyUsage'
    )
    try {
        return Get-ADObject -Identity "CN=$TemplateName,$($Paths.TemplateContainer)" -Properties $properties @AdParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

function Test-TemplateGenericAllAccessRule {
    param(
        [Parameter(Mandatory = $true)]$AccessRule,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$Sid
    )

    if ($AccessRule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }
    if ($AccessRule.IsInherited) { return $false }
    if (-not (Test-AuditIdentityReferenceMatchesSid -IdentityReference $AccessRule.IdentityReference -Sid $Sid)) { return $false }
    return (($AccessRule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)
}

function Get-TemplateGenericAllAceCount {
    param(
        [Parameter(Mandatory = $true)][string]$TemplateDistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    $acl = Get-Acl -Path "AD:\$TemplateDistinguishedName" -ErrorAction Stop
    return @($acl.Access | Where-Object { Test-TemplateGenericAllAccessRule -AccessRule $_ -Sid $PrincipalSid }).Count
}

function Get-ScenarioCurrentState {
    $adParameters = Get-AdServerParameters
    Import-Module ActiveDirectory -ErrorAction Stop
    Ensure-AuditAdDrive -AdParameters $adParameters

    $domain = Get-ADDomain @adParameters -ErrorAction Stop
    $paths = Get-LabAdcsPaths -AdParameters $adParameters
    $template = Get-CertificateTemplateOrNull -TemplateName $script:TemplateName -Paths $paths -AdParameters $adParameters
    $controlUser = Get-ADUser -Identity $script:ControlPrincipal -Properties SID @adParameters -ErrorAction SilentlyContinue
    $genericAllAceCount = 0
    $templateDn = ''
    $templateOid = ''
    $nameFlags = 0
    $enrollmentFlags = 0
    $raSignature = 0
    $ekus = @()
    $applicationPolicies = @()

    if ($null -ne $template) {
        $templateDn = [string]$template.DistinguishedName
        $templateOid = [string](ConvertTo-AuditSingleValue -Value $template.'msPKI-Cert-Template-OID' -AttributeName 'msPKI-Cert-Template-OID' -DistinguishedName $templateDn)
        $nameFlags = ConvertTo-AuditInt32 -Value $template.'msPKI-Certificate-Name-Flag' -AttributeName 'msPKI-Certificate-Name-Flag' -DistinguishedName $templateDn
        $enrollmentFlags = ConvertTo-AuditInt32 -Value $template.'msPKI-Enrollment-Flag' -AttributeName 'msPKI-Enrollment-Flag' -DistinguishedName $templateDn
        $raSignature = ConvertTo-AuditInt32 -Value $template.'msPKI-RA-Signature' -AttributeName 'msPKI-RA-Signature' -DistinguishedName $templateDn
        $ekus = @(ConvertTo-AuditStringArray -Value $template.pKIExtendedKeyUsage)
        $applicationPolicies = @(ConvertTo-AuditStringArray -Value $template.'msPKI-Certificate-Application-Policy')
        if ($null -ne $controlUser) {
            $genericAllAceCount = Get-TemplateGenericAllAceCount -TemplateDistinguishedName $templateDn -PrincipalSid ([Security.Principal.SecurityIdentifier]$controlUser.SID)
        }
    }

    $enrollmentServices = @(Get-ADObject -SearchBase $paths.EnrollmentServices -SearchScope OneLevel -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties certificateTemplates @adParameters -ErrorAction Stop)
    $publishedByCa = [string[]]@($enrollmentServices | Where-Object {
            @(ConvertTo-AuditStringArray -Value $_.certificateTemplates) -icontains $script:TemplateName
        } | ForEach-Object { [string]$_.Name } | Sort-Object)

    return [pscustomobject]@{
        DomainDistinguishedName                   = [string]$domain.DistinguishedName
        ConfigurationNamingContext                = [string]$paths.ConfigurationNamingContext
        TemplateExists                            = ($null -ne $template)
        TemplateDistinguishedName                 = $templateDn
        TemplateMarker                            = if ($null -eq $template) { '' } else { [string]$template.adminDescription }
        TemplateDisplayName                       = if ($null -eq $template) { '' } else { [string]$template.displayName }
        TemplateOid                               = $templateOid
        ClientAuthenticationEkuPresent            = ($ekus -contains $script:ClientAuthenticationOid)
        ClientAuthenticationApplicationPolicyPresent = ($applicationPolicies -contains $script:ClientAuthenticationOid)
        EnrolleeSuppliesSubject                   = (($nameFlags -band $script:EnrolleeSuppliesSubjectFlag) -ne 0)
        RequiresManagerApproval                   = (($enrollmentFlags -band $script:PendAllRequestsFlag) -ne 0)
        AuthorizedSignatureCount                  = [int]$raSignature
        ControlPrincipal                          = $script:ControlPrincipal
        ControlPrincipalExists                    = ($null -ne $controlUser)
        GenericAllAceCount                        = [int]$genericAllAceCount
        PublishedOnCaNames                        = [string[]]$publishedByCa
        PublishedOnCaCount                        = [int]$publishedByCa.Count
        CertificateRequestExecutedByScript        = $false
        PrivateKeyMaterialRead                    = $false
    }
}

Add-EventLogMatches -LogName 'Security' -EventId $script:DirectoryServiceChangeEventIds -Check 'Directory service changes'
Add-EventLogMatches -LogName 'Security' -EventId $script:DirectoryServiceAccessEventIds -Check 'Directory service access'
Add-EventLogMatches -LogName 'Security' -EventId $script:ObjectPermissionChangeEventIds -Check 'Template permission changes'
Add-EventLogMatches -LogName 'Security' -EventId $script:ProcessCreationEventIds -Check 'Process creation'
Add-EventLogMatches -LogName 'Security' -EventId $script:CertificationServicesEventIds -Check 'Certification Services audit events'
Add-EventLogMatches -LogName 'Microsoft-Windows-PowerShell/Operational' -EventId $script:PowerShellOperationalEventIds -Check 'PowerShell operational logging'
Add-EventLogMatches -LogName 'Microsoft-Windows-Sysmon/Operational' -EventId $script:SysmonEventIds -Check 'Optional Sysmon EDR-style telemetry'

$currentState = $null
if (-not $SkipCurrentState) {
    try {
        $currentState = Get-ScenarioCurrentState
    }
    catch {
        Add-AuditFinding -Status Warning -Source 'LDAP' -Check 'Current ESC4 template ACL posture' -Signal 'Unable to collect current state' -Data $_.Exception.Message
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
