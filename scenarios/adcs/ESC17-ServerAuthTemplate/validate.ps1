#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$TemplateName = 'ESC17LabServerAuth',
    [string]$EnrollmentPrincipal = 'Domain Users',
    [string]$CACommonName,
    [string]$OutputPath,
    [string]$Server,
    [switch]$FailOnValidationError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:TemplateMarker = 'windows-ad-lab:ESC17-ServerAuthTemplate'
$script:ServerAuthenticationOid = '1.3.6.1.5.5.7.3.1'
$script:ClientAuthenticationOid = '1.3.6.1.5.5.7.3.2'
$script:SmartCardLogonOid = '1.3.6.1.4.1.311.20.2.2'
$script:PkinitClientAuthenticationOid = '1.3.6.1.5.2.3.4'
$script:CertificateRequestAgentOid = '1.3.6.1.4.1.311.20.2.1'
$script:EnrollExtendedRight = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$script:EnrolleeSuppliesSubject = 0x00000001
$script:PendAllRequests = 0x00000002
$script:NoSecurityExtension = 0x00080000
$AdServerParameters = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $AdServerParameters['Server'] = $Server
}

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module ADCSAdministration -ErrorAction SilentlyContinue

function Assert-TemplateShortName {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ParameterName
    )

    if ($Name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
        throw "$ParameterName must be a certificate template short name containing only letters, digits, dot, underscore, or hyphen: '$Name'"
    }
}

function ConvertTo-LdapFilterValue {
    param([Parameter(Mandatory = $true)][string]$Value)

    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace(([string][char]0), '\00')
}

function ConvertTo-StringArray {
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [array] -and -not ($Value -is [byte[]])) {
        return @($Value | ForEach-Object { [string]$_ })
    }
    if ($Value -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) {
        return @($Value | ForEach-Object { [string]$_ })
    }
    return @([string]$Value)
}

function New-ValidationResult {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('Passed', 'Failed', 'Skipped')][string]$Status,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [string]$Message = ''
    )

    return [pscustomobject]@{
        Name     = $Name
        Status   = $Status
        Expected = $Expected
        Actual   = $Actual
        Message  = $Message
    }
}

function Add-ValidationResult {
    param(
        [System.Collections.Generic.List[object]]$Results,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [string]$Message = ''
    )

    $status = if ($Passed) { 'Passed' } else { 'Failed' }
    $Results.Add((New-ValidationResult -Name $Name -Status $status -Expected $Expected -Actual $Actual -Message $Message))
}

function Get-LabAdcsPaths {
    $rootDse = Get-ADRootDSE @AdServerParameters
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
        [Parameter(Mandatory = $true)]$Paths
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
        'msPKI-Template-Schema-Version',
        'pKIExtendedKeyUsage'
    )
    try {
        return Get-ADObject -Identity "CN=$TemplateName,$($Paths.TemplateContainer)" -Properties $properties @AdServerParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

function Get-QualifiedPrincipalName {
    param([Parameter(Mandatory = $true)][string]$Principal)

    if ($Principal -match '\\') { return $Principal }
    $domain = Get-ADDomain @AdServerParameters
    return "$($domain.NetBIOSName)\$Principal"
}

function Ensure-AdDrive {
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
    if ($AdServerParameters.ContainsKey('Server')) {
        $driveParameters['Server'] = $AdServerParameters['Server']
    }
    New-PSDrive @driveParameters | Out-Null
}

function Test-TemplateEnrollAccessRule {
    param(
        [Parameter(Mandatory = $true)]$AccessRule,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$Sid
    )

    if ($AccessRule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }
    try {
        $ruleSid = $AccessRule.IdentityReference.Translate([Security.Principal.SecurityIdentifier])
    }
    catch {
        return $false
    }
    if ($ruleSid.Value -ne $Sid.Value) { return $false }
    if (($AccessRule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) { return $true }
    if (($AccessRule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) { return $false }
    return ($AccessRule.ObjectType -eq $script:EnrollExtendedRight -or $AccessRule.ObjectType -eq [guid]::Empty)
}

function Test-TemplateEnrollRight {
    param(
        [Parameter(Mandatory = $true)][string]$TemplateDistinguishedName,
        [Parameter(Mandatory = $true)][string]$QualifiedPrincipal
    )

    $sid = (New-Object Security.Principal.NTAccount($QualifiedPrincipal)).Translate([Security.Principal.SecurityIdentifier])
    Ensure-AdDrive
    $path = "AD:\$TemplateDistinguishedName"
    $acl = Get-Acl -Path $path -ErrorAction Stop
    $matches = New-Object System.Collections.Generic.List[string]
    foreach ($accessRule in @($acl.Access)) {
        if (Test-TemplateEnrollAccessRule -AccessRule $accessRule -Sid $sid) {
            $matches.Add("$($accessRule.IdentityReference):$($accessRule.ActiveDirectoryRights):$($accessRule.ObjectType)")
        }
    }
    return [pscustomobject]@{
        HasEnroll = ($matches.Count -gt 0)
        Rules     = @($matches)
    }
}

function Get-ActiveCaName {
    param([string]$RequestedName)

    if (-not [string]::IsNullOrWhiteSpace($RequestedName)) {
        return $RequestedName
    }
    $caRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
    $active = (Get-ItemProperty -Path $caRoot -Name Active -ErrorAction Stop).Active
    if ([string]::IsNullOrWhiteSpace([string]$active)) {
        throw 'No active local Certification Authority was found.'
    }
    return [string]$active
}

function Get-CaEnrollmentService {
    param(
        [Parameter(Mandatory = $true)]$Paths,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $escapedName = ConvertTo-LdapFilterValue -Value $Name
    $caObjects = @(Get-ADObject -SearchBase $Paths.EnrollmentServices -SearchScope OneLevel -LDAPFilter "(cn=$escapedName)" -Properties certificateTemplates @AdServerParameters)
    if ($caObjects.Count -ne 1) {
        return $null
    }
    return $caObjects[0]
}

function Get-CaTemplateObjectName {
    param([Parameter(Mandatory = $true)]$TemplateObject)

    foreach ($propertyName in @('Name', 'ObjectName', 'Object Name')) {
        $property = $TemplateObject.PSObject.Properties[$propertyName]
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            return [string]$property.Value
        }
    }
    return [string]$TemplateObject
}

function Test-LocalCaTemplatePublished {
    param([Parameter(Mandatory = $true)][string]$TemplateName)

    $command = Get-Command -Name Get-CATemplate -Module ADCSAdministration -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        return $null
    }
    $names = @(& $command | ForEach-Object { Get-CaTemplateObjectName -TemplateObject $_ })
    return ($names -icontains $TemplateName)
}

function New-RecommendationDifference {
    param(
        [Parameter(Mandatory = $true)][string]$Setting,
        [Parameter(Mandatory = $true)][string]$MicrosoftRecommended,
        [Parameter(Mandatory = $true)][string]$LabTemplate,
        [Parameter(Mandatory = $true)][string]$Impact
    )

    return [pscustomobject]@{
        Setting              = $Setting
        MicrosoftRecommended = $MicrosoftRecommended
        LabTemplate          = $LabTemplate
        Impact               = $Impact
    }
}

$results = New-Object System.Collections.Generic.List[object]
$differences = New-Object System.Collections.Generic.List[object]
Assert-TemplateShortName -Name $TemplateName -ParameterName 'TemplateName'
$paths = Get-LabAdcsPaths
$qualifiedPrincipal = Get-QualifiedPrincipalName -Principal $EnrollmentPrincipal

try {
    $template = Get-CertificateTemplateOrNull -TemplateName $TemplateName -Paths $paths
    Add-ValidationResult -Results $results -Name 'Template exists' -Passed ($null -ne $template) -Expected "CN=$TemplateName" -Actual $(if ($null -eq $template) { 'Missing' } else { $template.DistinguishedName })

    if ($null -eq $template) {
        foreach ($missingCheck in @('Enroll permission', 'Server Authentication EKU', 'Client Authentication absent', 'Subject Name setting', 'Issuance state', 'CA Publish state')) {
            $results.Add((New-ValidationResult -Name $missingCheck -Status Failed -Expected 'Template exists' -Actual 'Template missing'))
        }
    }
    else {
        Add-ValidationResult -Results $results -Name 'Template lab marker' -Passed ([string]$template.adminDescription -ceq $script:TemplateMarker) -Expected $script:TemplateMarker -Actual ([string]$template.adminDescription)

        $enroll = Test-TemplateEnrollRight -TemplateDistinguishedName ([string]$template.DistinguishedName) -QualifiedPrincipal $qualifiedPrincipal
        Add-ValidationResult -Results $results -Name 'Enroll permission' -Passed ([bool]$enroll.HasEnroll) -Expected "Allow Certificate-Enrollment for $qualifiedPrincipal" -Actual (($enroll.Rules) -join '; ')

        $ekuValues = @(ConvertTo-StringArray -Value $template.pKIExtendedKeyUsage | Sort-Object -Unique)
        $applicationPolicies = @(ConvertTo-StringArray -Value $template.'msPKI-Certificate-Application-Policy' | Sort-Object -Unique)
        $combinedPolicyValues = @($ekuValues + $applicationPolicies | Sort-Object -Unique)
        $hasServerAuth = ($combinedPolicyValues -contains $script:ServerAuthenticationOid)
        Add-ValidationResult -Results $results -Name 'Server Authentication EKU' -Passed $hasServerAuth -Expected "Server Authentication ($script:ServerAuthenticationOid)" -Actual ($combinedPolicyValues -join ',') -Message 'ESC17 is enrollee-supplied subject plus Server Authentication, not Client Authentication.'

        $authenticationEkus = @($script:ClientAuthenticationOid, $script:SmartCardLogonOid, $script:PkinitClientAuthenticationOid, $script:CertificateRequestAgentOid)
        $presentAuthenticationEkus = @($combinedPolicyValues | Where-Object { $authenticationEkus -contains $_ })
        Add-ValidationResult -Results $results -Name 'Client Authentication absent' -Passed ($presentAuthenticationEkus.Count -eq 0) -Expected 'No Client Authentication, Smart Card Logon, PKINIT, or Certificate Request Agent' -Actual $(if ($presentAuthenticationEkus.Count -eq 0) { 'None' } else { $presentAuthenticationEkus -join ',' }) -Message 'This fixture is not ESC1 or ESC3.'

        $nameFlags = if ($null -eq $template.'msPKI-Certificate-Name-Flag') { 0 } else { [int]($template.'msPKI-Certificate-Name-Flag') }
        $suppliesSubject = (($nameFlags -band $script:EnrolleeSuppliesSubject) -ne 0)
        Add-ValidationResult -Results $results -Name 'Subject Name setting' -Passed $suppliesSubject -Expected 'CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT set' -Actual ("0x{0:X8}" -f $nameFlags) -Message 'ESC17 requires a request-supplied subject for an arbitrary DNS SAN.'

        $enrollmentFlags = if ($null -eq $template.'msPKI-Enrollment-Flag') { 0 } else { [int]($template.'msPKI-Enrollment-Flag') }
        $raSignature = if ($null -eq $template.'msPKI-RA-Signature') { 0 } else { [int]($template.'msPKI-RA-Signature') }
        $autoIssues = (($enrollmentFlags -band $script:PendAllRequests) -eq 0 -and $raSignature -eq 0)
        $noSecurityExtension = (($enrollmentFlags -band $script:NoSecurityExtension) -ne 0)
        Add-ValidationResult -Results $results -Name 'Issuance state' -Passed $autoIssues -Expected 'No manager approval and 0 authorized signatures' -Actual ("EnrollmentFlags=0x{0:X8}; msPKI-RA-Signature={1}" -f $enrollmentFlags, $raSignature)
        Add-ValidationResult -Results $results -Name 'ESC9 flag absent' -Passed (-not $noSecurityExtension) -Expected 'CT_FLAG_NO_SECURITY_EXTENSION not set' -Actual ("0x{0:X8}" -f $enrollmentFlags) -Message 'This scenario is ESC17, not ESC9.'

        $caName = Get-ActiveCaName -RequestedName $CACommonName
        $ca = Get-CaEnrollmentService -Paths $paths -Name $caName
        $publishedInAd = ($null -ne $ca -and @($ca.certificateTemplates) -icontains $TemplateName)
        $publishedByCmdlet = Test-LocalCaTemplatePublished -TemplateName $TemplateName
        $localCaText = if ($null -eq $publishedByCmdlet) { 'Not checked; ADCSAdministration Get-CATemplate unavailable' } else { [string]$publishedByCmdlet }
        Add-ValidationResult -Results $results -Name 'CA Publish state' -Passed ($publishedInAd -and ($publishedByCmdlet -ne $false)) -Expected "Published on CA '$caName'" -Actual "AD=$publishedInAd; LocalCA=$localCaText"
    }

    $differences.Add((New-RecommendationDifference -Setting 'EKU' -MicrosoftRecommended 'Server Authentication templates used for TLS should not be enrollable by a broad low-privilege group.' -LabTemplate 'Server Authentication 1.3.6.1.5.5.7.3.1 is the only EKU.' -Impact 'A certificate can impersonate a TLS server name such as an internal WSUS host.'))
    $differences.Add((New-RecommendationDifference -Setting 'Enrollment scope' -MicrosoftRecommended 'Grant Enroll only to a purpose-specific security group.' -LabTemplate "Enroll is granted to $qualifiedPrincipal." -Impact 'Broad low-privileged enrollment is an ESC17 precondition.'))
    $differences.Add((New-RecommendationDifference -Setting 'Issuance gates' -MicrosoftRecommended 'Enrollee-supplied subject plus Server Authentication should not auto-issue to a broad enrollment group.' -LabTemplate 'Manager approval is off and authorized signatures are 0.' -Impact 'Requests are issued automatically.'))
    $differences.Add((New-RecommendationDifference -Setting 'Subject Name' -MicrosoftRecommended 'Keep subject construction in Active Directory unless a documented TLS SAN exception exists, and then require manager approval.' -LabTemplate 'Enrollee-supplied subject is on. Client Authentication is absent, so this fixture is ESC17 rather than ESC1.' -Impact 'ESC17 is a request-supplied DNS SAN for Server Authentication, not a client-auth impersonation path.'))
    $differences.Add((New-RecommendationDifference -Setting 'CA publication' -MicrosoftRecommended 'Publish only templates that are intentionally available on each issuing CA.' -LabTemplate 'The learning template is published on the lab CA.' -Impact 'The template is available for enrollment, completing the ESC17 path.'))

    $failed = @($results | Where-Object Status -eq 'Failed').Count
    $status = if ($failed -eq 0) { 'Passed' } else { 'Failed' }
    $report = [pscustomobject]@{
        Status                          = $status
        TemplateName                    = $TemplateName
        EnrollmentPrincipal             = $qualifiedPrincipal
        Results                         = $results.ToArray()
        MicrosoftRecommendedDifferences = $differences.ToArray()
    }

    Write-Host ''
    Write-Host 'Validation'
    $results | Format-Table -AutoSize | Out-Host
    Write-Host ''
    Write-Host 'Microsoft recommended differences'
    $differences | Format-Table -AutoSize | Out-Host

    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $parent = Split-Path -Parent $OutputPath
        if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    }

    if ($FailOnValidationError -and $failed -gt 0) {
        throw "ESC17 template validation failed with $failed failed check(s)."
    }

    $report
}
catch {
    throw
}
