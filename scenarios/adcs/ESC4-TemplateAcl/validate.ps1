#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$TemplateName = 'ESC4LabUser',
    [string]$ControlPrincipal = 'alice.brown',
    [string]$CACommonName,
    [string]$OutputPath,
    [string]$Server,
    [switch]$FailOnValidationError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:TemplateMarker = 'windows-ad-lab:ESC4-TemplateAcl'
$script:ClientAuthenticationOid = '1.3.6.1.5.5.7.3.2'
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
        'msPKI-Certificate-Application-Policy',
        'msPKI-Certificate-Name-Flag',
        'msPKI-Enrollment-Flag',
        'msPKI-RA-Signature',
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

function Test-IdentityReferenceMatchesSid {
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

function Test-TemplateGenericAllAccessRule {
    param(
        [Parameter(Mandatory = $true)]$AccessRule,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$Sid
    )

    if ($AccessRule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }
    if ($AccessRule.IsInherited) { return $false }
    if (-not (Test-IdentityReferenceMatchesSid -IdentityReference $AccessRule.IdentityReference -Sid $Sid)) { return $false }
    return (($AccessRule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)
}

function Test-TemplateGenericAllRight {
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
        if (Test-TemplateGenericAllAccessRule -AccessRule $accessRule -Sid $sid) {
            $matches.Add("$($accessRule.IdentityReference):$($accessRule.ActiveDirectoryRights)")
        }
    }
    return [pscustomobject]@{
        HasGenericAll = ($matches.Count -gt 0)
        Rules         = @($matches)
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
$qualifiedPrincipal = Get-QualifiedPrincipalName -Principal $ControlPrincipal

try {
    $template = Get-CertificateTemplateOrNull -TemplateName $TemplateName -Paths $paths
    Add-ValidationResult -Results $results -Name 'Template exists' -Passed ($null -ne $template) -Expected "CN=$TemplateName" -Actual $(if ($null -eq $template) { 'Missing' } else { $template.DistinguishedName })

    if ($null -eq $template) {
        foreach ($missingCheck in @('Template lab marker', 'GenericAll permission', 'Subject Name setting', 'Client Authentication EKU', 'CA Publish state')) {
            $results.Add((New-ValidationResult -Name $missingCheck -Status Failed -Expected 'Template exists' -Actual 'Template missing'))
        }
    }
    else {
        Add-ValidationResult -Results $results -Name 'Template lab marker' -Passed ([string]$template.adminDescription -ceq $script:TemplateMarker) -Expected $script:TemplateMarker -Actual ([string]$template.adminDescription)

        $acl = Test-TemplateGenericAllRight -TemplateDistinguishedName ([string]$template.DistinguishedName) -QualifiedPrincipal $qualifiedPrincipal
        Add-ValidationResult -Results $results -Name 'GenericAll permission' -Passed ([bool]$acl.HasGenericAll) -Expected "Allow GenericAll for $qualifiedPrincipal" -Actual (($acl.Rules) -join '; ') -Message 'ESC4 is the template ACL, not the current EKU or subject-name flags.'

        $nameFlags = if ($null -eq $template.'msPKI-Certificate-Name-Flag') { 0 } else { [int]($template.'msPKI-Certificate-Name-Flag') }
        $suppliesSubject = (($nameFlags -band $script:EnrolleeSuppliesSubject) -ne 0)
        Add-ValidationResult -Results $results -Name 'Subject Name setting' -Passed (-not $suppliesSubject) -Expected 'CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT not set' -Actual ("0x{0:X8}" -f $nameFlags) -Message 'This fixture is not already ESC1. GenericAll is enough to add enrollee-supplied subject later.'

        $ekuValues = @(
            ConvertTo-StringArray -Value $template.pKIExtendedKeyUsage
            ConvertTo-StringArray -Value $template.'msPKI-Certificate-Application-Policy'
        ) | Sort-Object -Unique
        $hasClientAuth = ($ekuValues -contains $script:ClientAuthenticationOid)
        Add-ValidationResult -Results $results -Name 'Client Authentication EKU' -Passed $hasClientAuth -Expected "Client Authentication ($script:ClientAuthenticationOid)" -Actual ($ekuValues -join ',') -Message 'Keeping an authentication EKU shows why template write access is enough to reach ESC1 later.'

        $enrollmentFlags = if ($null -eq $template.'msPKI-Enrollment-Flag') { 0 } else { [int]($template.'msPKI-Enrollment-Flag') }
        $noSecurityExtension = (($enrollmentFlags -band $script:NoSecurityExtension) -ne 0)
        Add-ValidationResult -Results $results -Name 'ESC9 flag absent' -Passed (-not $noSecurityExtension) -Expected 'CT_FLAG_NO_SECURITY_EXTENSION not set' -Actual ("0x{0:X8}" -f $enrollmentFlags) -Message 'This scenario is ESC4, not ESC9.'

        $caName = Get-ActiveCaName -RequestedName $CACommonName
        $ca = Get-CaEnrollmentService -Paths $paths -Name $caName
        $publishedInAd = ($null -ne $ca -and @($ca.certificateTemplates) -icontains $TemplateName)
        $publishedByCmdlet = Test-LocalCaTemplatePublished -TemplateName $TemplateName
        $localCaText = if ($null -eq $publishedByCmdlet) { 'Not checked; ADCSAdministration Get-CATemplate unavailable' } else { [string]$publishedByCmdlet }
        Add-ValidationResult -Results $results -Name 'CA Publish state' -Passed ($publishedInAd -and ($publishedByCmdlet -ne $false)) -Expected "Published on CA '$caName'" -Actual "AD=$publishedInAd; LocalCA=$localCaText"
    }

    $differences.Add((New-RecommendationDifference -Setting 'Template ACL' -MicrosoftRecommended 'Grant write, WriteDacl, WriteOwner, and GenericAll on templates only to PKI administrators.' -LabTemplate "GenericAll is granted to $qualifiedPrincipal." -Impact 'A low-privilege principal can turn the template into ESC1 or ESC3 conditions.'))
    $differences.Add((New-RecommendationDifference -Setting 'Current template flags' -MicrosoftRecommended 'Review both ACL and current issuance flags. A safe-looking template is still ESC4 if it is writable.' -LabTemplate 'Enrollee-supplied subject is off. The ACL is the finding.' -Impact 'Collection tools classify this as ESC4, not ESC1.'))
    $differences.Add((New-RecommendationDifference -Setting 'CA publication' -MicrosoftRecommended 'Do not publish templates that a non-admin can modify.' -LabTemplate 'The learning template is published on the lab CA.' -Impact 'After an ACL-driven flag change, the template is already available for enrollment.'))

    $failed = @($results | Where-Object Status -eq 'Failed').Count
    $status = if ($failed -eq 0) { 'Passed' } else { 'Failed' }
    $report = [pscustomobject]@{
        Status                          = $status
        TemplateName                    = $TemplateName
        ControlPrincipal                = $qualifiedPrincipal
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
        throw "ESC4 template ACL validation failed with $failed failed check(s)."
    }

    $report
}
catch {
    throw
}
