#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$AgentTemplateName = 'ESC3LabAgent',
    [string]$OnBehalfTemplateName = 'ESC3LabOnBehalf',
    [string]$EnrollmentPrincipal = 'Domain Users',
    [string]$CACommonName,
    [string]$OutputPath,
    [string]$Server,
    [switch]$FailOnValidationError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CertificateRequestAgentOid = '1.3.6.1.4.1.311.20.2.1'
$script:ClientAuthenticationOid = '1.3.6.1.5.5.7.3.2'
$script:EnrollExtendedRight = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$script:EnrolleeSuppliesSubject = 0x00000001
$script:PendAllRequests = 0x00000002
$script:NoSecurityExtension = 0x00080000
$script:AgentMarker = 'windows-ad-lab:ESC3-EnrollmentAgent'
$script:OnBehalfMarker = 'windows-ad-lab:ESC3-OnBehalf'
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
        'msPKI-RA-Application-Policies',
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

function Test-StringSetEqual {
    param(
        [AllowNull()]$Actual,
        [string[]]$Expected
    )

    $actualValues = @(ConvertTo-StringArray -Value $Actual | Sort-Object)
    $expectedValues = @($Expected | ForEach-Object { [string]$_ } | Sort-Object)
    return (@(Compare-Object -ReferenceObject $expectedValues -DifferenceObject $actualValues).Count -eq 0)
}

$results = New-Object System.Collections.Generic.List[object]
$differences = New-Object System.Collections.Generic.List[object]
Assert-TemplateShortName -Name $AgentTemplateName -ParameterName 'AgentTemplateName'
Assert-TemplateShortName -Name $OnBehalfTemplateName -ParameterName 'OnBehalfTemplateName'
$paths = Get-LabAdcsPaths
$qualifiedPrincipal = Get-QualifiedPrincipalName -Principal $EnrollmentPrincipal
$caName = Get-ActiveCaName -RequestedName $CACommonName
$ca = Get-CaEnrollmentService -Paths $paths -Name $caName

try {
    $agent = Get-CertificateTemplateOrNull -TemplateName $AgentTemplateName -Paths $paths
    Add-ValidationResult -Results $results -Name 'Enrollment agent template exists' -Passed ($null -ne $agent) -Expected "CN=$AgentTemplateName" -Actual $(if ($null -eq $agent) { 'Missing' } else { $agent.DistinguishedName })

    $onBehalf = Get-CertificateTemplateOrNull -TemplateName $OnBehalfTemplateName -Paths $paths
    Add-ValidationResult -Results $results -Name 'On-behalf template exists' -Passed ($null -ne $onBehalf) -Expected "CN=$OnBehalfTemplateName" -Actual $(if ($null -eq $onBehalf) { 'Missing' } else { $onBehalf.DistinguishedName })

    if ($null -eq $agent) {
        foreach ($missingCheck in @('Enrollment agent marker', 'Enrollment agent EKU', 'Enrollment agent Enroll permission', 'Enrollment agent issuance state', 'Enrollment agent CA Publish state')) {
            $results.Add((New-ValidationResult -Name $missingCheck -Status Failed -Expected 'Template exists' -Actual 'Template missing'))
        }
    }
    else {
        Add-ValidationResult -Results $results -Name 'Enrollment agent marker' -Passed ([string]$agent.adminDescription -ceq $script:AgentMarker) -Expected $script:AgentMarker -Actual ([string]$agent.adminDescription)

        $agentEkus = @(ConvertTo-StringArray -Value $agent.pKIExtendedKeyUsage | Sort-Object -Unique)
        Add-ValidationResult -Results $results -Name 'Enrollment agent EKU' -Passed ($agentEkus -contains $script:CertificateRequestAgentOid) -Expected "Certificate Request Agent ($script:CertificateRequestAgentOid)" -Actual ($agentEkus -join ',')

        $agentEnroll = Test-TemplateEnrollRight -TemplateDistinguishedName ([string]$agent.DistinguishedName) -QualifiedPrincipal $qualifiedPrincipal
        Add-ValidationResult -Results $results -Name 'Enrollment agent Enroll permission' -Passed ([bool]$agentEnroll.HasEnroll) -Expected "Allow Certificate-Enrollment for $qualifiedPrincipal" -Actual (($agentEnroll.Rules) -join '; ')

        $agentEnrollmentFlags = if ($null -eq $agent.'msPKI-Enrollment-Flag') { 0 } else { [int]($agent.'msPKI-Enrollment-Flag') }
        $agentRaSignature = if ($null -eq $agent.'msPKI-RA-Signature') { 0 } else { [int]($agent.'msPKI-RA-Signature') }
        $agentNameFlags = if ($null -eq $agent.'msPKI-Certificate-Name-Flag') { 0 } else { [int]($agent.'msPKI-Certificate-Name-Flag') }
        $agentAutoIssues = (($agentEnrollmentFlags -band $script:PendAllRequests) -eq 0 -and $agentRaSignature -eq 0)
        Add-ValidationResult -Results $results -Name 'Enrollment agent issuance state' -Passed $agentAutoIssues -Expected 'No manager approval and 0 authorized signatures' -Actual ("EnrollmentFlags=0x{0:X8}; msPKI-RA-Signature={1}" -f $agentEnrollmentFlags, $agentRaSignature)
        Add-ValidationResult -Results $results -Name 'Enrollment agent subject' -Passed (($agentNameFlags -band $script:EnrolleeSuppliesSubject) -eq 0) -Expected 'CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT not set' -Actual ("0x{0:X8}" -f $agentNameFlags) -Message 'ESC3 does not require a request-supplied subject.'

        $agentPublishedInAd = ($null -ne $ca -and @($ca.certificateTemplates) -icontains $AgentTemplateName)
        $agentPublishedByCmdlet = Test-LocalCaTemplatePublished -TemplateName $AgentTemplateName
        $agentLocalCaText = if ($null -eq $agentPublishedByCmdlet) { 'Not checked; ADCSAdministration Get-CATemplate unavailable' } else { [string]$agentPublishedByCmdlet }
        Add-ValidationResult -Results $results -Name 'Enrollment agent CA Publish state' -Passed ($agentPublishedInAd -and ($agentPublishedByCmdlet -ne $false)) -Expected "Published on CA '$caName'" -Actual "AD=$agentPublishedInAd; LocalCA=$agentLocalCaText"
    }

    if ($null -eq $onBehalf) {
        foreach ($missingCheck in @('On-behalf marker', 'On-behalf EKU', 'On-behalf RA signature', 'On-behalf RA application policy', 'On-behalf Enroll permission', 'On-behalf issuance state', 'On-behalf CA Publish state')) {
            $results.Add((New-ValidationResult -Name $missingCheck -Status Failed -Expected 'Template exists' -Actual 'Template missing'))
        }
    }
    else {
        Add-ValidationResult -Results $results -Name 'On-behalf marker' -Passed ([string]$onBehalf.adminDescription -ceq $script:OnBehalfMarker) -Expected $script:OnBehalfMarker -Actual ([string]$onBehalf.adminDescription)

        $onBehalfEkus = @(ConvertTo-StringArray -Value $onBehalf.pKIExtendedKeyUsage | Sort-Object -Unique)
        $onBehalfPolicies = @(ConvertTo-StringArray -Value $onBehalf.'msPKI-Certificate-Application-Policy' | Sort-Object -Unique)
        $onBehalfCombined = @($onBehalfEkus + $onBehalfPolicies | Sort-Object -Unique)
        Add-ValidationResult -Results $results -Name 'On-behalf EKU' -Passed ($onBehalfCombined -contains $script:ClientAuthenticationOid) -Expected "Client Authentication ($script:ClientAuthenticationOid)" -Actual ($onBehalfCombined -join ',')

        $onBehalfRaSignature = if ($null -eq $onBehalf.'msPKI-RA-Signature') { 0 } else { [int]($onBehalf.'msPKI-RA-Signature') }
        Add-ValidationResult -Results $results -Name 'On-behalf RA signature' -Passed ($onBehalfRaSignature -eq 1) -Expected 'msPKI-RA-Signature = 1' -Actual ([string]$onBehalfRaSignature)

        $onBehalfRaPolicies = @(ConvertTo-StringArray -Value $onBehalf.'msPKI-RA-Application-Policies' | Sort-Object -Unique)
        Add-ValidationResult -Results $results -Name 'On-behalf RA application policy' -Passed (Test-StringSetEqual -Actual $onBehalfRaPolicies -Expected @($script:CertificateRequestAgentOid)) -Expected $script:CertificateRequestAgentOid -Actual ($onBehalfRaPolicies -join ',')

        $onBehalfEnroll = Test-TemplateEnrollRight -TemplateDistinguishedName ([string]$onBehalf.DistinguishedName) -QualifiedPrincipal $qualifiedPrincipal
        Add-ValidationResult -Results $results -Name 'On-behalf Enroll permission' -Passed ([bool]$onBehalfEnroll.HasEnroll) -Expected "Allow Certificate-Enrollment for $qualifiedPrincipal" -Actual (($onBehalfEnroll.Rules) -join '; ')

        $onBehalfEnrollmentFlags = if ($null -eq $onBehalf.'msPKI-Enrollment-Flag') { 0 } else { [int]($onBehalf.'msPKI-Enrollment-Flag') }
        $onBehalfNameFlags = if ($null -eq $onBehalf.'msPKI-Certificate-Name-Flag') { 0 } else { [int]($onBehalf.'msPKI-Certificate-Name-Flag') }
        $onBehalfNoManagerApproval = (($onBehalfEnrollmentFlags -band $script:PendAllRequests) -eq 0)
        $noSecurityExtension = (($onBehalfEnrollmentFlags -band $script:NoSecurityExtension) -ne 0)
        Add-ValidationResult -Results $results -Name 'On-behalf issuance state' -Passed $onBehalfNoManagerApproval -Expected 'No manager approval' -Actual ("EnrollmentFlags=0x{0:X8}" -f $onBehalfEnrollmentFlags)
        Add-ValidationResult -Results $results -Name 'On-behalf subject' -Passed (($onBehalfNameFlags -band $script:EnrolleeSuppliesSubject) -eq 0) -Expected 'CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT not set' -Actual ("0x{0:X8}" -f $onBehalfNameFlags)
        Add-ValidationResult -Results $results -Name 'ESC9 flag absent' -Passed (-not $noSecurityExtension) -Expected 'CT_FLAG_NO_SECURITY_EXTENSION not set' -Actual ("0x{0:X8}" -f $onBehalfEnrollmentFlags) -Message 'This scenario is ESC3, not ESC9.'

        $onBehalfPublishedInAd = ($null -ne $ca -and @($ca.certificateTemplates) -icontains $OnBehalfTemplateName)
        $onBehalfPublishedByCmdlet = Test-LocalCaTemplatePublished -TemplateName $OnBehalfTemplateName
        $onBehalfLocalCaText = if ($null -eq $onBehalfPublishedByCmdlet) { 'Not checked; ADCSAdministration Get-CATemplate unavailable' } else { [string]$onBehalfPublishedByCmdlet }
        Add-ValidationResult -Results $results -Name 'On-behalf CA Publish state' -Passed ($onBehalfPublishedInAd -and ($onBehalfPublishedByCmdlet -ne $false)) -Expected "Published on CA '$caName'" -Actual "AD=$onBehalfPublishedInAd; LocalCA=$onBehalfLocalCaText"
    }

    $differences.Add((New-RecommendationDifference -Setting 'Enrollment Agent template' -MicrosoftRecommended 'Limit Certificate Request Agent to a dedicated, tightly scoped group and require approval.' -LabTemplate "ESC3LabAgent has Certificate Request Agent and Enroll for $qualifiedPrincipal." -Impact 'A low-privilege principal can obtain an enrollment-agent certificate.'))
    $differences.Add((New-RecommendationDifference -Setting 'On-behalf template' -MicrosoftRecommended 'Do not combine Client Authentication with a required enrollment-agent signature on a broadly enrollable template.' -LabTemplate 'ESC3LabOnBehalf requires one Certificate Request Agent signature and has Client Authentication.' -Impact 'The agent certificate can be used to request an authentication certificate for another account.'))
    $differences.Add((New-RecommendationDifference -Setting 'Issuance gates' -MicrosoftRecommended 'Keep manager approval or additional issuance policy on enrollment-agent paths.' -LabTemplate 'Manager approval is off on both learning templates.' -Impact 'The two-template ESC3 condition set can auto-issue.'))
    $differences.Add((New-RecommendationDifference -Setting 'CA publication' -MicrosoftRecommended 'Publish enrollment-agent templates only on CAs that intentionally issue them.' -LabTemplate 'Both learning templates are published on the lab CA.' -Impact 'The ESC3 pair is available for enrollment.'))

    $failed = @($results | Where-Object Status -eq 'Failed').Count
    $status = if ($failed -eq 0) { 'Passed' } else { 'Failed' }
    $report = [pscustomobject]@{
        Status                          = $status
        AgentTemplateName               = $AgentTemplateName
        OnBehalfTemplateName            = $OnBehalfTemplateName
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
        throw "ESC3 template validation failed with $failed failed check(s)."
    }

    $report
}
catch {
    throw
}
