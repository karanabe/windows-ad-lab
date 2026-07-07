#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$KdcTemplateName = 'LAB-PKINIT-KDCAuthentication',
    [string]$SourceKdcTemplateName = 'KerberosAuthentication',
    [string]$CACommonName,
    [string]$OutputPath,
    [string]$Server,
    [switch]$FailOnValidationError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'PKINIT-KDCCertificate'
$script:TemplateMarker = 'windows-ad-lab:PKINIT-KDCCertificate'
$script:KdcAuthenticationOid = '1.3.6.1.5.2.3.5'
$script:EnrollExtendedRight = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$script:EnrolleeSuppliesSubject = 0x00000001
$script:PendAllRequests = 0x00000002
$script:TemplateInformationExtensionOid = '1.3.6.1.4.1.311.21.7'
$script:SubjectAlternativeNameExtensionOid = '2.5.29.17'
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

function Add-AdAttributeItem {
    param(
        [AllowNull()]$Value,
        [AllowEmptyCollection()][System.Collections.Generic.List[object]]$Items,
        [bool]$FlattenByteArray
    )

    if ($null -eq $Items) {
        $Items = New-Object 'System.Collections.Generic.List[object]'
    }
    $valueObject = if ($null -eq $Value) { $null } else { $Value.PSObject.BaseObject }
    if ($null -eq $valueObject) {
        return
    }
    if ($valueObject -is [byte[]]) {
        if ($FlattenByteArray) {
            foreach ($byteValue in $valueObject) {
                [void]$Items.Add([byte]$byteValue)
            }
        }
        else {
            [void]$Items.Add($valueObject)
        }
        return
    }
    if ($valueObject -is [System.Collections.IEnumerable] -and -not ($valueObject -is [string])) {
        foreach ($item in $valueObject) {
            Add-AdAttributeItem -Value $item -Items $Items -FlattenByteArray $FlattenByteArray
        }
        return
    }
    [void]$Items.Add($valueObject)
}

function ConvertTo-StringArray {
    param([AllowNull()]$Value)

    $items = New-Object 'System.Collections.Generic.List[object]'
    Add-AdAttributeItem -Value $Value -Items $items -FlattenByteArray $false

    $values = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in $items.ToArray()) {
        if ($null -ne $item) {
            [void]$values.Add([string]$item)
        }
    }
    return $values.ToArray()
}

function ConvertTo-SingleStringOrNull {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)][string]$AttributeName
    )

    $values = @(ConvertTo-StringArray -Value $Value)
    if ($values.Count -eq 0) { return $null }
    if ($values.Count -gt 1) {
        throw "Attribute '$AttributeName' should have one value, found $($values.Count)."
    }
    return [string]$values[0]
}

function Test-OidString {
    param([AllowNull()][string]$Value)

    return (-not [string]::IsNullOrWhiteSpace($Value) -and $Value -match '^\d+(?:\.\d+)+$')
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
        [AllowEmptyCollection()][System.Collections.Generic.List[object]]$Results,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [string]$Message = ''
    )

    $status = if ($Passed) { 'Passed' } else { 'Failed' }
    [void]$Results.Add((New-ValidationResult -Name $Name -Status $status -Expected $Expected -Actual $Actual -Message $Message))
}

function Add-SkippedResult {
    param(
        [AllowEmptyCollection()][System.Collections.Generic.List[object]]$Results,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [string]$Message = ''
    )

    [void]$Results.Add((New-ValidationResult -Name $Name -Status Skipped -Expected $Expected -Actual $Actual -Message $Message))
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
        'description',
        'displayName',
        'flags',
        'msPKI-Certificate-Application-Policy',
        'msPKI-Certificate-Name-Flag',
        'msPKI-Cert-Template-OID',
        'msPKI-Enrollment-Flag',
        'msPKI-Minimal-Key-Size',
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
            [void]$matches.Add("$($accessRule.IdentityReference):$($accessRule.ActiveDirectoryRights):$($accessRule.ObjectType)")
        }
    }
    return [pscustomobject]@{
        HasEnroll = ($matches.Count -gt 0)
        Rules     = [string[]]$matches.ToArray()
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

function Read-DerLength {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][ref]$Offset
    )

    $index = [int]$Offset.Value
    if ($index -ge $Bytes.Length) {
        throw 'DER length is truncated.'
    }
    $first = [int]$Bytes[$index]
    $index++
    if (($first -band 0x80) -eq 0) {
        $Offset.Value = $index
        return $first
    }

    $lengthBytes = $first -band 0x7F
    if ($lengthBytes -eq 0 -or $lengthBytes -gt 4) {
        throw "Unsupported DER length octet count: $lengthBytes."
    }
    if (($index + $lengthBytes) -gt $Bytes.Length) {
        throw 'DER long-form length is truncated.'
    }

    $length = 0
    for ($i = 0; $i -lt $lengthBytes; $i++) {
        $length = ($length * 256) + [int]$Bytes[$index]
        $index++
    }
    $Offset.Value = $index
    return $length
}

function ConvertFrom-DerOidValue {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    if ($Bytes.Length -eq 0) {
        throw 'OID value is empty.'
    }
    $first = [int]$Bytes[0]
    $firstArc = if ($first -ge 80) { 2 } else { [Math]::Floor($first / 40) }
    $secondArc = if ($first -ge 80) { $first - 80 } else { $first % 40 }
    $parts = New-Object 'System.Collections.Generic.List[string]'
    [void]$parts.Add([string]$firstArc)
    [void]$parts.Add([string]$secondArc)

    $value = [Int64]0
    for ($index = 1; $index -lt $Bytes.Length; $index++) {
        $byteValue = [int]$Bytes[$index]
        $value = ($value * 128) + ($byteValue -band 0x7F)
        if (($byteValue -band 0x80) -eq 0) {
            [void]$parts.Add([string]$value)
            $value = [Int64]0
        }
    }
    if (($Bytes[$Bytes.Length - 1] -band 0x80) -ne 0) {
        throw 'OID value ended in the middle of a base-128 component.'
    }
    return ($parts.ToArray() -join '.')
}

function Get-CertificateTemplateOidFromCertificate {
    param([Parameter(Mandatory = $true)]$Certificate)

    $extension = @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq $script:TemplateInformationExtensionOid } | Select-Object -First 1)
    if ($extension.Count -eq 0) {
        return $null
    }

    $bytes = [byte[]]$extension[0].RawData
    $offset = 0
    if ($bytes.Length -eq 0 -or [int]$bytes[$offset] -ne 0x30) {
        throw "Certificate '$($Certificate.Thumbprint)' has an unexpected certificate template extension."
    }
    $offset++
    $sequenceLength = Read-DerLength -Bytes $bytes -Offset ([ref]$offset)
    $sequenceEnd = $offset + $sequenceLength
    if ($sequenceEnd -gt $bytes.Length) {
        throw "Certificate '$($Certificate.Thumbprint)' has a truncated certificate template extension."
    }
    if ($offset -ge $sequenceEnd -or [int]$bytes[$offset] -ne 0x06) {
        throw "Certificate '$($Certificate.Thumbprint)' certificate template extension does not start with an OID."
    }
    $offset++
    $oidLength = Read-DerLength -Bytes $bytes -Offset ([ref]$offset)
    if (($offset + $oidLength) -gt $sequenceEnd) {
        throw "Certificate '$($Certificate.Thumbprint)' has a truncated certificate template OID."
    }
    $oidBytes = New-Object 'byte[]' $oidLength
    [Array]::Copy($bytes, $offset, $oidBytes, 0, $oidLength)
    return ConvertFrom-DerOidValue -Bytes $oidBytes
}

function Get-DnsSubjectAlternativeNames {
    param([Parameter(Mandatory = $true)]$Certificate)

    $dnsNames = New-Object 'System.Collections.Generic.List[string]'
    $extension = @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq $script:SubjectAlternativeNameExtensionOid } | Select-Object -First 1)
    if ($extension.Count -eq 0) {
        return $dnsNames.ToArray()
    }

    $bytes = [byte[]]$extension[0].RawData
    $offset = 0
    if ($bytes.Length -eq 0 -or [int]$bytes[$offset] -ne 0x30) {
        throw "Certificate '$($Certificate.Thumbprint)' has an unexpected SAN extension."
    }
    $offset++
    $sequenceLength = Read-DerLength -Bytes $bytes -Offset ([ref]$offset)
    $sequenceEnd = $offset + $sequenceLength
    if ($sequenceEnd -gt $bytes.Length) {
        throw "Certificate '$($Certificate.Thumbprint)' has a truncated SAN extension."
    }

    while ($offset -lt $sequenceEnd) {
        $tag = [int]$bytes[$offset]
        $offset++
        $length = Read-DerLength -Bytes $bytes -Offset ([ref]$offset)
        if (($offset + $length) -gt $sequenceEnd) {
            throw "Certificate '$($Certificate.Thumbprint)' has a truncated SAN value."
        }
        if ($tag -eq 0x82) {
            [void]$dnsNames.Add([Text.Encoding]::ASCII.GetString($bytes, $offset, $length))
        }
        $offset += $length
    }
    return $dnsNames.ToArray()
}

function Test-CertificateHasKdcEku {
    param([Parameter(Mandatory = $true)]$Certificate)

    $ekuValues = @($Certificate.EnhancedKeyUsageList | ForEach-Object { [string]$_.ObjectId })
    return ($ekuValues -contains $script:KdcAuthenticationOid)
}

function Get-ScenarioKdcCertificates {
    param([Parameter(Mandatory = $true)][string]$TemplateOid)

    $matches = New-Object 'System.Collections.Generic.List[object]'
    foreach ($certificate in @(Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction Stop)) {
        try {
            $certificateTemplateOid = Get-CertificateTemplateOidFromCertificate -Certificate $certificate
        }
        catch {
            continue
        }
        if ([string]$certificateTemplateOid -eq $TemplateOid) {
            [void]$matches.Add($certificate)
        }
    }
    return $matches.ToArray()
}

function Invoke-CertUtilCapture {
    param(
        [Parameter(Mandatory = $true)][string[]]$ArgumentList
    )

    $output = @(& certutil.exe @ArgumentList 2>&1)
    return [pscustomobject]@{
        ExitCode = [int]$LASTEXITCODE
        Output   = [string[]]$output
    }
}

function Test-CertificateChain {
    param([Parameter(Mandatory = $true)]$Certificate)

    $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
    try {
        $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag = [Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        $chain.ChainPolicy.VerificationFlags = [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $chain.ChainPolicy.UrlRetrievalTimeout = New-TimeSpan -Seconds 30
        [void]$chain.ChainPolicy.ApplicationPolicy.Add((New-Object Security.Cryptography.Oid $script:KdcAuthenticationOid))
        $passed = $chain.Build($Certificate)
        $statusText = @($chain.ChainStatus | ForEach-Object { "$($_.Status):$($_.StatusInformation.Trim())" })
        if ($statusText.Count -eq 0) {
            $statusText = @('No chain errors')
        }
        return [pscustomobject]@{
            Passed = [bool]$passed
            Actual = ($statusText -join '; ')
        }
    }
    finally {
        if ($chain -is [IDisposable]) {
            $chain.Dispose()
        }
    }
}

$results = New-Object System.Collections.Generic.List[object]
$enrollmentPrincipal = 'Domain Controllers'
$qualifiedPrincipal = $null
$caName = $null
$templateOid = $null
$selectedCertificate = $null

Assert-TemplateShortName -Name $KdcTemplateName -ParameterName 'KdcTemplateName'
Assert-TemplateShortName -Name $SourceKdcTemplateName -ParameterName 'SourceKdcTemplateName'

try {
    $paths = Get-LabAdcsPaths
    $domain = Get-ADDomain @AdServerParameters
    $dcFqdn = "$($env:COMPUTERNAME).$($domain.DNSRoot)"
    $qualifiedPrincipal = Get-QualifiedPrincipalName -Principal $enrollmentPrincipal

    $sourceTemplate = Get-CertificateTemplateOrNull -TemplateName $SourceKdcTemplateName -Paths $paths
    Add-ValidationResult -Results $results -Name 'Source template exists' -Passed ($null -ne $sourceTemplate) -Expected "CN=$SourceKdcTemplateName" -Actual $(if ($null -eq $sourceTemplate) { 'Missing' } else { $sourceTemplate.DistinguishedName })

    $template = Get-CertificateTemplateOrNull -TemplateName $KdcTemplateName -Paths $paths
    Add-ValidationResult -Results $results -Name 'Template exists' -Passed ($null -ne $template) -Expected "CN=$KdcTemplateName" -Actual $(if ($null -eq $template) { 'Missing' } else { $template.DistinguishedName })

    if ($null -eq $template) {
        foreach ($missingCheck in @('Template lab marker', 'Template KDC Authentication EKU', 'Template subject source', 'Template issuance state', 'Enroll permission', 'CA Publish state', 'LocalMachine certificate count', 'Certificate private key', 'Certificate KDC Authentication EKU', 'Certificate DC identity', 'Certificate chain and revocation', 'certutil DCInfo Verify')) {
            [void]$results.Add((New-ValidationResult -Name $missingCheck -Status Failed -Expected 'Template exists' -Actual 'Template missing'))
        }
    }
    else {
        Add-ValidationResult -Results $results -Name 'Template lab marker' -Passed ([string]$template.adminDescription -ceq $script:TemplateMarker) -Expected $script:TemplateMarker -Actual ([string]$template.adminDescription)
        $templateOid = ConvertTo-SingleStringOrNull -Value $template.'msPKI-Cert-Template-OID' -AttributeName 'msPKI-Cert-Template-OID'
        Add-ValidationResult -Results $results -Name 'Template OID' -Passed (Test-OidString -Value $templateOid) -Expected 'Valid OID' -Actual $templateOid

        $templateEkus = @(
            ConvertTo-StringArray -Value $template.pKIExtendedKeyUsage
            ConvertTo-StringArray -Value $template.'msPKI-Certificate-Application-Policy'
        ) | Sort-Object -Unique
        Add-ValidationResult -Results $results -Name 'Template KDC Authentication EKU' -Passed ($templateEkus -contains $script:KdcAuthenticationOid) -Expected $script:KdcAuthenticationOid -Actual ($templateEkus -join ',')

        $nameFlags = if ($null -eq $template.'msPKI-Certificate-Name-Flag') { 0 } else { [int]($template.'msPKI-Certificate-Name-Flag') }
        $suppliesSubject = (($nameFlags -band $script:EnrolleeSuppliesSubject) -ne 0)
        Add-ValidationResult -Results $results -Name 'Template subject source' -Passed (-not $suppliesSubject) -Expected 'Subject/SAN built from Active Directory' -Actual ("0x{0:X8}" -f $nameFlags)

        $enrollmentFlags = if ($null -eq $template.'msPKI-Enrollment-Flag') { 0 } else { [int]($template.'msPKI-Enrollment-Flag') }
        $raSignature = if ($null -eq $template.'msPKI-RA-Signature') { 0 } else { [int]($template.'msPKI-RA-Signature') }
        $autoIssues = (($enrollmentFlags -band $script:PendAllRequests) -eq 0 -and $raSignature -eq 0)
        Add-ValidationResult -Results $results -Name 'Template issuance state' -Passed $autoIssues -Expected 'No manager approval and 0 authorized signatures' -Actual ("EnrollmentFlags=0x{0:X8}; msPKI-RA-Signature={1}" -f $enrollmentFlags, $raSignature)

        $enroll = Test-TemplateEnrollRight -TemplateDistinguishedName ([string]$template.DistinguishedName) -QualifiedPrincipal $qualifiedPrincipal
        Add-ValidationResult -Results $results -Name 'Enroll permission' -Passed ([bool]$enroll.HasEnroll) -Expected "Allow Certificate-Enrollment for $qualifiedPrincipal" -Actual (($enroll.Rules) -join '; ')

        $caName = Get-ActiveCaName -RequestedName $CACommonName
        $ca = Get-CaEnrollmentService -Paths $paths -Name $caName
        $publishedInAd = ($null -ne $ca -and @($ca.certificateTemplates) -icontains $KdcTemplateName)
        $publishedByCmdlet = Test-LocalCaTemplatePublished -TemplateName $KdcTemplateName
        $localCaText = if ($null -eq $publishedByCmdlet) { 'Not checked; ADCSAdministration Get-CATemplate unavailable' } else { [string]$publishedByCmdlet }
        Add-ValidationResult -Results $results -Name 'CA Publish state' -Passed ($publishedInAd -and ($publishedByCmdlet -ne $false)) -Expected "Published on CA '$caName'" -Actual "AD=$publishedInAd; LocalCA=$localCaText"

        if (Test-OidString -Value $templateOid) {
            $scenarioCertificates = @(Get-ScenarioKdcCertificates -TemplateOid $templateOid)
            $now = Get-Date
            $validCertificates = @($scenarioCertificates | Where-Object { $_.NotBefore -le $now -and $_.NotAfter -gt $now })
            Add-ValidationResult -Results $results -Name 'LocalMachine certificate count' -Passed ($validCertificates.Count -eq 1) -Expected 'Exactly one currently valid scenario certificate in Cert:\LocalMachine\My' -Actual "Valid=$($validCertificates.Count); Total=$($scenarioCertificates.Count)"

            if ($validCertificates.Count -gt 0) {
                $selectedCertificate = @($validCertificates | Sort-Object NotAfter -Descending | Select-Object -First 1)[0]
                Add-ValidationResult -Results $results -Name 'Certificate private key' -Passed ([bool]$selectedCertificate.HasPrivateKey) -Expected 'Has private key' -Actual ([bool]$selectedCertificate.HasPrivateKey)

                $certificateEkus = @($selectedCertificate.EnhancedKeyUsageList | ForEach-Object { [string]$_.ObjectId } | Sort-Object -Unique)
                Add-ValidationResult -Results $results -Name 'Certificate KDC Authentication EKU' -Passed (Test-CertificateHasKdcEku -Certificate $selectedCertificate) -Expected $script:KdcAuthenticationOid -Actual ($certificateEkus -join ',')

                $dnsNames = @(Get-DnsSubjectAlternativeNames -Certificate $selectedCertificate)
                $hasDcName = (@($dnsNames | Where-Object { [string]$_ -ieq $dcFqdn }).Count -gt 0 -or [string]$selectedCertificate.Subject -imatch [regex]::Escape($dcFqdn))
                Add-ValidationResult -Results $results -Name 'Certificate DC identity' -Passed $hasDcName -Expected "DNS SAN or Subject contains $dcFqdn" -Actual "Subject=$($selectedCertificate.Subject); DNS=$($dnsNames -join ',')"

                $chain = Test-CertificateChain -Certificate $selectedCertificate
                Add-ValidationResult -Results $results -Name 'Certificate chain and revocation' -Passed ([bool]$chain.Passed) -Expected 'Trusted chain with online revocation and KDC application policy' -Actual ([string]$chain.Actual)
            }
            else {
                foreach ($missingCertCheck in @('Certificate private key', 'Certificate KDC Authentication EKU', 'Certificate DC identity', 'Certificate chain and revocation')) {
                    [void]$results.Add((New-ValidationResult -Name $missingCertCheck -Status Failed -Expected 'One currently valid scenario certificate' -Actual 'Certificate missing'))
                }
            }

            $dcInfo = Invoke-CertUtilCapture -ArgumentList @('-DCInfo', [string]$domain.DNSRoot, 'Verify')
            $dcInfoPreview = (@($dcInfo.Output | Select-Object -Last 8) -join [Environment]::NewLine)
            Add-ValidationResult -Results $results -Name 'certutil DCInfo Verify' -Passed ($dcInfo.ExitCode -eq 0) -Expected 'ExitCode=0' -Actual "ExitCode=$($dcInfo.ExitCode)" -Message $dcInfoPreview
        }
        else {
            foreach ($skippedCheck in @('LocalMachine certificate count', 'Certificate private key', 'Certificate KDC Authentication EKU', 'Certificate DC identity', 'Certificate chain and revocation', 'certutil DCInfo Verify')) {
                Add-SkippedResult -Results $results -Name $skippedCheck -Expected 'Valid template OID' -Actual 'Template OID invalid'
            }
        }
    }

    $failed = @($results | Where-Object Status -eq 'Failed').Count
    $status = if ($failed -eq 0) { 'Passed' } else { 'Failed' }
    $report = [pscustomobject]@{
        Status                = $status
        KdcTemplateName       = $KdcTemplateName
        SourceKdcTemplateName = $SourceKdcTemplateName
        EnrollmentPrincipal   = $qualifiedPrincipal
        CACommonName          = $caName
        TemplateOid           = $templateOid
        DomainControllerFqdn  = $dcFqdn
        CertificateThumbprint = $(if ($null -eq $selectedCertificate) { $null } else { [string]$selectedCertificate.Thumbprint })
        Results               = $results.ToArray()
    }

    Write-Host ''
    Write-Host 'Validation'
    $results | Format-Table -AutoSize | Out-Host

    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $parent = Split-Path -Parent $OutputPath
        if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    }

    if ($FailOnValidationError -and $failed -gt 0) {
        throw "PKINIT KDC certificate validation failed with $failed failed check(s)."
    }

    $report
}
catch {
    throw
}
