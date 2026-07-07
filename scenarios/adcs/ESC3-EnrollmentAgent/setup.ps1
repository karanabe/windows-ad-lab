#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$AgentTemplateName = 'ESC3LabAgent',
    [string]$AgentTemplateDisplayName = 'ESC3 Lab Enrollment Agent',
    [string]$OnBehalfTemplateName = 'ESC3LabOnBehalf',
    [string]$OnBehalfTemplateDisplayName = 'ESC3 Lab On-Behalf Authentication',
    [string]$SourceTemplateName = 'User',
    [string]$EnrollmentPrincipal = 'Domain Users',
    [string]$CACommonName,
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CertificateRequestAgentOid = '1.3.6.1.4.1.311.20.2.1'
$script:ClientAuthenticationOid = '1.3.6.1.5.5.7.3.2'
$script:EnrollExtendedRight = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$script:EnrolleeSuppliesSubject = 0x00000001
$script:PendAllRequests = 0x00000002
$script:IsDefaultTemplate = 0x00010000
$script:IsModifiedTemplate = 0x00020000
$script:TemplateSpecs = @(
    [pscustomobject]@{
        Name                      = $AgentTemplateName
        DisplayName               = $AgentTemplateDisplayName
        Marker                    = 'windows-ad-lab:ESC3-EnrollmentAgent'
        Description               = 'LAB ONLY: ESC3 enrollment-agent learning template. Do not use in production.'
        EkuOids                   = [string[]]@($script:CertificateRequestAgentOid)
        ApplicationPolicyOids     = [string[]]@($script:CertificateRequestAgentOid)
        RaSignature               = 0
        RaApplicationPolicyOids   = [string[]]@()
        SettingsAction            = 'Update ESC3 enrollment-agent template settings'
    },
    [pscustomobject]@{
        Name                      = $OnBehalfTemplateName
        DisplayName               = $OnBehalfTemplateDisplayName
        Marker                    = 'windows-ad-lab:ESC3-OnBehalf'
        Description               = 'LAB ONLY: ESC3 on-behalf authentication learning template. Do not use in production.'
        EkuOids                   = [string[]]@($script:ClientAuthenticationOid)
        ApplicationPolicyOids     = [string[]]@($script:ClientAuthenticationOid)
        RaSignature               = 1
        RaApplicationPolicyOids   = [string[]]@($script:CertificateRequestAgentOid)
        SettingsAction            = 'Update ESC3 on-behalf template settings'
    }
)
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

function Get-RandomHex {
    param([Parameter(Mandatory = $true)][int]$Length)

    $characters = '0123456789ABCDEF'
    $builder = New-Object System.Text.StringBuilder
    for ($index = 0; $index -lt $Length; $index++) {
        [void]$builder.Append($characters.Substring((Get-Random -Minimum 0 -Maximum $characters.Length), 1))
    }
    return $builder.ToString()
}

function Add-AdAttributeItem {
    param(
        [AllowNull()]$Value,
        [System.Collections.Generic.List[object]]$Items,
        [bool]$FlattenByteArray
    )

    $valueObject = if ($null -eq $Value) { $null } else { $Value.PSObject.BaseObject }
    if ($null -eq $valueObject) {
        return
    }

    if ($valueObject -is [byte[]]) {
        if ($FlattenByteArray) {
            foreach ($byteValue in $valueObject) {
                $Items.Add([byte]$byteValue)
            }
        }
        else {
            $Items.Add($valueObject)
        }
        return
    }

    if ($valueObject -is [System.Collections.IEnumerable] -and -not ($valueObject -is [string])) {
        foreach ($item in $valueObject) {
            Add-AdAttributeItem -Value $item -Items $Items -FlattenByteArray $FlattenByteArray
        }
        return
    }

    $Items.Add($valueObject)
}

function ConvertTo-StringArray {
    param([AllowNull()]$Value)

    $items = New-Object 'System.Collections.Generic.List[object]'
    Add-AdAttributeItem -Value $Value -Items $items -FlattenByteArray $false

    $values = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in $items.ToArray()) {
        if ($null -ne $item) {
            $values.Add([string]$item)
        }
    }
    return $values.ToArray()
}

function ConvertTo-AdAttributeValue {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)][string]$AttributeName,
        [Parameter(Mandatory = $true)][bool]$SingleValued,
        [Parameter(Mandatory = $true)][bool]$OctetString
    )

    $items = New-Object 'System.Collections.Generic.List[object]'
    Add-AdAttributeItem -Value $Value -Items $items -FlattenByteArray ($SingleValued -and $OctetString)

    $result = [pscustomobject]@{
        HasValue = $false
        Value    = $null
    }
    if ($items.Count -eq 0) { return $result }
    if ($SingleValued -and $OctetString) {
        $bytes = New-Object 'System.Collections.Generic.List[byte]'
        foreach ($item in $items.ToArray()) {
            $itemObject = if ($null -eq $item) { $null } else { $item.PSObject.BaseObject }
            if ($null -eq $itemObject) {
                continue
            }
            if ($itemObject -is [byte]) {
                $bytes.Add([byte]$itemObject)
                continue
            }
            if ($itemObject -is [int] -and $itemObject -ge 0 -and $itemObject -le 255) {
                $bytes.Add([byte]$itemObject)
                continue
            }
            throw "Source template attribute '$AttributeName' is an octet string but returned non-byte value '$itemObject'."
        }
        if ($bytes.Count -eq 0) { return $result }
        $result.HasValue = $true
        $result.Value = [byte[]]$bytes.ToArray()
        return $result
    }

    if ($SingleValued) {
        if ($items.Count -gt 1) {
            throw "Source template attribute '$AttributeName' is single-valued but returned $($items.Count) values."
        }
        $singleValue = $items[0]
        $result.HasValue = $true
        $result.Value = $singleValue
        return $result
    }

    $result.HasValue = $true
    $result.Value = $items.ToArray()
    return $result
}

function ConvertTo-SortedUniqueStringArray {
    param([AllowNull()][string[]]$Value)

    $values = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in @($Value | Sort-Object -Unique)) {
        $itemObject = if ($null -eq $item) { $null } else { $item.PSObject.BaseObject }
        if ($null -ne $itemObject) {
            $values.Add([string]$itemObject)
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

function Test-StringSetEqual {
    param(
        [AllowNull()]$Actual,
        [string[]]$Expected
    )

    $actualValues = @(ConvertTo-StringArray -Value $Actual | Sort-Object)
    $expectedValues = @($Expected | ForEach-Object { [string]$_ } | Sort-Object)
    return (@(Compare-Object -ReferenceObject $expectedValues -DifferenceObject $actualValues).Count -eq 0)
}

function Get-LabAdcsPaths {
    $rootDse = Get-ADRootDSE @AdServerParameters
    $configNc = [string]$rootDse.configurationNamingContext
    return [pscustomobject]@{
        ConfigurationNamingContext = $configNc
        SchemaNamingContext        = [string]$rootDse.schemaNamingContext
        TemplateContainer          = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNc"
        OidContainer               = "CN=OID,CN=Public Key Services,CN=Services,$configNc"
        EnrollmentServices         = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNc"
    }
}

function Get-AdAttributeSchema {
    param(
        [Parameter(Mandatory = $true)]$Paths,
        [Parameter(Mandatory = $true)][string[]]$AttributeName
    )

    $result = @{}
    foreach ($name in @($AttributeName)) {
        $escapedName = ConvertTo-LdapFilterValue -Value $name
        $schemaObjects = @(Get-ADObject -SearchBase $Paths.SchemaNamingContext -SearchScope OneLevel -LDAPFilter "(&(objectClass=attributeSchema)(lDAPDisplayName=$escapedName))" -Properties lDAPDisplayName, isSingleValued, attributeSyntax, oMSyntax @AdServerParameters)
        if ($schemaObjects.Count -ne 1) {
            throw "Expected one schema attribute named '$name', found $($schemaObjects.Count)."
        }
        $result[$name] = [pscustomobject]@{
            IsSingleValued  = [bool]$schemaObjects[0].isSingleValued
            IsOctetString   = ([string]$schemaObjects[0].attributeSyntax -eq '2.5.5.10')
            AttributeSyntax = [string]$schemaObjects[0].attributeSyntax
            OMSyntax        = [int]$schemaObjects[0].oMSyntax
        }
    }
    return $result
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
        'msPKI-Certificate-Policy',
        'msPKI-Cert-Template-OID',
        'msPKI-Enrollment-Flag',
        'msPKI-Minimal-Key-Size',
        'msPKI-Private-Key-Flag',
        'msPKI-RA-Application-Policies',
        'msPKI-RA-Policies',
        'msPKI-RA-Signature',
        'msPKI-Supersede-Templates',
        'msPKI-Template-Minor-Revision',
        'msPKI-Template-Schema-Version',
        'pKICriticalExtensions',
        'pKIDefaultCSPs',
        'pKIDefaultKeySpec',
        'pKIExpirationPeriod',
        'pKIExtendedKeyUsage',
        'pKIKeyUsage',
        'pKIMaxIssuingDepth',
        'pKIOverlapPeriod',
        'revision'
    )
    try {
        return Get-ADObject -Identity "CN=$TemplateName,$($Paths.TemplateContainer)" -Properties $properties @AdServerParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

function New-LabTemplateOid {
    param(
        [Parameter(Mandatory = $true)]$Paths,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [Parameter(Mandatory = $true)][string]$Marker
    )

    $escapedMarker = ConvertTo-LdapFilterValue -Value $Marker
    $oidProperties = @('msPKI-Cert-Template-OID', 'adminDescription', 'displayName')
    $existing = @(Get-ADObject -SearchBase $Paths.OidContainer -SearchScope OneLevel -LDAPFilter "(&(objectClass=msPKI-Enterprise-Oid)(adminDescription=$escapedMarker))" -Properties $oidProperties @AdServerParameters)
    if ($existing.Count -eq 1) {
        $existingTemplateOid = ConvertTo-SingleStringOrNull -Value $existing[0].'msPKI-Cert-Template-OID' -AttributeName 'msPKI-Cert-Template-OID'
        if (Test-OidString -Value $existingTemplateOid) {
            return [pscustomobject]@{
                Name        = [string]$existing[0].Name
                TemplateOid = $existingTemplateOid
                Existing    = $true
            }
        }

        if ($PSCmdlet.ShouldProcess($existing[0].DistinguishedName, "Delete invalid lab OID object with msPKI-Cert-Template-OID='$existingTemplateOid'")) {
            Remove-ADObject -Identity $existing[0].DistinguishedName -Confirm:$false @AdServerParameters -ErrorAction Stop
            $existing = @()
        }
        else {
            throw "Lab OID object '$($existing[0].DistinguishedName)' has invalid msPKI-Cert-Template-OID '$existingTemplateOid'."
        }
    }
    if ($existing.Count -gt 1) {
        throw "Multiple lab OID objects were found with marker '$Marker'. Run cleanup.ps1 and retry."
    }

    $forestBaseOidObject = Get-ADObject -Identity $Paths.OidContainer -Properties 'msPKI-Cert-Template-OID' @AdServerParameters
    $forestBaseOid = ConvertTo-SingleStringOrNull -Value $forestBaseOidObject.'msPKI-Cert-Template-OID' -AttributeName 'msPKI-Cert-Template-OID'
    if ([string]::IsNullOrWhiteSpace($forestBaseOid)) {
        throw "The forest OID container '$($Paths.OidContainer)' does not have msPKI-Cert-Template-OID."
    }
    if (-not (Test-OidString -Value $forestBaseOid)) {
        throw "The forest OID container '$($Paths.OidContainer)' has invalid msPKI-Cert-Template-OID '$forestBaseOid'."
    }

    do {
        $oidPart1 = Get-Random -Minimum 1000000 -Maximum 99999999
        $oidPart2 = Get-Random -Minimum 10000000 -Maximum 99999999
        $name = "$oidPart2.$(Get-RandomHex -Length 32)"
        $templateOid = "$forestBaseOid.$oidPart1.$oidPart2"
        if (-not (Test-OidString -Value $templateOid)) {
            throw "Generated invalid template OID '$templateOid'."
        }
        $escapedName = ConvertTo-LdapFilterValue -Value $name
        $escapedOid = ConvertTo-LdapFilterValue -Value $templateOid
        $collision = @(Get-ADObject -SearchBase $Paths.OidContainer -SearchScope OneLevel -LDAPFilter "(|(cn=$escapedName)(msPKI-Cert-Template-OID=$escapedOid))" @AdServerParameters)
    } while ($collision.Count -gt 0)

    return [pscustomobject]@{
        Name        = $name
        TemplateOid = $templateOid
        Existing    = $false
    }
}

function New-LabCertificateTemplate {
    param(
        [Parameter(Mandatory = $true)]$Paths,
        [Parameter(Mandatory = $true)]$SourceTemplate,
        [Parameter(Mandatory = $true)]$Specification,
        [Parameter(Mandatory = $true)][string]$TemplateOid
    )

    $TemplateName = [string]$Specification.Name
    $DisplayName = [string]$Specification.DisplayName

    $copyAttributes = @(
        'flags',
        'revision',
        'msPKI-Certificate-Policy',
        'msPKI-Minimal-Key-Size',
        'msPKI-Private-Key-Flag',
        'msPKI-Supersede-Templates',
        'msPKI-Template-Schema-Version',
        'pKICriticalExtensions',
        'pKIDefaultCSPs',
        'pKIDefaultKeySpec',
        'pKIExpirationPeriod',
        'pKIKeyUsage',
        'pKIMaxIssuingDepth',
        'pKIOverlapPeriod'
    )
    $attributes = @{}
    $attributeSchema = Get-AdAttributeSchema -Paths $Paths -AttributeName $copyAttributes
    foreach ($attributeName in $copyAttributes) {
        $schema = $attributeSchema[$attributeName]
        $converted = ConvertTo-AdAttributeValue -Value (, $SourceTemplate.$attributeName) -AttributeName $attributeName -SingleValued ([bool]$schema.IsSingleValued) -OctetString ([bool]$schema.IsOctetString)
        if ([bool]$converted.HasValue) {
            $attributes[$attributeName] = $converted.Value
        }
    }

    $sourceFlags = if ($null -eq $SourceTemplate.flags) { 0 } else { [int]($SourceTemplate.flags) }
    $sourceNameFlags = if ($null -eq $SourceTemplate.'msPKI-Certificate-Name-Flag') { 0 } else { [int]($SourceTemplate.'msPKI-Certificate-Name-Flag') }
    $sourceEnrollmentFlags = if ($null -eq $SourceTemplate.'msPKI-Enrollment-Flag') { 0 } else { [int]($SourceTemplate.'msPKI-Enrollment-Flag') }
    $ekus = [string[]]@($Specification.EkuOids)
    $applicationPolicies = [string[]]@($Specification.ApplicationPolicyOids)

    $attributes['displayName'] = $DisplayName
    $attributes['description'] = [string]$Specification.Description
    $attributes['adminDescription'] = [string]$Specification.Marker
    $attributes['flags'] = (($sourceFlags -bor $script:IsModifiedTemplate) -band (-bnot $script:IsDefaultTemplate))
    $attributes['msPKI-Cert-Template-OID'] = $TemplateOid
    $attributes['msPKI-Certificate-Name-Flag'] = ($sourceNameFlags -band (-bnot $script:EnrolleeSuppliesSubject))
    $attributes['msPKI-Enrollment-Flag'] = ($sourceEnrollmentFlags -band (-bnot $script:PendAllRequests))
    if (-not $attributes.ContainsKey('msPKI-Minimal-Key-Size')) {
        $attributes['msPKI-Minimal-Key-Size'] = 2048
    }
    $attributes['msPKI-RA-Signature'] = [int]$Specification.RaSignature
    $attributes['msPKI-Template-Minor-Revision'] = 1
    $attributes['msPKI-Template-Schema-Version'] = 2
    $attributes['pKIExtendedKeyUsage'] = [string[]](ConvertTo-SortedUniqueStringArray -Value $ekus)
    $attributes['msPKI-Certificate-Application-Policy'] = [string[]](ConvertTo-SortedUniqueStringArray -Value $applicationPolicies)
    $raApplicationPolicies = [string[]]@($Specification.RaApplicationPolicyOids)
    if ($raApplicationPolicies.Count -gt 0) {
        $attributes['msPKI-RA-Application-Policies'] = [string[]](ConvertTo-SortedUniqueStringArray -Value $raApplicationPolicies)
    }

    if ($PSCmdlet.ShouldProcess($TemplateName, "Create certificate template from $SourceTemplateName")) {
        try {
            New-ADObject -Name $TemplateName -Type 'pKICertificateTemplate' -Path $Paths.TemplateContainer -OtherAttributes $attributes @AdServerParameters -ErrorAction Stop | Out-Null
        }
        catch {
            $attributeSummary = (@($attributes.Keys | Sort-Object | ForEach-Object {
                $attributeValue = $attributes[$_]
                $typeName = if ($null -eq $attributeValue) { '<null>' } else { $attributeValue.GetType().FullName }
                "$_=$typeName"
            }) -join '; ')
            throw "Create certificate template '$TemplateName' failed in '$($Paths.TemplateContainer)' with TemplateOid='$TemplateOid'. Attributes: $attributeSummary. Error: $($_.Exception.Message)"
        }
        return $true
    }
    return $false
}

function Ensure-LabTemplateSettings {
    param(
        [Parameter(Mandatory = $true)]$Template,
        [Parameter(Mandatory = $true)]$Specification
    )

    $DisplayName = [string]$Specification.DisplayName
    $currentNameFlags = if ($null -eq $Template.'msPKI-Certificate-Name-Flag') { 0 } else { [int]($Template.'msPKI-Certificate-Name-Flag') }
    $currentEnrollmentFlags = if ($null -eq $Template.'msPKI-Enrollment-Flag') { 0 } else { [int]($Template.'msPKI-Enrollment-Flag') }
    $currentRaSignature = if ($null -eq $Template.'msPKI-RA-Signature') { -1 } else { [int]($Template.'msPKI-RA-Signature') }
    $ekus = [string[]]@($Specification.EkuOids)
    $applicationPolicies = [string[]]@($Specification.ApplicationPolicyOids)
    $raApplicationPolicies = [string[]]@($Specification.RaApplicationPolicyOids)
    $desiredNameFlags = $currentNameFlags -band (-bnot $script:EnrolleeSuppliesSubject)
    $desiredEnrollmentFlags = $currentEnrollmentFlags -band (-bnot $script:PendAllRequests)
    $replace = @{}
    $clear = New-Object 'System.Collections.Generic.List[string]'
    if ([string]$Template.displayName -cne $DisplayName) { $replace['displayName'] = $DisplayName }
    if ([string]$Template.adminDescription -cne [string]$Specification.Marker) { $replace['adminDescription'] = [string]$Specification.Marker }
    if ($currentNameFlags -ne $desiredNameFlags) { $replace['msPKI-Certificate-Name-Flag'] = $desiredNameFlags }
    if ($currentEnrollmentFlags -ne $desiredEnrollmentFlags) { $replace['msPKI-Enrollment-Flag'] = $desiredEnrollmentFlags }
    if ($null -eq $Template.'msPKI-Minimal-Key-Size') { $replace['msPKI-Minimal-Key-Size'] = 2048 }
    if ($currentRaSignature -ne [int]$Specification.RaSignature) { $replace['msPKI-RA-Signature'] = [int]$Specification.RaSignature }
    if ($null -eq $Template.'msPKI-Template-Schema-Version' -or [int]($Template.'msPKI-Template-Schema-Version') -lt 2) { $replace['msPKI-Template-Schema-Version'] = 2 }
    if (-not (Test-StringSetEqual -Actual $Template.pKIExtendedKeyUsage -Expected $ekus)) { $replace['pKIExtendedKeyUsage'] = [string[]](ConvertTo-SortedUniqueStringArray -Value $ekus) }
    if (-not (Test-StringSetEqual -Actual $Template.'msPKI-Certificate-Application-Policy' -Expected $applicationPolicies)) { $replace['msPKI-Certificate-Application-Policy'] = [string[]](ConvertTo-SortedUniqueStringArray -Value $applicationPolicies) }
    if ($raApplicationPolicies.Count -gt 0) {
        if (-not (Test-StringSetEqual -Actual $Template.'msPKI-RA-Application-Policies' -Expected $raApplicationPolicies)) {
            $replace['msPKI-RA-Application-Policies'] = [string[]](ConvertTo-SortedUniqueStringArray -Value $raApplicationPolicies)
        }
    }
    elseif (@(ConvertTo-StringArray -Value $Template.'msPKI-RA-Application-Policies').Count -gt 0) {
        $clear.Add('msPKI-RA-Application-Policies')
    }

    $hasUpdate = ($replace.Count -gt 0 -or $clear.Count -gt 0)
    if ($hasUpdate -and $PSCmdlet.ShouldProcess($Template.DistinguishedName, [string]$Specification.SettingsAction)) {
        try {
            $setParameters = @{
                Identity    = $Template.DistinguishedName
                ErrorAction = 'Stop'
            }
            if ($replace.Count -gt 0) {
                $setParameters['Replace'] = $replace
            }
            if ($clear.Count -gt 0) {
                $setParameters['Clear'] = [string[]]$clear.ToArray()
            }
            Set-ADObject @setParameters @AdServerParameters
        }
        catch {
            throw "$($Specification.SettingsAction) failed for '$($Template.DistinguishedName)'. ReplaceKeys=$((@($replace.Keys | Sort-Object) -join ',')); ClearKeys=$((@($clear.ToArray()) -join ',')). Error: $($_.Exception.Message)"
        }
        return $true
    }
    return $false
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

    try {
        New-PSDrive @driveParameters | Out-Null
    }
    catch {
        throw "Create ActiveDirectory PSDrive 'AD' failed. Error: $($_.Exception.Message)"
    }
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

function Ensure-TemplateEnrollRight {
    param(
        [Parameter(Mandatory = $true)][string]$TemplateDistinguishedName,
        [Parameter(Mandatory = $true)][string]$TemplateName,
        [Parameter(Mandatory = $true)][string]$Principal
    )

    $qualifiedPrincipal = Get-QualifiedPrincipalName -Principal $Principal
    $sid = (New-Object Security.Principal.NTAccount($qualifiedPrincipal)).Translate([Security.Principal.SecurityIdentifier])
    Ensure-AdDrive
    $path = "AD:\$TemplateDistinguishedName"
    try {
        $acl = Get-Acl -Path $path -ErrorAction Stop
    }
    catch {
        throw "Read certificate template ACL failed for path '$path'. Error: $($_.Exception.Message)"
    }
    foreach ($accessRule in @($acl.Access)) {
        if (Test-TemplateEnrollAccessRule -AccessRule $accessRule -Sid $sid) {
            return $false
        }
    }

    $rule = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @(
        $sid,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $script:EnrollExtendedRight,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    )
    $acl.AddAccessRule($rule)
    if ($PSCmdlet.ShouldProcess($TemplateName, "Grant Enroll to $qualifiedPrincipal")) {
        try {
            Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
        }
        catch {
            throw "Grant Enroll to '$qualifiedPrincipal' failed for certificate template ACL path '$path'. Error: $($_.Exception.Message)"
        }
        return $true
    }
    return $false
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
        throw "Expected one CA enrollment service named '$Name', found $($caObjects.Count)."
    }
    return $caObjects[0]
}

function Ensure-CaPublishesTemplate {
    param(
        [Parameter(Mandatory = $true)]$Ca,
        [Parameter(Mandatory = $true)][string]$TemplateName
    )

    if (@($Ca.certificateTemplates) -icontains $TemplateName) {
        return $false
    }

    $addCommand = Get-Command -Name Add-CATemplate -Module ADCSAdministration -ErrorAction SilentlyContinue
    if ($null -ne $addCommand) {
        if ($PSCmdlet.ShouldProcess($Ca.Name, "Publish certificate template $TemplateName")) {
            try {
                & $addCommand -Name $TemplateName -Force -ErrorAction Stop | Out-Null
                return $true
            }
            catch {
                Write-Warning "Add-CATemplate failed; falling back to the CA object's certificateTemplates attribute. Error: $($_.Exception.Message)"
            }
        }
        else {
            return $false
        }
    }

    if ($PSCmdlet.ShouldProcess($Ca.DistinguishedName, "Add certificateTemplates=$TemplateName")) {
        try {
            Set-ADObject -Identity $Ca.DistinguishedName -Add @{ certificateTemplates = $TemplateName } @AdServerParameters -ErrorAction Stop
        }
        catch {
            throw "Add certificate template '$TemplateName' to CA enrollment service '$($Ca.DistinguishedName)' failed. Error: $($_.Exception.Message)"
        }
        $certSvc = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
        if ($null -ne $certSvc -and $certSvc.Status -eq 'Running' -and $PSCmdlet.ShouldProcess('CertSvc', 'Restart after direct CA publication update')) {
            Restart-Service -Name CertSvc -Force -ErrorAction Stop
        }
        return $true
    }
    return $false
}

$paths = Get-LabAdcsPaths
$changed = $false
$templateResults = New-Object 'System.Collections.Generic.List[object]'

try {
    Assert-TemplateShortName -Name $AgentTemplateName -ParameterName 'AgentTemplateName'
    Assert-TemplateShortName -Name $OnBehalfTemplateName -ParameterName 'OnBehalfTemplateName'
    Assert-TemplateShortName -Name $SourceTemplateName -ParameterName 'SourceTemplateName'
    if ($AgentTemplateName -ieq $OnBehalfTemplateName) {
        throw 'AgentTemplateName and OnBehalfTemplateName must be different.'
    }

    $sourceTemplate = Get-CertificateTemplateOrNull -TemplateName $SourceTemplateName -Paths $paths
    if ($null -eq $sourceTemplate) {
        throw "Source certificate template '$SourceTemplateName' was not found."
    }

    $caName = Get-ActiveCaName -RequestedName $CACommonName
    $ca = Get-CaEnrollmentService -Paths $paths -Name $caName
    $qualifiedPrincipal = Get-QualifiedPrincipalName -Principal $EnrollmentPrincipal

    foreach ($specification in @($script:TemplateSpecs)) {
        $templateName = [string]$specification.Name
        $template = Get-CertificateTemplateOrNull -TemplateName $templateName -Paths $paths
        if ($null -ne $template -and [string]$template.adminDescription -cne [string]$specification.Marker) {
            throw "Certificate template '$templateName' already exists but is not marked as this lab scenario. Cleanup is blocked to avoid changing unrelated templates."
        }

        if ($null -eq $template) {
            $oid = New-LabTemplateOid -Paths $paths -DisplayName ([string]$specification.DisplayName) -Marker ([string]$specification.Marker)
            if (-not [bool]$oid.Existing -and $PSCmdlet.ShouldProcess($oid.Name, "Create enterprise OID for $templateName")) {
                try {
                    New-ADObject -Name $oid.Name -Type 'msPKI-Enterprise-Oid' -Path $paths.OidContainer -OtherAttributes @{
                        displayName               = [string]$specification.DisplayName
                        adminDescription          = [string]$specification.Marker
                        flags                     = 1
                        'msPKI-Cert-Template-OID' = $oid.TemplateOid
                    } @AdServerParameters -ErrorAction Stop | Out-Null
                }
                catch {
                    throw "Create enterprise OID object '$($oid.Name)' failed in '$($paths.OidContainer)' with TemplateOid='$($oid.TemplateOid)'. Error: $($_.Exception.Message)"
                }
                $changed = $true
            }
            if (New-LabCertificateTemplate -Paths $paths -SourceTemplate $sourceTemplate -Specification $specification -TemplateOid $oid.TemplateOid) {
                $changed = $true
            }
            $template = Get-CertificateTemplateOrNull -TemplateName $templateName -Paths $paths
        }

        if ($null -eq $template) {
            if ($WhatIfPreference) {
                [pscustomobject]@{
                    Status              = 'WhatIf'
                    Changed             = $false
                    AgentTemplateName   = $AgentTemplateName
                    OnBehalfTemplateName = $OnBehalfTemplateName
                    SourceTemplateName  = $SourceTemplateName
                    EnrollmentPrincipal = $qualifiedPrincipal
                    CACommonName        = $caName
                }
                return
            }
            throw "Certificate template '$templateName' was not created."
        }

        if (Ensure-LabTemplateSettings -Template $template -Specification $specification) {
            $changed = $true
            $template = Get-CertificateTemplateOrNull -TemplateName $templateName -Paths $paths
        }

        if (Ensure-TemplateEnrollRight -TemplateDistinguishedName ([string]$template.DistinguishedName) -TemplateName $templateName -Principal $EnrollmentPrincipal) {
            $changed = $true
        }

        if (Ensure-CaPublishesTemplate -Ca $ca -TemplateName $templateName) {
            $changed = $true
            $ca = Get-CaEnrollmentService -Paths $paths -Name $caName
        }

        $templateResults.Add([pscustomobject]@{
                TemplateName        = $templateName
                TemplateDisplayName = [string]$specification.DisplayName
                Marker              = [string]$specification.Marker
                DistinguishedName   = [string]$template.DistinguishedName
            })
    }

    [pscustomobject]@{
        Status               = 'Succeeded'
        Changed              = $changed
        AgentTemplateName    = $AgentTemplateName
        OnBehalfTemplateName = $OnBehalfTemplateName
        SourceTemplateName   = $SourceTemplateName
        EnrollmentPrincipal  = $qualifiedPrincipal
        CACommonName         = $caName
        Templates            = $templateResults.ToArray()
    }
}
catch {
    throw
}
