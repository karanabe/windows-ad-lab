#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$KdcTemplateName = 'LAB-PKINIT-KDCAuthentication',
    [string]$CACommonName,
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'PKINIT-KDCCertificate'
$script:TemplateMarker = 'windows-ad-lab:PKINIT-KDCCertificate'
$script:TemplateInformationExtensionOid = '1.3.6.1.4.1.311.21.7'
$script:StateRoot = Join-Path $env:ProgramData "ADLabBootstrap\Scenarios\$script:ScenarioName"
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

function Get-LabAdcsPaths {
    $rootDse = Get-ADRootDSE @AdServerParameters
    $configNc = [string]$rootDse.configurationNamingContext
    return [pscustomobject]@{
        ConfigurationNamingContext = $configNc
        TemplateContainer          = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNc"
        OidContainer               = "CN=OID,CN=Public Key Services,CN=Services,$configNc"
        EnrollmentServices         = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNc"
    }
}

function Get-CertificateTemplateOrNull {
    param(
        [Parameter(Mandatory = $true)][string]$TemplateName,
        [Parameter(Mandatory = $true)]$Paths
    )

    $properties = @('adminDescription', 'displayName', 'msPKI-Cert-Template-OID')
    try {
        return Get-ADObject -Identity "CN=$TemplateName,$($Paths.TemplateContainer)" -Properties $properties @AdServerParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
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

function Remove-TemplateFromLocalCa {
    param([Parameter(Mandatory = $true)][string]$TemplateName)

    $removeCommand = Get-Command -Name Remove-CATemplate -Module ADCSAdministration -ErrorAction SilentlyContinue
    if ($null -eq $removeCommand) {
        return $false
    }

    $published = Test-LocalCaTemplatePublished -TemplateName $TemplateName
    if ($published -ne $true) {
        return $false
    }

    if ($PSCmdlet.ShouldProcess($TemplateName, 'Remove PKINIT KDC template from local CA publication list')) {
        & $removeCommand -Name $TemplateName -Force -ErrorAction Stop | Out-Null
        return $true
    }
    return $false
}

function Remove-TemplateFromEnrollmentServices {
    param(
        [Parameter(Mandatory = $true)]$Paths,
        [Parameter(Mandatory = $true)][string]$TemplateName
    )

    $escapedName = ConvertTo-LdapFilterValue -Value $TemplateName
    $caObjects = @(Get-ADObject -SearchBase $Paths.EnrollmentServices -SearchScope OneLevel -LDAPFilter "(certificateTemplates=$escapedName)" -Properties certificateTemplates @AdServerParameters)
    $removed = 0
    foreach ($ca in $caObjects) {
        if (@($ca.certificateTemplates) -icontains $TemplateName) {
            if ($PSCmdlet.ShouldProcess($ca.DistinguishedName, "Remove certificateTemplates=$TemplateName")) {
                Set-ADObject -Identity $ca.DistinguishedName -Remove @{ certificateTemplates = $TemplateName } @AdServerParameters -ErrorAction Stop
                $removed++
            }
        }
    }
    return $removed
}

function Get-LabOidObjects {
    param(
        [Parameter(Mandatory = $true)]$Paths,
        [string]$TemplateOid,
        [switch]$TemplateWasMarked
    )

    $marker = ConvertTo-LdapFilterValue -Value $script:TemplateMarker
    if (-not [string]::IsNullOrWhiteSpace($TemplateOid) -and $TemplateWasMarked) {
        $escapedOid = ConvertTo-LdapFilterValue -Value $TemplateOid
        $properties = @('adminDescription', 'msPKI-Cert-Template-OID')
        return @(Get-ADObject -SearchBase $Paths.OidContainer -SearchScope OneLevel -LDAPFilter "(&(objectClass=msPKI-Enterprise-Oid)(|(adminDescription=$marker)(msPKI-Cert-Template-OID=$escapedOid)))" -Properties $properties @AdServerParameters)
    }
    $properties = @('adminDescription', 'msPKI-Cert-Template-OID')
    return @(Get-ADObject -SearchBase $Paths.OidContainer -SearchScope OneLevel -LDAPFilter "(&(objectClass=msPKI-Enterprise-Oid)(adminDescription=$marker))" -Properties $properties @AdServerParameters)
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

function Read-ScenarioStateOrNull {
    $statePath = Join-Path $script:StateRoot 'state.json'
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        return $null
    }
    try {
        $state = Get-Content -LiteralPath $statePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ([string]$state.Scenario -ne $script:ScenarioName) {
            return $null
        }
        if ([string]$state.TemplateName -ne $KdcTemplateName) {
            return $null
        }
        return $state
    }
    catch {
        return $null
    }
}

function Remove-ScenarioKdcCertificates {
    param([Parameter(Mandatory = $true)][string]$TemplateOid)

    $removed = 0
    $thumbprints = New-Object 'System.Collections.Generic.List[string]'
    foreach ($certificate in @(Get-ScenarioKdcCertificates -TemplateOid $TemplateOid)) {
        $thumbprint = [string]$certificate.Thumbprint
        if ($PSCmdlet.ShouldProcess("Cert:\LocalMachine\My\$thumbprint", 'Remove scenario-issued PKINIT KDC certificate')) {
            Remove-Item -LiteralPath "Cert:\LocalMachine\My\$thumbprint" -ErrorAction Stop
            $removed++
            [void]$thumbprints.Add($thumbprint)
        }
    }
    return [pscustomobject]@{
        Removed     = $removed
        Thumbprints = [string[]]$thumbprints.ToArray()
    }
}

function Restart-KdcService {
    param([Parameter(Mandatory = $true)][string]$Reason)

    if ($PSCmdlet.ShouldProcess('KDC', "Restart Kerberos Key Distribution Center service; $Reason")) {
        Restart-Service -Name KDC -Force -ErrorAction Stop
        return $true
    }
    return $false
}

function Remove-ScenarioStateFiles {
    if (-not (Test-Path -LiteralPath $script:StateRoot -PathType Container)) {
        return 0
    }

    $removed = 0
    foreach ($item in @(Get-ChildItem -LiteralPath $script:StateRoot -Force -ErrorAction Stop)) {
        if ($PSCmdlet.ShouldProcess($item.FullName, 'Remove PKINIT scenario state or temporary file')) {
            Remove-Item -LiteralPath $item.FullName -Force -Recurse -ErrorAction Stop
            $removed++
        }
    }
    $remaining = @(Get-ChildItem -LiteralPath $script:StateRoot -Force -ErrorAction SilentlyContinue)
    if ($remaining.Count -eq 0 -and $PSCmdlet.ShouldProcess($script:StateRoot, 'Remove empty PKINIT scenario state directory')) {
        Remove-Item -LiteralPath $script:StateRoot -Force -ErrorAction Stop
    }
    return $removed
}

Assert-TemplateShortName -Name $KdcTemplateName -ParameterName 'KdcTemplateName'
$paths = Get-LabAdcsPaths
$template = Get-CertificateTemplateOrNull -TemplateName $KdcTemplateName -Paths $paths
$templateWasMarked = ($null -ne $template -and [string]$template.adminDescription -ceq $script:TemplateMarker)

if ($null -ne $template -and -not $templateWasMarked) {
    throw "Certificate template '$KdcTemplateName' exists but is not marked as this lab scenario. Refusing to delete it."
}

$changed = $false
$certificateRemovals = [pscustomobject]@{ Removed = 0; Thumbprints = @() }
$kdcRestarted = $false
$state = Read-ScenarioStateOrNull
$templateOid = if ($null -eq $template) { $null } else { ConvertTo-SingleStringOrNull -Value $template.'msPKI-Cert-Template-OID' -AttributeName 'msPKI-Cert-Template-OID' }
if (-not (Test-OidString -Value $templateOid) -and $null -ne $state -and (Test-OidString -Value ([string]$state.TemplateOid))) {
    $templateOid = [string]$state.TemplateOid
}

if ((Test-OidString -Value $templateOid) -and ($templateWasMarked -or $null -ne $state)) {
    $certificateRemovals = Remove-ScenarioKdcCertificates -TemplateOid $templateOid
    if ($certificateRemovals.Removed -gt 0) {
        $changed = $true
        $kdcRestarted = Restart-KdcService -Reason "removed $($certificateRemovals.Removed) scenario certificate(s)"
    }
}

$localCaRemoved = Remove-TemplateFromLocalCa -TemplateName $KdcTemplateName
if ($localCaRemoved) { $changed = $true }

$enrollmentServiceRemovals = Remove-TemplateFromEnrollmentServices -Paths $paths -TemplateName $KdcTemplateName
if ($enrollmentServiceRemovals -gt 0) {
    $changed = $true
    $certSvc = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
    if ($null -ne $certSvc -and $certSvc.Status -eq 'Running' -and $PSCmdlet.ShouldProcess('CertSvc', 'Restart after direct CA publication update')) {
        Restart-Service -Name CertSvc -Force -ErrorAction Stop
    }
}

$templateRemoved = $false
if ($null -ne $template) {
    if ($PSCmdlet.ShouldProcess($template.DistinguishedName, 'Delete lab PKINIT KDC certificate template')) {
        Remove-ADObject -Identity $template.DistinguishedName -Confirm:$false @AdServerParameters -ErrorAction Stop
        $changed = $true
        $templateRemoved = $true
    }
}

$oidObjects = Get-LabOidObjects -Paths $paths -TemplateOid $templateOid -TemplateWasMarked:$templateWasMarked
$oidRemovals = 0
foreach ($oidObject in $oidObjects) {
    if ([string]$oidObject.adminDescription -ceq $script:TemplateMarker -or $templateWasMarked) {
        if ($PSCmdlet.ShouldProcess($oidObject.DistinguishedName, 'Delete lab PKINIT template OID object')) {
            Remove-ADObject -Identity $oidObject.DistinguishedName -Confirm:$false @AdServerParameters -ErrorAction Stop
            $oidRemovals++
            $changed = $true
        }
    }
}

$stateFileRemovals = Remove-ScenarioStateFiles
if ($stateFileRemovals -gt 0) {
    $changed = $true
}

[pscustomobject]@{
    Status                    = 'Succeeded'
    Changed                   = $changed
    KdcTemplateName           = $KdcTemplateName
    CACommonName              = $(if ([string]::IsNullOrWhiteSpace($CACommonName)) { $null } else { $CACommonName })
    TemplateOid               = $templateOid
    CertificatesRemoved       = [int]$certificateRemovals.Removed
    CertificateThumbprints    = [string[]]$certificateRemovals.Thumbprints
    KdcRestarted              = $kdcRestarted
    LocalCaPublicationRemoved = $localCaRemoved
    EnrollmentServiceRemovals = $enrollmentServiceRemovals
    TemplateFound             = ($null -ne $template)
    TemplateRemoved           = $templateRemoved
    OidObjectRemovals         = $oidRemovals
    StateFileRemovals         = $stateFileRemovals
}
