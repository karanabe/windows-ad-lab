#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$AgentTemplateName = 'ESC3LabAgent',
    [string]$OnBehalfTemplateName = 'ESC3LabOnBehalf',
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

    if ($PSCmdlet.ShouldProcess($TemplateName, 'Remove template from local CA publication list')) {
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
        [Parameter(Mandatory = $true)][string]$Marker,
        [string]$TemplateOid,
        [switch]$TemplateWasMarked
    )

    $escapedMarker = ConvertTo-LdapFilterValue -Value $Marker
    $properties = @('adminDescription', 'msPKI-Cert-Template-OID')
    if (-not [string]::IsNullOrWhiteSpace($TemplateOid) -and $TemplateWasMarked) {
        $escapedOid = ConvertTo-LdapFilterValue -Value $TemplateOid
        return @(Get-ADObject -SearchBase $Paths.OidContainer -SearchScope OneLevel -LDAPFilter "(&(objectClass=msPKI-Enterprise-Oid)(|(adminDescription=$escapedMarker)(msPKI-Cert-Template-OID=$escapedOid)))" -Properties $properties @AdServerParameters)
    }
    return @(Get-ADObject -SearchBase $Paths.OidContainer -SearchScope OneLevel -LDAPFilter "(&(objectClass=msPKI-Enterprise-Oid)(adminDescription=$escapedMarker))" -Properties $properties @AdServerParameters)
}

function Remove-LabTemplateFixture {
    param(
        [Parameter(Mandatory = $true)]$Paths,
        [Parameter(Mandatory = $true)][string]$TemplateName,
        [Parameter(Mandatory = $true)][string]$Marker
    )

    $template = Get-CertificateTemplateOrNull -TemplateName $TemplateName -Paths $Paths
    $templateWasMarked = ($null -ne $template -and [string]$template.adminDescription -ceq $Marker)
    if ($null -ne $template -and -not $templateWasMarked) {
        throw "Certificate template '$TemplateName' exists but is not marked as this lab scenario. Refusing to delete it."
    }

    $localCaRemoved = Remove-TemplateFromLocalCa -TemplateName $TemplateName
    $enrollmentServiceRemovals = Remove-TemplateFromEnrollmentServices -Paths $Paths -TemplateName $TemplateName
    $templateOid = if ($null -eq $template) { $null } else { [string]$template.'msPKI-Cert-Template-OID' }
    $templateRemoved = $false
    if ($null -ne $template) {
        if ($PSCmdlet.ShouldProcess($template.DistinguishedName, 'Delete lab certificate template')) {
            Remove-ADObject -Identity $template.DistinguishedName -Confirm:$false @AdServerParameters -ErrorAction Stop
            $templateRemoved = $true
        }
    }

    $oidObjects = Get-LabOidObjects -Paths $Paths -Marker $Marker -TemplateOid $templateOid -TemplateWasMarked:$templateWasMarked
    $oidRemovals = 0
    foreach ($oidObject in $oidObjects) {
        if ([string]$oidObject.adminDescription -ceq $Marker -or $templateWasMarked) {
            if ($PSCmdlet.ShouldProcess($oidObject.DistinguishedName, 'Delete lab template OID object')) {
                Remove-ADObject -Identity $oidObject.DistinguishedName -Confirm:$false @AdServerParameters -ErrorAction Stop
                $oidRemovals++
            }
        }
    }

    return [pscustomobject]@{
        TemplateName              = $TemplateName
        LocalCaPublicationRemoved = $localCaRemoved
        EnrollmentServiceRemovals = $enrollmentServiceRemovals
        TemplateFound             = ($null -ne $template)
        TemplateRemoved           = $templateRemoved
        OidObjectRemovals         = $oidRemovals
        Changed                   = ($localCaRemoved -or $enrollmentServiceRemovals -gt 0 -or $templateRemoved -or $oidRemovals -gt 0)
    }
}

Assert-TemplateShortName -Name $AgentTemplateName -ParameterName 'AgentTemplateName'
Assert-TemplateShortName -Name $OnBehalfTemplateName -ParameterName 'OnBehalfTemplateName'
$paths = Get-LabAdcsPaths
$agentResult = Remove-LabTemplateFixture -Paths $paths -TemplateName $AgentTemplateName -Marker $script:AgentMarker
$onBehalfResult = Remove-LabTemplateFixture -Paths $paths -TemplateName $OnBehalfTemplateName -Marker $script:OnBehalfMarker
$changed = ([bool]$agentResult.Changed -or [bool]$onBehalfResult.Changed)
if ($changed) {
    $certSvc = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
    if ($null -ne $certSvc -and $certSvc.Status -eq 'Running' -and (($agentResult.EnrollmentServiceRemovals -gt 0) -or ($onBehalfResult.EnrollmentServiceRemovals -gt 0)) -and $PSCmdlet.ShouldProcess('CertSvc', 'Restart after direct CA publication update')) {
        Restart-Service -Name CertSvc -Force -ErrorAction Stop
    }
}

[pscustomobject]@{
    Status  = 'Succeeded'
    Changed = $changed
    Agent   = $agentResult
    OnBehalf = $onBehalfResult
}
