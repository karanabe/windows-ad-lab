#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$TemplateName = 'ESC13LabAma',
    [string]$GroupName = 'UG_ESC13_AMA',
    [string]$ResourceComputer = 'CLIENT01',
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:TemplateMarker = 'windows-ad-lab:ESC13-IssuancePolicy'
$script:IssuancePolicyMarker = 'windows-ad-lab:ESC13-IssuancePolicy-Oid'
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

function Remove-ResourceComputerGenericWrite {
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][string]$GroupName
    )

    $computer = $null
    try {
        $computer = Get-ADComputer -Identity $ComputerName @AdServerParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return 0
    }

    $sid = $null
    try {
        $domain = Get-ADDomain @AdServerParameters
        $qualified = if ($GroupName -match '\\') { $GroupName } else { "$($domain.NetBIOSName)\$GroupName" }
        $sid = (New-Object Security.Principal.NTAccount($qualified)).Translate([Security.Principal.SecurityIdentifier])
    }
    catch {
        return 0
    }

    Ensure-AdDrive
    $path = "AD:\$($computer.DistinguishedName)"
    $acl = Get-Acl -Path $path -ErrorAction Stop
    $removed = 0
    $rulesToRemove = New-Object 'System.Collections.Generic.List[object]'
    foreach ($rule in @($acl.Access)) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if ($rule.IsInherited) { continue }
        try {
            $ruleSid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier])
        }
        catch { continue }
        if ([string]$ruleSid.Value -ne [string]$sid.Value) { continue }
        $isWrite = (($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)
        $isAll = (($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)
        if ($isWrite -or $isAll) {
            [void]$rulesToRemove.Add($rule)
        }
    }
    if ($rulesToRemove.Count -gt 0 -and $PSCmdlet.ShouldProcess($computer.DistinguishedName, "Remove GenericWrite ACEs for $GroupName")) {
        foreach ($rule in $rulesToRemove.ToArray()) {
            [void]$acl.RemoveAccessRuleSpecific($rule)
            $removed++
        }
        Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
    }
    return $removed
}

Assert-TemplateShortName -Name $TemplateName -ParameterName 'TemplateName'
$paths = Get-LabAdcsPaths
$template = Get-CertificateTemplateOrNull -TemplateName $TemplateName -Paths $paths
$templateWasMarked = ($null -ne $template -and [string]$template.adminDescription -ceq $script:TemplateMarker)

if ($null -ne $template -and -not $templateWasMarked) {
    throw "Certificate template '$TemplateName' exists but is not marked as this lab scenario. Refusing to delete it."
}

$changed = $false
$localCaRemoved = Remove-TemplateFromLocalCa -TemplateName $TemplateName
if ($localCaRemoved) { $changed = $true }

$enrollmentServiceRemovals = Remove-TemplateFromEnrollmentServices -Paths $paths -TemplateName $TemplateName
if ($enrollmentServiceRemovals -gt 0) {
    $changed = $true
    $certSvc = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
    if ($null -ne $certSvc -and $certSvc.Status -eq 'Running' -and $PSCmdlet.ShouldProcess('CertSvc', 'Restart after direct CA publication update')) {
        Restart-Service -Name CertSvc -Force -ErrorAction Stop
    }
}

$templateOid = if ($null -eq $template) { $null } else { [string]$template.'msPKI-Cert-Template-OID' }
$templateRemoved = $false
if ($null -ne $template) {
    if ($PSCmdlet.ShouldProcess($template.DistinguishedName, 'Delete lab certificate template')) {
        Remove-ADObject -Identity $template.DistinguishedName -Confirm:$false @AdServerParameters -ErrorAction Stop
        $changed = $true
        $templateRemoved = $true
    }
}

$oidObjects = Get-LabOidObjects -Paths $paths -TemplateOid $templateOid -TemplateWasMarked:$templateWasMarked
$oidRemovals = 0
foreach ($oidObject in $oidObjects) {
    if ([string]$oidObject.adminDescription -ceq $script:TemplateMarker -or $templateWasMarked) {
        if ($PSCmdlet.ShouldProcess($oidObject.DistinguishedName, 'Delete lab template OID object')) {
            Remove-ADObject -Identity $oidObject.DistinguishedName -Confirm:$false @AdServerParameters -ErrorAction Stop
            $oidRemovals++
            $changed = $true
        }
    }
}

$issuanceMarker = ConvertTo-LdapFilterValue -Value $script:IssuancePolicyMarker
$issuanceOids = @(Get-ADObject -SearchBase $paths.OidContainer -SearchScope OneLevel -LDAPFilter "(&(objectClass=msPKI-Enterprise-Oid)(adminDescription=$issuanceMarker))" -Properties adminDescription @AdServerParameters)
$issuanceOidRemovals = 0
foreach ($oidObject in $issuanceOids) {
    if ($PSCmdlet.ShouldProcess($oidObject.DistinguishedName, 'Delete lab issuance-policy OID object')) {
        Remove-ADObject -Identity $oidObject.DistinguishedName -Confirm:$false @AdServerParameters -ErrorAction Stop
        $issuanceOidRemovals++
        $changed = $true
    }
}

$computerAceRemovals = Remove-ResourceComputerGenericWrite -ComputerName $ResourceComputer -GroupName $GroupName
if ($computerAceRemovals -gt 0) { $changed = $true }

$groupRemoved = $false
$group = $null
try {
    $group = Get-ADGroup -Identity $GroupName -Properties adminDescription @AdServerParameters -ErrorAction Stop
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    $group = $null
}
if ($null -ne $group) {
    if ([string]$group.adminDescription -cne $script:TemplateMarker) {
        throw "Group '$GroupName' exists but is not marked as this lab scenario. Refusing to delete it."
    }
    if ($PSCmdlet.ShouldProcess($group.DistinguishedName, 'Delete lab AMA group')) {
        Remove-ADGroup -Identity $group.DistinguishedName -Confirm:$false @AdServerParameters -ErrorAction Stop
        $groupRemoved = $true
        $changed = $true
    }
}

[pscustomobject]@{
    Status                    = 'Succeeded'
    Changed                   = $changed
    TemplateName              = $TemplateName
    LocalCaPublicationRemoved = $localCaRemoved
    EnrollmentServiceRemovals = $enrollmentServiceRemovals
    TemplateFound             = ($null -ne $template)
    TemplateRemoved           = $templateRemoved
    OidObjectRemovals         = $oidRemovals
    IssuanceOidRemovals       = $issuanceOidRemovals
    ResourceComputerAceRemovals = $computerAceRemovals
    GroupRemoved              = $groupRemoved
}
