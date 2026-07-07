#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ControlPrincipal = 'operator01',
    [string]$CACommonName,
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CaAccessManageCa = 0x00000001
# This scenario grants Manage CA only. It does not enable EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6).
$AdServerParameters = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $AdServerParameters['Server'] = $Server
}

Import-Module ActiveDirectory -ErrorAction Stop

function Assert-SamAccountName {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($Value -notmatch '^[A-Za-z0-9._-]{1,20}$') {
        throw "$Name must be a valid 1-20 character sAMAccountName: '$Value'"
    }
}

function ConvertTo-LdapFilterValue {
    param([Parameter(Mandatory = $true)][string]$Value)

    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace(([string][char]0), '\00')
}

function Get-QualifiedPrincipalName {
    param([Parameter(Mandatory = $true)][string]$Principal)

    if ($Principal -match '\\') { return $Principal }
    $domain = Get-ADDomain @AdServerParameters
    return "$($domain.NetBIOSName)\$Principal"
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

function Get-CaRegistryPath {
    param([Parameter(Mandatory = $true)][string]$CaName)

    return "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName"
}

function Get-CaSecurityBytes {
    param([Parameter(Mandatory = $true)][string]$RegistryPath)

    $security = (Get-ItemProperty -Path $RegistryPath -Name Security -ErrorAction Stop).Security
    if ($null -eq $security) {
        throw "CA registry path '$RegistryPath' does not contain a Security value."
    }
    $valueObject = $security.PSObject.BaseObject
    if ($valueObject -is [byte[]]) {
        return [byte[]]$valueObject
    }
    throw "CA Security value at '$RegistryPath' is not a binary security descriptor."
}

function ConvertTo-CaSecurityDescriptor {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return New-Object System.Security.AccessControl.CommonSecurityDescriptor $false, $false, $Bytes, 0
}

function ConvertFrom-CaSecurityDescriptor {
    param([Parameter(Mandatory = $true)]$Descriptor)

    $bytes = New-Object byte[] $Descriptor.BinaryLength
    $Descriptor.GetBinaryForm($bytes, 0)
    return [byte[]]$bytes
}

function Test-CaManageCaAce {
    param(
        [Parameter(Mandatory = $true)]$Ace,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$Sid
    )

    if ($Ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowed) { return $false }
    if ([string]$Ace.SecurityIdentifier.Value -ne [string]$Sid.Value) { return $false }
    return (($Ace.AccessMask -band $script:CaAccessManageCa) -eq $script:CaAccessManageCa)
}

function Ensure-RegistryManageCaAce {
    param(
        [Parameter(Mandatory = $true)][string]$RegistryPath,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$Sid,
        [Parameter(Mandatory = $true)][string]$QualifiedPrincipal
    )

    $bytes = Get-CaSecurityBytes -RegistryPath $RegistryPath
    $descriptor = ConvertTo-CaSecurityDescriptor -Bytes $bytes
    if ($null -eq $descriptor.DiscretionaryAcl) {
        throw "CA security descriptor at '$RegistryPath' has no DACL."
    }

    foreach ($ace in @($descriptor.DiscretionaryAcl)) {
        if (Test-CaManageCaAce -Ace $ace -Sid $Sid) {
            return $false
        }
    }

    if ($PSCmdlet.ShouldProcess($RegistryPath, "Grant ManageCA to $QualifiedPrincipal")) {
        $descriptor.DiscretionaryAcl.AddAccess(
            [System.Security.AccessControl.AccessControlType]::Allow,
            $Sid,
            $script:CaAccessManageCa,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None
        )
        $updated = ConvertFrom-CaSecurityDescriptor -Descriptor $descriptor
        Set-ItemProperty -Path $RegistryPath -Name Security -Value $updated -Type Binary -ErrorAction Stop
        return $true
    }
    return $false
}

function Get-CaEnrollmentService {
    param([Parameter(Mandatory = $true)][string]$Name)

    $rootDse = Get-ADRootDSE @AdServerParameters
    $searchBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$($rootDse.configurationNamingContext)"
    $escapedName = ConvertTo-LdapFilterValue -Value $Name
    $caObjects = @(Get-ADObject -SearchBase $searchBase -SearchScope OneLevel -LDAPFilter "(cn=$escapedName)" @AdServerParameters)
    if ($caObjects.Count -ne 1) {
        throw "Expected one CA enrollment service named '$Name', found $($caObjects.Count)."
    }
    return $caObjects[0]
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

function Test-AdManageCaAccessRule {
    param(
        [Parameter(Mandatory = $true)]$AccessRule,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$Sid
    )

    if ($AccessRule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }
    if ($AccessRule.IsInherited) { return $false }
    if (-not (Test-IdentityReferenceMatchesSid -IdentityReference $AccessRule.IdentityReference -Sid $Sid)) { return $false }
    if (($AccessRule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) { return $false }
    return (($AccessRule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild) -eq [System.DirectoryServices.ActiveDirectoryRights]::CreateChild)
}

function Ensure-AdManageCaAce {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$Sid,
        [Parameter(Mandatory = $true)][string]$QualifiedPrincipal
    )

    Ensure-AdDrive
    $path = "AD:\$DistinguishedName"
    $acl = Get-Acl -Path $path -ErrorAction Stop
    foreach ($accessRule in @($acl.Access)) {
        if (Test-AdManageCaAccessRule -AccessRule $accessRule -Sid $Sid) {
            return $false
        }
    }

    $rule = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @(
        $Sid,
        [System.DirectoryServices.ActiveDirectoryRights]::CreateChild,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    )
    $acl.AddAccessRule($rule)
    if ($PSCmdlet.ShouldProcess($DistinguishedName, "Grant ManageCA (access mask 0x1) to $QualifiedPrincipal")) {
        Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
        return $true
    }
    return $false
}

Assert-SamAccountName -Value $ControlPrincipal -Name 'ControlPrincipal'
$controlUser = Get-ADUser -Identity $ControlPrincipal @AdServerParameters -ErrorAction SilentlyContinue
if ($null -eq $controlUser) {
    throw "Control principal '$ControlPrincipal' was not found. Restore 06-ADCS-HTTP-CDP before running this scenario."
}

$qualifiedPrincipal = Get-QualifiedPrincipalName -Principal $ControlPrincipal
$sid = (New-Object Security.Principal.NTAccount($qualifiedPrincipal)).Translate([Security.Principal.SecurityIdentifier])
$caName = Get-ActiveCaName -RequestedName $CACommonName
$registryPath = Get-CaRegistryPath -CaName $caName
$changed = $false

if (Ensure-RegistryManageCaAce -RegistryPath $registryPath -Sid $sid -QualifiedPrincipal $qualifiedPrincipal) {
    $changed = $true
    $certSvc = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
    if ($null -ne $certSvc -and $PSCmdlet.ShouldProcess('CertSvc', 'Restart after CA security descriptor update')) {
        Restart-Service -Name CertSvc -Force -ErrorAction Stop
    }
}

$ca = Get-CaEnrollmentService -Name $caName
if (Ensure-AdManageCaAce -DistinguishedName ([string]$ca.DistinguishedName) -Sid $sid -QualifiedPrincipal $qualifiedPrincipal) {
    $changed = $true
}

[pscustomobject]@{
    Status           = 'Succeeded'
    Changed          = $changed
    ControlPrincipal = $qualifiedPrincipal
    CACommonName     = $caName
    RegistryPath     = $registryPath
    CaAdObject       = [string]$ca.DistinguishedName
    Right            = 'ManageCA'
}
