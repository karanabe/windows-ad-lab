#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ControlPrincipal = 'bob.taylor',
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'ESC5-PkiObjectAcl'
$script:NtAuthCommonName = 'NTAuthCertificates'
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

function Get-QualifiedPrincipalName {
    param([Parameter(Mandatory = $true)][string]$Principal)

    if ($Principal -match '\\') { return $Principal }
    $domain = Get-ADDomain @AdServerParameters
    return "$($domain.NetBIOSName)\$Principal"
}

function Get-NtAuthCertificatesObject {
    $rootDse = Get-ADRootDSE @AdServerParameters
    $dn = "CN=$script:NtAuthCommonName,CN=Public Key Services,CN=Services,$($rootDse.configurationNamingContext)"
    try {
        return Get-ADObject -Identity $dn -Properties nTSecurityDescriptor, objectClass @AdServerParameters -ErrorAction Stop
    }
    catch {
        throw "NTAuthCertificates object '$dn' was not found. Restore 06-ADCS-HTTP-CDP before running this scenario. Error: $($_.Exception.Message)"
    }
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

function Test-GenericAllAccessRule {
    param(
        [Parameter(Mandatory = $true)]$AccessRule,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$Sid
    )

    if ($AccessRule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }
    if ($AccessRule.IsInherited) { return $false }
    if (-not (Test-IdentityReferenceMatchesSid -IdentityReference $AccessRule.IdentityReference -Sid $Sid)) { return $false }
    return (($AccessRule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)
}

function Ensure-NtAuthGenericAllRight {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][string]$Principal
    )

    $qualifiedPrincipal = Get-QualifiedPrincipalName -Principal $Principal
    $sid = (New-Object Security.Principal.NTAccount($qualifiedPrincipal)).Translate([Security.Principal.SecurityIdentifier])
    Ensure-AdDrive
    $path = "AD:\$DistinguishedName"
    try {
        $acl = Get-Acl -Path $path -ErrorAction Stop
    }
    catch {
        throw "Read NTAuthCertificates ACL failed for path '$path'. Error: $($_.Exception.Message)"
    }

    foreach ($accessRule in @($acl.Access)) {
        if (Test-GenericAllAccessRule -AccessRule $accessRule -Sid $sid) {
            return $false
        }
    }

    $rule = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @(
        $sid,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    )
    $acl.AddAccessRule($rule)
    if ($PSCmdlet.ShouldProcess($DistinguishedName, "Grant GenericAll to $qualifiedPrincipal")) {
        try {
            Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
        }
        catch {
            throw "Grant GenericAll to '$qualifiedPrincipal' failed for NTAuthCertificates ACL path '$path'. Error: $($_.Exception.Message)"
        }
        return $true
    }
    return $false
}

Assert-SamAccountName -Value $ControlPrincipal -Name 'ControlPrincipal'
$controlUser = Get-ADUser -Identity $ControlPrincipal @AdServerParameters -ErrorAction SilentlyContinue
if ($null -eq $controlUser) {
    throw "Control principal '$ControlPrincipal' was not found. Restore 06-ADCS-HTTP-CDP before running this scenario."
}

$ntAuth = Get-NtAuthCertificatesObject
$changed = Ensure-NtAuthGenericAllRight -DistinguishedName ([string]$ntAuth.DistinguishedName) -Principal $ControlPrincipal

[pscustomobject]@{
    Status              = 'Succeeded'
    Changed             = $changed
    ControlPrincipal    = (Get-QualifiedPrincipalName -Principal $ControlPrincipal)
    PkiObject           = [string]$ntAuth.DistinguishedName
    PkiObjectCommonName = $script:NtAuthCommonName
}
