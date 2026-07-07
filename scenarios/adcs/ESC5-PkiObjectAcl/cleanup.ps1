#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$ControlPrincipal = 'bob.taylor',
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:NtAuthCommonName = 'NTAuthCertificates'
$AdServerParameters = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $AdServerParameters['Server'] = $Server
}

Import-Module ActiveDirectory -ErrorAction Stop

function Get-QualifiedPrincipalName {
    param([Parameter(Mandatory = $true)][string]$Principal)

    if ($Principal -match '\\') { return $Principal }
    $domain = Get-ADDomain @AdServerParameters
    return "$($domain.NetBIOSName)\$Principal"
}

function Get-NtAuthCertificatesObjectOrNull {
    $rootDse = Get-ADRootDSE @AdServerParameters
    $dn = "CN=$script:NtAuthCommonName,CN=Public Key Services,CN=Services,$($rootDse.configurationNamingContext)"
    try {
        return Get-ADObject -Identity $dn @AdServerParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
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

$ntAuth = Get-NtAuthCertificatesObjectOrNull
if ($null -eq $ntAuth) {
    [pscustomobject]@{
        Status                    = 'Succeeded'
        Changed                   = $false
        ControlPrincipal          = $ControlPrincipal
        PkiObjectFound            = $false
        GenericAllAceRemovals     = 0
    }
    return
}

$qualifiedPrincipal = Get-QualifiedPrincipalName -Principal $ControlPrincipal
$sid = $null
try {
    $sid = (New-Object Security.Principal.NTAccount($qualifiedPrincipal)).Translate([Security.Principal.SecurityIdentifier])
}
catch {
    $sid = $null
}

Ensure-AdDrive
$path = "AD:\$($ntAuth.DistinguishedName)"
$acl = Get-Acl -Path $path -ErrorAction Stop
$rulesToRemove = New-Object 'System.Collections.Generic.List[object]'
if ($null -ne $sid) {
    foreach ($rule in @($acl.Access)) {
        if (Test-GenericAllAccessRule -AccessRule $rule -Sid $sid) {
            [void]$rulesToRemove.Add($rule)
        }
    }
}

$removed = 0
if ($rulesToRemove.Count -gt 0 -and $PSCmdlet.ShouldProcess($ntAuth.DistinguishedName, "Remove GenericAll ACEs for $qualifiedPrincipal")) {
    foreach ($rule in $rulesToRemove.ToArray()) {
        [void]$acl.RemoveAccessRuleSpecific($rule)
        $removed++
    }
    Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
}

[pscustomobject]@{
    Status                = 'Succeeded'
    Changed               = ($removed -gt 0)
    ControlPrincipal      = $qualifiedPrincipal
    PkiObjectFound        = $true
    PkiObject             = [string]$ntAuth.DistinguishedName
    GenericAllAceRemovals = $removed
}
