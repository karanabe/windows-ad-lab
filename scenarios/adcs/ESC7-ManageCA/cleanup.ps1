#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$ControlPrincipal = 'operator01',
    [string]$CACommonName,
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CaAccessManageCa = 0x00000001
$AdServerParameters = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $AdServerParameters['Server'] = $Server
}

Import-Module ActiveDirectory -ErrorAction Stop

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
    $active = (Get-ItemProperty -Path $caRoot -Name Active -ErrorAction SilentlyContinue).Active
    if ([string]::IsNullOrWhiteSpace([string]$active)) {
        return $null
    }
    return [string]$active
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

$changed = $false
$registryRemovals = 0
$adRemovals = 0
$caName = Get-ActiveCaName -RequestedName $CACommonName
$qualifiedPrincipal = Get-QualifiedPrincipalName -Principal $ControlPrincipal
$sid = $null
try {
    $sid = (New-Object Security.Principal.NTAccount($qualifiedPrincipal)).Translate([Security.Principal.SecurityIdentifier])
}
catch {
    $sid = $null
}

if ($null -ne $caName -and $null -ne $sid) {
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName"
    try {
        $security = (Get-ItemProperty -Path $registryPath -Name Security -ErrorAction Stop).Security
        $valueObject = $security.PSObject.BaseObject
        if ($valueObject -is [byte[]]) {
            $descriptor = New-Object System.Security.AccessControl.CommonSecurityDescriptor $false, $false, ([byte[]]$valueObject), 0
            $matching = New-Object 'System.Collections.Generic.List[object]'
            if ($null -ne $descriptor.DiscretionaryAcl) {
                foreach ($ace in @($descriptor.DiscretionaryAcl)) {
                    if ($ace.AceType -eq [System.Security.AccessControl.AceType]::AccessAllowed -and
                        [string]$ace.SecurityIdentifier.Value -eq [string]$sid.Value -and
                        (($ace.AccessMask -band $script:CaAccessManageCa) -eq $script:CaAccessManageCa) -and
                        $ace.AccessMask -eq $script:CaAccessManageCa) {
                        [void]$matching.Add($ace)
                    }
                }
            }
            if ($matching.Count -gt 0 -and $PSCmdlet.ShouldProcess($registryPath, "Remove ManageCA ACEs for $qualifiedPrincipal")) {
                [void]$descriptor.DiscretionaryAcl.RemoveAccess(
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    $sid,
                    $script:CaAccessManageCa,
                    [System.Security.AccessControl.InheritanceFlags]::None,
                    [System.Security.AccessControl.PropagationFlags]::None
                )
                $registryRemovals = $matching.Count
                $updated = New-Object byte[] $descriptor.BinaryLength
                $descriptor.GetBinaryForm($updated, 0)
                Set-ItemProperty -Path $registryPath -Name Security -Value $updated -Type Binary -ErrorAction Stop
                $changed = $true
            }
        }
    }
    catch {
        throw "Remove ManageCA from CA registry security at '$registryPath' failed. Error: $($_.Exception.Message)"
    }

    $rootDse = Get-ADRootDSE @AdServerParameters
    $searchBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$($rootDse.configurationNamingContext)"
    $escapedName = ConvertTo-LdapFilterValue -Value $caName
    $caObjects = @(Get-ADObject -SearchBase $searchBase -SearchScope OneLevel -LDAPFilter "(cn=$escapedName)" @AdServerParameters)
    if ($caObjects.Count -eq 1) {
        Ensure-AdDrive
        $path = "AD:\$($caObjects[0].DistinguishedName)"
        $acl = Get-Acl -Path $path -ErrorAction Stop
        $rulesToRemove = New-Object 'System.Collections.Generic.List[object]'
        foreach ($rule in @($acl.Access)) {
            if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            if ($rule.IsInherited) { continue }
            if (-not (Test-IdentityReferenceMatchesSid -IdentityReference $rule.IdentityReference -Sid $sid)) { continue }
            if (($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) { continue }
            if (($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild) -eq [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -and
                $rule.ActiveDirectoryRights -eq [System.DirectoryServices.ActiveDirectoryRights]::CreateChild) {
                [void]$rulesToRemove.Add($rule)
            }
        }
        if ($rulesToRemove.Count -gt 0 -and $PSCmdlet.ShouldProcess($caObjects[0].DistinguishedName, "Remove ManageCA ACEs for $qualifiedPrincipal")) {
            foreach ($rule in $rulesToRemove.ToArray()) {
                [void]$acl.RemoveAccessRuleSpecific($rule)
                $adRemovals++
            }
            Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
            $changed = $true
        }
    }
}

if ($registryRemovals -gt 0) {
    $certSvc = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
    if ($null -ne $certSvc -and $PSCmdlet.ShouldProcess('CertSvc', 'Restart after CA security descriptor update')) {
        Restart-Service -Name CertSvc -Force -ErrorAction Stop
    }
}

[pscustomobject]@{
    Status            = 'Succeeded'
    Changed           = $changed
    ControlPrincipal  = $qualifiedPrincipal
    CACommonName      = $caName
    RegistryRemovals  = $registryRemovals
    AdAceRemovals     = $adRemovals
}
