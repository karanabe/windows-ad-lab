#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$ControlPrincipal = 'alice.brown',
    [string]$TargetUser = 'operator01',
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:AltSecurityIdentitiesAttribute = 'altSecurityIdentities'
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

function ConvertTo-StringArray {
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return @() }
    $valueObject = $Value.PSObject.BaseObject
    if ($valueObject -is [string]) {
        if ([string]::IsNullOrWhiteSpace($valueObject)) { return @() }
        return [string[]]@([string]$valueObject)
    }
    if ($valueObject -is [System.Collections.IEnumerable] -and -not ($valueObject -is [string])) {
        $values = New-Object 'System.Collections.Generic.List[string]'
        foreach ($item in $valueObject) {
            if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace([string]$item)) {
                [void]$values.Add([string]$item)
            }
        }
        return [string[]]$values.ToArray()
    }
    return [string[]]@([string]$valueObject)
}

function Get-AltSecurityIdentitiesSchemaIdOrNull {
    try {
        $rootDse = Get-ADRootDSE @AdServerParameters
        $schemaNc = [string]$rootDse.schemaNamingContext
        $schemaObjects = @(Get-ADObject -SearchBase $schemaNc -SearchScope OneLevel -LDAPFilter "(&(objectClass=attributeSchema)(lDAPDisplayName=$script:AltSecurityIdentitiesAttribute))" -Properties schemaIDGUID @AdServerParameters)
        if ($schemaObjects.Count -ne 1) { return $null }
        return New-Object System.Guid (, [byte[]]$schemaObjects[0].schemaIDGUID)
    }
    catch {
        return $null
    }
}

function Get-WeakRfc822Mapping {
    param(
        [Parameter(Mandatory = $true)]$ControlUser,
        [Parameter(Mandatory = $true)]$Domain
    )

    $mail = [string]$ControlUser.mail
    if (-not [string]::IsNullOrWhiteSpace($mail)) {
        return "X509:<RFC822>$mail"
    }
    $upn = [string]$ControlUser.UserPrincipalName
    if (-not [string]::IsNullOrWhiteSpace($upn)) {
        return "X509:<RFC822>$upn"
    }
    return "X509:<RFC822>$($ControlUser.SamAccountName)@$($Domain.DNSRoot)"
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

function Test-AltSecurityIdentitiesWriteRule {
    param(
        [Parameter(Mandatory = $true)]$AccessRule,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$Sid,
        [Parameter(Mandatory = $true)][guid]$AttributeGuid
    )

    if ($AccessRule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }
    if ($AccessRule.IsInherited) { return $false }
    if (-not (Test-IdentityReferenceMatchesSid -IdentityReference $AccessRule.IdentityReference -Sid $Sid)) { return $false }
    if (($AccessRule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) {
        return $true
    }
    if (($AccessRule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) {
        return ($AccessRule.ObjectType -eq [guid]::Empty -or $AccessRule.ObjectType -eq $AttributeGuid)
    }
    if (($AccessRule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -ne [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) {
        return $false
    }
    return ($AccessRule.ObjectType -eq [guid]::Empty -or $AccessRule.ObjectType -eq $AttributeGuid)
}

$domain = Get-ADDomain @AdServerParameters
$target = $null
try {
    $target = Get-ADUser -Identity $TargetUser -Properties altSecurityIdentities @AdServerParameters -ErrorAction Stop
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    $target = $null
}

if ($null -eq $target) {
    [pscustomobject]@{
        Status                    = 'Succeeded'
        Changed                   = $false
        ControlPrincipal          = $ControlPrincipal
        TargetUser                = $TargetUser
        TargetFound               = $false
        MappingRemovals           = 0
        WritePropertyAceRemovals  = 0
    }
    return
}

$changed = $false
$mappingRemovals = 0
$aceRemovals = 0
$qualifiedPrincipal = Get-QualifiedPrincipalName -Principal $ControlPrincipal

$controlUser = $null
try {
    $controlUser = Get-ADUser -Identity $ControlPrincipal -Properties UserPrincipalName, mail @AdServerParameters -ErrorAction Stop
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    $controlUser = $null
}

if ($null -ne $controlUser) {
    $mapping = Get-WeakRfc822Mapping -ControlUser $controlUser -Domain $domain
    $current = @(ConvertTo-StringArray -Value $target.altSecurityIdentities)
    if ($current -contains $mapping) {
        if ($PSCmdlet.ShouldProcess($target.DistinguishedName, "Remove weak explicit mapping $mapping")) {
            Set-ADUser -Identity $target.DistinguishedName -Remove @{ altSecurityIdentities = $mapping } @AdServerParameters -ErrorAction Stop
            $mappingRemovals = 1
            $changed = $true
        }
    }
}

$attributeGuid = Get-AltSecurityIdentitiesSchemaIdOrNull
$sid = $null
try {
    $sid = (New-Object Security.Principal.NTAccount($qualifiedPrincipal)).Translate([Security.Principal.SecurityIdentifier])
}
catch {
    $sid = $null
}

if ($null -ne $sid -and $null -ne $attributeGuid) {
    Ensure-AdDrive
    $path = "AD:\$($target.DistinguishedName)"
    $acl = Get-Acl -Path $path -ErrorAction Stop
    $rulesToRemove = New-Object 'System.Collections.Generic.List[object]'
    foreach ($rule in @($acl.Access)) {
        if (Test-AltSecurityIdentitiesWriteRule -AccessRule $rule -Sid $sid -AttributeGuid $attributeGuid) {
            [void]$rulesToRemove.Add($rule)
        }
    }
    if ($rulesToRemove.Count -gt 0 -and $PSCmdlet.ShouldProcess($target.DistinguishedName, "Remove altSecurityIdentities write ACEs for $qualifiedPrincipal")) {
        foreach ($rule in $rulesToRemove.ToArray()) {
            [void]$acl.RemoveAccessRuleSpecific($rule)
            $aceRemovals++
        }
        Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
        $changed = $true
    }
}

[pscustomobject]@{
    Status                   = 'Succeeded'
    Changed                  = $changed
    ControlPrincipal         = $qualifiedPrincipal
    TargetUser               = [string]$target.SamAccountName
    TargetFound              = $true
    MappingRemovals          = $mappingRemovals
    WritePropertyAceRemovals = $aceRemovals
}
