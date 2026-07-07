#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
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

function Get-AltSecurityIdentitiesSchemaId {
    $rootDse = Get-ADRootDSE @AdServerParameters
    $schemaNc = [string]$rootDse.schemaNamingContext
    $schemaObjects = @(Get-ADObject -SearchBase $schemaNc -SearchScope OneLevel -LDAPFilter "(&(objectClass=attributeSchema)(lDAPDisplayName=$script:AltSecurityIdentitiesAttribute))" -Properties lDAPDisplayName, schemaIDGUID @AdServerParameters)
    if ($schemaObjects.Count -ne 1) {
        throw "Expected one schema attribute named '$script:AltSecurityIdentitiesAttribute', found $($schemaObjects.Count)."
    }
    $guidBytes = [byte[]]$schemaObjects[0].schemaIDGUID
    return New-Object System.Guid (, $guidBytes)
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

function Ensure-AltSecurityIdentitiesWriteRight {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][string]$Principal,
        [Parameter(Mandatory = $true)][guid]$AttributeGuid
    )

    $qualifiedPrincipal = Get-QualifiedPrincipalName -Principal $Principal
    $sid = (New-Object Security.Principal.NTAccount($qualifiedPrincipal)).Translate([Security.Principal.SecurityIdentifier])
    Ensure-AdDrive
    $path = "AD:\$DistinguishedName"
    try {
        $acl = Get-Acl -Path $path -ErrorAction Stop
    }
    catch {
        throw "Read user ACL failed for path '$path'. Error: $($_.Exception.Message)"
    }

    foreach ($accessRule in @($acl.Access)) {
        if (Test-AltSecurityIdentitiesWriteRule -AccessRule $accessRule -Sid $sid -AttributeGuid $AttributeGuid) {
            return $false
        }
    }

    $rule = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @(
        $sid,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $AttributeGuid,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    )
    $acl.AddAccessRule($rule)
    if ($PSCmdlet.ShouldProcess($DistinguishedName, "Grant WriteProperty(altSecurityIdentities) to $qualifiedPrincipal")) {
        try {
            Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
        }
        catch {
            throw "Grant WriteProperty(altSecurityIdentities) to '$qualifiedPrincipal' failed for '$path'. Error: $($_.Exception.Message)"
        }
        return $true
    }
    return $false
}

function Ensure-WeakExplicitMapping {
    param(
        [Parameter(Mandatory = $true)]$Target,
        [Parameter(Mandatory = $true)][string]$Mapping
    )

    $current = @(ConvertTo-StringArray -Value $Target.altSecurityIdentities)
    foreach ($item in $current) {
        if ([string]$item -ceq $Mapping) {
            return $false
        }
    }

    if ($PSCmdlet.ShouldProcess($Target.DistinguishedName, "Add weak explicit mapping $Mapping")) {
        try {
            Set-ADUser -Identity $Target.DistinguishedName -Add @{ altSecurityIdentities = $Mapping } @AdServerParameters -ErrorAction Stop
        }
        catch {
            throw "Add altSecurityIdentities '$Mapping' failed for '$($Target.DistinguishedName)'. Error: $($_.Exception.Message)"
        }
        return $true
    }
    return $false
}

Assert-SamAccountName -Value $ControlPrincipal -Name 'ControlPrincipal'
Assert-SamAccountName -Value $TargetUser -Name 'TargetUser'
if ($ControlPrincipal -ieq $TargetUser) {
    throw 'ControlPrincipal and TargetUser must be different accounts.'
}

$controlUser = Get-ADUser -Identity $ControlPrincipal -Properties UserPrincipalName, mail @AdServerParameters -ErrorAction SilentlyContinue
if ($null -eq $controlUser) {
    throw "Control principal '$ControlPrincipal' was not found. Restore 06-ADCS-HTTP-CDP before running this scenario."
}
$target = Get-ADUser -Identity $TargetUser -Properties altSecurityIdentities @AdServerParameters -ErrorAction SilentlyContinue
if ($null -eq $target) {
    throw "Target user '$TargetUser' was not found. Restore 06-ADCS-HTTP-CDP before running this scenario."
}

$domain = Get-ADDomain @AdServerParameters
$mapping = Get-WeakRfc822Mapping -ControlUser $controlUser -Domain $domain
$attributeGuid = Get-AltSecurityIdentitiesSchemaId
$changed = $false

if (Ensure-AltSecurityIdentitiesWriteRight -DistinguishedName ([string]$target.DistinguishedName) -Principal $ControlPrincipal -AttributeGuid $attributeGuid) {
    $changed = $true
}
if (Ensure-WeakExplicitMapping -Target $target -Mapping $mapping) {
    $changed = $true
}

[pscustomobject]@{
    Status              = 'Succeeded'
    Changed             = $changed
    ControlPrincipal    = (Get-QualifiedPrincipalName -Principal $ControlPrincipal)
    TargetUser          = [string]$target.SamAccountName
    TargetDistinguishedName = [string]$target.DistinguishedName
    WeakMapping         = $mapping
    AttributeGuid       = [string]$attributeGuid
}
