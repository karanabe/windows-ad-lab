#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ResourceComputerName = 'FILE01',
    [string]$DelegatingComputerName = 'WEB01',
    [string]$ControlComputerName = 'CLIENT01',
    [string]$DelegatedWriterSamAccountName = 'svc_web',
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'RBCD'
$script:Marker = 'windows-ad-lab:RBCD'
$script:RootOuName = 'LAB'
$script:Changed = $false
$script:RbcdAttribute = 'msDS-AllowedToActOnBehalfOfOtherIdentity'
$script:RbcdAttributeGuid = [guid]'3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'
$script:RbcdAccessMaskSddl = 'CCDCLCSWRPWPDTLOCRSDRCWDWO'
$script:RbcdAccessMask = 0x000F01FF
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

function Assert-ComputerName {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($Value -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,14}$') {
        throw "$Name must be a valid 1-15 character NetBIOS computer name: '$Value'"
    }
}

function ConvertTo-LdapFilterValue {
    param([Parameter(Mandatory = $true)][string]$Value)

    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace(([string][char]0), '\00')
}

function ConvertTo-SingleAdValue {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)][string]$AttributeName,
        [Parameter(Mandatory = $true)][string]$DistinguishedName
    )

    if ($null -eq $Value) {
        return $null
    }
    $valueObject = $Value.PSObject.BaseObject
    if ($valueObject -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) {
        if ($valueObject.Count -eq 0) { return $null }
        if ($valueObject.Count -gt 1) {
            throw "Attribute '$AttributeName' on '$DistinguishedName' should have one value, found $($valueObject.Count)."
        }
        return $valueObject[0]
    }
    if ($valueObject -is [array] -and -not ($valueObject -is [byte[]])) {
        if ($valueObject.Count -eq 0) { return $null }
        if ($valueObject.Count -gt 1) {
            throw "Attribute '$AttributeName' on '$DistinguishedName' should have one value, found $($valueObject.Count)."
        }
        return $valueObject[0]
    }
    return $valueObject
}

function ConvertTo-GuidValue {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($null -eq $Value) {
        throw "$Context did not contain a GUID value."
    }
    $valueObject = $Value.PSObject.BaseObject
    if ($valueObject -is [Guid]) {
        return [Guid]$valueObject
    }
    if ($valueObject -is [byte[]]) {
        return New-Object -TypeName System.Guid -ArgumentList (, ([byte[]]$valueObject))
    }
    return [Guid]([string]$valueObject)
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

function Assert-RbcdSchema {
    $rootDse = Get-ADRootDSE @AdServerParameters -ErrorAction Stop
    $schemaNc = [string]$rootDse.schemaNamingContext
    $escapedName = ConvertTo-LdapFilterValue -Value $script:RbcdAttribute
    $attributes = @(Get-ADObject -SearchBase $schemaNc -SearchScope OneLevel -LDAPFilter "(lDAPDisplayName=$escapedName)" -Properties lDAPDisplayName, schemaIDGUID, isSingleValued, attributeSyntax, oMSyntax @AdServerParameters -ErrorAction Stop)
    if ($attributes.Count -ne 1) {
        throw "Expected one schema attribute named '$script:RbcdAttribute', found $($attributes.Count)."
    }
    $schemaGuid = ConvertTo-GuidValue -Value $attributes[0].schemaIDGUID -Context "schemaIDGUID for $script:RbcdAttribute"
    if ($schemaGuid -ne $script:RbcdAttributeGuid) {
        throw "Schema GUID for '$script:RbcdAttribute' is '$schemaGuid', expected '$script:RbcdAttributeGuid'."
    }
    if (-not [bool]$attributes[0].isSingleValued -or [string]$attributes[0].attributeSyntax -ne '2.5.5.15' -or [int]$attributes[0].oMSyntax -ne 66) {
        throw "Schema for '$script:RbcdAttribute' does not match the expected single-valued security descriptor syntax."
    }
}

function Get-ScenarioComputerOrNull {
    param([Parameter(Mandatory = $true)][string]$ComputerName)

    try {
        return Get-ADComputer -Identity $ComputerName -Properties Description, Enabled, ServicePrincipalName, msDS-AllowedToActOnBehalfOfOtherIdentity, PrincipalsAllowedToDelegateToAccount, SID @AdServerParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

function Get-ScenarioUserBySamOrNull {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)

    $escapedSam = ConvertTo-LdapFilterValue -Value $SamAccountName
    $users = @(Get-ADUser -LDAPFilter "(sAMAccountName=$escapedSam)" -Properties Enabled, adminDescription, SID @AdServerParameters -ErrorAction Stop)
    if ($users.Count -gt 1) {
        throw "Multiple users were returned for sAMAccountName '$SamAccountName'."
    }
    if ($users.Count -eq 0) {
        return $null
    }
    return $users[0]
}

function ConvertTo-RbcdRawSecurityDescriptor {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)][string]$DistinguishedName
    )

    $singleValue = ConvertTo-SingleAdValue -Value $Value -AttributeName $script:RbcdAttribute -DistinguishedName $DistinguishedName
    if ($null -eq $singleValue) {
        return $null
    }
    $valueObject = $singleValue.PSObject.BaseObject
    if ($valueObject -is [System.Security.AccessControl.RawSecurityDescriptor]) {
        return $valueObject
    }
    if ($valueObject -is [System.DirectoryServices.ActiveDirectorySecurity]) {
        $sddl = $valueObject.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
        return New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $sddl
    }
    if ($valueObject -is [byte[]]) {
        return [System.Security.AccessControl.RawSecurityDescriptor]::new([byte[]]$valueObject, 0)
    }
    if ($valueObject -is [string]) {
        return New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList ([string]$valueObject)
    }
    throw "Attribute '$script:RbcdAttribute' on '$DistinguishedName' returned unsupported value type '$($valueObject.GetType().FullName)'."
}

function Get-RbcdAllowedSidValues {
    param([AllowNull()][System.Security.AccessControl.RawSecurityDescriptor]$Descriptor)

    if ($null -eq $Descriptor -or $null -eq $Descriptor.DiscretionaryAcl) {
        return @()
    }

    $sids = New-Object 'System.Collections.Generic.List[string]'
    foreach ($ace in $Descriptor.DiscretionaryAcl) {
        if ($ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowed) {
            continue
        }
        if ($null -eq $ace.SecurityIdentifier) {
            continue
        }
        [void]$sids.Add([string]$ace.SecurityIdentifier.Value)
    }
    return [string[]]($sids.ToArray() | Sort-Object -Unique)
}

function Test-RbcdDescriptorOnlyAllowsSid {
    param(
        [AllowNull()][System.Security.AccessControl.RawSecurityDescriptor]$Descriptor,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$ExpectedSid
    )

    if ($null -eq $Descriptor -or $null -eq $Descriptor.DiscretionaryAcl) {
        return $false
    }
    $aces = @($Descriptor.DiscretionaryAcl)
    if ($aces.Count -ne 1) {
        return $false
    }
    $ace = $aces[0]
    if ($ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowed) {
        return $false
    }
    if ($null -eq $ace.SecurityIdentifier -or [string]$ace.SecurityIdentifier.Value -ne [string]$ExpectedSid.Value) {
        return $false
    }
    return ([int]$ace.AccessMask -eq [int]$script:RbcdAccessMask)
}

function New-RbcdSecurityDescriptorBytes {
    param([Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$DelegatingComputerSid)

    $sddl = 'O:BAD:(A;;{0};;;{1})' -f $script:RbcdAccessMaskSddl, $DelegatingComputerSid.Value
    $descriptor = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $sddl
    $bytes = New-Object 'byte[]' $descriptor.BinaryLength
    $descriptor.GetBinaryForm($bytes, 0)
    return ,([byte[]]$bytes)
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

function Test-RbcdWriteAce {
    param(
        [Parameter(Mandatory = $true)]$AccessRule,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    if ($AccessRule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }
    if (-not (Test-IdentityReferenceMatchesSid -IdentityReference $AccessRule.IdentityReference -Sid $PrincipalSid)) { return $false }
    if (($AccessRule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -ne [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) { return $false }
    return ($AccessRule.ObjectType -eq $script:RbcdAttributeGuid)
}

function Ensure-RbcdWriteAce {
    param(
        [Parameter(Mandatory = $true)][string]$ResourceDistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$WriterSid
    )

    Ensure-AdDrive
    $path = "AD:\$ResourceDistinguishedName"
    $acl = Get-Acl -Path $path -ErrorAction Stop
    $existingRules = @($acl.Access | Where-Object { -not $_.IsInherited -and (Test-RbcdWriteAce -AccessRule $_ -PrincipalSid $WriterSid) })
    if ($existingRules.Count -gt 0) {
        return $false
    }

    $rule = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @(
        $WriterSid,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $script:RbcdAttributeGuid
    )
    if ($PSCmdlet.ShouldProcess($ResourceDistinguishedName, "Grant $DelegatedWriterSamAccountName WriteProperty on $script:RbcdAttribute")) {
        $acl.AddAccessRule($rule)
        Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
        $script:Changed = $true
    }
    return $true
}

function Ensure-ScenarioRbcdAttribute {
    param(
        [Parameter(Mandatory = $true)]$ResourceComputer,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$DelegatingComputerSid
    )

    $descriptor = ConvertTo-RbcdRawSecurityDescriptor -Value $ResourceComputer.($script:RbcdAttribute) -DistinguishedName ([string]$ResourceComputer.DistinguishedName)
    if (Test-RbcdDescriptorOnlyAllowsSid -Descriptor $descriptor -ExpectedSid $DelegatingComputerSid) {
        return $false
    }
    if ($null -ne $descriptor) {
        $allowed = @(Get-RbcdAllowedSidValues -Descriptor $descriptor)
        throw "Computer '$($ResourceComputer.Name)' already has '$script:RbcdAttribute' with allowed SID(s): $($allowed -join ', '). Refusing to replace a non-scenario RBCD descriptor."
    }

    $bytes = New-RbcdSecurityDescriptorBytes -DelegatingComputerSid $DelegatingComputerSid
    $replace = @{}
    $replace[$script:RbcdAttribute] = $bytes
    if ($PSCmdlet.ShouldProcess($ResourceComputer.DistinguishedName, "Set $script:RbcdAttribute to allow $DelegatingComputerName")) {
        Set-ADObject -Identity $ResourceComputer.DistinguishedName -Replace $replace @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }
    return $true
}

Assert-ComputerName -Value $ResourceComputerName -Name 'ResourceComputerName'
Assert-ComputerName -Value $DelegatingComputerName -Name 'DelegatingComputerName'
Assert-ComputerName -Value $ControlComputerName -Name 'ControlComputerName'
Assert-SamAccountName -Value $DelegatedWriterSamAccountName -Name 'DelegatedWriterSamAccountName'
if ($ResourceComputerName -ieq $DelegatingComputerName) {
    throw 'ResourceComputerName and DelegatingComputerName must be different.'
}
if ($ControlComputerName -ieq $DelegatingComputerName -or $ControlComputerName -ieq $ResourceComputerName) {
    throw 'ControlComputerName must be different from ResourceComputerName and DelegatingComputerName.'
}

$domain = Get-ADDomain @AdServerParameters -ErrorAction Stop
if ([string]$domain.DNSRoot -ine 'ad.lab.exceeds.test') {
    throw "Current domain '$($domain.DNSRoot)' is not the expected Baseline 06 domain 'ad.lab.exceeds.test'."
}

$domainDn = [string]$domain.DistinguishedName
$rootOuDn = "OU=$script:RootOuName,$domainDn"
if ($null -eq (Get-ADOrganizationalUnit -Identity $rootOuDn @AdServerParameters -ErrorAction SilentlyContinue)) {
    throw "Baseline root OU '$rootOuDn' was not found. Restore 06-ADCS-HTTP-CDP before running this scenario."
}

Assert-RbcdSchema
$resourceComputer = Get-ScenarioComputerOrNull -ComputerName $ResourceComputerName
$delegatingComputer = Get-ScenarioComputerOrNull -ComputerName $DelegatingComputerName
$controlComputer = Get-ScenarioComputerOrNull -ComputerName $ControlComputerName
$delegatedWriter = Get-ScenarioUserBySamOrNull -SamAccountName $DelegatedWriterSamAccountName
foreach ($requiredObject in @(
    @{ Name = $ResourceComputerName; Object = $resourceComputer; Type = 'computer' },
    @{ Name = $DelegatingComputerName; Object = $delegatingComputer; Type = 'computer' },
    @{ Name = $ControlComputerName; Object = $controlComputer; Type = 'computer' },
    @{ Name = $DelegatedWriterSamAccountName; Object = $delegatedWriter; Type = 'user' }
)) {
    if ($null -eq $requiredObject.Object) {
        throw "Required baseline $($requiredObject.Type) '$($requiredObject.Name)' was not found. Restore 06-ADCS-HTTP-CDP before running this scenario."
    }
}

$rbcdAttributeChanged = Ensure-ScenarioRbcdAttribute -ResourceComputer $resourceComputer -DelegatingComputerSid $delegatingComputer.SID
$writeAceChanged = Ensure-RbcdWriteAce -ResourceDistinguishedName ([string]$resourceComputer.DistinguishedName) -WriterSid $delegatedWriter.SID
$resourceComputer = Get-ScenarioComputerOrNull -ComputerName $ResourceComputerName
$descriptor = ConvertTo-RbcdRawSecurityDescriptor -Value $resourceComputer.($script:RbcdAttribute) -DistinguishedName ([string]$resourceComputer.DistinguishedName)
$allowedSids = @(Get-RbcdAllowedSidValues -Descriptor $descriptor)

[pscustomobject]@{
    Scenario                         = $script:ScenarioName
    Changed                          = $script:Changed
    Baseline                         = '06-ADCS-HTTP-CDP'
    ResourceComputer                 = $resourceComputer.DistinguishedName
    DelegatingComputer               = $delegatingComputer.DistinguishedName
    ControlComputer                  = $controlComputer.DistinguishedName
    DelegatedWriter                  = $delegatedWriter.DistinguishedName
    RbcdAttribute                    = $script:RbcdAttribute
    RbcdAttributeChanged             = $rbcdAttributeChanged
    RbcdAllowedSidValues             = [string[]]$allowedSids
    RbcdAllowedComputer              = $DelegatingComputerName
    RbcdWriteAceChanged              = $writeAceChanged
    MachineAccountQuotaUnchanged     = $true
}
