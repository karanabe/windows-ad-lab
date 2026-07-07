#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$ResourceComputerName = 'FILE01',
    [string]$DelegatingComputerName = 'WEB01',
    [string]$DelegatedWriterSamAccountName = 'svc_web',
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'RBCD'
$script:Marker = 'windows-ad-lab:RBCD'
$script:Changed = $false
$script:RbcdAttribute = 'msDS-AllowedToActOnBehalfOfOtherIdentity'
$script:RbcdAttributeGuid = [guid]'3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'
$script:RbcdAccessMask = 0x000F01FF
$AdServerParameters = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $AdServerParameters['Server'] = $Server
}

Import-Module ActiveDirectory -ErrorAction Stop

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

function Get-ScenarioComputerOrNull {
    param([Parameter(Mandatory = $true)][string]$ComputerName)

    try {
        return Get-ADComputer -Identity $ComputerName -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, SID @AdServerParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

function Get-ScenarioUserBySamOrNull {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)

    $escapedSam = ConvertTo-LdapFilterValue -Value $SamAccountName
    $users = @(Get-ADUser -LDAPFilter "(sAMAccountName=$escapedSam)" -Properties SID @AdServerParameters -ErrorAction Stop)
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

function Clear-ScenarioRbcdAttribute {
    param(
        [Parameter(Mandatory = $true)]$ResourceComputer,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$DelegatingComputerSid
    )

    $descriptor = ConvertTo-RbcdRawSecurityDescriptor -Value $ResourceComputer.($script:RbcdAttribute) -DistinguishedName ([string]$ResourceComputer.DistinguishedName)
    if ($null -eq $descriptor) {
        return $false
    }
    if (-not (Test-RbcdDescriptorOnlyAllowsSid -Descriptor $descriptor -ExpectedSid $DelegatingComputerSid)) {
        $allowed = @(Get-RbcdAllowedSidValues -Descriptor $descriptor)
        throw "Computer '$($ResourceComputer.Name)' has a non-scenario '$script:RbcdAttribute' value with allowed SID(s): $($allowed -join ', '). Refusing to clear it."
    }

    if ($PSCmdlet.ShouldProcess($ResourceComputer.DistinguishedName, "Clear scenario $script:RbcdAttribute")) {
        Set-ADObject -Identity $ResourceComputer.DistinguishedName -Clear $script:RbcdAttribute @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }
    return $true
}

function Remove-ScenarioRbcdWriteAce {
    param(
        [Parameter(Mandatory = $true)][string]$ResourceDistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$WriterSid
    )

    Ensure-AdDrive
    $path = "AD:\$ResourceDistinguishedName"
    $acl = Get-Acl -Path $path -ErrorAction Stop
    $rulesToRemove = @($acl.Access | Where-Object {
        -not $_.IsInherited -and (Test-RbcdWriteAce -AccessRule $_ -PrincipalSid $WriterSid)
    })
    if ($rulesToRemove.Count -eq 0) {
        return 0
    }

    if ($PSCmdlet.ShouldProcess($ResourceDistinguishedName, "Remove scenario WriteProperty ACE for $script:RbcdAttribute")) {
        foreach ($rule in $rulesToRemove) {
            [void]$acl.RemoveAccessRuleSpecific($rule)
        }
        Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
        $script:Changed = $true
    }
    return $rulesToRemove.Count
}

function Assert-BaselineRestored {
    param(
        [Parameter(Mandatory = $true)]$ResourceComputer,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$WriterSid
    )

    $current = Get-ScenarioComputerOrNull -ComputerName ([string]$ResourceComputer.Name)
    if ($null -eq $current) {
        throw "Resource computer '$($ResourceComputer.Name)' was removed during cleanup."
    }
    $descriptor = ConvertTo-RbcdRawSecurityDescriptor -Value $current.($script:RbcdAttribute) -DistinguishedName ([string]$current.DistinguishedName)
    $remainingAceCount = 0
    Ensure-AdDrive
    $acl = Get-Acl -Path "AD:\$($current.DistinguishedName)" -ErrorAction Stop
    $remainingAceCount = @($acl.Access | Where-Object { -not $_.IsInherited -and (Test-RbcdWriteAce -AccessRule $_ -PrincipalSid $WriterSid) }).Count
    if ($null -ne $descriptor -or $remainingAceCount -gt 0) {
        throw "Cleanup finished but Baseline 06 does not match. Remaining RBCD descriptor present=$($null -ne $descriptor); remaining writer ACE count=$remainingAceCount"
    }
}

$domain = Get-ADDomain @AdServerParameters -ErrorAction Stop
if ([string]$domain.DNSRoot -ine 'ad.lab.exceeds.test') {
    throw "Current domain '$($domain.DNSRoot)' is not the expected Baseline 06 domain 'ad.lab.exceeds.test'."
}

$resourceComputer = Get-ScenarioComputerOrNull -ComputerName $ResourceComputerName
$delegatingComputer = Get-ScenarioComputerOrNull -ComputerName $DelegatingComputerName
$delegatedWriter = Get-ScenarioUserBySamOrNull -SamAccountName $DelegatedWriterSamAccountName
foreach ($requiredObject in @(
    @{ Name = $ResourceComputerName; Object = $resourceComputer; Type = 'computer' },
    @{ Name = $DelegatingComputerName; Object = $delegatingComputer; Type = 'computer' },
    @{ Name = $DelegatedWriterSamAccountName; Object = $delegatedWriter; Type = 'user' }
)) {
    if ($null -eq $requiredObject.Object) {
        throw "Required baseline $($requiredObject.Type) '$($requiredObject.Name)' was not found. Restore 06-ADCS-HTTP-CDP before running cleanup."
    }
}

$rbcdCleared = Clear-ScenarioRbcdAttribute -ResourceComputer $resourceComputer -DelegatingComputerSid $delegatingComputer.SID
$removedAceCount = Remove-ScenarioRbcdWriteAce -ResourceDistinguishedName ([string]$resourceComputer.DistinguishedName) -WriterSid $delegatedWriter.SID
if ($WhatIfPreference) {
    Write-Host 'WhatIf: Baseline restored check skipped because no objects were changed.'
}
else {
    Assert-BaselineRestored -ResourceComputer $resourceComputer -WriterSid $delegatedWriter.SID
}

[pscustomobject]@{
    Scenario                = $script:ScenarioName
    Changed                 = $script:Changed
    Baseline                = '06-ADCS-HTTP-CDP'
    BaselineRestored        = (-not $WhatIfPreference)
    ResourceComputer        = $resourceComputer.DistinguishedName
    RbcdAttributeCleared    = $rbcdCleared
    RbcdWriteAcesRemoved    = $removedAceCount
}
