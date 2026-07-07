#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$ResourceComputerName = 'FILE01',
    [string]$DelegatingComputerName = 'WEB01',
    [string]$ControlComputerName = 'CLIENT01',
    [string]$DelegatedWriterSamAccountName = 'svc_web',
    [string]$OutputPath,
    [string]$Server,
    [switch]$IncludeAcl,
    [switch]$PassThru,
    [switch]$FailOnValidationError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'RBCD'
$script:Marker = 'windows-ad-lab:RBCD'
$script:RootOuName = 'LAB'
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

function New-ValidationResult {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('Passed', 'Failed', 'Skipped')][string]$Status,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [string]$Message = ''
    )

    return [pscustomobject]@{
        Name     = $Name
        Status   = $Status
        Expected = $Expected
        Actual   = $Actual
        Message  = $Message
    }
}

function Add-ValidationResult {
    param(
        [AllowEmptyCollection()][System.Collections.Generic.List[object]]$Results,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [string]$Message = ''
    )

    $status = if ($Passed) { 'Passed' } else { 'Failed' }
    [void]$Results.Add((New-ValidationResult -Name $Name -Status $status -Expected $Expected -Actual $Actual -Message $Message))
}

function Add-SkippedResult {
    param(
        [AllowEmptyCollection()][System.Collections.Generic.List[object]]$Results,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [string]$Message = ''
    )

    [void]$Results.Add((New-ValidationResult -Name $Name -Status Skipped -Expected $Expected -Actual $Actual -Message $Message))
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
        return Get-ADComputer -Identity $ComputerName -Properties Description, Enabled, ServicePrincipalName, msDS-AllowedToActOnBehalfOfOtherIdentity, PrincipalsAllowedToDelegateToAccount, SID, whenChanged, whenCreated @AdServerParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

function Get-ScenarioUserBySamOrNull {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)

    $escapedSam = ConvertTo-LdapFilterValue -Value $SamAccountName
    $users = @(Get-ADUser -LDAPFilter "(sAMAccountName=$escapedSam)" -Properties Enabled, SID @AdServerParameters -ErrorAction Stop)
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

function Test-RbcdDescriptorHasScenarioAccessMask {
    param(
        [AllowNull()][System.Security.AccessControl.RawSecurityDescriptor]$Descriptor,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$ExpectedSid
    )

    if ($null -eq $Descriptor -or $null -eq $Descriptor.DiscretionaryAcl) {
        return $false
    }
    $matchingAces = @($Descriptor.DiscretionaryAcl | Where-Object {
        $_.AceType -eq [System.Security.AccessControl.AceType]::AccessAllowed -and
        $null -ne $_.SecurityIdentifier -and
        [string]$_.SecurityIdentifier.Value -eq [string]$ExpectedSid.Value
    })
    if ($matchingAces.Count -ne 1) {
        return $false
    }
    return ([int]$matchingAces[0].AccessMask -eq [int]$script:RbcdAccessMask)
}

function ConvertTo-StringArray {
    param([AllowNull()]$Value)

    if ($null -eq $Value) {
        return @()
    }
    if ($Value -is [array] -and -not ($Value -is [byte[]])) {
        return @($Value | ForEach-Object { [string]$_ })
    }
    if ($Value -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) {
        return @($Value | ForEach-Object { [string]$_ })
    }
    return @([string]$Value)
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

function Format-Ace {
    param([Parameter(Mandatory = $true)]$AccessRule)

    return '{0};{1};{2};ObjectType={3};Inherited={4}' -f
        $AccessRule.IdentityReference,
        $AccessRule.AccessControlType,
        $AccessRule.ActiveDirectoryRights,
        $AccessRule.ObjectType,
        $AccessRule.IsInherited
}

function Get-PrincipalAceSummary {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    Ensure-AdDrive
    $acl = Get-Acl -Path "AD:\$DistinguishedName" -ErrorAction Stop
    return [string[]]@($acl.Access | Where-Object {
        -not $_.IsInherited -and (Test-IdentityReferenceMatchesSid -IdentityReference $_.IdentityReference -Sid $PrincipalSid)
    } | ForEach-Object { Format-Ace -AccessRule $_ })
}

function Get-RbcdWriteAceCount {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$PrincipalSid
    )

    Ensure-AdDrive
    $acl = Get-Acl -Path "AD:\$DistinguishedName" -ErrorAction Stop
    return @($acl.Access | Where-Object { -not $_.IsInherited -and (Test-RbcdWriteAce -AccessRule $_ -PrincipalSid $PrincipalSid) }).Count
}

function Get-DomainMachineAccountQuota {
    param([Parameter(Mandatory = $true)][string]$DomainDistinguishedName)

    $domainObject = Get-ADObject -Identity $DomainDistinguishedName -Properties ms-DS-MachineAccountQuota @AdServerParameters -ErrorAction Stop
    return [int]$domainObject.'ms-DS-MachineAccountQuota'
}

$domain = Get-ADDomain @AdServerParameters -ErrorAction Stop
if ([string]$domain.DNSRoot -ine 'ad.lab.exceeds.test') {
    throw "Current domain '$($domain.DNSRoot)' is not the expected Baseline 06 domain 'ad.lab.exceeds.test'."
}

$results = New-Object 'System.Collections.Generic.List[object]'
$resourceComputer = Get-ScenarioComputerOrNull -ComputerName $ResourceComputerName
$delegatingComputer = Get-ScenarioComputerOrNull -ComputerName $DelegatingComputerName
$controlComputer = Get-ScenarioComputerOrNull -ComputerName $ControlComputerName
$delegatedWriter = Get-ScenarioUserBySamOrNull -SamAccountName $DelegatedWriterSamAccountName

Add-ValidationResult -Results $results -Name 'Resource computer exists' -Passed ($null -ne $resourceComputer) -Expected $ResourceComputerName -Actual $(if ($null -eq $resourceComputer) { '<missing>' } else { $resourceComputer.DistinguishedName })
Add-ValidationResult -Results $results -Name 'Delegating computer exists' -Passed ($null -ne $delegatingComputer) -Expected $DelegatingComputerName -Actual $(if ($null -eq $delegatingComputer) { '<missing>' } else { $delegatingComputer.DistinguishedName })
Add-ValidationResult -Results $results -Name 'Control computer exists' -Passed ($null -ne $controlComputer) -Expected $ControlComputerName -Actual $(if ($null -eq $controlComputer) { '<missing>' } else { $controlComputer.DistinguishedName })
Add-ValidationResult -Results $results -Name 'Delegated writer exists' -Passed ($null -ne $delegatedWriter) -Expected $DelegatedWriterSamAccountName -Actual $(if ($null -eq $delegatedWriter) { '<missing>' } else { $delegatedWriter.DistinguishedName })

if ($null -ne $resourceComputer -and $null -ne $delegatingComputer -and $null -ne $controlComputer -and $null -ne $delegatedWriter) {
    $descriptor = ConvertTo-RbcdRawSecurityDescriptor -Value $resourceComputer.($script:RbcdAttribute) -DistinguishedName ([string]$resourceComputer.DistinguishedName)
    $allowedSidValues = @(Get-RbcdAllowedSidValues -Descriptor $descriptor)
    $principalsAllowed = @(ConvertTo-StringArray -Value $resourceComputer.PrincipalsAllowedToDelegateToAccount)
    $resourceSpns = @(ConvertTo-StringArray -Value $resourceComputer.ServicePrincipalName)
    $delegatingSpns = @(ConvertTo-StringArray -Value $delegatingComputer.ServicePrincipalName)
    $writerAceCount = Get-RbcdWriteAceCount -DistinguishedName ([string]$resourceComputer.DistinguishedName) -PrincipalSid $delegatedWriter.SID
    $machineAccountQuota = Get-DomainMachineAccountQuota -DomainDistinguishedName ([string]$domain.DistinguishedName)

    Add-ValidationResult -Results $results -Name 'S4U2Proxy metadata: RBCD attribute present' -Passed ($null -ne $descriptor) -Expected 'Security descriptor set' -Actual $(if ($null -eq $descriptor) { '<not set>' } else { $descriptor.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All) })
    Add-ValidationResult -Results $results -Name 'Delegating computer is allowed on resource' -Passed ($allowedSidValues -contains [string]$delegatingComputer.SID.Value) -Expected ([string]$delegatingComputer.SID.Value) -Actual ($allowedSidValues -join ', ')
    Add-ValidationResult -Results $results -Name 'RBCD descriptor uses scenario access mask' -Passed (Test-RbcdDescriptorHasScenarioAccessMask -Descriptor $descriptor -ExpectedSid $delegatingComputer.SID) -Expected ('0x{0:X}' -f $script:RbcdAccessMask) -Actual $(if ($null -eq $descriptor) { '<not set>' } else { $descriptor.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All) })
    Add-ValidationResult -Results $results -Name 'Control computer is not allowed' -Passed (-not ($allowedSidValues -contains [string]$controlComputer.SID.Value)) -Expected "No $($controlComputer.SID.Value)" -Actual ($allowedSidValues -join ', ')
    Add-ValidationResult -Results $results -Name 'Delegated writer has RBCD WriteProperty' -Passed ($writerAceCount -gt 0) -Expected 'svc_web explicit WriteProperty ACE on msDS-AllowedToActOnBehalfOfOtherIdentity' -Actual "Count=$writerAceCount"
    Add-ValidationResult -Results $results -Name 'PrincipalsAllowedToDelegateToAccount resolves delegating computer' -Passed (($principalsAllowed -join ';') -imatch [regex]::Escape($DelegatingComputerName)) -Expected $DelegatingComputerName -Actual ($principalsAllowed -join '; ')
    if ($resourceSpns.Count -gt 0) {
        Add-ValidationResult -Results $results -Name 'Resource computer has SPN surface' -Passed $true -Expected 'Observation only' -Actual ($resourceSpns -join '; ') -Message 'RBCD controls delegation permission, but the requested target service still depends on SPN selection.'
    }
    else {
        Add-SkippedResult -Results $results -Name 'Resource computer has SPN surface' -Expected 'Observation only' -Actual '<none on prestaged object>' -Message 'A prestaged but never domain-joined computer object may not have HOST or service SPNs yet.'
    }
    if ($delegatingSpns.Count -gt 0) {
        Add-ValidationResult -Results $results -Name 'Delegating computer has SPN surface' -Passed $true -Expected 'Observation only' -Actual ($delegatingSpns -join '; ') -Message 'This is the service principal surface used when testing S4U2Self.'
    }
    else {
        Add-SkippedResult -Results $results -Name 'Delegating computer has SPN surface' -Expected 'Observation only' -Actual '<none on prestaged object>' -Message 'A prestaged but never domain-joined computer object may not have HOST or service SPNs yet.'
    }
    Add-ValidationResult -Results $results -Name 'MachineAccountQuota observed' -Passed ($machineAccountQuota -ge 0) -Expected 'Read current value without changing it' -Actual $machineAccountQuota -Message 'MachineAccountQuota is intentionally not changed by this scenario.'

    if ($IncludeAcl) {
        $aceSummaries = @(Get-PrincipalAceSummary -DistinguishedName ([string]$resourceComputer.DistinguishedName) -PrincipalSid $delegatedWriter.SID)
        Add-ValidationResult -Results $results -Name 'Delegated writer explicit ACE summary' -Passed ($aceSummaries.Count -gt 0) -Expected 'At least one explicit ACE' -Actual ($aceSummaries -join ' | ')
    }
}
else {
    Add-SkippedResult -Results $results -Name 'RBCD checks' -Expected 'All baseline objects present' -Actual 'One or more objects are missing'
}

$resultRows = $results.ToArray()
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $parent = Split-Path -Parent $OutputPath
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $resultRows | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
}

$failed = @($resultRows | Where-Object Status -eq 'Failed')
if ($FailOnValidationError -and $failed.Count -gt 0) {
    $failedNames = @($failed | ForEach-Object { $_.Name })
    throw "$script:ScenarioName validation failed: $($failedNames -join '; ')"
}

if ($PassThru) {
    return $resultRows
}

$resultRows | Format-Table -AutoSize
