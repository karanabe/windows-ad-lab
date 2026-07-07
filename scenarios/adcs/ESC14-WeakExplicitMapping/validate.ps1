#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$ControlPrincipal = 'alice.brown',
    [string]$TargetUser = 'operator01',
    [string]$OutputPath,
    [string]$Server,
    [switch]$FailOnValidationError
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
        [System.Collections.Generic.List[object]]$Results,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [string]$Message = ''
    )

    $status = if ($Passed) { 'Passed' } else { 'Failed' }
    $Results.Add((New-ValidationResult -Name $Name -Status $status -Expected $Expected -Actual $Actual -Message $Message))
}

function New-RecommendationDifference {
    param(
        [Parameter(Mandatory = $true)][string]$Setting,
        [Parameter(Mandatory = $true)][string]$MicrosoftRecommended,
        [Parameter(Mandatory = $true)][string]$LabTemplate,
        [Parameter(Mandatory = $true)][string]$Impact
    )

    return [pscustomobject]@{
        Setting              = $Setting
        MicrosoftRecommended = $MicrosoftRecommended
        LabTemplate          = $LabTemplate
        Impact               = $Impact
    }
}

function Get-AltSecurityIdentitiesSchemaId {
    $rootDse = Get-ADRootDSE @AdServerParameters
    $schemaNc = [string]$rootDse.schemaNamingContext
    $schemaObjects = @(Get-ADObject -SearchBase $schemaNc -SearchScope OneLevel -LDAPFilter "(&(objectClass=attributeSchema)(lDAPDisplayName=$script:AltSecurityIdentitiesAttribute))" -Properties schemaIDGUID @AdServerParameters)
    if ($schemaObjects.Count -ne 1) {
        throw "Expected one schema attribute named '$script:AltSecurityIdentitiesAttribute', found $($schemaObjects.Count)."
    }
    return New-Object System.Guid (, [byte[]]$schemaObjects[0].schemaIDGUID)
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

function Test-MappingIsWeakRfc822 {
    param([AllowNull()][string]$Value)

    return (-not [string]::IsNullOrWhiteSpace($Value) -and $Value -like 'X509:<RFC822>*')
}

function Test-MappingIsStrong {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return ($Value -like 'X509:<SKI>*' -or $Value -like 'X509:<SHA1-PUKEY>*' -or $Value -like 'X509:<I>*<SR>*')
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

$results = New-Object System.Collections.Generic.List[object]
$differences = New-Object System.Collections.Generic.List[object]
$qualifiedPrincipal = Get-QualifiedPrincipalName -Principal $ControlPrincipal
$domain = Get-ADDomain @AdServerParameters

try {
    $controlUser = Get-ADUser -Identity $ControlPrincipal -Properties UserPrincipalName, mail @AdServerParameters -ErrorAction SilentlyContinue
    Add-ValidationResult -Results $results -Name 'Control principal exists' -Passed ($null -ne $controlUser) -Expected $ControlPrincipal -Actual $(if ($null -eq $controlUser) { 'Missing' } else { [string]$controlUser.SamAccountName })

    $target = Get-ADUser -Identity $TargetUser -Properties altSecurityIdentities @AdServerParameters -ErrorAction SilentlyContinue
    Add-ValidationResult -Results $results -Name 'Target user exists' -Passed ($null -ne $target) -Expected $TargetUser -Actual $(if ($null -eq $target) { 'Missing' } else { [string]$target.SamAccountName })

    $expectedMapping = ''
    $attributeGuid = $null
    if ($null -ne $controlUser) {
        $expectedMapping = Get-WeakRfc822Mapping -ControlUser $controlUser -Domain $domain
    }

    if ($null -eq $controlUser -or $null -eq $target) {
        $results.Add((New-ValidationResult -Name 'WriteProperty altSecurityIdentities' -Status Failed -Expected "Allow WriteProperty for $qualifiedPrincipal" -Actual 'Prerequisite missing'))
        $results.Add((New-ValidationResult -Name 'Weak RFC822 mapping' -Status Failed -Expected $expectedMapping -Actual 'Prerequisite missing'))
    }
    else {
        $attributeGuid = Get-AltSecurityIdentitiesSchemaId
        $sid = (New-Object Security.Principal.NTAccount($qualifiedPrincipal)).Translate([Security.Principal.SecurityIdentifier])
        Ensure-AdDrive
        $acl = Get-Acl -Path "AD:\$($target.DistinguishedName)" -ErrorAction Stop
        $matches = New-Object System.Collections.Generic.List[string]
        foreach ($accessRule in @($acl.Access)) {
            if (Test-AltSecurityIdentitiesWriteRule -AccessRule $accessRule -Sid $sid -AttributeGuid $attributeGuid) {
                [void]$matches.Add("$($accessRule.IdentityReference):$($accessRule.ActiveDirectoryRights):$($accessRule.ObjectType)")
            }
        }
        Add-ValidationResult -Results $results -Name 'WriteProperty altSecurityIdentities' -Passed ($matches.Count -gt 0) -Expected "Allow WriteProperty(altSecurityIdentities) for $qualifiedPrincipal" -Actual (($matches.ToArray()) -join '; ') -Message 'ESC14 Scenario A is write access on altSecurityIdentities, not template ACL (ESC4) and not Manage CA (ESC7).'

        $actualMappings = @(ConvertTo-StringArray -Value $target.altSecurityIdentities)
        $hasExpected = $false
        $strongPresent = $false
        foreach ($item in $actualMappings) {
            if ([string]$item -ceq $expectedMapping) { $hasExpected = $true }
            if (Test-MappingIsStrong -Value $item) { $strongPresent = $true }
        }
        Add-ValidationResult -Results $results -Name 'Weak RFC822 mapping' -Passed $hasExpected -Expected $expectedMapping -Actual ($actualMappings -join '; ') -Message 'This fixture uses X509:<RFC822>, not X509:<SKI> or X509:<SHA1-PUKEY>.'
        Add-ValidationResult -Results $results -Name 'Strong mapping absent' -Passed (-not $strongPresent) -Expected 'No SKI / SHA1-PUKEY / Issuer+Serial mapping' -Actual ($actualMappings -join '; ')
        Add-ValidationResult -Results $results -Name 'Mapping is weak RFC822' -Passed (Test-MappingIsWeakRfc822 -Value $expectedMapping) -Expected 'X509:<RFC822>...' -Actual $expectedMapping
    }

    $differences.Add((New-RecommendationDifference -Setting 'Explicit mapping strength' -MicrosoftRecommended 'Use X509:<SKI> or X509:<SHA1-PUKEY>, or Issuer plus serial.' -LabTemplate "The target has $expectedMapping." -Impact 'A certificate whose SAN RFC822 matches the control principal can map to the target account.'))
    $differences.Add((New-RecommendationDifference -Setting 'altSecurityIdentities ACL' -MicrosoftRecommended 'Do not grant WriteProperty(altSecurityIdentities) to a low-privilege principal.' -LabTemplate "WriteProperty is granted to $qualifiedPrincipal on $TargetUser." -Impact 'The control principal can replace the mapping with one that matches a certificate they can enroll.'))
    $differences.Add((New-RecommendationDifference -Setting 'Scope' -MicrosoftRecommended 'Treat explicit mapping as a certificate-to-account binding, not a template or CA flag.' -LabTemplate 'No template is created and CT_FLAG_NO_SECURITY_EXTENSION is not set.' -Impact 'This fixture is ESC14, not ESC9 or ESC10.'))

    $failed = @($results | Where-Object Status -eq 'Failed').Count
    $status = if ($failed -eq 0) { 'Passed' } else { 'Failed' }
    $report = [pscustomobject]@{
        Status                          = $status
        ControlPrincipal                = $qualifiedPrincipal
        TargetUser                      = $TargetUser
        WeakMapping                     = $expectedMapping
        Results                         = $results.ToArray()
        MicrosoftRecommendedDifferences = $differences.ToArray()
    }

    Write-Host ''
    Write-Host 'Validation'
    $results | Format-Table -AutoSize | Out-Host
    Write-Host ''
    Write-Host 'Microsoft recommended differences'
    $differences | Format-Table -AutoSize | Out-Host

    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $parent = Split-Path -Parent $OutputPath
        if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    }

    if ($FailOnValidationError -and $failed -gt 0) {
        throw "ESC14 weak explicit mapping validation failed with $failed failed check(s)."
    }

    $report
}
catch {
    throw
}
