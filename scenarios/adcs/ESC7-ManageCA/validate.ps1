#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$ControlPrincipal = 'operator01',
    [string]$CACommonName,
    [string]$OutputPath,
    [string]$Server,
    [switch]$FailOnValidationError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CaAccessManageCa = 0x00000001
$script:WindowsGenericAll = 0x10000000
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

function Get-CaSecurityDescriptorOrNull {
    param([Parameter(Mandatory = $true)][string]$RegistryPath)

    try {
        $security = (Get-ItemProperty -Path $RegistryPath -Name Security -ErrorAction Stop).Security
    }
    catch {
        return $null
    }
    if ($null -eq $security) {
        return $null
    }
    $valueObject = $security.PSObject.BaseObject
    if ($valueObject -isnot [byte[]]) {
        return $null
    }
    return New-Object System.Security.AccessControl.CommonSecurityDescriptor $false, $false, ([byte[]]$valueObject), 0
}

function Get-CaEnrollmentServiceOrNull {
    param([Parameter(Mandatory = $true)][string]$Name)

    $rootDse = Get-ADRootDSE @AdServerParameters
    $searchBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$($rootDse.configurationNamingContext)"
    $escapedName = ConvertTo-LdapFilterValue -Value $Name
    $caObjects = @(Get-ADObject -SearchBase $searchBase -SearchScope OneLevel -LDAPFilter "(cn=$escapedName)" @AdServerParameters)
    if ($caObjects.Count -ne 1) {
        return $null
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

$results = New-Object System.Collections.Generic.List[object]
$differences = New-Object System.Collections.Generic.List[object]
$qualifiedPrincipal = Get-QualifiedPrincipalName -Principal $ControlPrincipal

try {
    $controlUser = Get-ADUser -Identity $ControlPrincipal @AdServerParameters -ErrorAction SilentlyContinue
    Add-ValidationResult -Results $results -Name 'Control principal exists' -Passed ($null -ne $controlUser) -Expected $ControlPrincipal -Actual $(if ($null -eq $controlUser) { 'Missing' } else { [string]$controlUser.SamAccountName })

    $caName = Get-ActiveCaName -RequestedName $CACommonName
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName"
    $descriptor = Get-CaSecurityDescriptorOrNull -RegistryPath $registryPath
    Add-ValidationResult -Results $results -Name 'CA security descriptor' -Passed ($null -ne $descriptor -and $null -ne $descriptor.DiscretionaryAcl) -Expected $registryPath -Actual $(if ($null -eq $descriptor) { 'Missing' } else { 'Present' })

    $sid = $null
    if ($null -ne $controlUser) {
        $sid = (New-Object Security.Principal.NTAccount($qualifiedPrincipal)).Translate([Security.Principal.SecurityIdentifier])
    }

    $registryManageCa = $false
    $registryGenericAll = $false
    $registryMasks = New-Object System.Collections.Generic.List[string]
    if ($null -ne $descriptor -and $null -ne $descriptor.DiscretionaryAcl -and $null -ne $sid) {
        foreach ($ace in @($descriptor.DiscretionaryAcl)) {
            if ($ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowed) { continue }
            if ([string]$ace.SecurityIdentifier.Value -ne [string]$sid.Value) { continue }
            $registryMasks.Add(('0x{0:X8}' -f [int]$ace.AccessMask))
            if (($ace.AccessMask -band $script:CaAccessManageCa) -eq $script:CaAccessManageCa) {
                $registryManageCa = $true
            }
            if (($ace.AccessMask -band $script:WindowsGenericAll) -eq $script:WindowsGenericAll) {
                $registryGenericAll = $true
            }
        }
    }
    Add-ValidationResult -Results $results -Name 'Registry ManageCA' -Passed $registryManageCa -Expected "Allow ManageCA (0x1) for $qualifiedPrincipal" -Actual $(if ($registryMasks.Count -eq 0) { 'None' } else { ($registryMasks.ToArray() -join '; ') })
    Add-ValidationResult -Results $results -Name 'Registry GenericAll absent' -Passed (-not $registryGenericAll) -Expected 'ManageCA without GenericAll' -Actual $(if ($registryGenericAll) { 'GenericAll present' } else { 'Absent' }) -Message 'ESC7 is Manage CA, not ESC5 GenericAll on a PKI object.'

    $ca = Get-CaEnrollmentServiceOrNull -Name $caName
    Add-ValidationResult -Results $results -Name 'CA enrollment service exists' -Passed ($null -ne $ca) -Expected $caName -Actual $(if ($null -eq $ca) { 'Missing' } else { $ca.DistinguishedName })

    $adManageCa = $false
    $adGenericAll = $false
    $adRules = New-Object System.Collections.Generic.List[string]
    if ($null -ne $ca -and $null -ne $sid) {
        Ensure-AdDrive
        $acl = Get-Acl -Path "AD:\$($ca.DistinguishedName)" -ErrorAction Stop
        foreach ($accessRule in @($acl.Access)) {
            if ($accessRule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            if ($accessRule.IsInherited) { continue }
            if (-not (Test-IdentityReferenceMatchesSid -IdentityReference $accessRule.IdentityReference -Sid $sid)) { continue }
            $adRules.Add("$($accessRule.IdentityReference):$($accessRule.ActiveDirectoryRights)")
            if (($accessRule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) {
                $adGenericAll = $true
            }
            if (($accessRule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild) -eq [System.DirectoryServices.ActiveDirectoryRights]::CreateChild) {
                $adManageCa = $true
            }
        }
    }
    Add-ValidationResult -Results $results -Name 'AD ManageCA' -Passed $adManageCa -Expected "Allow access mask 0x1 for $qualifiedPrincipal on the CA AD object" -Actual $(if ($adRules.Count -eq 0) { 'None' } else { ($adRules.ToArray() -join '; ') })
    Add-ValidationResult -Results $results -Name 'AD GenericAll absent' -Passed (-not $adGenericAll) -Expected 'ManageCA without GenericAll' -Actual $(if ($adGenericAll) { 'GenericAll present' } else { 'Absent' }) -Message 'This fixture is ESC7, not ESC5.'

    $differences.Add((New-RecommendationDifference -Setting 'CA security' -MicrosoftRecommended 'Grant Manage CA only to a dedicated PKI administrator group.' -LabTemplate "Manage CA is granted to $qualifiedPrincipal." -Impact 'A low-privilege principal can change CA flags, including enabling SAN on any request (ESC6).'))
    $differences.Add((New-RecommendationDifference -Setting 'Right type' -MicrosoftRecommended 'Separate Manage CA, Manage Certificates, and directory GenericAll on PKI objects.' -LabTemplate 'Only Manage CA (0x1) is granted. EDITF_ATTRIBUTESUBJECTALTNAME2 is not enabled.' -Impact 'ESC7 is the CA ACL. ESC6 would be the follow-on CA flag change.'))

    $failed = @($results | Where-Object Status -eq 'Failed').Count
    $status = if ($failed -eq 0) { 'Passed' } else { 'Failed' }
    $report = [pscustomobject]@{
        Status                          = $status
        ControlPrincipal                = $qualifiedPrincipal
        CACommonName                    = $caName
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
        throw "ESC7 Manage CA validation failed with $failed failed check(s)."
    }

    $report
}
catch {
    throw
}
