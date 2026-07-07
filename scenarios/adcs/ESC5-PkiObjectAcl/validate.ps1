#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$ControlPrincipal = 'bob.taylor',
    [string]$OutputPath,
    [string]$Server,
    [switch]$FailOnValidationError
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

function Get-NtAuthCertificatesObjectOrNull {
    $rootDse = Get-ADRootDSE @AdServerParameters
    $dn = "CN=$script:NtAuthCommonName,CN=Public Key Services,CN=Services,$($rootDse.configurationNamingContext)"
    try {
        return Get-ADObject -Identity $dn -Properties objectClass @AdServerParameters -ErrorAction Stop
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

function Test-NtAuthGenericAllRight {
    param(
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][string]$QualifiedPrincipal
    )

    $sid = (New-Object Security.Principal.NTAccount($QualifiedPrincipal)).Translate([Security.Principal.SecurityIdentifier])
    Ensure-AdDrive
    $acl = Get-Acl -Path "AD:\$DistinguishedName" -ErrorAction Stop
    $matches = New-Object System.Collections.Generic.List[string]
    foreach ($accessRule in @($acl.Access)) {
        if (Test-GenericAllAccessRule -AccessRule $accessRule -Sid $sid) {
            $matches.Add("$($accessRule.IdentityReference):$($accessRule.ActiveDirectoryRights)")
        }
    }
    return [pscustomobject]@{
        HasGenericAll = ($matches.Count -gt 0)
        Rules         = @($matches)
    }
}

$results = New-Object System.Collections.Generic.List[object]
$differences = New-Object System.Collections.Generic.List[object]
$qualifiedPrincipal = Get-QualifiedPrincipalName -Principal $ControlPrincipal

try {
    $controlUser = Get-ADUser -Identity $ControlPrincipal @AdServerParameters -ErrorAction SilentlyContinue
    Add-ValidationResult -Results $results -Name 'Control principal exists' -Passed ($null -ne $controlUser) -Expected $ControlPrincipal -Actual $(if ($null -eq $controlUser) { 'Missing' } else { [string]$controlUser.SamAccountName })

    $ntAuth = Get-NtAuthCertificatesObjectOrNull
    Add-ValidationResult -Results $results -Name 'NTAuthCertificates exists' -Passed ($null -ne $ntAuth) -Expected "CN=$script:NtAuthCommonName" -Actual $(if ($null -eq $ntAuth) { 'Missing' } else { $ntAuth.DistinguishedName })

    if ($null -eq $ntAuth -or $null -eq $controlUser) {
        $results.Add((New-ValidationResult -Name 'GenericAll permission' -Status Failed -Expected "Allow GenericAll for $qualifiedPrincipal" -Actual 'Prerequisite missing'))
    }
    else {
        $acl = Test-NtAuthGenericAllRight -DistinguishedName ([string]$ntAuth.DistinguishedName) -QualifiedPrincipal $qualifiedPrincipal
        Add-ValidationResult -Results $results -Name 'GenericAll permission' -Passed ([bool]$acl.HasGenericAll) -Expected "Allow GenericAll for $qualifiedPrincipal on NTAuthCertificates" -Actual (($acl.Rules) -join '; ') -Message 'ESC5 is PKI-object control. This fixture does not grant Manage CA and does not modify a certificate template.'
    }

    $differences.Add((New-RecommendationDifference -Setting 'NTAuth store ACL' -MicrosoftRecommended 'Only Enterprise Admins / PKI administrators should write NTAuthCertificates.' -LabTemplate "GenericAll is granted to $qualifiedPrincipal." -Impact 'A low-privilege principal could add a rogue CA certificate to the NT authentication store.'))
    $differences.Add((New-RecommendationDifference -Setting 'Object class' -MicrosoftRecommended 'Treat Public Key Services containers as tier-0 objects, not ordinary AD objects.' -LabTemplate 'The ACE is on NTAuthCertificates, not a certificate template and not the CA security SD.' -Impact 'This is ESC5, distinct from ESC4 and ESC7.'))

    $failed = @($results | Where-Object Status -eq 'Failed').Count
    $status = if ($failed -eq 0) { 'Passed' } else { 'Failed' }
    $report = [pscustomobject]@{
        Status                          = $status
        ControlPrincipal                = $qualifiedPrincipal
        PkiObject                       = if ($null -eq $ntAuth) { '' } else { [string]$ntAuth.DistinguishedName }
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
        throw "ESC5 PKI object ACL validation failed with $failed failed check(s)."
    }

    $report
}
catch {
    throw
}
