#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ScenarioOuName = 'KeyCredentialLink-Lab',
    [string]$SampleSamAccountName = 'kcl.sample',
    [string]$ControlSamAccountName = 'kcl.control',
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScenarioName = 'KeyCredentialLink-Observation'
$script:Marker = 'windows-ad-lab:KeyCredentialLink-Observation'
$script:RootOuName = 'LAB'
$script:Changed = $false

$AdServerParameters = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $AdServerParameters['Server'] = $Server
}

Import-Module ActiveDirectory -ErrorAction Stop

function ConvertTo-LdapFilterValue {
    param([Parameter(Mandatory = $true)][string]$Value)

    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace(([string][char]0), '\00')
}

function Get-AdOrganizationalUnitOrNull {
    param([Parameter(Mandatory = $true)][string]$DistinguishedName)

    try {
        return Get-ADOrganizationalUnit -Identity $DistinguishedName -Properties adminDescription, ProtectedFromAccidentalDeletion @AdServerParameters -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

function Get-ScenarioUserBySamOrNull {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)

    $escapedSam = ConvertTo-LdapFilterValue -Value $SamAccountName
    $users = @(Get-ADUser -LDAPFilter "(sAMAccountName=$escapedSam)" -Properties adminDescription @AdServerParameters)
    if ($users.Count -gt 1) {
        throw "Multiple users were returned for sAMAccountName '$SamAccountName'."
    }
    if ($users.Count -eq 0) {
        return $null
    }
    return $users[0]
}

function Remove-ScenarioUser {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)

    $user = Get-ScenarioUserBySamOrNull -SamAccountName $SamAccountName
    if ($null -eq $user) {
        return
    }
    if ([string]$user.adminDescription -cne $script:Marker) {
        throw "User '$SamAccountName' exists but is not marked for this scenario. Refusing to delete it."
    }

    if ($PSCmdlet.ShouldProcess($user.DistinguishedName, 'Delete scenario user')) {
        Remove-ADObject -Identity $user.DistinguishedName -Confirm:$false @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }
}

function Remove-ScenarioOuIfEmpty {
    param([Parameter(Mandatory = $true)][string]$DistinguishedName)

    $ou = Get-AdOrganizationalUnitOrNull -DistinguishedName $DistinguishedName
    if ($null -eq $ou) {
        return
    }
    if ([string]$ou.adminDescription -cne $script:Marker) {
        throw "OU '$DistinguishedName' exists but is not marked for this scenario. Refusing to delete it."
    }

    $children = @(Get-ADObject -SearchBase $DistinguishedName -SearchScope OneLevel -LDAPFilter '(objectClass=*)' @AdServerParameters)
    if ($children.Count -gt 0) {
        if ($WhatIfPreference) {
            Write-Host "WhatIf: scenario OU still contains $($children.Count) child object(s); deletion would be retried after deleting managed users."
            return
        }
        $childList = (($children | Select-Object -ExpandProperty DistinguishedName) -join '; ')
        throw "Scenario OU still contains object(s) not removed by cleanup: $childList"
    }

    if ([bool]$ou.ProtectedFromAccidentalDeletion -and $PSCmdlet.ShouldProcess($DistinguishedName, 'Disable accidental deletion protection')) {
        Set-ADOrganizationalUnit -Identity $DistinguishedName -ProtectedFromAccidentalDeletion $false @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }
    if ($PSCmdlet.ShouldProcess($DistinguishedName, 'Delete scenario OU')) {
        Remove-ADOrganizationalUnit -Identity $DistinguishedName -Confirm:$false @AdServerParameters -ErrorAction Stop
        $script:Changed = $true
    }
}

function Assert-BaselineRestored {
    param(
        [Parameter(Mandatory = $true)][string]$ScenarioOuDn,
        [Parameter(Mandatory = $true)][string[]]$SamAccountNames,
        [Parameter(Mandatory = $true)][string]$DomainDn
    )

    $remaining = New-Object 'System.Collections.Generic.List[string]'
    if ($null -ne (Get-AdOrganizationalUnitOrNull -DistinguishedName $ScenarioOuDn)) {
        $remaining.Add($ScenarioOuDn)
    }
    foreach ($sam in $SamAccountNames) {
        $user = Get-ScenarioUserBySamOrNull -SamAccountName $sam
        if ($null -ne $user) {
            $remaining.Add($user.DistinguishedName)
        }
    }

    $escapedMarker = ConvertTo-LdapFilterValue -Value $script:Marker
    $markedObjects = @(Get-ADObject -SearchBase $DomainDn -SearchScope Subtree -LDAPFilter "(adminDescription=$escapedMarker)" @AdServerParameters)
    foreach ($markedObject in $markedObjects) {
        if ($remaining -notcontains [string]$markedObject.DistinguishedName) {
            $remaining.Add([string]$markedObject.DistinguishedName)
        }
    }

    if ($remaining.Count -gt 0) {
        throw "Cleanup finished but Baseline 06 does not match. Remaining scenario object(s): $($remaining.ToArray() -join '; ')"
    }
}

$domain = Get-ADDomain @AdServerParameters -ErrorAction Stop
if ([string]$domain.DNSRoot -ine 'ad.lab.exceeds.test') {
    throw "Current domain '$($domain.DNSRoot)' is not the expected Baseline 06 domain 'ad.lab.exceeds.test'."
}

$domainDn = [string]$domain.DistinguishedName
$rootOuDn = "OU=$script:RootOuName,$domainDn"
$scenarioOuDn = "OU=$ScenarioOuName,$rootOuDn"

Remove-ScenarioUser -SamAccountName $SampleSamAccountName
Remove-ScenarioUser -SamAccountName $ControlSamAccountName
Remove-ScenarioOuIfEmpty -DistinguishedName $scenarioOuDn
if ($WhatIfPreference) {
    Write-Host 'WhatIf: Baseline restored check skipped because no objects were deleted.'
}
else {
    Assert-BaselineRestored -ScenarioOuDn $scenarioOuDn -SamAccountNames @($SampleSamAccountName, $ControlSamAccountName) -DomainDn $domainDn
}

[pscustomobject]@{
    Scenario          = $script:ScenarioName
    Changed           = $script:Changed
    Baseline          = '06-ADCS-HTTP-CDP'
    BaselineRestored  = (-not $WhatIfPreference)
    RemovedObjects    = @($SampleSamAccountName, $ControlSamAccountName, $scenarioOuDn)
}
