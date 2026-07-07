Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Esc16ScenarioName = 'ESC16-DisableExtensionList'
$script:Esc16StateRoot = Join-Path $env:ProgramData "ADLabBootstrap\Scenarios\$script:Esc16ScenarioName"
$script:Esc16StatePath = Join-Path $script:Esc16StateRoot 'state.json'
$script:Esc16CertSvcConfigurationRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
$script:Esc16DisableExtensionListValueName = 'DisableExtensionList'
$script:Esc16NtdsCaSecurityExtOid = '1.3.6.1.4.1.311.25.2'

function Get-Esc16ScenarioName {
    return $script:Esc16ScenarioName
}

function Get-Esc16StateRoot {
    return $script:Esc16StateRoot
}

function Get-Esc16StatePath {
    return $script:Esc16StatePath
}

function Get-Esc16NtdsCaSecurityExtOid {
    return $script:Esc16NtdsCaSecurityExtOid
}

function Get-Esc16PropertyValue {
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()]$Default = $null
    )

    if ($null -eq $InputObject) { return $Default }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
}

function ConvertTo-Esc16StringArray {
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
    if (-not [string]::IsNullOrWhiteSpace([string]$valueObject)) {
        return [string[]]@([string]$valueObject)
    }
    return @()
}

function Test-Esc16StringSetEqual {
    param(
        [AllowNull()]$Actual,
        [AllowNull()]$Expected
    )

    $actualValues = @(ConvertTo-Esc16StringArray -Value $Actual | Sort-Object)
    $expectedValues = @(ConvertTo-Esc16StringArray -Value $Expected | Sort-Object)
    if ($actualValues.Count -eq 0 -and $expectedValues.Count -eq 0) {
        return $true
    }
    return (@(Compare-Object -ReferenceObject $expectedValues -DifferenceObject $actualValues).Count -eq 0)
}

function Get-Esc16ActiveCaName {
    $active = (Get-ItemProperty -Path $script:Esc16CertSvcConfigurationRoot -Name Active -ErrorAction Stop).Active
    if ([string]::IsNullOrWhiteSpace([string]$active)) {
        throw 'No active local Certification Authority was found.'
    }
    return [string]$active
}

function Get-Esc16PolicyModulePath {
    param([string]$CAName)

    if ([string]::IsNullOrWhiteSpace($CAName)) {
        $CAName = Get-Esc16ActiveCaName
    }
    $policyRoot = Join-Path (Join-Path $script:Esc16CertSvcConfigurationRoot $CAName) 'PolicyModules'
    if (-not (Test-Path -LiteralPath $policyRoot -PathType Container)) {
        throw "CA policy module path '$policyRoot' was not found."
    }
    $active = ''
    try {
        $active = [string](Get-ItemProperty -LiteralPath $policyRoot -Name Active -ErrorAction Stop).Active
    }
    catch {
        $active = ''
    }
    if ([string]::IsNullOrWhiteSpace($active)) {
        $children = @(Get-ChildItem -LiteralPath $policyRoot -ErrorAction Stop)
        if ($children.Count -eq 1) {
            $active = [string]$children[0].PSChildName
        }
        else {
            throw "CA policy module Active value is missing under '$policyRoot'."
        }
    }
    return [pscustomobject]@{
        ActiveCaName      = $CAName
        PolicyModuleName  = $active
        PolicyModulePath  = (Join-Path $policyRoot $active)
    }
}

function Get-Esc16DisableExtensionListState {
    $certSvc = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
    $certSvcInstalled = ($null -ne $certSvc)
    $certSvcStatus = if ($certSvcInstalled) { [string]$certSvc.Status } else { 'Missing' }
    $certSvcStartType = if ($certSvcInstalled) { [string]$certSvc.StartType } else { 'Missing' }
    $activeCa = ''
    $policyModuleName = ''
    $policyModulePath = ''
    $valueExists = $false
    $extensions = @()
    $readable = $false
    $registryError = ''

    try {
        $policy = Get-Esc16PolicyModulePath
        $activeCa = [string]$policy.ActiveCaName
        $policyModuleName = [string]$policy.PolicyModuleName
        $policyModulePath = [string]$policy.PolicyModulePath
        $item = Get-ItemProperty -LiteralPath $policyModulePath -ErrorAction Stop
        $property = $item.PSObject.Properties[$script:Esc16DisableExtensionListValueName]
        if ($null -ne $property) {
            $valueExists = $true
            $extensions = @(ConvertTo-Esc16StringArray -Value $property.Value)
        }
        $readable = $true
    }
    catch {
        $registryError = $_.Exception.Message
    }

    $sidExtensionDisabled = $false
    foreach ($extension in @($extensions)) {
        if ([string]$extension -eq $script:Esc16NtdsCaSecurityExtOid) {
            $sidExtensionDisabled = $true
            break
        }
    }

    $caConfigured = ($certSvcInstalled -and $readable -and -not [string]::IsNullOrWhiteSpace($activeCa))
    $certSvcRunning = ([string]$certSvcStatus -eq 'Running')
    $vulnerable = ($caConfigured -and $sidExtensionDisabled)
    $hardened = ($caConfigured -and -not $sidExtensionDisabled)

    return [pscustomobject]@{
        CertSvcInstalled              = $certSvcInstalled
        CertSvcStatus                 = $certSvcStatus
        CertSvcStartType              = $certSvcStartType
        ActiveCaName                  = $activeCa
        PolicyModuleName              = $policyModuleName
        PolicyModulePath              = $policyModulePath
        DisableExtensionListExists    = $valueExists
        DisableExtensionList          = [string[]]$extensions
        DisableExtensionListReadable  = $readable
        DisableExtensionListError     = $registryError
        NtdsCaSecurityExtOid          = $script:Esc16NtdsCaSecurityExtOid
        SidSecurityExtensionDisabled  = $sidExtensionDisabled
        Vulnerable                    = $vulnerable
        Hardened                      = $hardened
        CertSvcRunning                = $certSvcRunning
    }
}

function Read-Esc16ScenarioState {
    if (-not (Test-Path -LiteralPath $script:Esc16StatePath -PathType Leaf)) {
        return $null
    }
    return (Get-Content -LiteralPath $script:Esc16StatePath -Raw -ErrorAction Stop | ConvertFrom-Json)
}

function Save-Esc16ScenarioState {
    param([Parameter(Mandatory = $true)]$State)

    if (-not (Test-Path -LiteralPath $script:Esc16StateRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $script:Esc16StateRoot -Force -ErrorAction Stop | Out-Null
    }
    $State | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:Esc16StatePath -Encoding UTF8 -ErrorAction Stop
}

function Initialize-Esc16ScenarioState {
    $existing = Read-Esc16ScenarioState
    if ($null -ne $existing) {
        return $existing
    }

    $current = Get-Esc16DisableExtensionListState
    if (-not [bool]$current.DisableExtensionListReadable) {
        throw "CA DisableExtensionList could not be read: $($current.DisableExtensionListError)"
    }
    $state = [ordered]@{
        SchemaVersion                    = 1
        ScenarioName                     = $script:Esc16ScenarioName
        CreatedAt                        = (Get-Date).ToString('o')
        UpdatedAt                        = (Get-Date).ToString('o')
        LastStage                        = ''
        ActiveCaNameBefore               = [string]$current.ActiveCaName
        PolicyModuleNameBefore           = [string]$current.PolicyModuleName
        DisableExtensionListExistsBefore = [bool]$current.DisableExtensionListExists
        DisableExtensionListBefore       = [string[]]@($current.DisableExtensionList)
        CertSvcStatusBefore              = [string]$current.CertSvcStatus
    }
    Save-Esc16ScenarioState -State $state
    return (Read-Esc16ScenarioState)
}

function Update-Esc16ScenarioState {
    param(
        [Parameter(Mandatory = $true)]$State,
        [string]$LastStage
    )

    $State | Add-Member -MemberType NoteProperty -Name UpdatedAt -Value (Get-Date).ToString('o') -Force
    if (-not [string]::IsNullOrWhiteSpace($LastStage)) {
        $State | Add-Member -MemberType NoteProperty -Name LastStage -Value $LastStage -Force
    }
    Save-Esc16ScenarioState -State $State
    return (Read-Esc16ScenarioState)
}

function Ensure-Esc16CertSvcRunning {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    $service = Get-Service -Name CertSvc -ErrorAction Stop
    if ($service.Status -eq 'Running') {
        return $false
    }
    if ($PSCmdlet.ShouldProcess('CertSvc', 'Start Certification Authority service')) {
        Start-Service -Name CertSvc -ErrorAction Stop
        $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(60))
        return $true
    }
    return $false
}

function Restart-Esc16CertSvc {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    $service = Get-Service -Name CertSvc -ErrorAction Stop
    if ($PSCmdlet.ShouldProcess('CertSvc', 'Restart Certification Authority service')) {
        if ($service.Status -eq 'Running') {
            Restart-Service -Name CertSvc -Force -ErrorAction Stop
        }
        else {
            Start-Service -Name CertSvc -ErrorAction Stop
        }
        $service = Get-Service -Name CertSvc -ErrorAction Stop
        $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(60))
        return $true
    }
    return $false
}

function Set-Esc16DisableExtensionList {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$PolicyModulePath,
        [AllowEmptyCollection()][string[]]$Extensions,
        [Parameter(Mandatory = $true)][bool]$ValueShouldExist
    )

    $current = Get-Esc16DisableExtensionListState
    if (-not [bool]$current.DisableExtensionListReadable) {
        throw "CA DisableExtensionList could not be read: $($current.DisableExtensionListError)"
    }

    $desired = @(ConvertTo-Esc16StringArray -Value $Extensions)
    $currentValues = @(ConvertTo-Esc16StringArray -Value $current.DisableExtensionList)
    if ([bool]$current.DisableExtensionListExists -eq $ValueShouldExist -and (Test-Esc16StringSetEqual -Actual $currentValues -Expected $desired)) {
        return $false
    }

    if (-not $ValueShouldExist) {
        if (-not [bool]$current.DisableExtensionListExists) {
            return $false
        }
        if ($PSCmdlet.ShouldProcess($PolicyModulePath, 'Remove DisableExtensionList')) {
            Remove-ItemProperty -LiteralPath $PolicyModulePath -Name $script:Esc16DisableExtensionListValueName -ErrorAction Stop
            return $true
        }
        return $false
    }

    if ($PSCmdlet.ShouldProcess($PolicyModulePath, "Set DisableExtensionList to $($desired -join ',')")) {
        if (-not [bool]$current.DisableExtensionListExists) {
            New-ItemProperty -LiteralPath $PolicyModulePath -Name $script:Esc16DisableExtensionListValueName -PropertyType MultiString -Value $desired -Force -ErrorAction Stop | Out-Null
        }
        else {
            Set-ItemProperty -LiteralPath $PolicyModulePath -Name $script:Esc16DisableExtensionListValueName -Value $desired -ErrorAction Stop
        }
        return $true
    }
    return $false
}

function Set-Esc16SidSecurityExtensionDisabled {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][bool]$Disabled)

    $current = Get-Esc16DisableExtensionListState
    if (-not [bool]$current.DisableExtensionListReadable) {
        throw "CA DisableExtensionList could not be read: $($current.DisableExtensionListError)"
    }

    $desired = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in @(ConvertTo-Esc16StringArray -Value $current.DisableExtensionList)) {
        if ([string]$item -ne $script:Esc16NtdsCaSecurityExtOid) {
            [void]$desired.Add([string]$item)
        }
    }
    if ($Disabled) {
        [void]$desired.Add($script:Esc16NtdsCaSecurityExtOid)
    }

    $valueShouldExist = ($desired.Count -gt 0 -or [bool]$current.DisableExtensionListExists)
    if ($desired.Count -eq 0 -and -not [bool]$current.DisableExtensionListExists) {
        $valueShouldExist = $false
    }
    if ($desired.Count -eq 0 -and [bool]$current.DisableExtensionListExists) {
        # Keep an empty REG_MULTI_SZ only when the value already existed with other OIDs removed.
        $valueShouldExist = $true
    }

    return (Set-Esc16DisableExtensionList -PolicyModulePath ([string]$current.PolicyModulePath) -Extensions ([string[]]$desired.ToArray()) -ValueShouldExist $valueShouldExist)
}

function Restore-Esc16DisableExtensionList {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$State)

    $current = Get-Esc16DisableExtensionListState
    if (-not [bool]$current.DisableExtensionListReadable) {
        throw "CA DisableExtensionList could not be read: $($current.DisableExtensionListError)"
    }

    $expectedCaName = [string](Get-Esc16PropertyValue -InputObject $State -Name 'ActiveCaNameBefore' -Default '')
    if (-not [string]::IsNullOrWhiteSpace($expectedCaName) -and [string]$current.ActiveCaName -ine $expectedCaName) {
        throw "Active CA changed from '$expectedCaName' to '$($current.ActiveCaName)'. Refusing to restore DisableExtensionList."
    }

    $existedBefore = [bool](Get-Esc16PropertyValue -InputObject $State -Name 'DisableExtensionListExistsBefore' -Default $false)
    $valuesBefore = @(ConvertTo-Esc16StringArray -Value (Get-Esc16PropertyValue -InputObject $State -Name 'DisableExtensionListBefore' -Default @()))
    return (Set-Esc16DisableExtensionList -PolicyModulePath ([string]$current.PolicyModulePath) -Extensions $valuesBefore -ValueShouldExist $existedBefore)
}

Export-ModuleMember -Function @(
    'Ensure-Esc16CertSvcRunning',
    'Get-Esc16DisableExtensionListState',
    'Get-Esc16NtdsCaSecurityExtOid',
    'Get-Esc16PropertyValue',
    'Get-Esc16ScenarioName',
    'Get-Esc16StatePath',
    'Get-Esc16StateRoot',
    'Initialize-Esc16ScenarioState',
    'Read-Esc16ScenarioState',
    'Restart-Esc16CertSvc',
    'Restore-Esc16DisableExtensionList',
    'Save-Esc16ScenarioState',
    'Set-Esc16SidSecurityExtensionDisabled',
    'Update-Esc16ScenarioState'
)
