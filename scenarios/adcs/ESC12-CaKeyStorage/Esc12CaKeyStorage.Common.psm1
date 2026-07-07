Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Esc12ScenarioName = 'ESC12-CaKeyStorage'
$script:Esc12StateRoot = Join-Path $env:ProgramData "ADLabBootstrap\Scenarios\$script:Esc12ScenarioName"
$script:Esc12StatePath = Join-Path $script:Esc12StateRoot 'state.json'
$script:Esc12CertSvcConfigurationRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
$script:Esc12YubiHsmProviderName = 'YubiHSM Key Storage Provider'
$script:Esc12YubiHsmRegistryPath = 'HKLM:\SOFTWARE\Yubico\YubiHSM'
$script:Esc12YubiHsmProgramDataPath = Join-Path $env:ProgramData 'YubiHSM'
$script:Esc12SoftwareProviders = @(
    'Microsoft Software Key Storage Provider',
    'Microsoft Strong Cryptographic Provider',
    'Microsoft Enhanced Cryptographic Provider v1.0',
    'Microsoft RSA SChannel Cryptographic Provider',
    'Microsoft Base Cryptographic Provider v1.0'
)

function Get-Esc12ScenarioName {
    return $script:Esc12ScenarioName
}

function Get-Esc12StateRoot {
    return $script:Esc12StateRoot
}

function Get-Esc12StatePath {
    return $script:Esc12StatePath
}

function Get-Esc12YubiHsmProviderName {
    return $script:Esc12YubiHsmProviderName
}

function Get-Esc12PropertyValue {
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

function ConvertTo-Esc12StringArray {
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

function Get-Esc12ActiveCaName {
    $active = (Get-ItemProperty -Path $script:Esc12CertSvcConfigurationRoot -Name Active -ErrorAction Stop).Active
    if ([string]::IsNullOrWhiteSpace([string]$active)) {
        throw 'No active local Certification Authority was found.'
    }
    return [string]$active
}

function Get-Esc12CaConfigurationPath {
    param([Parameter(Mandatory = $true)][string]$CAName)

    return (Join-Path $script:Esc12CertSvcConfigurationRoot $CAName)
}

function Get-Esc12CspProperty {
    param(
        [Parameter(Mandatory = $true)][string]$CspPath,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()]$Default = $null
    )

    try {
        $item = Get-ItemProperty -LiteralPath $CspPath -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch {
        return $Default
    }
}

function Test-Esc12ProviderIsSoftware {
    param([AllowNull()][string]$Provider)

    if ([string]::IsNullOrWhiteSpace($Provider)) { return $false }
    foreach ($name in @($script:Esc12SoftwareProviders)) {
        if ([string]$Provider -ieq $name) { return $true }
    }
    if ([string]$Provider -like 'Microsoft*Cryptographic Provider*') { return $true }
    if ([string]$Provider -ieq 'Microsoft Software Key Storage Provider') { return $true }
    return $false
}

function Test-Esc12ProviderIsYubiHsm {
    param([AllowNull()][string]$Provider)

    if ([string]::IsNullOrWhiteSpace($Provider)) { return $false }
    return ([string]$Provider -like '*YubiHSM*')
}

function Get-Esc12CaKeyStorageState {
    $certSvc = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
    $certSvcInstalled = ($null -ne $certSvc)
    $certSvcStatus = if ($certSvcInstalled) { [string]$certSvc.Status } else { 'Missing' }
    $certSvcStartType = if ($certSvcInstalled) { [string]$certSvc.StartType } else { 'Missing' }
    $activeCa = ''
    $caConfigPath = ''
    $cspPath = ''
    $provider = ''
    $providerType = 0
    $keyContainer = ''
    $machineKeyset = $false
    $readable = $false
    $registryError = ''

    try {
        $activeCa = Get-Esc12ActiveCaName
        $caConfigPath = Get-Esc12CaConfigurationPath -CAName $activeCa
        $cspPath = Join-Path $caConfigPath 'CSP'
        $provider = [string](Get-Esc12CspProperty -CspPath $cspPath -Name 'Provider' -Default '')
        $providerTypeValue = Get-Esc12CspProperty -CspPath $cspPath -Name 'ProviderType' -Default 0
        if ($null -ne $providerTypeValue -and -not [string]::IsNullOrWhiteSpace([string]$providerTypeValue)) {
            $providerType = [int]$providerTypeValue
        }
        $keyContainer = [string](Get-Esc12CspProperty -CspPath $cspPath -Name 'KeyContainer' -Default '')
        $machineKeysetValue = Get-Esc12CspProperty -CspPath $cspPath -Name 'MachineKeyset' -Default 0
        $machineKeyset = ([int]$machineKeysetValue -ne 0)
        $readable = $true
    }
    catch {
        $registryError = $_.Exception.Message
    }

    $yubiHsmRegistryPresent = Test-Path -LiteralPath $script:Esc12YubiHsmRegistryPath
    $yubiHsmProgramDataPresent = Test-Path -LiteralPath $script:Esc12YubiHsmProgramDataPath
    $yubiHsmConfigFiles = @()
    if ($yubiHsmProgramDataPresent) {
        $yubiHsmConfigFiles = @(Get-ChildItem -LiteralPath $script:Esc12YubiHsmProgramDataPath -Force -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.Name })
    }

    $usesYubiHsm = (Test-Esc12ProviderIsYubiHsm -Provider $provider)
    $usesSoftwareProvider = (Test-Esc12ProviderIsSoftware -Provider $provider)
    $esc12HardwareClassPresent = ($usesYubiHsm -or $yubiHsmRegistryPresent -or $yubiHsmProgramDataPresent)

    return [pscustomobject]@{
        CertSvcInstalled           = $certSvcInstalled
        CertSvcStatus              = $certSvcStatus
        CertSvcStartType           = $certSvcStartType
        ActiveCaName               = $activeCa
        CaConfigurationPath        = $caConfigPath
        CspPath                    = $cspPath
        Provider                   = $provider
        ProviderType               = [int]$providerType
        KeyContainer               = $keyContainer
        MachineKeyset              = [bool]$machineKeyset
        CspReadable                = $readable
        CspRegistryError           = $registryError
        UsesSoftwareProvider       = $usesSoftwareProvider
        UsesYubiHsmProvider        = $usesYubiHsm
        YubiHsmRegistryPresent     = [bool]$yubiHsmRegistryPresent
        YubiHsmProgramDataPresent  = [bool]$yubiHsmProgramDataPresent
        YubiHsmConfigFiles         = [string[]]$yubiHsmConfigFiles
        Esc12HardwareClassPresent  = [bool]$esc12HardwareClassPresent
        PrivateKeyMaterialRead     = $false
        PrivateKeyExported         = $false
    }
}

function Read-Esc12ScenarioState {
    if (-not (Test-Path -LiteralPath $script:Esc12StatePath -PathType Leaf)) {
        return $null
    }
    return (Get-Content -LiteralPath $script:Esc12StatePath -Raw -ErrorAction Stop | ConvertFrom-Json)
}

function Save-Esc12ScenarioState {
    param([Parameter(Mandatory = $true)]$State)

    if (-not (Test-Path -LiteralPath $script:Esc12StateRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $script:Esc12StateRoot -Force -ErrorAction Stop | Out-Null
    }
    $State | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:Esc12StatePath -Encoding UTF8 -ErrorAction Stop
}

function Initialize-Esc12ScenarioState {
    $existing = Read-Esc12ScenarioState
    if ($null -ne $existing) {
        return $existing
    }

    $current = Get-Esc12CaKeyStorageState
    if (-not [bool]$current.CspReadable) {
        throw "CA CSP could not be read: $($current.CspRegistryError)"
    }
    $state = [ordered]@{
        SchemaVersion      = 1
        ScenarioName       = $script:Esc12ScenarioName
        CreatedAt          = (Get-Date).ToString('o')
        UpdatedAt          = (Get-Date).ToString('o')
        ActiveCaNameBefore = [string]$current.ActiveCaName
        ProviderBefore     = [string]$current.Provider
        KeyContainerBefore = [string]$current.KeyContainer
        ProviderTypeBefore = [int]$current.ProviderType
        CertSvcStatusBefore = [string]$current.CertSvcStatus
    }
    Save-Esc12ScenarioState -State $state
    return (Read-Esc12ScenarioState)
}

function Update-Esc12ScenarioState {
    param([Parameter(Mandatory = $true)]$State)

    $State | Add-Member -MemberType NoteProperty -Name UpdatedAt -Value (Get-Date).ToString('o') -Force
    Save-Esc12ScenarioState -State $State
    return (Read-Esc12ScenarioState)
}

function Ensure-Esc12CertSvcRunning {
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

Export-ModuleMember -Function @(
    'Ensure-Esc12CertSvcRunning',
    'Get-Esc12CaKeyStorageState',
    'Get-Esc12PropertyValue',
    'Get-Esc12ScenarioName',
    'Get-Esc12StatePath',
    'Get-Esc12StateRoot',
    'Get-Esc12YubiHsmProviderName',
    'Initialize-Esc12ScenarioState',
    'Read-Esc12ScenarioState',
    'Save-Esc12ScenarioState',
    'Update-Esc12ScenarioState'
)
