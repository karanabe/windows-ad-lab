Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Esc11ScenarioName = 'ESC11-RpcEnrollment'
$script:Esc11StateRoot = Join-Path $env:ProgramData "ADLabBootstrap\Scenarios\$script:Esc11ScenarioName"
$script:Esc11StatePath = Join-Path $script:Esc11StateRoot 'state.json'
$script:Esc11CertSvcConfigurationRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
$script:Esc11InterfaceFlagsDisplayName = 'CA\InterfaceFlags'
$script:Esc11InterfaceFlagsValueName = 'InterfaceFlags'
$script:Esc11NoRpcCertRequestFlag = 0x00000008
$script:Esc11EnforceEncryptCertRequestFlag = 0x00000200

function Get-Esc11ScenarioName {
    return $script:Esc11ScenarioName
}

function Get-Esc11StateRoot {
    return $script:Esc11StateRoot
}

function Get-Esc11StatePath {
    return $script:Esc11StatePath
}

function Get-Esc11EnforceEncryptCertRequestFlag {
    return $script:Esc11EnforceEncryptCertRequestFlag
}

function Get-Esc11PropertyValue {
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

function Get-Esc11ActiveCaName {
    $active = (Get-ItemProperty -Path $script:Esc11CertSvcConfigurationRoot -Name Active -ErrorAction Stop).Active
    if ([string]::IsNullOrWhiteSpace([string]$active)) {
        throw 'No active local Certification Authority was found.'
    }
    return [string]$active
}

function Get-Esc11CaConfigurationPath {
    param([Parameter(Mandatory = $true)][string]$CAName)

    return (Join-Path $script:Esc11CertSvcConfigurationRoot $CAName)
}

function Get-Esc11KnownInterfaceFlags {
    return @(
        [pscustomobject]@{ Name = 'IF_NOREMOTEICERTREQUEST'; Value = 0x00000002 },
        [pscustomobject]@{ Name = 'IF_NOLOCALICERTREQUEST'; Value = 0x00000004 },
        [pscustomobject]@{ Name = 'IF_NORPCICERTREQUEST'; Value = 0x00000008 },
        [pscustomobject]@{ Name = 'IF_NOREMOTEICERTADMIN'; Value = 0x00000010 },
        [pscustomobject]@{ Name = 'IF_NOLOCALICERTADMIN'; Value = 0x00000020 },
        [pscustomobject]@{ Name = 'IF_NOREMOTEICERTADMINBACKUP'; Value = 0x00000040 },
        [pscustomobject]@{ Name = 'IF_NOLOCALICERTADMINBACKUP'; Value = 0x00000080 },
        [pscustomobject]@{ Name = 'IF_NOSNAPSHOTBACKUP'; Value = 0x00000100 },
        [pscustomobject]@{ Name = 'IF_ENFORCEENCRYPTICERTREQUEST'; Value = $script:Esc11EnforceEncryptCertRequestFlag },
        [pscustomobject]@{ Name = 'IF_ENFORCEENCRYPTICERTADMIN'; Value = 0x00000400 },
        [pscustomobject]@{ Name = 'IF_ENABLEEXITKEYRETRIEVAL'; Value = 0x00000800 },
        [pscustomobject]@{ Name = 'IF_ENABLEADMINASAUDITOR'; Value = 0x00001000 }
    )
}

function ConvertTo-Esc11InterfaceFlagNames {
    param([int]$InterfaceFlags)

    $names = New-Object System.Collections.Generic.List[string]
    foreach ($definition in @(Get-Esc11KnownInterfaceFlags)) {
        if (($InterfaceFlags -band [int]$definition.Value) -eq [int]$definition.Value) {
            [void]$names.Add([string]$definition.Name)
        }
    }
    return [string[]]$names.ToArray()
}

function Format-Esc11InterfaceFlags {
    param([int]$InterfaceFlags)

    return ('0x{0:X8} ({1})' -f [int]$InterfaceFlags, [int]$InterfaceFlags)
}

function Test-Esc11InterfaceFlag {
    param(
        [int]$InterfaceFlags,
        [int]$Flag
    )

    return (($InterfaceFlags -band $Flag) -eq $Flag)
}

function Get-Esc11RpcEnrollmentState {
    $certSvc = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
    $certSvcInstalled = ($null -ne $certSvc)
    $certSvcStatus = if ($certSvcInstalled) { [string]$certSvc.Status } else { 'Missing' }
    $certSvcStartType = if ($certSvcInstalled) { [string]$certSvc.StartType } else { 'Missing' }
    $activeCa = ''
    $caConfigPath = ''
    $interfaceFlags = 0
    $interfaceFlagsPropertyExists = $false
    $interfaceFlagsReadable = $false
    $registryError = ''

    try {
        $activeCa = Get-Esc11ActiveCaName
        $caConfigPath = Get-Esc11CaConfigurationPath -CAName $activeCa
        $configuration = Get-ItemProperty -Path $caConfigPath -Name $script:Esc11InterfaceFlagsValueName -ErrorAction SilentlyContinue
        $interfaceFlagsProperty = if ($null -eq $configuration) { $null } else { $configuration.PSObject.Properties[$script:Esc11InterfaceFlagsValueName] }
        if ($null -ne $interfaceFlagsProperty) {
            $interfaceFlagsPropertyExists = $true
            $interfaceFlags = [int]$interfaceFlagsProperty.Value
        }
        $interfaceFlagsReadable = $true
    }
    catch {
        $registryError = $_.Exception.Message
    }

    $packetPrivacyEnforced = Test-Esc11InterfaceFlag -InterfaceFlags $interfaceFlags -Flag $script:Esc11EnforceEncryptCertRequestFlag
    $rpcCertificateEnrollmentDisabled = Test-Esc11InterfaceFlag -InterfaceFlags $interfaceFlags -Flag $script:Esc11NoRpcCertRequestFlag
    $caConfigured = ($certSvcInstalled -and -not [string]::IsNullOrWhiteSpace($activeCa) -and $interfaceFlagsReadable)
    $certSvcRunning = ([string]$certSvcStatus -eq 'Running')
    $relayPrerequisitesPresent = (
        $caConfigured -and
        $certSvcRunning -and
        -not $rpcCertificateEnrollmentDisabled -and
        -not $packetPrivacyEnforced
    )
    $hardened = ($caConfigured -and $packetPrivacyEnforced)

    return [pscustomobject]@{
        CertSvcInstalled                 = $certSvcInstalled
        CertSvcStatus                    = $certSvcStatus
        CertSvcStartType                 = $certSvcStartType
        ActiveCaName                     = $activeCa
        CaConfigurationPath              = $caConfigPath
        InterfaceFlagsPropertyExists     = $interfaceFlagsPropertyExists
        InterfaceFlagsReadable           = $interfaceFlagsReadable
        InterfaceFlagsRegistryError      = $registryError
        InterfaceFlags                   = [int]$interfaceFlags
        InterfaceFlagsHex                = (Format-Esc11InterfaceFlags -InterfaceFlags $interfaceFlags)
        InterfaceFlagNames               = [string[]](ConvertTo-Esc11InterfaceFlagNames -InterfaceFlags $interfaceFlags)
        RpcCertificateEnrollmentDisabled = $rpcCertificateEnrollmentDisabled
        PacketPrivacyEnforced            = $packetPrivacyEnforced
        RelayPrerequisitesPresent        = $relayPrerequisitesPresent
        Hardened                         = $hardened
    }
}

function Read-Esc11ScenarioState {
    if (-not (Test-Path -LiteralPath $script:Esc11StatePath -PathType Leaf)) {
        return $null
    }
    return (Get-Content -LiteralPath $script:Esc11StatePath -Raw -ErrorAction Stop | ConvertFrom-Json)
}

function Save-Esc11ScenarioState {
    param([Parameter(Mandatory = $true)]$State)

    if (-not (Test-Path -LiteralPath $script:Esc11StateRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $script:Esc11StateRoot -Force -ErrorAction Stop | Out-Null
    }
    $State | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:Esc11StatePath -Encoding UTF8 -ErrorAction Stop
}

function Initialize-Esc11ScenarioState {
    $existing = Read-Esc11ScenarioState
    if ($null -ne $existing) {
        return $existing
    }

    $current = Get-Esc11RpcEnrollmentState
    if (-not [bool]$current.InterfaceFlagsReadable) {
        throw "CA InterfaceFlags could not be read: $($current.InterfaceFlagsRegistryError)"
    }
    $state = [ordered]@{
        SchemaVersion                     = 1
        ScenarioName                      = $script:Esc11ScenarioName
        CreatedAt                         = (Get-Date).ToString('o')
        UpdatedAt                         = (Get-Date).ToString('o')
        LastStage                         = ''
        ActiveCaNameBefore                = [string]$current.ActiveCaName
        InterfaceFlagsPropertyExistsBefore = [bool]$current.InterfaceFlagsPropertyExists
        InterfaceFlagsBefore              = [int]$current.InterfaceFlags
        CertSvcStatusBefore               = [string]$current.CertSvcStatus
        CertSvcStartTypeBefore            = [string]$current.CertSvcStartType
    }
    Save-Esc11ScenarioState -State $state
    return (Read-Esc11ScenarioState)
}

function Update-Esc11ScenarioState {
    param(
        [Parameter(Mandatory = $true)]$State,
        [string]$LastStage
    )

    $State | Add-Member -MemberType NoteProperty -Name UpdatedAt -Value (Get-Date).ToString('o') -Force
    if (-not [string]::IsNullOrWhiteSpace($LastStage)) {
        $State | Add-Member -MemberType NoteProperty -Name LastStage -Value $LastStage -Force
    }
    Save-Esc11ScenarioState -State $State
    return (Read-Esc11ScenarioState)
}

function Ensure-Esc11CertSvcRunning {
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

function Restart-Esc11CertSvc {
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

function Set-Esc11InterfaceFlags {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([int]$InterfaceFlags)

    $current = Get-Esc11RpcEnrollmentState
    if (-not [bool]$current.InterfaceFlagsReadable) {
        throw "CA InterfaceFlags could not be read: $($current.InterfaceFlagsRegistryError)"
    }
    if ([int]$current.InterfaceFlags -eq [int]$InterfaceFlags) {
        return $false
    }

    $caConfigPath = [string]$current.CaConfigurationPath
    if ($PSCmdlet.ShouldProcess($caConfigPath, "Set CA InterfaceFlags to $(Format-Esc11InterfaceFlags -InterfaceFlags $InterfaceFlags)")) {
        if (-not [bool]$current.InterfaceFlagsPropertyExists) {
            New-ItemProperty -Path $caConfigPath -Name $script:Esc11InterfaceFlagsValueName -PropertyType DWord -Value $InterfaceFlags -Force -ErrorAction Stop | Out-Null
        }
        else {
            Set-ItemProperty -Path $caConfigPath -Name $script:Esc11InterfaceFlagsValueName -Value $InterfaceFlags -ErrorAction Stop
        }
        return $true
    }
    return $false
}

function Set-Esc11PacketPrivacyRequirement {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][bool]$Required)

    $current = Get-Esc11RpcEnrollmentState
    $desiredFlags = [int]$current.InterfaceFlags
    if ($Required) {
        $desiredFlags = ($desiredFlags -bor $script:Esc11EnforceEncryptCertRequestFlag)
    }
    else {
        $desiredFlags = ($desiredFlags -band (-bnot $script:Esc11EnforceEncryptCertRequestFlag))
    }
    return (Set-Esc11InterfaceFlags -InterfaceFlags $desiredFlags)
}

function Restore-Esc11InterfaceFlags {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$State)

    $current = Get-Esc11RpcEnrollmentState
    if (-not [bool]$current.InterfaceFlagsReadable) {
        throw "CA InterfaceFlags could not be read: $($current.InterfaceFlagsRegistryError)"
    }

    $expectedCaName = [string](Get-Esc11PropertyValue -InputObject $State -Name 'ActiveCaNameBefore' -Default '')
    if (-not [string]::IsNullOrWhiteSpace($expectedCaName) -and [string]$current.ActiveCaName -ine $expectedCaName) {
        throw "Active CA changed from '$expectedCaName' to '$($current.ActiveCaName)'. Refusing to restore InterfaceFlags."
    }

    $existedBefore = [bool](Get-Esc11PropertyValue -InputObject $State -Name 'InterfaceFlagsPropertyExistsBefore' -Default $true)
    $flagsBefore = [int](Get-Esc11PropertyValue -InputObject $State -Name 'InterfaceFlagsBefore' -Default 0)
    if ($existedBefore) {
        return (Set-Esc11InterfaceFlags -InterfaceFlags $flagsBefore)
    }

    if (-not [bool]$current.InterfaceFlagsPropertyExists) {
        return $false
    }
    if ($PSCmdlet.ShouldProcess([string]$current.CaConfigurationPath, 'Remove scenario-created InterfaceFlags registry value')) {
        Remove-ItemProperty -Path ([string]$current.CaConfigurationPath) -Name $script:Esc11InterfaceFlagsValueName -ErrorAction Stop
        return $true
    }
    return $false
}

Export-ModuleMember -Function @(
    'Format-Esc11InterfaceFlags',
    'Get-Esc11EnforceEncryptCertRequestFlag',
    'Get-Esc11PropertyValue',
    'Get-Esc11RpcEnrollmentState',
    'Get-Esc11ScenarioName',
    'Get-Esc11StatePath',
    'Get-Esc11StateRoot',
    'Initialize-Esc11ScenarioState',
    'Read-Esc11ScenarioState',
    'Restart-Esc11CertSvc',
    'Restore-Esc11InterfaceFlags',
    'Save-Esc11ScenarioState',
    'Set-Esc11InterfaceFlags',
    'Set-Esc11PacketPrivacyRequirement',
    'Ensure-Esc11CertSvcRunning',
    'Update-Esc11ScenarioState'
)
