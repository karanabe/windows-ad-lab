#Requires -Version 5.1
#Requires -RunAsAdministrator
#Requires -Modules Hyper-V

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ConfigPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'config\LabConfig.psd1'),

    [ValidateSet('Prerequisites', 'OSBaseline', 'NewForest', 'ADBaseline', 'DefensiveAuditing', 'ADCS', 'ADCSHttpCdp', 'Validation')]
    [string[]]$Phase = @('Prerequisites', 'OSBaseline', 'NewForest', 'ADBaseline', 'DefensiveAuditing', 'ADCS', 'ADCSHttpCdp', 'Validation'),

    [PSCredential]$LocalCredential,
    [PSCredential]$DomainCredential,
    [Security.SecureString]$DsrmPassword,
    [Security.SecureString]$DefaultUserPassword,
    [string]$SecretsPath,
    [string]$GuestConfigurationName,
    [switch]$ResetExistingPasswords,
    [switch]$SkipDcDiag,
    [ValidateRange(60, 3600)][int]$RestartTimeoutSeconds = 600
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Assert-LabAdministrator
Assert-LabPowerShellDirectClient
$config = Import-LabConfig -Path $ConfigPath
$timeZoneId = [string]$config.Time.WindowsTimeZoneId
if ($timeZoneId -eq 'Host') {
    $timeZoneId = (Get-TimeZone -ErrorAction Stop).Id
}
if ([string]::IsNullOrWhiteSpace($timeZoneId)) {
    throw 'The target Windows time zone ID could not be determined.'
}
$vmName = [string]$config.Lab.VMName
$guestRoot = [string]$config.Lab.GuestBootstrapPath
$configSha256 = (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256 -ErrorAction Stop).Hash
$buildCommitPath = Join-Path $repositoryRoot 'BUILD_COMMIT'
$buildStatusPath = Join-Path $repositoryRoot 'BUILD_STATUS'
$buildPublishedAtPath = Join-Path $repositoryRoot 'BUILD_PUBLISHED_AT'
$bootstrapCommit = if (Test-Path -LiteralPath $buildCommitPath -PathType Leaf) { ([string](Get-Content -LiteralPath $buildCommitPath -Raw)).Trim() } else { 'Unavailable' }
$bootstrapStatus = if (Test-Path -LiteralPath $buildStatusPath -PathType Leaf) { ([string](Get-Content -LiteralPath $buildStatusPath -Raw)).Trim() } else { 'Unavailable' }
$bootstrapPublishedAt = if (Test-Path -LiteralPath $buildPublishedAtPath -PathType Leaf) { ([string](Get-Content -LiteralPath $buildPublishedAtPath -Raw)).Trim() } else { 'Unavailable' }
if ([string]::IsNullOrWhiteSpace($bootstrapStatus)) { $bootstrapStatus = 'Clean' }
$orderedPhases = @('Prerequisites', 'OSBaseline', 'NewForest', 'ADBaseline', 'DefensiveAuditing', 'ADCS', 'ADCSHttpCdp', 'Validation')
$selectedPhases = @($orderedPhases | Where-Object { $Phase -contains $_ })
$lastSuccessfulPhase = 'None'
$activePhase = 'Bootstrap'
$session = $null
$hostLog = $null
$activeDirectoryDnsEnsured = $false

function ConvertFrom-LabEncryptedSecret {
    param([AllowNull()][string]$Value, [string]$Name)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    if ($Value -match '^<.*>$') { throw "Secret '$Name' still contains the placeholder from LabSecrets.example.psd1." }
    try { return ConvertTo-SecureString -String $Value -ErrorAction Stop }
    catch { throw "Secret '$Name' could not be decrypted for the current Windows user on this host." }
}

function Write-HostPhaseLog {
    param([string]$CurrentPhase, [string]$Action, [string]$Status, [string]$Message)
    Write-Host ("{0} Phase={1} Action={2} Status={3} Target={4} Message={5}" -f (Get-Date).ToString('o'), $CurrentPhase, $Action, $Status, $vmName, $Message)
}

function Enter-HostPhase {
    param([Parameter(Mandatory = $true)][string]$Name, [string]$Message = 'Starting phase.')
    $script:activePhase = $Name
    Write-HostPhaseLog -CurrentPhase $Name -Action 'Start' -Status Running -Message $Message
}

function New-LabDirectSession {
    param([Parameter(Mandatory = $true)][PSCredential]$Credential, [int]$TimeoutSeconds = 60)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastError = $null
    do {
        $newSession = $null
        try {
            $sessionParameters = @{
                VMName      = $vmName
                Credential  = $Credential
                ErrorAction = 'Stop'
            }
            if (-not [string]::IsNullOrWhiteSpace($GuestConfigurationName)) {
                $sessionParameters.ConfigurationName = $GuestConfigurationName
            }
            $newSession = New-PSSession @sessionParameters
            Invoke-Command -Session $newSession -ScriptBlock { $true } -ErrorAction Stop | Out-Null
            return $newSession
        }
        catch {
            $lastError = $_.Exception.Message
            if ($null -ne $newSession) { Remove-PSSession -Session $newSession -ErrorAction SilentlyContinue }
            Start-Sleep -Seconds 5
        }
    } while ((Get-Date) -lt $deadline)
    throw "PowerShell Direct did not become available within $TimeoutSeconds seconds. Last error: $lastError"
}

function Restart-LabVmAndConnect {
    param([Parameter(Mandatory = $true)][PSCredential]$Credential)
    Enter-HostPhase -Name 'Restart' -Message 'Waiting for a new guest boot before continuing.'
    $previousBootTime = [datetime](Invoke-Command -Session $script:session -ScriptBlock {
        (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
    } -ErrorAction Stop)
    if ($null -ne $script:session) {
        Remove-PSSession -Session $script:session -ErrorAction SilentlyContinue
        $script:session = $null
    }
    Write-HostPhaseLog -CurrentPhase 'Restart' -Action 'RestartVM' -Status Changed -Message 'Restarting through Hyper-V; no checkpoint is created.'
    Restart-VM -Name $vmName -Force -ErrorAction Stop | Out-Null
    $deadline = (Get-Date).AddSeconds($RestartTimeoutSeconds)
    $lastError = 'The guest boot time has not advanced.'
    $attempt = 0
    do {
        $candidateSession = $null
        try {
            $remainingSeconds = [int][Math]::Max(5, [Math]::Min(30, ($deadline - (Get-Date)).TotalSeconds))
            $candidateSession = New-LabDirectSession -Credential $Credential -TimeoutSeconds $remainingSeconds
            $currentBootTime = [datetime](Invoke-Command -Session $candidateSession -ScriptBlock {
                (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
            } -ErrorAction Stop)
            if ($currentBootTime -gt $previousBootTime) {
                $script:session = $candidateSession
                Write-HostPhaseLog -CurrentPhase 'Restart' -Action 'WaitBoot' -Status Unchanged -Message "Guest boot time advanced from $($previousBootTime.ToString('o')) to $($currentBootTime.ToString('o'))."
                return
            }
            $lastError = "Guest boot time is still $($currentBootTime.ToString('o'))."
        }
        catch {
            $lastError = $_.Exception.Message
        }
        if ($null -ne $candidateSession) {
            Remove-PSSession -Session $candidateSession -ErrorAction SilentlyContinue
        }
        $attempt++
        if ($attempt -eq 1 -or $attempt % 6 -eq 0) {
            Write-HostPhaseLog -CurrentPhase 'Restart' -Action 'WaitBoot' -Status Info -Message "Waiting for a new guest boot. Last observation: $lastError"
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    throw "VM '$vmName' did not complete a new boot within $RestartTimeoutSeconds seconds. Last observation: $lastError"
}

function Wait-LabActiveDirectoryReady {
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession]$Session,
        [int]$TimeoutSeconds = 600
    )

    Enter-HostPhase -Name 'ActiveDirectory' -Message 'Waiting for ADWS, NTDS, and the local domain.'
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $initialAdws = $null
    $adwsConfigurationChanged = $false
    $lastError = $null
    $attempt = 0
    do {
        try {
            if ($null -eq $initialAdws) {
                $initialAdws = Invoke-Command -Session $Session -ScriptBlock {
                    $service = Get-Service -Name 'ADWS' -ErrorAction Stop
                    [pscustomobject]@{
                        Status    = [string]$service.Status
                        StartType = [string]$service.StartType
                    }
                } -ErrorAction Stop
                $adwsConfigurationChanged = (
                    [string]$initialAdws.StartType -ne 'Automatic' -or
                    [string]$initialAdws.Status -ne 'Running'
                )
            }
            $readiness = Invoke-Command -Session $Session -ScriptBlock {
                $adws = Get-Service -Name 'ADWS' -ErrorAction Stop
                if ([string]$adws.StartType -ne 'Automatic') {
                    Set-Service -Name 'ADWS' -StartupType Automatic -ErrorAction Stop
                }
                $adws = Get-Service -Name 'ADWS' -ErrorAction Stop
                if ($adws.Status -ne 'Running') {
                    Start-Service -Name 'ADWS' -ErrorAction Stop
                }

                $services = @(Get-Service -Name 'ADWS', 'NTDS' -ErrorAction Stop)
                $notRunning = @($services | Where-Object Status -ne 'Running')
                if ($notRunning.Count -gt 0) {
                    throw "Active Directory services are not running: $(@($notRunning.Name) -join ', ')."
                }
                $adwsService = @($services | Where-Object Name -eq 'ADWS')[0]

                Import-Module ActiveDirectory -ErrorAction Stop -WarningAction SilentlyContinue
                $domain = Get-ADDomain -Server $env:COMPUTERNAME -ErrorAction Stop
                [pscustomobject]@{
                    ADWSStartType = [string]$adwsService.StartType
                    ADWSStatus    = [string]$adwsService.Status
                    Domain        = [string]$domain.DNSRoot
                    Server        = $env:COMPUTERNAME
                }
            } -ErrorAction Stop

            $configurationStatus = if ($adwsConfigurationChanged) { 'Changed' } else { 'Unchanged' }
            Write-HostPhaseLog `
                -CurrentPhase 'ActiveDirectory' `
                -Action 'ConfigureADWS' `
                -Status $configurationStatus `
                -Message "StartType=$($readiness.ADWSStartType); Status=$($readiness.ADWSStatus)"
            Write-HostPhaseLog `
                -CurrentPhase 'ActiveDirectory' `
                -Action 'WaitReady' `
                -Status Unchanged `
                -Message "ADWS and NTDS are ready; Domain=$($readiness.Domain); Server=$($readiness.Server)"
            return
        }
        catch {
            $lastError = $_.Exception.Message
            $attempt++
            if ($attempt -eq 1 -or $attempt % 6 -eq 0) {
                Write-HostPhaseLog `
                    -CurrentPhase 'ActiveDirectory' `
                    -Action 'WaitReady' `
                    -Status Info `
                    -Message "Configuring or waiting for ADWS, NTDS, and Get-ADDomain. Last error: $lastError"
            }
            Start-Sleep -Seconds 5
        }
    } while ((Get-Date) -lt $deadline)

    throw "Active Directory did not become ready within $TimeoutSeconds seconds. Last error: $lastError"
}

function Ensure-LabActiveDirectoryDns {
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory = $true)][string]$RemoteConfigPath,
        [int]$TimeoutSeconds = 600
    )

    Enter-HostPhase -Name 'ActiveDirectoryDNS' -Message 'Waiting for DNS directory partitions, zones, and SRV records.'
    $scriptPath = Join-Path $guestRoot 'scripts\guest\15-EnsureADDns.ps1'
    Invoke-Command -Session $Session -ArgumentList $scriptPath, $RemoteConfigPath, $TimeoutSeconds -ScriptBlock {
        param($Path, $Config, $Timeout)
        & $Path -ConfigPath $Config -TimeoutSeconds $Timeout
    } -ErrorAction Stop | Out-Host
}

function Copy-LabPayloadFiles {
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$SourceConfigPath
    )

    Copy-Item -LiteralPath $SourceConfigPath -Destination (Join-Path $guestRoot 'config\LabConfig.psd1') -ToSession $Session -Force -ErrorAction Stop
    Copy-Item -Path (Join-Path $SourceRoot 'scripts\guest\*') -Destination (Join-Path $guestRoot 'scripts\guest') -ToSession $Session -Force -Recurse -ErrorAction Stop
    Copy-Item -Path (Join-Path $SourceRoot 'modules\*') -Destination (Join-Path $guestRoot 'modules') -ToSession $Session -Force -Recurse -ErrorAction Stop
    foreach ($metadataPath in @($buildCommitPath, $buildStatusPath, $buildPublishedAtPath)) {
        if (Test-Path -LiteralPath $metadataPath -PathType Leaf) {
            $sourceMetadataPath = Join-Path $SourceRoot (Split-Path $metadataPath -Leaf)
            Copy-Item -LiteralPath $sourceMetadataPath -Destination (Join-Path $guestRoot (Split-Path $metadataPath -Leaf)) -ToSession $Session -Force -ErrorAction Stop
        }
    }
}

function Copy-LabPayload {
    param([Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession]$Session)

    Invoke-Command -Session $Session -ArgumentList $guestRoot -ScriptBlock {
        param($Destination)
        foreach ($path in @(
            $Destination,
            (Join-Path $Destination 'config'),
            (Join-Path $Destination 'scripts'),
            (Join-Path $Destination 'scripts\guest'),
            (Join-Path $Destination 'modules')
        )) {
            if (-not (Test-Path -LiteralPath $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
        }
    } -ErrorAction Stop

    try {
        Copy-LabPayloadFiles -Session $Session -SourceRoot $repositoryRoot -SourceConfigPath $ConfigPath
    }
    catch {
        if (-not ($repositoryRoot.StartsWith('\\') -or $ConfigPath.StartsWith('\\'))) { throw }

        $directError = $_.Exception.Message
        $temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('ADLabPayload-' + [guid]::NewGuid().ToString('N'))
        if ($temporaryRoot.StartsWith('\\')) {
            throw "Direct UNC payload transfer failed: $directError. The host temporary directory is also a UNC path: '$temporaryRoot'."
        }

        Write-HostPhaseLog -CurrentPhase 'Staging' -Action 'CopyPayload' -Status Info -Message 'Direct transfer from a UNC source failed; retrying through a temporary local host copy.'
        try {
            New-Item -ItemType Directory -Path $temporaryRoot -ErrorAction Stop | Out-Null
            foreach ($relativeDirectory in @('config', 'scripts\guest', 'modules')) {
                New-Item -ItemType Directory -Path (Join-Path $temporaryRoot $relativeDirectory) -Force -ErrorAction Stop | Out-Null
            }
            $temporaryConfigPath = Join-Path $temporaryRoot 'config\LabConfig.psd1'
            Copy-Item -LiteralPath $ConfigPath -Destination $temporaryConfigPath -Force -ErrorAction Stop
            Copy-Item -Path (Join-Path $repositoryRoot 'scripts\guest\*') -Destination (Join-Path $temporaryRoot 'scripts\guest') -Force -Recurse -ErrorAction Stop
            Copy-Item -Path (Join-Path $repositoryRoot 'modules\*') -Destination (Join-Path $temporaryRoot 'modules') -Force -Recurse -ErrorAction Stop
            foreach ($metadataPath in @($buildCommitPath, $buildStatusPath, $buildPublishedAtPath)) {
                if (Test-Path -LiteralPath $metadataPath -PathType Leaf) {
                    Copy-Item -LiteralPath $metadataPath -Destination (Join-Path $temporaryRoot (Split-Path $metadataPath -Leaf)) -Force -ErrorAction Stop
                }
            }
            Copy-LabPayloadFiles -Session $Session -SourceRoot $temporaryRoot -SourceConfigPath $temporaryConfigPath
        }
        catch {
            throw "Direct UNC payload transfer failed: $directError. Retry through a temporary local host copy failed: $($_.Exception.Message)"
        }
        finally {
            if (Test-Path -LiteralPath $temporaryRoot) {
                try { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction Stop }
                catch { Write-Warning "Could not remove temporary lab payload '$temporaryRoot': $($_.Exception.Message)" }
            }
        }
    }
    Write-HostPhaseLog -CurrentPhase 'Staging' -Action 'CopyPayload' -Status Changed -Message $guestRoot
}

try {
    $logDirectory = Join-Path $repositoryRoot 'logs'
    if (-not (Test-Path -LiteralPath $logDirectory)) { New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null }
    $hostLog = Join-Path $logDirectory "$(Get-Date -Format 'yyyyMMdd-HHmmss')-host-bootstrap.log"
    Start-Transcript -Path $hostLog -Force | Out-Null
    Write-HostPhaseLog -CurrentPhase 'Bootstrap' -Action 'Provenance' -Status Info -Message "Commit=$bootstrapCommit; PublishedAt=$bootstrapPublishedAt; LabConfigSHA256=$configSha256"

    if (-not [string]::IsNullOrWhiteSpace($SecretsPath)) {
        if (-not (Test-Path -LiteralPath $SecretsPath -PathType Leaf)) { throw "Secrets file not found: $SecretsPath" }
        $secrets = Import-PowerShellDataFile -LiteralPath $SecretsPath
        if ($null -eq $DsrmPassword) { $DsrmPassword = ConvertFrom-LabEncryptedSecret -Value ([string]$secrets.DsrmPassword) -Name 'DsrmPassword' }
        if ($null -eq $DefaultUserPassword) { $DefaultUserPassword = ConvertFrom-LabEncryptedSecret -Value ([string]$secrets.DefaultUserPassword) -Name 'DefaultUserPassword' }
        if ($null -eq $LocalCredential -and -not [string]::IsNullOrWhiteSpace([string]$secrets.LocalAdministratorUser)) {
            $password = ConvertFrom-LabEncryptedSecret -Value ([string]$secrets.LocalAdministratorPassword) -Name 'LocalAdministratorPassword'
            $LocalCredential = New-Object Management.Automation.PSCredential([string]$secrets.LocalAdministratorUser, $password)
        }
        if ($null -eq $DomainCredential -and -not [string]::IsNullOrWhiteSpace([string]$secrets.DomainAdministratorUser)) {
            $password = ConvertFrom-LabEncryptedSecret -Value ([string]$secrets.DomainAdministratorPassword) -Name 'DomainAdministratorPassword'
            $DomainCredential = New-Object Management.Automation.PSCredential([string]$secrets.DomainAdministratorUser, $password)
        }
    }

    $needsLocalCredential = @($selectedPhases | Where-Object { $_ -in @('OSBaseline', 'NewForest') }).Count -gt 0
    $needsDomainCredential = @($selectedPhases | Where-Object { $_ -in @('ADBaseline', 'DefensiveAuditing', 'ADCS', 'ADCSHttpCdp', 'Validation') }).Count -gt 0
    if ($needsLocalCredential -and $null -eq $LocalCredential) {
        $LocalCredential = Get-Credential -UserName '.\Administrator' -Message "Enter the local Administrator credential for '$vmName'."
    }
    if ($selectedPhases -contains 'NewForest' -and $null -eq $DomainCredential -and $null -ne $LocalCredential) {
        # On a fresh promotion the built-in Administrator keeps its password.
        # Creating this credential without converting the SecureString also lets
        # a full rerun reconnect when the VM is already a domain controller.
        $DomainCredential = New-Object Management.Automation.PSCredential("$($config.Domain.NetBIOSName)\Administrator", $LocalCredential.Password)
    }
    if (-not $needsLocalCredential -and $needsDomainCredential -and $null -eq $DomainCredential) {
        $DomainCredential = Get-Credential -UserName "$($config.Domain.NetBIOSName)\Administrator" -Message "Enter the domain Administrator credential for '$vmName'."
    }
    if ($needsLocalCredential -and $needsDomainCredential -and $selectedPhases -notcontains 'NewForest' -and $null -eq $DomainCredential) {
        $DomainCredential = Get-Credential -UserName "$($config.Domain.NetBIOSName)\Administrator" -Message "Enter the domain Administrator credential for the post-baseline phases on '$vmName'."
    }
    $initialCredential = if ($needsLocalCredential) { $LocalCredential } else { $DomainCredential }
    if ($null -eq $initialCredential) {
        $initialCredential = Get-Credential -Message "Enter a current administrator credential for '$vmName'."
    }

    Enter-HostPhase -Name 'Prerequisites' -Message 'Read-only checks; no checkpoint will be created.'
    try {
        $preflight = & (Join-Path $repositoryRoot 'scripts\host\Test-HyperVPrerequisites.ps1') -ConfigPath $ConfigPath -Credential $initialCredential -GuestConfigurationName $GuestConfigurationName
    }
    catch {
        if ($null -eq $DomainCredential -or $initialCredential.UserName -ieq $DomainCredential.UserName) { throw }
        Write-HostPhaseLog -CurrentPhase 'Prerequisites' -Action 'RetryCredential' -Status Info -Message 'Initial credential failed; retrying the configured domain Administrator for an idempotent rerun.'
        $initialCredential = $DomainCredential
        $preflight = & (Join-Path $repositoryRoot 'scripts\host\Test-HyperVPrerequisites.ps1') -ConfigPath $ConfigPath -Credential $initialCredential -GuestConfigurationName $GuestConfigurationName
    }
    $preflight | Format-List | Out-Host
    $lastSuccessfulPhase = 'Prerequisites'

    if ($WhatIfPreference) {
        foreach ($plannedPhase in @($selectedPhases | Where-Object { $_ -ne 'Prerequisites' })) {
            Write-HostPhaseLog -CurrentPhase $plannedPhase -Action 'Plan' -Status Info -Message 'WhatIf: payload copy, guest changes, and restarts are skipped.'
        }
        return [pscustomobject]@{ VMName = $vmName; LastSuccessfulPhase = $lastSuccessfulPhase; WhatIf = $true; HostLog = $hostLog }
    }

    if (@($selectedPhases | Where-Object { $_ -ne 'Prerequisites' }).Count -gt 0) {
        Enter-HostPhase -Name 'Staging' -Message 'Connecting to the guest and copying the lab payload.'
        $session = New-LabDirectSession -Credential $initialCredential -TimeoutSeconds 60
        Copy-LabPayload -Session $session
    }

    $remoteConfig = Join-Path $guestRoot 'config\LabConfig.psd1'
    $isExistingDomainController = $false
    if ($selectedPhases -contains 'NewForest') {
        $isExistingDomainController = [bool](Invoke-Command -Session $session -ScriptBlock {
            [int](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).DomainRole -ge 4
        } -ErrorAction Stop)
    }
    if ($selectedPhases -contains 'OSBaseline') {
        Enter-HostPhase -Name 'OSBaseline'
        $scriptPath = Join-Path $guestRoot 'scripts\guest\00-PrepareServer.ps1'
        $output = Invoke-Command -Session $session -ArgumentList $scriptPath, $remoteConfig, $timeZoneId -ScriptBlock {
            param($Path, $Config, $TargetTimeZoneId)
            & $Path -ConfigPath $Config -TimeZoneId $TargetTimeZoneId
        } -ErrorAction Stop
        $output | Out-Host
        $phaseResult = @($output | Where-Object { $_.Phase -eq 'OSBaseline' })[-1]
        if ($null -ne $phaseResult -and [bool]$phaseResult.RebootRequired) {
            Restart-LabVmAndConnect -Credential $LocalCredential
        }
        $lastSuccessfulPhase = 'OSBaseline'
        Write-Host 'Recommended checkpoint: 02-Baseline (create manually after reviewing validation).'
    }

    if ($selectedPhases -contains 'NewForest') {
        Enter-HostPhase -Name 'NewForest'
        if ($isExistingDomainController) {
            Wait-LabActiveDirectoryReady -Session $session -TimeoutSeconds $RestartTimeoutSeconds
        }
        elseif ($null -eq $DsrmPassword) {
            $DsrmPassword = Read-Host 'Enter the DSRM password' -AsSecureString
        }
        Enter-HostPhase -Name 'NewForest' -Message 'Creating or confirming the forest.'
        $scriptPath = Join-Path $guestRoot 'scripts\guest\10-NewForest.ps1'
        $output = Invoke-Command -Session $session -ArgumentList $scriptPath, $remoteConfig, $DsrmPassword -ScriptBlock {
            param($Path, $Config, $Password)
            & $Path -ConfigPath $Config -DsrmPassword $Password -DeferRestart
        } -ErrorAction Stop
        $output | Out-Host
        $phaseResult = @($output | Where-Object { $_.Phase -eq 'NewForest' })[-1]
        if ($null -ne $phaseResult -and [bool]$phaseResult.RebootRequired) {
            Restart-LabVmAndConnect -Credential $DomainCredential
        }
        elseif ($needsDomainCredential) {
            if ($null -ne $session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
            $session = New-LabDirectSession -Credential $DomainCredential -TimeoutSeconds 60
        }
        Wait-LabActiveDirectoryReady -Session $session -TimeoutSeconds $RestartTimeoutSeconds
        Ensure-LabActiveDirectoryDns -Session $session -RemoteConfigPath $remoteConfig -TimeoutSeconds $RestartTimeoutSeconds
        $activeDirectoryDnsEnsured = $true
        $lastSuccessfulPhase = 'NewForest'
        Write-Host 'Recommended checkpoint: 03-Forest (create manually after reviewing validation).'
    }

    if ($needsDomainCredential -and $needsLocalCredential -and $selectedPhases -notcontains 'NewForest') {
        Enter-HostPhase -Name 'Staging' -Message 'Reconnecting with the domain credential and refreshing the guest payload.'
        if ($null -ne $session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
        $session = New-LabDirectSession -Credential $DomainCredential -TimeoutSeconds 60
        Copy-LabPayload -Session $session
    }

    if ($needsDomainCredential) {
        Wait-LabActiveDirectoryReady -Session $session -TimeoutSeconds $RestartTimeoutSeconds
        if (-not $activeDirectoryDnsEnsured) {
            Ensure-LabActiveDirectoryDns -Session $session -RemoteConfigPath $remoteConfig -TimeoutSeconds $RestartTimeoutSeconds
            $activeDirectoryDnsEnsured = $true
        }
    }

    if ($selectedPhases -contains 'ADBaseline') {
        Enter-HostPhase -Name 'ADBaseline'
        if ($null -eq $DefaultUserPassword) {
            $passwordNeeded = Invoke-Command -Session $session -ArgumentList $remoteConfig, ([bool]$ResetExistingPasswords) -ScriptBlock {
                param($Config, $Reset)
                $bootstrapRoot = Split-Path (Split-Path $Config -Parent) -Parent
                Import-Module (Join-Path $bootstrapRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
                Import-Module (Join-Path $bootstrapRoot 'modules\Lab.ActiveDirectory.psm1') -Force -ErrorAction Stop
                $loadedConfig = Import-LabConfig -Path $Config
                Test-LabNeedsUserPassword -Config $loadedConfig -ResetExistingPasswords:$Reset
            } -ErrorAction Stop
            if ([bool]$passwordNeeded) { $DefaultUserPassword = Read-Host 'Enter the password for new lab users' -AsSecureString }
        }
        $scriptPath = Join-Path $guestRoot 'scripts\guest\20-BootstrapAD.ps1'
        $output = Invoke-Command -Session $session -ArgumentList $scriptPath, $remoteConfig, $DefaultUserPassword, ([bool]$ResetExistingPasswords) -ScriptBlock {
            param($Path, $Config, $Password, $Reset)
            & $Path -ConfigPath $Config -DefaultUserPassword $Password -ResetExistingPasswords:$Reset
        } -ErrorAction Stop
        $output | Out-Host
        $lastSuccessfulPhase = 'ADBaseline'
    }

    if ($selectedPhases -contains 'DefensiveAuditing') {
        Enter-HostPhase -Name 'DefensiveAuditing'
        $scriptPath = Join-Path $guestRoot 'scripts\guest\40-EnableDefensiveAuditing.ps1'
        Invoke-Command -Session $session -ArgumentList $scriptPath, $remoteConfig -ScriptBlock { param($Path, $Config) & $Path -ConfigPath $Config } -ErrorAction Stop | Out-Host
        $lastSuccessfulPhase = 'DefensiveAuditing'
        Write-Host 'Recommended checkpoint: 04-AD-Baseline (create manually after reviewing validation).'
    }

    if ($selectedPhases -contains 'ADCS') {
        Enter-HostPhase -Name 'ADCS'
        $scriptPath = Join-Path $guestRoot 'scripts\guest\30-InstallADCS.ps1'
        Invoke-Command -Session $session -ArgumentList $scriptPath, $remoteConfig -ScriptBlock { param($Path, $Config) & $Path -ConfigPath $Config } -ErrorAction Stop | Out-Host
        $lastSuccessfulPhase = 'ADCS'
        Write-Host 'Recommended checkpoint: 05-ADCS-Baseline (create manually after reviewing validation).'
    }

    if ($selectedPhases -contains 'ADCSHttpCdp') {
        Enter-HostPhase -Name 'ADCSHttpCdp'
        $scriptPath = Join-Path $guestRoot 'scripts\guest\50-EnableADCSHttpCdp.ps1'
        Invoke-Command -Session $session -ArgumentList $scriptPath, $remoteConfig -ScriptBlock { param($Path, $Config) & $Path -ConfigPath $Config } -ErrorAction Stop | Out-Host
        $lastSuccessfulPhase = 'ADCSHttpCdp'
        Write-Host 'Recommended checkpoint: 06-ADCS-HTTP-CDP (create manually after reviewing validation).'
    }

    if ($selectedPhases -contains 'Validation') {
        Enter-HostPhase -Name 'Validation'
        $scriptPath = Join-Path $guestRoot 'scripts\guest\90-ValidateLab.ps1'
        Invoke-Command -Session $session -ArgumentList $scriptPath, $remoteConfig, $timeZoneId, ([bool]$SkipDcDiag), ($selectedPhases -contains 'ADCSHttpCdp') -ScriptBlock {
            param($Path, $Config, $TargetTimeZoneId, $Skip, $ExpectHttpCdp)
            & $Path -ConfigPath $Config -TimeZoneId $TargetTimeZoneId -SkipDcDiag:$Skip -ExpectAdcsHttpCdp:$ExpectHttpCdp -FailOnValidationError
        } -ErrorAction Stop | Out-Host
        $lastSuccessfulPhase = 'Validation'
    }

    $summaryPath = Join-Path $logDirectory "$(Get-Date -Format 'yyyyMMdd-HHmmss')-host-summary.json"
    [ordered]@{
        Timestamp = (Get-Date).ToString('o')
        VMName = $vmName
        RequestedPhases = $selectedPhases
        LastSuccessfulPhase = $lastSuccessfulPhase
        Status = 'Succeeded'
        BootstrapCommit = $bootstrapCommit
        BootstrapWorkingTree = $bootstrapStatus
        BootstrapPublishedAt = $bootstrapPublishedAt
        LabConfigSha256 = $configSha256
        HostLog = $hostLog
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

    [pscustomobject]@{
        VMName = $vmName
        Status = 'Succeeded'
        LastSuccessfulPhase = $lastSuccessfulPhase
        HostLog = $hostLog
        Summary = $summaryPath
    }
}
catch {
    Write-HostPhaseLog -CurrentPhase $activePhase -Action 'Run' -Status Failed -Message "$($_.Exception.Message); FailedPhase=$activePhase; LastSuccessfulPhase=$lastSuccessfulPhase"
    if ($null -ne $hostLog) {
        $failureSummaryPath = Join-Path (Split-Path $hostLog -Parent) "$(Get-Date -Format 'yyyyMMdd-HHmmss')-host-summary-failed.json"
        [ordered]@{
            Timestamp = (Get-Date).ToString('o')
            VMName = $vmName
            RequestedPhases = $selectedPhases
            FailedPhase = $activePhase
            LastSuccessfulPhase = $lastSuccessfulPhase
            Status = 'Failed'
            BootstrapCommit = $bootstrapCommit
            BootstrapWorkingTree = $bootstrapStatus
            BootstrapPublishedAt = $bootstrapPublishedAt
            LabConfigSha256 = $configSha256
            Error = $_.Exception.Message
            HostLog = $hostLog
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $failureSummaryPath -Encoding UTF8
    }
    throw
}
finally {
    if ($null -ne $session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
    if ($null -ne $hostLog) { try { Stop-Transcript | Out-Null } catch { } }
}
