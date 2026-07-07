#Requires -Version 5.1
#Requires -RunAsAdministrator
#Requires -Modules Hyper-V

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$ConfigPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'config\LabConfig.psd1'),

    [Parameter(Mandatory = $true)]
    [string[]]$ScenarioName,

    [ValidateSet('Setup', 'Validate', 'Cleanup', 'Audit')]
    [string]$Action = 'Setup',

    [hashtable]$ScriptParameters = @{},
    [hashtable]$ValidationInputFiles = @{},
    [PSCredential]$Credential,
    [string]$GuestConfigurationName,
    [switch]$AcknowledgeIsolatedLabRisk,
    [switch]$SkipSync,
    [ValidateRange(30, 1800)][int]$ReadinessTimeoutSeconds = 600
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path $PSScriptRoot -Parent
$scenariosRoot = $PSScriptRoot
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Assert-LabAdministrator
Assert-LabPowerShellDirectClient
$config = Import-LabConfig -Path $ConfigPath
$vmName = [string]$config.Lab.VMName
$guestRoot = [string]$config.Lab.GuestBootstrapPath
$guestScenariosRoot = Join-Path $guestRoot 'scenarios'
$hostValidationInputsRoot = Join-Path $repositoryRoot 'artifacts\scenario-validation'
$guestValidationInputsRoot = Join-Path $guestRoot 'scenario-validation-inputs'
if ($null -eq $ScriptParameters) {
    $ScriptParameters = @{}
}
if ($null -eq $ValidationInputFiles) {
    $ValidationInputFiles = @{}
}
$scriptFileName = switch ($Action) {
    'Setup' { 'setup.ps1' }
    'Validate' { 'validate.ps1' }
    'Cleanup' { 'cleanup.ps1' }
    'Audit' { 'Audit.ps1' }
}
$session = $null
$hostLog = $null
$lastScenario = 'None'
$validationInputHostDirectory = $null
$effectiveScriptParameterNames = @()

function Write-ScenarioHostLog {
    param(
        [string]$CurrentScenario,
        [string]$CurrentAction,
        [string]$Status,
        [string]$Message
    )
    Write-Host ("{0} Scenario={1} Action={2} Status={3} Target={4} Message={5}" -f (Get-Date).ToString('o'), $CurrentScenario, $CurrentAction, $Status, $vmName, $Message)
}

function ConvertTo-LabScenarioRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$FullName,
        [string]$ScenariosRoot = $scenariosRoot
    )

    $relativePath = $FullName.Substring($ScenariosRoot.Length).TrimStart([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    return $relativePath.Replace([System.IO.Path]::DirectorySeparatorChar, '/').Replace([System.IO.Path]::AltDirectorySeparatorChar, '/')
}

function Normalize-LabScenarioName {
    param([Parameter(Mandatory = $true)][string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        throw 'ScenarioName cannot contain an empty value.'
    }
    $normalizedName = $Name.Replace('\', '/')
    if ($normalizedName -match '^[A-Za-z]:' -or $normalizedName.StartsWith('/') -or $normalizedName.StartsWith('~')) {
        throw "ScenarioName must be a relative scenario name: '$Name'"
    }
    if ($normalizedName.IndexOfAny([char[]]@('*', '?', '[')) -ge 0) {
        throw "ScenarioName must identify one scenario; wildcard characters are not supported: '$Name'"
    }
    foreach ($segment in @($normalizedName -split '/')) {
        if ([string]::IsNullOrWhiteSpace($segment) -or $segment -eq '.' -or $segment -eq '..') {
            throw "ScenarioName contains an invalid path segment: '$Name'"
        }
    }
    return $normalizedName
}

function Join-LabScenarioRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$BasePath,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )

    $joinedPath = $BasePath
    foreach ($segment in @($RelativePath -split '/')) {
        $joinedPath = Join-Path $joinedPath $segment
    }
    return $joinedPath
}

function Get-LabScenarioManifest {
    param([Parameter(Mandatory = $true)][string]$Directory)

    $manifestPath = Join-Path $Directory 'scenario.psd1'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        return $null
    }

    return Import-PowerShellDataFile -LiteralPath $manifestPath
}

function Get-LabScenarioResolutionNames {
    param([Parameter(Mandatory = $true)]$Scenario)

    $names = New-Object 'System.Collections.Generic.List[string]'
    foreach ($candidate in @(
        [string]$Scenario.Name
        [string]$Scenario.LeafName
        [string]$Scenario.Id
    ) + @($Scenario.Aliases)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$candidate)) {
            [void]$names.Add((Normalize-LabScenarioName -Name ([string]$candidate)))
        }
    }

    return $names.ToArray()
}

function Get-LabScenarioInventory {
    param(
        [Parameter(Mandatory = $true)][string]$ScenariosRoot,
        [Parameter(Mandatory = $true)][string]$RequiredScript
    )

    return @(Get-ChildItem -LiteralPath $ScenariosRoot -Recurse -Directory -ErrorAction Stop | Where-Object {
        Test-Path -LiteralPath (Join-Path $_.FullName $RequiredScript) -PathType Leaf
    } | ForEach-Object {
        $relativePath = ConvertTo-LabScenarioRelativePath -FullName $_.FullName -ScenariosRoot $ScenariosRoot
        $manifest = Get-LabScenarioManifest -Directory $_.FullName
        $aliases = @()
        $id = $null
        if ($null -ne $manifest) {
            if ($manifest.ContainsKey('Id') -and -not [string]::IsNullOrWhiteSpace([string]$manifest.Id)) {
                $id = [string]$manifest.Id
            }
            if ($manifest.ContainsKey('Aliases')) {
                $aliases = @($manifest.Aliases | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            }
        }
        [pscustomobject]@{
            Name         = $relativePath
            LeafName     = [string]$_.Name
            RelativePath = $relativePath
            FullName     = [string]$_.FullName
            Id           = $id
            Aliases      = $aliases
        }
    })
}

function Resolve-LabScenarioDirectory {
    param(
        [Parameter(Mandatory = $true)][string[]]$Name,
        [Parameter(Mandatory = $true)][string]$RequiredScript,
        [string]$ScenariosRoot = $scenariosRoot
    )

    $allScenarios = @(Get-LabScenarioInventory -ScenariosRoot $ScenariosRoot -RequiredScript $RequiredScript)
    if ($allScenarios.Count -eq 0) {
        throw "No scenario directories with '$RequiredScript' were found under '$ScenariosRoot'."
    }

    $resolved = New-Object 'System.Collections.Generic.List[object]'
    $seen = @{}
    foreach ($requestedName in @($Name)) {
        $normalizedName = Normalize-LabScenarioName -Name $requestedName

        $matches = @($allScenarios | Where-Object {
            $identityNames = @(Get-LabScenarioResolutionNames -Scenario $_)
            $identityNames -contains $normalizedName
        })
        if ($matches.Count -eq 0) {
            $available = (@($allScenarios | ForEach-Object { $_.Name } | Sort-Object) -join ', ')
            throw "Scenario '$requestedName' was not found for action '$Action'. Available: $available"
        }
        if ($matches.Count -gt 1) {
            $availableMatches = (@($matches | ForEach-Object { $_.Name } | Sort-Object) -join ', ')
            throw "Scenario '$requestedName' is ambiguous for action '$Action'. Use a relative scenario path. Matches: $availableMatches"
        }
        foreach ($match in @($matches | Sort-Object Name)) {
            if (-not $seen.ContainsKey($match.FullName)) {
                $seen[$match.FullName] = $true
                $resolved.Add($match)
            }
        }
    }

    return $resolved.ToArray()
}

function Get-LabScenarioScriptParameterNames {
    param([Parameter(Mandatory = $true)][string]$Path)

    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
    if (@($parseErrors).Count -gt 0) {
        $details = (@($parseErrors | ForEach-Object { $_.Message }) -join '; ')
        throw "Cannot inspect scenario script parameters in '$Path': $details"
    }
    if ($null -eq $ast.ParamBlock) {
        return @()
    }

    return @($ast.ParamBlock.Parameters | ForEach-Object { [string]$_.Name.VariablePath.UserPath })
}

function Assert-LabValidationInputConfiguration {
    param(
        [Parameter(Mandatory = $true)][object[]]$Scenarios,
        [Parameter(Mandatory = $true)][string]$CurrentAction,
        [Parameter(Mandatory = $true)][string]$ActionScript,
        [hashtable]$Files = @{},
        [hashtable]$Parameters = @{}
    )

    if (@($Files.Keys).Count -eq 0) {
        return
    }
    if ($CurrentAction -ne 'Validate') {
        throw 'ValidationInputFiles can only be used with -Action Validate.'
    }
    if ($Scenarios.Count -ne 1) {
        throw 'ValidationInputFiles requires exactly one resolved scenario so each file can be mapped to that validate.ps1 parameter set.'
    }

    $scriptPath = Join-Path ([string]$Scenarios[0].FullName) $ActionScript
    $allowedParameters = @{}
    foreach ($allowedParameter in @(Get-LabScenarioScriptParameterNames -Path $scriptPath)) {
        $allowedParameters[[string]$allowedParameter] = $true
    }

    foreach ($key in @($Files.Keys)) {
        $parameterName = [string]$key
        if ([string]::IsNullOrWhiteSpace($parameterName) -or $parameterName -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
            throw "ValidationInputFiles contains an invalid script parameter name: '$parameterName'."
        }
        if (-not $allowedParameters.ContainsKey($parameterName)) {
            throw "ValidationInputFiles parameter '$parameterName' is not declared by '$scriptPath'."
        }
        if ($Parameters.ContainsKey($parameterName)) {
            throw "Script parameter '$parameterName' cannot be supplied by both ScriptParameters and ValidationInputFiles."
        }
        $sourcePath = $Files[$key]
        if ($sourcePath -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$sourcePath)) {
            throw "ValidationInputFiles parameter '$parameterName' must map to a non-empty host file path string."
        }
    }
}

function Resolve-LabScenarioValidationInputFiles {
    param(
        [hashtable]$Files = @{},
        [Parameter(Mandatory = $true)][string]$HostDirectory
    )

    $hostDirectoryFullPath = [System.IO.Path]::GetFullPath($HostDirectory).TrimEnd([char[]]@('\', '/'))
    $hostDirectoryPrefix = $hostDirectoryFullPath + [System.IO.Path]::DirectorySeparatorChar
    $resolvedInputs = New-Object 'System.Collections.Generic.List[object]'

    foreach ($key in @($Files.Keys | Sort-Object { [string]$_ })) {
        $parameterName = [string]$key
        $configuredPath = [string]$Files[$key]
        if ([System.IO.Path]::IsPathRooted($configuredPath)) {
            $candidatePath = $configuredPath
        }
        else {
            $candidatePath = [System.IO.Path]::GetFullPath((Join-Path $hostDirectoryFullPath $configuredPath))
            if (-not $candidatePath.StartsWith($hostDirectoryPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Relative validation input path for '$parameterName' must remain under '$hostDirectoryFullPath': '$configuredPath'."
            }
        }

        if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
            throw "Host validation input for '$parameterName' was not found as a file: '$candidatePath'. Place relative inputs under '$hostDirectoryFullPath' or supply an absolute host path."
        }

        $hostFile = Get-Item -LiteralPath $candidatePath -Force -ErrorAction Stop
        $hostHash = Get-FileHash -LiteralPath $hostFile.FullName -Algorithm SHA256 -ErrorAction Stop
        $extension = [System.IO.Path]::GetExtension([string]$hostFile.Name)
        $resolvedInputs.Add([pscustomobject]@{
            ParameterName = $parameterName
            HostPath      = [string]$hostFile.FullName
            GuestFileName = $parameterName + $extension
            Length        = [long]$hostFile.Length
            SHA256        = [string]$hostHash.Hash
        })
    }

    return $resolvedInputs.ToArray()
}

function New-LabScenarioDirectSession {
    param([Parameter(Mandatory = $true)][PSCredential]$ConnectionCredential)

    $newSession = $null
    $sessionParameters = @{
        VMName      = $vmName
        Credential  = $ConnectionCredential
        ErrorAction = 'Stop'
    }
    if (-not [string]::IsNullOrWhiteSpace($GuestConfigurationName)) {
        $sessionParameters.ConfigurationName = $GuestConfigurationName
    }

    try {
        $newSession = New-PSSession @sessionParameters
        Invoke-Command -Session $newSession -ScriptBlock { $true } -ErrorAction Stop | Out-Null
        return $newSession
    }
    catch {
        if ($null -ne $newSession) {
            Remove-PSSession -Session $newSession -ErrorAction SilentlyContinue
        }
        throw "PowerShell Direct connection to '$vmName' failed: $($_.Exception.Message)"
    }
}

function Wait-LabScenarioActiveDirectoryReady {
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession]$Session,
        [int]$TimeoutSeconds = 600
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastError = $null
    $attempt = 0
    do {
        try {
            $readiness = Invoke-Command -Session $Session -ScriptBlock {
                $services = @(Get-Service -Name 'ADWS', 'NTDS' -ErrorAction Stop)
                $notRunning = @($services | Where-Object Status -ne 'Running')
                if ($notRunning.Count -gt 0) {
                    throw "Active Directory services are not running: $(@($notRunning.Name) -join ', ')."
                }
                Import-Module ActiveDirectory -ErrorAction Stop -WarningAction SilentlyContinue
                $domain = Get-ADDomain -Server $env:COMPUTERNAME -ErrorAction Stop
                [pscustomobject]@{
                    Domain = [string]$domain.DNSRoot
                    Server = $env:COMPUTERNAME
                }
            } -ErrorAction Stop
            Write-ScenarioHostLog -CurrentScenario 'ActiveDirectory' -CurrentAction 'WaitReady' -Status Unchanged -Message "Domain=$($readiness.Domain); Server=$($readiness.Server)"
            return
        }
        catch {
            $lastError = $_.Exception.Message
            $attempt++
            if ($attempt -eq 1 -or $attempt % 6 -eq 0) {
                Write-ScenarioHostLog -CurrentScenario 'ActiveDirectory' -CurrentAction 'WaitReady' -Status Info -Message "Waiting for ADWS, NTDS, and Get-ADDomain. Last error: $lastError"
            }
            Start-Sleep -Seconds 5
        }
    } while ((Get-Date) -lt $deadline)

    throw "Active Directory did not become ready within $TimeoutSeconds seconds. Last error: $lastError"
}

function Invoke-LabScenarioUncTransferRetry {
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$DirectError,
        [Parameter(Mandatory = $true)][string]$CurrentScenario,
        [Parameter(Mandatory = $true)][string]$CurrentAction,
        [switch]$Recurse
    )

    $temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('ADLabScenario-' + [guid]::NewGuid().ToString('N'))
    if ($temporaryRoot.StartsWith('\\') -or $temporaryRoot.StartsWith('//')) {
        throw "Direct UNC transfer failed: $DirectError. The host temporary directory is also a UNC path: '$temporaryRoot'."
    }

    Write-ScenarioHostLog -CurrentScenario $CurrentScenario -CurrentAction $CurrentAction -Status Info -Message 'Direct transfer from the UNC source did not complete. Retrying via a temporary local host copy; a later Status=Changed confirms success.'
    try {
        New-Item -ItemType Directory -Path $temporaryRoot -ErrorAction Stop | Out-Null
        $localSourcePath = Join-Path $temporaryRoot (Split-Path $SourcePath -Leaf)
        Copy-Item -LiteralPath $SourcePath -Destination $localSourcePath -Force -Recurse:$Recurse -ErrorAction Stop
        Copy-Item -LiteralPath $localSourcePath -Destination $Destination -ToSession $Session -Force -Recurse:$Recurse -ErrorAction Stop
    }
    catch {
        $message = "Direct UNC transfer from '$SourcePath' failed: $DirectError. Retry through a temporary local host copy failed: $($_.Exception.Message)"
        throw [System.InvalidOperationException]::new($message, $_.Exception)
    }
    finally {
        if (Test-Path -LiteralPath $temporaryRoot) {
            try { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction Stop }
            catch { Write-Warning "Could not remove temporary scenario copy '$temporaryRoot': $($_.Exception.Message)" }
        }
    }
}

function Sync-LabScenario {
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory = $true)]$Scenario
    )

    $remoteScenarioPath = Join-LabScenarioRelativePath -BasePath $guestScenariosRoot -RelativePath ([string]$Scenario.RelativePath)
    $remoteScenarioParentPath = Split-Path $remoteScenarioPath -Parent
    Invoke-Command -Session $Session -ArgumentList $guestScenariosRoot -ScriptBlock {
        param($Destination)
        if (-not (Test-Path -LiteralPath $Destination)) {
            New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        }
    } -ErrorAction Stop
    Invoke-Command -Session $Session -ArgumentList $remoteScenarioParentPath -ScriptBlock {
        param($Destination)
        if (-not (Test-Path -LiteralPath $Destination)) {
            New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        }
    } -ErrorAction Stop

    if ($PSCmdlet.ShouldProcess($remoteScenarioPath, "Sync scenario '$($Scenario.Name)'")) {
        try {
            Copy-Item -LiteralPath $Scenario.FullName -Destination $remoteScenarioParentPath -ToSession $Session -Force -Recurse -ErrorAction Stop
        }
        catch {
            if (-not ($Scenario.FullName.StartsWith('\\') -or $Scenario.FullName.StartsWith('//'))) { throw }
            Invoke-LabScenarioUncTransferRetry -Session $Session -SourcePath $Scenario.FullName -Destination $remoteScenarioParentPath -DirectError $_.Exception.Message -CurrentScenario $Scenario.Name -CurrentAction 'Sync' -Recurse
        }
        Write-ScenarioHostLog -CurrentScenario $Scenario.Name -CurrentAction 'Sync' -Status Changed -Message $remoteScenarioPath
    }

    return $remoteScenarioPath
}

function Sync-LabScenarioValidationInputs {
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory = $true)]$Scenario,
        [Parameter(Mandatory = $true)][object[]]$Inputs
    )

    $guestInputDirectory = Join-LabScenarioRelativePath -BasePath $guestValidationInputsRoot -RelativePath ([string]$Scenario.RelativePath)
    Invoke-Command -Session $Session -ArgumentList $guestInputDirectory -ScriptBlock {
        param($Destination)
        if (-not (Test-Path -LiteralPath $Destination)) {
            New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        }
    } -ErrorAction Stop

    $transfers = New-Object 'System.Collections.Generic.List[object]'
    foreach ($input in @($Inputs)) {
        $guestPath = Join-Path $guestInputDirectory ([string]$input.GuestFileName)
        if (-not $PSCmdlet.ShouldProcess($guestPath, "Copy host validation input for parameter '$($input.ParameterName)'")) {
            throw "Validation input transfer was not approved for '$guestPath'."
        }

        try {
            try {
                Copy-Item -LiteralPath $input.HostPath -Destination $guestPath -ToSession $Session -Force -ErrorAction Stop
            }
            catch {
                if (-not ($input.HostPath.StartsWith('\\') -or $input.HostPath.StartsWith('//'))) { throw }
                Invoke-LabScenarioUncTransferRetry -Session $Session -SourcePath $input.HostPath -Destination $guestPath -DirectError $_.Exception.Message -CurrentScenario $Scenario.Name -CurrentAction 'ValidationInput'
            }
            $guestMetadataItems = @(Invoke-Command -Session $Session -ArgumentList $guestPath -ScriptBlock {
                param($Path)
                if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
                    throw "Transferred validation input was not found: $Path"
                }
                $file = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
                $hash = Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop
                [pscustomobject]@{
                    Length = [long]$file.Length
                    SHA256 = [string]$hash.Hash
                }
            } -ErrorAction Stop)
            if ($guestMetadataItems.Count -ne 1) {
                throw "Expected one guest metadata result, received $($guestMetadataItems.Count)."
            }
            $guestMetadata = $guestMetadataItems[0]
            if ([long]$guestMetadata.Length -ne [long]$input.Length -or [string]$guestMetadata.SHA256 -ine [string]$input.SHA256) {
                throw "SHA-256 or length mismatch after copying '$($input.HostPath)' to '$guestPath'."
            }
        }
        catch {
            $message = "Host validation input transfer failed for parameter '$($input.ParameterName)' from '$($input.HostPath)' to '$guestPath': $($_.Exception.Message)"
            throw [System.InvalidOperationException]::new($message, $_.Exception)
        }

        Write-ScenarioHostLog -CurrentScenario $Scenario.Name -CurrentAction 'ValidationInput' -Status Changed -Message "Parameter=$($input.ParameterName); GuestPath=$guestPath; Bytes=$($input.Length); SHA256=$($input.SHA256)"
        $transfers.Add([pscustomobject]@{
            ParameterName = [string]$input.ParameterName
            HostPath      = [string]$input.HostPath
            GuestPath     = $guestPath
            Length        = [long]$input.Length
            SHA256        = [string]$input.SHA256
        })
    }

    return $transfers.ToArray()
}

function Invoke-LabScenarioAction {
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory = $true)]$Scenario,
        [Parameter(Mandatory = $true)][string]$RemoteScenarioPath,
        [Parameter(Mandatory = $true)][string]$ActionScript,
        [hashtable]$Parameters = @{}
    )

    $remoteScriptPath = Join-Path $RemoteScenarioPath $ActionScript
    if (-not $PSCmdlet.ShouldProcess($remoteScriptPath, "Invoke scenario action '$Action'")) {
        return $null
    }

    Write-ScenarioHostLog -CurrentScenario $Scenario.Name -CurrentAction $Action -Status Running -Message $remoteScriptPath
    $output = Invoke-Command -Session $Session -ArgumentList $remoteScriptPath, $Parameters -ScriptBlock {
        param($Path, $ArgumentHash)
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "Scenario script not found on guest: $Path"
        }
        if ($null -eq $ArgumentHash) {
            $ArgumentHash = @{}
        }
        & $Path @ArgumentHash
    } -ErrorAction Stop
    $output | Out-Host
    Write-ScenarioHostLog -CurrentScenario $Scenario.Name -CurrentAction $Action -Status Succeeded -Message $remoteScriptPath
    return $output
}

try {
    $scenarios = @(Resolve-LabScenarioDirectory -Name $ScenarioName -RequiredScript $scriptFileName)
    Assert-LabValidationInputConfiguration -Scenarios $scenarios -CurrentAction $Action -ActionScript $scriptFileName -Files $ValidationInputFiles -Parameters $ScriptParameters
    if (@($ValidationInputFiles.Keys).Count -gt 0) {
        $validationInputHostDirectory = Join-LabScenarioRelativePath -BasePath $hostValidationInputsRoot -RelativePath ([string]$scenarios[0].RelativePath)
    }
    $effectiveScriptParameterNames = @(
        @($ScriptParameters.Keys) + @($ValidationInputFiles.Keys) |
            ForEach-Object { [string]$_ } |
            Sort-Object -Unique
    )
    if ($Action -eq 'Setup' -and -not $WhatIfPreference -and -not $AcknowledgeIsolatedLabRisk) {
        throw 'Scenario setup intentionally changes the isolated lab. Rerun with -AcknowledgeIsolatedLabRisk after confirming the VM is not connected to external networks.'
    }

    $plan = @($scenarios | ForEach-Object {
        [pscustomobject]@{
            Scenario          = $_.Name
            Action            = $Action
            HostPath          = $_.FullName
            GuestPath         = (Join-LabScenarioRelativePath -BasePath $guestScenariosRoot -RelativePath ([string]$_.RelativePath))
            Script            = $scriptFileName
            Sync              = -not [bool]$SkipSync
            ScriptParameters  = $effectiveScriptParameterNames
            ValidationInputs  = @($ValidationInputFiles.Keys | ForEach-Object { [string]$_ } | Sort-Object)
            ValidationInputHostDirectory = $validationInputHostDirectory
        }
    })
    if ($WhatIfPreference) {
        $plan | Format-Table -AutoSize | Out-Host
        return $plan
    }

    $logDirectory = Join-Path $repositoryRoot 'logs'
    if (-not (Test-Path -LiteralPath $logDirectory)) {
        New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
    }
    $hostLog = Join-Path $logDirectory "$(Get-Date -Format 'yyyyMMdd-HHmmss')-host-scenario-$($Action.ToLowerInvariant()).log"
    Start-Transcript -Path $hostLog -Force | Out-Null

    Write-ScenarioHostLog -CurrentScenario 'Scenario' -CurrentAction 'Plan' -Status Info -Message "Action=$Action; Scenarios=$((@($scenarios | ForEach-Object Name) -join ', ')); Script=$scriptFileName"

    $resolvedValidationInputs = @()
    if (@($ValidationInputFiles.Keys).Count -gt 0) {
        if (-not (Test-Path -LiteralPath $validationInputHostDirectory)) {
            New-Item -ItemType Directory -Path $validationInputHostDirectory -Force | Out-Null
            Write-ScenarioHostLog -CurrentScenario $scenarios[0].Name -CurrentAction 'ValidationInput' -Status Changed -Message "Created host input directory: $validationInputHostDirectory"
        }
        $resolvedValidationInputs = @(Resolve-LabScenarioValidationInputFiles -Files $ValidationInputFiles -HostDirectory $validationInputHostDirectory)
        foreach ($resolvedValidationInput in @($resolvedValidationInputs)) {
            Write-ScenarioHostLog -CurrentScenario $scenarios[0].Name -CurrentAction 'ValidationInput' -Status Info -Message "Parameter=$($resolvedValidationInput.ParameterName); HostPath=$($resolvedValidationInput.HostPath); Bytes=$($resolvedValidationInput.Length); SHA256=$($resolvedValidationInput.SHA256)"
        }
    }

    $vm = Get-VM -Name $vmName -ErrorAction Stop
    if ($vm.State -ne 'Running') {
        throw "VM '$vmName' must be running; current state is '$($vm.State)'."
    }
    $adapters = @(Get-VMNetworkAdapter -VMName $vmName -ErrorAction Stop)
    if ($adapters.Count -ne 1) {
        throw "VM '$vmName' must have exactly one NIC; found $($adapters.Count)."
    }
    if ([string]$adapters[0].SwitchName -ine [string]$config.Network.SwitchName) {
        throw "VM '$vmName' is connected to switch '$($adapters[0].SwitchName)', expected '$($config.Network.SwitchName)'."
    }
    $switch = Get-VMSwitch -Name ([string]$config.Network.SwitchName) -ErrorAction Stop
    if ([string]$switch.SwitchType -ine [string]$config.Network.SwitchType) {
        throw "Hyper-V switch '$($switch.Name)' is '$($switch.SwitchType)', expected '$($config.Network.SwitchType)'."
    }

    if ($null -eq $Credential) {
        $Credential = Get-Credential -UserName "$($config.Domain.NetBIOSName)\Administrator" -Message "Enter the domain Administrator credential for '$vmName'."
    }
    $session = New-LabScenarioDirectSession -ConnectionCredential $Credential
    Wait-LabScenarioActiveDirectoryReady -Session $session -TimeoutSeconds $ReadinessTimeoutSeconds

    $results = New-Object 'System.Collections.Generic.List[object]'
    $allValidationInputTransfers = New-Object 'System.Collections.Generic.List[object]'
    foreach ($scenario in $scenarios) {
        $lastScenario = [string]$scenario.Name
        $remoteScenarioPath = Join-LabScenarioRelativePath -BasePath $guestScenariosRoot -RelativePath ([string]$scenario.RelativePath)
        if (-not $SkipSync) {
            $remoteScenarioPath = Sync-LabScenario -Session $session -Scenario $scenario
        }
        $effectiveParameters = @{}
        foreach ($key in @($ScriptParameters.Keys)) {
            $effectiveParameters[$key] = $ScriptParameters[$key]
        }
        $validationInputTransfers = @()
        if ($resolvedValidationInputs.Count -gt 0) {
            $validationInputTransfers = @(Sync-LabScenarioValidationInputs -Session $session -Scenario $scenario -Inputs $resolvedValidationInputs)
            foreach ($transfer in @($validationInputTransfers)) {
                $effectiveParameters[[string]$transfer.ParameterName] = [string]$transfer.GuestPath
                $allValidationInputTransfers.Add($transfer)
            }
        }
        $output = Invoke-LabScenarioAction -Session $session -Scenario $scenario -RemoteScenarioPath $remoteScenarioPath -ActionScript $scriptFileName -Parameters $effectiveParameters
        $results.Add([pscustomobject]@{
            PSTypeName         = 'ADLab.ScenarioActionResult'
            Status             = 'Succeeded'
            VMName             = $vmName
            Scenario           = [string]$scenario.Name
            Action             = $Action
            HostPath           = [string]$scenario.FullName
            GuestPath          = $remoteScenarioPath
            GuestScript        = (Join-Path $remoteScenarioPath $scriptFileName)
            Synced             = -not [bool]$SkipSync
            ScriptParameterNames = $effectiveScriptParameterNames
            ValidationInputs   = @($validationInputTransfers)
            HostLog            = $hostLog
            OutputCount        = @($output).Count
        })
    }

    $summaryPath = Join-Path $logDirectory "$(Get-Date -Format 'yyyyMMdd-HHmmss')-host-scenario-$($Action.ToLowerInvariant())-summary.json"
    [ordered]@{
        Timestamp = (Get-Date).ToString('o')
        VMName = $vmName
        Action = $Action
        Scenarios = @($scenarios | ForEach-Object { $_.Name })
        Status = 'Succeeded'
        Synced = -not [bool]$SkipSync
        ScriptParameterNames = $effectiveScriptParameterNames
        ValidationInputHostDirectory = $validationInputHostDirectory
        ValidationInputs = @($allValidationInputTransfers.ToArray())
        HostLog = $hostLog
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

    foreach ($result in $results.ToArray()) {
        $result | Add-Member -NotePropertyName Summary -NotePropertyValue $summaryPath -Force
        $result
    }
}
catch {
    Write-ScenarioHostLog -CurrentScenario $lastScenario -CurrentAction $Action -Status Failed -Message $_.Exception.Message
    if ($null -ne $hostLog) {
        $failureSummaryPath = Join-Path (Split-Path $hostLog -Parent) "$(Get-Date -Format 'yyyyMMdd-HHmmss')-host-scenario-$($Action.ToLowerInvariant())-summary-failed.json"
        [ordered]@{
            Timestamp = (Get-Date).ToString('o')
            VMName = $vmName
            Action = $Action
            Scenarios = @($ScenarioName)
            LastScenario = $lastScenario
            Status = 'Failed'
            Error = $_.Exception.Message
            ValidationInputParameterNames = @($ValidationInputFiles.Keys | ForEach-Object { [string]$_ } | Sort-Object)
            ValidationInputHostDirectory = $validationInputHostDirectory
            HostLog = $hostLog
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $failureSummaryPath -Encoding UTF8
    }
    throw "Scenario action failed after scenario '$lastScenario': $($_.Exception.Message)"
}
finally {
    if ($null -ne $session) {
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
    }
    if ($null -ne $hostLog) {
        try { Stop-Transcript | Out-Null } catch { }
    }
}
