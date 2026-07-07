#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ConfigPath = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'config\LabConfig.psd1'),
    [string]$TimeZoneId,
    [switch]$Restart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Assert-LabAdministrator
$config = Import-LabConfig -Path $ConfigPath
$phase = 'OSBaseline'
$log = Start-LabTranscript -Phase $phase
$changed = $false
$rebootRequired = $false
$result = $null

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "Transcript=$log"
    $targetTimeZone = if ($PSBoundParameters.ContainsKey('TimeZoneId')) { $TimeZoneId } else { [string]$config.Time.WindowsTimeZoneId }
    if ([string]::IsNullOrWhiteSpace($targetTimeZone) -or $targetTimeZone -eq 'Host') {
        throw 'TimeZoneId is required when Time.WindowsTimeZoneId is Host. Run through the host bootstrap or pass -TimeZoneId.'
    }
    $currentTimeZone = (Get-TimeZone -ErrorAction Stop).Id
    if ($currentTimeZone -ine $targetTimeZone) {
        if ($PSCmdlet.ShouldProcess($targetTimeZone, 'Set Windows time zone')) {
            Set-TimeZone -Id $targetTimeZone -ErrorAction Stop
            $changed = $true
            Write-LabLog -Phase $phase -Action 'SetTimeZone' -Status Changed -Target $targetTimeZone
        }
    }
    else {
        Write-LabLog -Phase $phase -Action 'SetTimeZone' -Status Unchanged -Target $targetTimeZone
    }

    $adapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.HardwareInterface -and $_.Status -ne 'Disabled' })
    if ($adapters.Count -ne 1) {
        throw "Expected exactly one enabled hardware network adapter, found $($adapters.Count). No network changes were made."
    }
    $adapter = $adapters[0]
    $network = $config.Network.DC01

    $ipInterface = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop
    if ($ipInterface.Dhcp -ne 'Disabled') {
        if ($PSCmdlet.ShouldProcess($adapter.Name, 'Disable IPv4 DHCP')) {
            Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -Dhcp Disabled -ErrorAction Stop
            $changed = $true
            Write-LabLog -Phase $phase -Action 'DisableDhcp' -Status Changed -Target $adapter.Name
        }
    }

    $addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.PrefixOrigin -ne 'WellKnown' })
    $targetAddress = @($addresses | Where-Object { $_.IPAddress -eq [string]$network.IPAddress -and $_.PrefixLength -eq [int]$network.PrefixLength })
    foreach ($address in @($addresses | Where-Object { $_.IPAddress -ne [string]$network.IPAddress -or $_.PrefixLength -ne [int]$network.PrefixLength })) {
        if ($PSCmdlet.ShouldProcess($address.IPAddress, "Remove IPv4 address from $($adapter.Name)")) {
            Remove-NetIPAddress -InputObject $address -Confirm:$false -ErrorAction Stop
            $changed = $true
            Write-LabLog -Phase $phase -Action 'RemoveIPAddress' -Status Changed -Target $address.IPAddress
        }
    }
    if ($targetAddress.Count -eq 0) {
        if ($PSCmdlet.ShouldProcess($adapter.Name, "Set IPv4 $($network.IPAddress)/$($network.PrefixLength)")) {
            New-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -IPAddress ([string]$network.IPAddress) -PrefixLength ([int]$network.PrefixLength) -ErrorAction Stop | Out-Null
            $changed = $true
            Write-LabLog -Phase $phase -Action 'SetIPAddress' -Status Changed -Target "$($network.IPAddress)/$($network.PrefixLength)"
        }
    }
    else {
        Write-LabLog -Phase $phase -Action 'SetIPAddress' -Status Unchanged -Target "$($network.IPAddress)/$($network.PrefixLength)"
    }

    $defaultRoutes = @(Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
    foreach ($route in $defaultRoutes) {
        if ($PSCmdlet.ShouldProcess($adapter.Name, "Remove default route via $($route.NextHop)")) {
            Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction Stop
            $changed = $true
            Write-LabLog -Phase $phase -Action 'RemoveDefaultGateway' -Status Changed -Target $route.NextHop
        }
    }
    if ($defaultRoutes.Count -eq 0) {
        Write-LabLog -Phase $phase -Action 'RemoveDefaultGateway' -Status Unchanged -Target $adapter.Name
    }

    $desiredDns = @($network.DnsServers | ForEach-Object { [string]$_ })
    $currentDns = @((Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses)
    if (($currentDns -join ',') -ine ($desiredDns -join ',')) {
        if ($PSCmdlet.ShouldProcess($adapter.Name, "Set DNS servers to $($desiredDns -join ', ')")) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $desiredDns -ErrorAction Stop
            $changed = $true
            Write-LabLog -Phase $phase -Action 'SetDnsServers' -Status Changed -Target $adapter.Name -Message ($desiredDns -join ',')
        }
    }
    else {
        Write-LabLog -Phase $phase -Action 'SetDnsServers' -Status Unchanged -Target $adapter.Name
    }

    $winRmService = Get-CimInstance Win32_Service -Filter "Name='WinRM'" -ErrorAction Stop
    $winRmRules = @(Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' -ErrorAction SilentlyContinue | Where-Object Enabled -eq 'True')
    $winRmListenerAvailable = $true
    try { Test-WSMan -ComputerName localhost -ErrorAction Stop | Out-Null }
    catch { $winRmListenerAvailable = $false }
    if ($winRmService.StartMode -ne 'Auto' -or $winRmService.State -ne 'Running' -or $winRmRules.Count -eq 0 -or -not $winRmListenerAvailable) {
        if ($PSCmdlet.ShouldProcess('WinRM', 'Enable PowerShell remoting and firewall rules')) {
            Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction Stop
            Set-Service -Name WinRM -StartupType Automatic -ErrorAction Stop
            $changed = $true
            Write-LabLog -Phase $phase -Action 'EnableWinRM' -Status Changed -Target 'WinRM' -Message 'Service, listener, and firewall rules enabled.'
        }
    }
    else {
        Write-LabLog -Phase $phase -Action 'EnableWinRM' -Status Unchanged -Target 'WinRM'
    }

    $targetName = [string]$config.Lab.ComputerName
    if ($env:COMPUTERNAME -ine $targetName) {
        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Rename computer to $targetName")) {
            Rename-Computer -NewName $targetName -Force -ErrorAction Stop
            $changed = $true
            $rebootRequired = $true
            Write-LabLog -Phase $phase -Action 'RenameComputer' -Status Changed -Target $targetName -Message 'Restart required'
        }
    }
    else {
        Write-LabLog -Phase $phase -Action 'RenameComputer' -Status Unchanged -Target $targetName
    }

    $result = New-LabPhaseResult -Phase $phase -Status Succeeded -Changed $changed -RebootRequired $rebootRequired -Message 'OS baseline is converged.'
}
catch {
    Write-LabLog -Phase $phase -Action 'Apply' -Status Failed -Target $env:COMPUTERNAME -Message $_.Exception.Message
    throw
}
finally {
    Stop-LabTranscript
}

$result
if ($Restart -and $rebootRequired -and -not $WhatIfPreference) {
    Restart-Computer -Force
}
