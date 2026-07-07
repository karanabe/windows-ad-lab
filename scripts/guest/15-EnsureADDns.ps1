#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ConfigPath = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'config\LabConfig.psd1'),
    [ValidateRange(60, 3600)][int]$TimeoutSeconds = 600
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $repositoryRoot 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
Assert-LabAdministrator
$config = Import-LabConfig -Path $ConfigPath
$phase = 'ActiveDirectoryDNS'
$log = Start-LabTranscript -Phase $phase
$changed = $false
$result = $null
$activeDnsAction = 'Initialize'
$activeDnsTarget = $env:COMPUTERNAME

function Get-LabDnsServerZoneOrNull {
    param([Parameter(Mandatory = $true)][string]$Name)

    return Get-DnsServerZone -Name $Name -ErrorAction SilentlyContinue |
        Select-Object -First 1
}

function Assert-LabDnsZoneConfiguration {
    param(
        [Parameter(Mandatory = $true)]$Zone,
        [Parameter(Mandatory = $true)][string]$ExpectedPartition
    )

    if ([string]$Zone.ZoneType -ine 'Primary' -or
        -not [bool]$Zone.IsDsIntegrated -or
        [string]$Zone.DynamicUpdate -ine 'Secure') {
        throw "Existing DNS zone '$($Zone.ZoneName)' must be an Active Directory-integrated primary zone with Secure dynamic updates."
    }

    if ($Zone.PSObject.Properties.Match('DirectoryPartitionName').Count -gt 0) {
        $actualPartition = [string]$Zone.DirectoryPartitionName
        if (-not [string]::IsNullOrWhiteSpace($actualPartition) -and
            $actualPartition -ine $ExpectedPartition) {
            throw "Existing DNS zone '$($Zone.ZoneName)' uses directory partition '$actualPartition'; expected '$ExpectedPartition'."
        }
    }
}

try {
    Write-LabLog -Phase $phase -Action 'Start' -Status Info -Target $env:COMPUTERNAME -Message "Transcript=$log"

    if ([int](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).DomainRole -lt 4) {
        throw 'The computer is not an Active Directory domain controller.'
    }

    Import-Module ActiveDirectory -ErrorAction Stop -WarningAction SilentlyContinue
    Import-Module DnsServer -ErrorAction Stop
    $domain = Get-LabCurrentDomain -Config $config
    $forest = Get-ADForest -Server $env:COMPUTERNAME -ErrorAction Stop
    $domainName = [string]$domain.DNSRoot
    $forestRoot = [string]$forest.RootDomain
    $domainPartition = "DomainDnsZones.$domainName"
    $forestPartition = "ForestDnsZones.$forestRoot"
    $expectedZones = @(
        [pscustomobject]@{
            Name      = $domainName
            Scope     = 'Domain'
            Partition = $domainPartition
        },
        [pscustomobject]@{
            Name      = "_msdcs.$forestRoot"
            Scope     = 'Forest'
            Partition = $forestPartition
        }
    )

    if ($WhatIfPreference) {
        foreach ($expectedZone in $expectedZones) {
            Write-LabLog -Phase $phase -Action 'PlanZone' -Status Info -Target $expectedZone.Name -Message "Ensure AD-integrated primary zone; ReplicationScope=$($expectedZone.Scope); DynamicUpdate=Secure"
        }
        $result = New-LabPhaseResult -Phase $phase -Status Skipped -Changed $false -Message 'WhatIf: AD DNS zones and domain controller records would be converged.'
    }
    else {
        $activeDnsAction = 'StartDNS'
        $activeDnsTarget = 'DNS'
        $dnsService = Get-Service -Name DNS -ErrorAction Stop
        if ([string]$dnsService.StartType -ne 'Automatic') {
            Set-Service -Name DNS -StartupType Automatic -ErrorAction Stop
            $changed = $true
        }
        if ($dnsService.Status -ne 'Running') {
            Start-Service -Name DNS -ErrorAction Stop
            $changed = $true
        }

        $activeDnsAction = 'WaitPartition'
        $activeDnsTarget = $domainName
        $partitionDeadline = (Get-Date).AddSeconds($TimeoutSeconds)
        $partitionAttempt = 0
        do {
            $pendingPartitions = @()
            foreach ($expectedZone in $expectedZones) {
                try {
                    $partition = Get-DnsServerDirectoryPartition -Name $expectedZone.Partition -ErrorAction Stop |
                        Select-Object -First 1
                    if ($null -eq $partition) {
                        $pendingPartitions += "$($expectedZone.Partition): not visible to DNS"
                    }
                    elseif ($partition.PSObject.Properties.Match('State').Count -gt 0 -and
                        [string]$partition.State -notmatch '(^0\b|DNS_DP_OKAY)') {
                        $pendingPartitions += "$($expectedZone.Partition): state=$($partition.State)"
                    }
                }
                catch {
                    $pendingPartitions += "$($expectedZone.Partition): $($_.Exception.Message)"
                }
            }
            if ($pendingPartitions.Count -eq 0) { break }
            $partitionAttempt++
            if ($partitionAttempt -eq 1 -or $partitionAttempt % 6 -eq 0) {
                Write-LabLog -Phase $phase -Action 'WaitPartition' -Status Info -Target $domainName -Message "Waiting for DNS directory partitions. Pending=$($pendingPartitions -join ' | ')"
            }
            Start-Sleep -Seconds 5
        } while ((Get-Date) -lt $partitionDeadline)
        if ($pendingPartitions.Count -gt 0) {
            throw "DNS directory partitions were not available within $TimeoutSeconds seconds: $($pendingPartitions -join ' | ')"
        }
        Write-LabLog -Phase $phase -Action 'WaitPartition' -Status Unchanged -Target $domainName -Message 'DomainDnsZones and ForestDnsZones are ready.'

        foreach ($expectedZone in $expectedZones) {
            $activeDnsAction = 'EnsureZone'
            $activeDnsTarget = $expectedZone.Name
            $zoneDeadline = (Get-Date).AddSeconds($TimeoutSeconds)
            $creationRequested = $false
            $zoneAttempt = 0
            $lastZoneError = 'Zone is not visible to DNS.'
            do {
                $zone = Get-LabDnsServerZoneOrNull -Name $expectedZone.Name
                if ($null -ne $zone) { break }
                if (-not $creationRequested) {
                    try {
                        Add-DnsServerPrimaryZone `
                            -Name $expectedZone.Name `
                            -ReplicationScope $expectedZone.Scope `
                            -DynamicUpdate Secure `
                            -ErrorAction Stop
                        $creationRequested = $true
                        $changed = $true
                        Write-LabLog -Phase $phase -Action 'CreateZone' -Status Changed -Target $expectedZone.Name -Message "ReplicationScope=$($expectedZone.Scope); DynamicUpdate=Secure"
                    }
                    catch {
                        $lastZoneError = $_.Exception.Message
                        $errorId = [string]$_.FullyQualifiedErrorId
                        if ($errorId -match '\b9718\b') {
                            $creationRequested = $true
                        }
                        elseif ($errorId -notmatch '\b(9901|9905)\b') {
                            throw
                        }
                    }
                }
                $zoneAttempt++
                if ($zoneAttempt -eq 1 -or $zoneAttempt % 6 -eq 0) {
                    Write-LabLog -Phase $phase -Action 'WaitZone' -Status Info -Target $expectedZone.Name -Message "Waiting for the DNS zone to become available. Last observation: $lastZoneError"
                }
                Start-Sleep -Seconds 5
            } while ((Get-Date) -lt $zoneDeadline)
            if ($null -eq $zone) {
                throw "DNS zone '$($expectedZone.Name)' was not available within $TimeoutSeconds seconds. Last observation: $lastZoneError"
            }
            if (-not $creationRequested) {
                Write-LabLog -Phase $phase -Action 'CreateZone' -Status Unchanged -Target $expectedZone.Name -Message "IsDsIntegrated=$([bool]$zone.IsDsIntegrated); DynamicUpdate=$($zone.DynamicUpdate)"
            }
            Assert-LabDnsZoneConfiguration -Zone $zone -ExpectedPartition $expectedZone.Partition
            Write-LabLog -Phase $phase -Action 'WaitZone' -Status Unchanged -Target $expectedZone.Name -Message 'AD-integrated zone is ready.'
        }

        $activeDnsAction = 'WaitSRV'
        $activeDnsTarget = $domainName
        $requiredSrvRecords = @(
            "_ldap._tcp.dc._msdcs.$domainName",
            "_kerberos._tcp.$domainName"
        )
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        $registrationAttempted = $false
        $attempt = 0
        $lastMissing = @()
        do {
            $lastMissing = @()
            foreach ($recordName in $requiredSrvRecords) {
                try {
                    $records = @(Resolve-DnsName `
                        -Name $recordName `
                        -Type SRV `
                        -Server ([string]$config.Network.DC01.IPAddress) `
                        -ErrorAction Stop)
                    if ($records.Count -eq 0) {
                        $lastMissing += "$recordName returned no SRV records."
                    }
                }
                catch {
                    $lastMissing += ("{0}: {1}" -f $recordName, $_.Exception.Message)
                }
            }

            if ($lastMissing.Count -eq 0) { break }

            if (-not $registrationAttempted) {
                Restart-Service -Name Netlogon -Force -ErrorAction Stop
                & ipconfig.exe /flushdns | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "ipconfig /flushdns failed with exit code $LASTEXITCODE." }
                & ipconfig.exe /registerdns | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "ipconfig /registerdns failed with exit code $LASTEXITCODE." }
                & nltest.exe /dsregdns | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "nltest /dsregdns failed with exit code $LASTEXITCODE." }
                $registrationAttempted = $true
                $changed = $true
                Write-LabLog -Phase $phase -Action 'RegisterRecords' -Status Changed -Target $env:COMPUTERNAME -Message 'Restarted Netlogon and requested host and DC locator DNS registration.'
            }

            $attempt++
            if ($attempt -eq 1 -or $attempt % 6 -eq 0) {
                Write-LabLog -Phase $phase -Action 'WaitReady' -Status Info -Target $domainName -Message "Waiting for required SRV records. Missing=$($lastMissing -join ' | ')"
            }
            Start-Sleep -Seconds 5
        } while ((Get-Date) -lt $deadline)

        if ($lastMissing.Count -gt 0) {
            throw "Required AD DNS SRV records were not ready within $TimeoutSeconds seconds: $($lastMissing -join ' | ')"
        }

        Write-LabLog -Phase $phase -Action 'WaitReady' -Status Unchanged -Target $domainName -Message "Zones and required SRV records are ready; DNS=$($config.Network.DC01.IPAddress)"
        $result = New-LabPhaseResult -Phase $phase -Status Succeeded -Changed $changed -Message "DomainZone=$domainName; ForestZone=_msdcs.$forestRoot"
    }
}
catch {
    Write-LabLog -Phase $phase -Action $activeDnsAction -Status Failed -Target $activeDnsTarget -Message $_.Exception.Message
    throw
}
finally {
    Stop-LabTranscript
}

$result
