#Requires -Version 5.1

function Test-ShippedLabInstance {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config,

        [Parameter(Mandatory = $true)]
        [System.Collections.IList]$Failures
    )

    foreach ($expectation in @(
        @{ Name = 'Domain DNS name'; Passed = [string]$Config.Domain.DnsName -eq 'ad.lab.exceeds.test' },
        @{ Name = 'NetBIOS name'; Passed = [string]$Config.Domain.NetBIOSName -eq 'LAB' },
        @{ Name = 'UPN suffix'; Passed = (@($Config.Domain.UpnSuffixes) -join ',') -eq 'exceeds.test' },
        @{ Name = 'Organization name'; Passed = [string]$Config.Organization.Name -eq 'Exceeds Lab' },
        @{ Name = 'Root OU'; Passed = [string]$Config.Organization.RootOU -eq 'LAB' },
        @{ Name = 'Time zone'; Passed = [string]$Config.Time.WindowsTimeZoneId -eq 'Host' },
        @{ Name = 'Switch name'; Passed = [string]$Config.Network.SwitchName -eq 'AD-Internal' },
        @{ Name = 'Internal prefix'; Passed = [string]$Config.Network.InternalPrefix -eq '10.10.6.0/28' },
        @{ Name = 'DC IPv4'; Passed = [string]$Config.Network.DC01.IPAddress -eq '10.10.6.10' },
        @{ Name = 'DC prefix length'; Passed = [int]$Config.Network.DC01.PrefixLength -eq 28 },
        @{ Name = 'DC DNS'; Passed = (@($Config.Network.DC01.DnsServers) -join ',') -eq '10.10.6.10' },
        @{ Name = 'AD CS target'; Passed = [string]$Config.ADCS.TargetComputerName -eq 'DC01' },
        @{ Name = 'AD CS common name'; Passed = [string]$Config.ADCS.CACommonName -eq 'LAB-ROOT-CA' }
    )) {
        if (-not [bool]$expectation.Passed) {
            [void]$Failures.Add("Shipped lab instance mismatch: $($expectation.Name)")
        }
    }

    $expectedUsers = @('alice.brown', 'bob.taylor', 'john.smith', 'operator01', 'svc_ansible', 'svc_backup', 'svc_sql', 'svc_web', 'yagami', 'yagami_adm')
    $actualUsers = @($Config.Users | ForEach-Object { [string]$_.SamAccountName } | Sort-Object)
    if (@(Compare-Object -ReferenceObject $expectedUsers -DifferenceObject $actualUsers).Count -gt 0) {
        [void]$Failures.Add('Shipped lab users do not match the current instance.')
    }

    $expectedComputers = @('CLIENT01', 'FILE01', 'WEB01')
    $actualComputers = @($Config.Computers | ForEach-Object { [string]$_.Name } | Sort-Object)
    if (@(Compare-Object -ReferenceObject $expectedComputers -DifferenceObject $actualComputers).Count -gt 0) {
        [void]$Failures.Add('Shipped lab computers do not match the current instance.')
    }

    $yagamiAdmin = $Config.Users | Where-Object SamAccountName -eq 'yagami_adm' | Select-Object -First 1
    if ($null -eq $yagamiAdmin -or @($yagamiAdmin.BuiltInGroups) -notcontains 'Domain Admins' -or @($yagamiAdmin.AbsentFromBuiltInGroups) -notcontains 'Enterprise Admins') {
        [void]$Failures.Add('yagami_adm privilege constraints do not match the shipped instance.')
    }

    foreach ($serviceAccount in @($Config.Users | Where-Object SamAccountName -like 'svc_*')) {
        if ([string]$serviceAccount.AccountType -ne 'ServiceAccount' -or @($serviceAccount.BuiltInGroups).Count -ne 0) {
            [void]$Failures.Add("Service account '$($serviceAccount.SamAccountName)' has an unexpected account type or privileged group.")
        }
    }
}
