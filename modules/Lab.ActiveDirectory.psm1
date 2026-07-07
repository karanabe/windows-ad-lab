Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-LabADUserOrNull {
    param([Parameter(Mandatory = $true)][string]$Identity)
    try {
        return Get-ADUser -Identity $Identity -Properties Department, Description, DisplayName, Enabled, GivenName, PasswordExpired, PasswordNeverExpires, ServicePrincipalName, Surname, UserPrincipalName -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { return $null }
}

function Get-LabADGroupOrNull {
    param([Parameter(Mandatory = $true)][string]$Identity)
    try {
        return Get-ADGroup -Identity $Identity -Properties Description, GroupCategory, GroupScope -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { return $null }
}

function Get-LabADComputerOrNull {
    param([Parameter(Mandatory = $true)][string]$Identity)
    try {
        return Get-ADComputer -Identity $Identity -Properties Description, Enabled -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { return $null }
}

function Get-LabADOrganizationalUnitOrNull {
    param([Parameter(Mandatory = $true)][string]$Identity)
    try { return Get-ADOrganizationalUnit -Identity $Identity -ErrorAction Stop }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { return $null }
}

function Test-LabNeedsUserPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Config,
        [switch]$ResetExistingPasswords
    )

    Import-Module ActiveDirectory -ErrorAction Stop
    if ($ResetExistingPasswords) { return $true }
    foreach ($userConfig in @($Config.Users)) {
        if ($null -eq (Get-LabADUserOrNull -Identity ([string]$userConfig.SamAccountName))) {
            return $true
        }
    }
    return $false
}

function Assert-LabObjectLocation {
    param(
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][string]$TargetOU,
        [Parameter(Mandatory = $true)][bool]$MoveExistingObjects,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCmdlet]$Cmdlet,
        [Parameter(Mandatory = $true)][ref]$Changed
    )

    $currentParent = Get-LabParentDistinguishedName -DistinguishedName $DistinguishedName
    if ($currentParent -ieq $TargetOU) { return }
    if (-not $MoveExistingObjects) {
        throw "$Type '$Name' exists in '$currentParent', not '$TargetOU'. Moving objects can change GPO scope; review it and set MoveExistingObjects=true explicitly."
    }
    if ($Cmdlet.ShouldProcess($DistinguishedName, "Move $Type to $TargetOU")) {
        Move-ADObject -Identity $DistinguishedName -TargetPath $TargetOU -ErrorAction Stop
        $Changed.Value = $true
        Write-LabLog -Phase 'ADBaseline' -Action "Move$Type" -Status Changed -Target $Name -Message $TargetOU
    }
}

function Set-LabADBaseline {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Config,
        [Security.SecureString]$DefaultUserPassword,
        [switch]$ResetExistingPasswords
    )

    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-LabCurrentDomain -Config $Config
    $forest = Get-ADForest -ErrorAction Stop
    $domainDn = [string]$domain.DistinguishedName
    $rootOu = [string]$Config.Organization.RootOU
    $changed = $false

    foreach ($suffix in @($Config.Domain.UpnSuffixes)) {
        $suffixText = [string]$suffix
        if (@($forest.UPNSuffixes) -inotcontains $suffixText) {
            if ($PSCmdlet.ShouldProcess($forest.Name, "Add UPN suffix $suffixText")) {
                Set-ADForest -Identity $forest -UPNSuffixes @{ Add = $suffixText } -ErrorAction Stop
                $changed = $true
                Write-LabLog -Phase 'ADBaseline' -Action 'AddUPNSuffix' -Status Changed -Target $suffixText
            }
        }
        else {
            Write-LabLog -Phase 'ADBaseline' -Action 'AddUPNSuffix' -Status Unchanged -Target $suffixText
        }
    }

    $rootOuDn = Get-LabOuDistinguishedName -RootOU $rootOu -DomainDistinguishedName $domainDn
    if ($null -eq (Get-LabADOrganizationalUnitOrNull -Identity $rootOuDn)) {
        if ($PSCmdlet.ShouldProcess($rootOuDn, 'Create root OU')) {
            New-ADOrganizationalUnit -Name $rootOu -Path $domainDn -ProtectedFromAccidentalDeletion $true -ErrorAction Stop | Out-Null
            $changed = $true
            Write-LabLog -Phase 'ADBaseline' -Action 'CreateOU' -Status Changed -Target $rootOuDn
        }
    }
    else {
        Write-LabLog -Phase 'ADBaseline' -Action 'CreateOU' -Status Unchanged -Target $rootOuDn
    }

    $ouDefinitions = @($Config.OrganizationalUnits | Sort-Object { @($_.Path).Count })
    foreach ($ouConfig in $ouDefinitions) {
        $path = @($ouConfig.Path)
        $ouDn = Get-LabOuDistinguishedName -RootOU $rootOu -RelativePath $path -DomainDistinguishedName $domainDn
        if ($null -ne (Get-LabADOrganizationalUnitOrNull -Identity $ouDn)) {
            Write-LabLog -Phase 'ADBaseline' -Action 'CreateOU' -Status Unchanged -Target $ouDn
            continue
        }
        $parentDn = Get-LabParentOuDistinguishedName -RootOU $rootOu -RelativePath $path -DomainDistinguishedName $domainDn
        if ($PSCmdlet.ShouldProcess($ouDn, 'Create OU')) {
            New-ADOrganizationalUnit -Name ([string]$path[-1]) -Path $parentDn -ProtectedFromAccidentalDeletion $true -ErrorAction Stop | Out-Null
            $changed = $true
            Write-LabLog -Phase 'ADBaseline' -Action 'CreateOU' -Status Changed -Target $ouDn
        }
    }

    foreach ($groupConfig in @($Config.Groups)) {
        $groupName = [string]$groupConfig.Name
        $targetOu = Get-LabOuDistinguishedName -RootOU $rootOu -RelativePath @($groupConfig.OU) -DomainDistinguishedName $domainDn
        $group = Get-LabADGroupOrNull -Identity $groupName
        if ($null -eq $group) {
            if ($PSCmdlet.ShouldProcess($groupName, "Create group in $targetOu")) {
                New-ADGroup -Name $groupName -SamAccountName $groupName -GroupScope ([string]$groupConfig.Scope) -GroupCategory ([string]$groupConfig.Category) -Path $targetOu -Description ([string]$groupConfig.Description) -ErrorAction Stop | Out-Null
                $changed = $true
                Write-LabLog -Phase 'ADBaseline' -Action 'CreateGroup' -Status Changed -Target $groupName
            }
            continue
        }

        if ([string]$group.GroupScope -ine [string]$groupConfig.Scope -or [string]$group.GroupCategory -ine [string]$groupConfig.Category) {
            throw "Group '$groupName' has scope/category '$($group.GroupScope)/$($group.GroupCategory)', expected '$($groupConfig.Scope)/$($groupConfig.Category)'. Review this potentially disruptive change manually."
        }
        Assert-LabObjectLocation -Type 'group' -Name $groupName -DistinguishedName $group.DistinguishedName -TargetOU $targetOu -MoveExistingObjects ([bool]$Config.MoveExistingObjects) -Cmdlet $PSCmdlet -Changed ([ref]$changed)
        if ([string]$group.Description -ine [string]$groupConfig.Description) {
            if ($PSCmdlet.ShouldProcess($groupName, 'Update group description')) {
                Set-ADGroup -Identity $group -Description ([string]$groupConfig.Description) -ErrorAction Stop
                $changed = $true
                Write-LabLog -Phase 'ADBaseline' -Action 'UpdateGroup' -Status Changed -Target $groupName
            }
        }
        else {
            Write-LabLog -Phase 'ADBaseline' -Action 'UpdateGroup' -Status Unchanged -Target $groupName
        }
    }

    foreach ($userConfig in @($Config.Users)) {
        $sam = [string]$userConfig.SamAccountName
        $targetOu = Get-LabOuDistinguishedName -RootOU $rootOu -RelativePath @($userConfig.OU) -DomainDistinguishedName $domainDn
        $upn = if ($userConfig.ContainsKey('UserPrincipalName')) { [string]$userConfig.UserPrincipalName } else { "$sam@$($Config.Domain.DnsName)" }
        $policyName = [string]$userConfig.AccountType
        if (-not $Config.PasswordPolicies.ContainsKey($policyName)) {
            throw "User '$sam' references undefined password policy '$policyName'."
        }
        $policy = $Config.PasswordPolicies[$policyName]
        $changeAtLogon = [bool]$policy.ChangePasswordAtLogon
        $neverExpires = [bool]$policy.PasswordNeverExpires
        if ($changeAtLogon -and $neverExpires) {
            throw "Password policy '$policyName' cannot enable ChangePasswordAtLogon and PasswordNeverExpires together."
        }

        $user = Get-LabADUserOrNull -Identity $sam
        if ($null -eq $user) {
            if ($PSCmdlet.ShouldProcess($sam, "Create user in $targetOu")) {
                if ($null -eq $DefaultUserPassword) {
                    throw "A DefaultUserPassword SecureString is required to create user '$sam'."
                }
                $newUser = @{
                    Name = [string]$userConfig.Name
                    DisplayName = [string]$userConfig.Name
                    SamAccountName = $sam
                    UserPrincipalName = $upn
                    Path = $targetOu
                    Description = [string]$userConfig.Description
                    Department = [string]$userConfig.Department
                    AccountPassword = $DefaultUserPassword
                    Enabled = [bool]$userConfig.Enabled
                    ChangePasswordAtLogon = $changeAtLogon
                    PasswordNeverExpires = $neverExpires
                    ErrorAction = 'Stop'
                }
                if (-not [string]::IsNullOrWhiteSpace([string]$userConfig.GivenName)) { $newUser.GivenName = [string]$userConfig.GivenName }
                if (-not [string]::IsNullOrWhiteSpace([string]$userConfig.Surname)) { $newUser.Surname = [string]$userConfig.Surname }
                New-ADUser @newUser
                $changed = $true
                Write-LabLog -Phase 'ADBaseline' -Action 'CreateUser' -Status Changed -Target $sam
            }
            $user = Get-LabADUserOrNull -Identity $sam
        }
        else {
            Assert-LabObjectLocation -Type 'user' -Name $sam -DistinguishedName $user.DistinguishedName -TargetOU $targetOu -MoveExistingObjects ([bool]$Config.MoveExistingObjects) -Cmdlet $PSCmdlet -Changed ([ref]$changed)
            $replace = @{}
            $clear = @()
            foreach ($mapping in @(
                @{ Property = 'displayName'; Current = [string]$user.DisplayName; Desired = [string]$userConfig.Name },
                @{ Property = 'givenName'; Current = [string]$user.GivenName; Desired = [string]$userConfig.GivenName },
                @{ Property = 'sn'; Current = [string]$user.Surname; Desired = [string]$userConfig.Surname },
                @{ Property = 'department'; Current = [string]$user.Department; Desired = [string]$userConfig.Department },
                @{ Property = 'description'; Current = [string]$user.Description; Desired = [string]$userConfig.Description },
                @{ Property = 'userPrincipalName'; Current = [string]$user.UserPrincipalName; Desired = $upn }
            )) {
                if ($mapping.Current -cne $mapping.Desired) {
                    if ([string]::IsNullOrEmpty([string]$mapping.Desired)) { $clear += [string]$mapping.Property }
                    else { $replace[$mapping.Property] = $mapping.Desired }
                }
            }
            if (($replace.Count -gt 0 -or $clear.Count -gt 0) -and $PSCmdlet.ShouldProcess($sam, 'Update user attributes')) {
                $setUserParams = @{ Identity = $user; ErrorAction = 'Stop' }
                if ($replace.Count -gt 0) { $setUserParams.Replace = $replace }
                if ($clear.Count -gt 0) { $setUserParams.Clear = $clear }
                Set-ADUser @setUserParams
                $changed = $true
                Write-LabLog -Phase 'ADBaseline' -Action 'UpdateUser' -Status Changed -Target $sam
            }
            elseif ($replace.Count -eq 0 -and $clear.Count -eq 0) {
                Write-LabLog -Phase 'ADBaseline' -Action 'UpdateUser' -Status Unchanged -Target $sam
            }

            if ($ResetExistingPasswords) {
                if ($null -eq $DefaultUserPassword) { throw 'DefaultUserPassword is required with ResetExistingPasswords.' }
                if ($PSCmdlet.ShouldProcess($sam, 'Reset existing user password')) {
                    Set-ADAccountPassword -Identity $user -Reset -NewPassword $DefaultUserPassword -ErrorAction Stop
                    $changed = $true
                    Write-LabLog -Phase 'ADBaseline' -Action 'ResetPassword' -Status Changed -Target $sam
                }
            }
            if ([bool]$user.PasswordNeverExpires -ne $neverExpires -and $PSCmdlet.ShouldProcess($sam, 'Update password expiration policy')) {
                Set-ADAccountControl -Identity $user -PasswordNeverExpires $neverExpires -ErrorAction Stop
                $changed = $true
            }
            if ([bool]$user.Enabled -ne [bool]$userConfig.Enabled -and $PSCmdlet.ShouldProcess($sam, 'Update account enabled state')) {
                if ([bool]$userConfig.Enabled) { Enable-ADAccount -Identity $user -ErrorAction Stop }
                else { Disable-ADAccount -Identity $user -ErrorAction Stop }
                $changed = $true
            }
            if ([bool]$user.PasswordExpired -ne $changeAtLogon -and $PSCmdlet.ShouldProcess($sam, 'Update change-password-at-logon policy')) {
                Set-ADUser -Identity $user -ChangePasswordAtLogon $changeAtLogon -ErrorAction Stop
                $changed = $true
            }
        }

        $user = Get-LabADUserOrNull -Identity $sam
        if ($null -eq $user) {
            Write-LabLog -Phase 'ADBaseline' -Action 'ConfigureUserMembership' -Status Info -Target $sam -Message 'Skipped because -WhatIf did not create the user.'
            continue
        }

        foreach ($groupName in @($userConfig.Groups) + @($userConfig.BuiltInGroups)) {
            if ([string]::IsNullOrWhiteSpace([string]$groupName)) { continue }
            $group = Get-LabADGroupOrNull -Identity ([string]$groupName)
            if ($null -eq $group) { throw "Configured group '$groupName' does not exist for user '$sam'." }
            $isMember = @((Get-ADGroupMember -Identity $group -ErrorAction Stop) | Where-Object { [string]$_.SID -eq [string]$user.SID }).Count -gt 0
            if (-not $isMember -and $PSCmdlet.ShouldProcess($sam, "Add to group $groupName")) {
                Add-ADGroupMember -Identity $group -Members $user -Confirm:$false -ErrorAction Stop
                $changed = $true
                Write-LabLog -Phase 'ADBaseline' -Action 'AddGroupMember' -Status Changed -Target "$groupName/$sam"
            }
        }

        foreach ($groupName in @($userConfig.AbsentFromBuiltInGroups)) {
            $group = Get-LabADGroupOrNull -Identity ([string]$groupName)
            if ($null -eq $group) { throw "Configured built-in group '$groupName' does not exist." }
            $isMember = @((Get-ADGroupMember -Identity $group -ErrorAction Stop) | Where-Object { [string]$_.SID -eq [string]$user.SID }).Count -gt 0
            if ($isMember -and $PSCmdlet.ShouldProcess($sam, "Remove from group $groupName")) {
                Remove-ADGroupMember -Identity $group -Members $user -Confirm:$false -ErrorAction Stop
                $changed = $true
                Write-LabLog -Phase 'ADBaseline' -Action 'RemoveGroupMember' -Status Changed -Target "$groupName/$sam"
            }
        }

        $configuredSpns = @($userConfig.ServicePrincipalNames | ForEach-Object { Expand-LabToken -Value ([string]$_) -Config $Config } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $missingSpns = @($configuredSpns | Where-Object { @($user.ServicePrincipalName) -notcontains $_ })
        if ($missingSpns.Count -gt 0 -and $PSCmdlet.ShouldProcess($sam, "Add SPNs: $($missingSpns -join ', ')")) {
            Set-ADUser -Identity $user -ServicePrincipalNames @{ Add = $missingSpns } -ErrorAction Stop
            $changed = $true
            Write-LabLog -Phase 'ADBaseline' -Action 'AddSPN' -Status Changed -Target $sam -Message ($missingSpns -join ',')
        }
    }

    foreach ($computerConfig in @($Config.Computers)) {
        $name = ([string]$computerConfig.Name).ToUpperInvariant()
        $targetOu = Get-LabOuDistinguishedName -RootOU $rootOu -RelativePath @($computerConfig.OU) -DomainDistinguishedName $domainDn
        $computer = Get-LabADComputerOrNull -Identity $name
        if ($null -eq $computer) {
            if ($PSCmdlet.ShouldProcess($name, "Pre-stage computer in $targetOu")) {
                New-ADComputer -Name $name -SamAccountName "$name`$" -Path $targetOu -Description ([string]$computerConfig.Description) -Enabled ([bool]$computerConfig.Enabled) -ErrorAction Stop | Out-Null
                $changed = $true
                Write-LabLog -Phase 'ADBaseline' -Action 'CreateComputer' -Status Changed -Target $name
            }
            continue
        }
        Assert-LabObjectLocation -Type 'computer' -Name $name -DistinguishedName $computer.DistinguishedName -TargetOU $targetOu -MoveExistingObjects ([bool]$Config.MoveExistingObjects) -Cmdlet $PSCmdlet -Changed ([ref]$changed)
        if ([string]$computer.Description -ine [string]$computerConfig.Description -and $PSCmdlet.ShouldProcess($name, 'Update computer description')) {
            Set-ADComputer -Identity $computer -Description ([string]$computerConfig.Description) -ErrorAction Stop
            $changed = $true
            Write-LabLog -Phase 'ADBaseline' -Action 'UpdateComputer' -Status Changed -Target $name
        }
        else {
            Write-LabLog -Phase 'ADBaseline' -Action 'UpdateComputer' -Status Unchanged -Target $name
        }
        if ([bool]$computer.Enabled -ne [bool]$computerConfig.Enabled -and $PSCmdlet.ShouldProcess($name, 'Update computer enabled state')) {
            if ([bool]$computerConfig.Enabled) { Enable-ADAccount -Identity $computer -ErrorAction Stop }
            else { Disable-ADAccount -Identity $computer -ErrorAction Stop }
            $changed = $true
            Write-LabLog -Phase 'ADBaseline' -Action 'SetComputerEnabled' -Status Changed -Target $name -Message "Enabled=$([bool]$computerConfig.Enabled)"
        }
    }

    return [pscustomobject]@{
        Changed = $changed
        Domain = [string]$domain.DNSRoot
        RootOU = $rootOuDn
    }
}

Export-ModuleMember -Function @(
    'Get-LabADComputerOrNull',
    'Get-LabADGroupOrNull',
    'Get-LabADOrganizationalUnitOrNull',
    'Get-LabADUserOrNull',
    'Set-LabADBaseline',
    'Test-LabNeedsUserPassword'
)
