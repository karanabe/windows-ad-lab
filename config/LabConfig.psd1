@{
    Lab = @{
        VMName             = 'DC01'
        ComputerName       = 'DC01'
        GuestBootstrapPath = 'C:\LabBootstrap'
    }

    Domain = @{
        DnsName       = 'ad.lab.exceeds.test'
        NetBIOSName   = 'LAB'
        UpnSuffixes   = @('exceeds.test')

        # Let Windows Server 2025 choose its highest supported functional level.
        # Explicit WinThreshold would force the Windows Server 2016 level.
        ForestMode    = 'Default'
        DomainMode    = 'Default'
    }

    Organization = @{
        Name     = 'Exceeds Lab'
        RootOU   = 'LAB'
        Location = 'Tokyo'
    }

    Time = @{
        # Resolve the Hyper-V host's (Get-TimeZone).Id when bootstrap runs.
        WindowsTimeZoneId = 'Host'
    }

    Network = @{
        SwitchName    = 'AD-Internal'
        SwitchType    = 'Private'
        InternalPrefix = '10.10.6.0/28'

        DC01 = @{
            IPAddress      = '10.10.6.10'
            PrefixLength   = 28
            DnsServers     = @('10.10.6.10')
            DefaultGateway = $null
        }

        # Informational only. EDGE01/NAT is deliberately outside this bootstrap.
        FutureEdge = @{
            HostName  = 'EDGE01'
            IPAddress = '10.10.6.2'
            Enabled   = $false
        }
    }

    OrganizationalUnits = @(
        @{ Path = @('Admin') }
        @{ Path = @('Users') }
        @{ Path = @('Users', 'IT') }
        @{ Path = @('Users', 'HR') }
        @{ Path = @('Users', 'Manufacturing') }
        @{ Path = @('Users', 'Sales') }
        @{ Path = @('Service Accounts') }
        @{ Path = @('Computers') }
        @{ Path = @('Computers', 'Servers') }
        @{ Path = @('Computers', 'Workstations') }
        @{ Path = @('Groups') }
        @{ Path = @('Disabled Objects') }
    )

    Groups = @(
        @{ Name = 'GG_IT'; Scope = 'Global'; Category = 'Security'; OU = @('Groups'); Description = 'IT department users' }
        @{ Name = 'GG_HR'; Scope = 'Global'; Category = 'Security'; OU = @('Groups'); Description = 'HR department users' }
        @{ Name = 'GG_Manufacturing'; Scope = 'Global'; Category = 'Security'; OU = @('Groups'); Description = 'Manufacturing department users' }
        @{ Name = 'GG_Sales'; Scope = 'Global'; Category = 'Security'; OU = @('Groups'); Description = 'Sales department users' }
        @{ Name = 'GG_Server_Admins'; Scope = 'Global'; Category = 'Security'; OU = @('Groups'); Description = 'Delegated server administrators' }
        @{ Name = 'GG_SQL_Admins'; Scope = 'Global'; Category = 'Security'; OU = @('Groups'); Description = 'Delegated SQL administrators' }
        @{ Name = 'GG_Backup_Operators'; Scope = 'Global'; Category = 'Security'; OU = @('Groups'); Description = 'Delegated backup operators' }
    )

    PasswordPolicies = @{
        StandardUser = @{
            ChangePasswordAtLogon = $false
            PasswordNeverExpires  = $false
        }

        # LAB ONLY: non-expiring service-account passwords are intentionally weak.
        # Do not carry this setting into production.
        ServiceAccount = @{
            ChangePasswordAtLogon = $false
            PasswordNeverExpires  = $true
        }
    }

    Users = @(
        @{
            Name = 'Yagami'; GivenName = 'Yagami'; Surname = ''; SamAccountName = 'yagami'
            Department = 'IT'; OU = @('Users', 'IT'); Description = 'IT user'; Enabled = $true
            AccountType = 'StandardUser'; Groups = @('GG_IT'); BuiltInGroups = @(); AbsentFromBuiltInGroups = @(); ServicePrincipalNames = @()
        }
        @{
            Name = 'Yagami Admin'; GivenName = 'Yagami'; Surname = 'Admin'; SamAccountName = 'yagami_adm'
            UserPrincipalName = 'yagami_adm@exceeds.test'; Department = 'IT'; OU = @('Admin')
            Description = 'Privileged lab administrator'; Enabled = $true; AccountType = 'StandardUser'
            Groups = @(); BuiltInGroups = @('Domain Admins'); AbsentFromBuiltInGroups = @('Enterprise Admins'); ServicePrincipalNames = @()
        }
        @{
            Name = 'John Smith'; GivenName = 'John'; Surname = 'Smith'; SamAccountName = 'john.smith'
            Department = 'IT'; OU = @('Users', 'IT'); Description = 'IT user'; Enabled = $true
            AccountType = 'StandardUser'; Groups = @('GG_IT'); BuiltInGroups = @(); AbsentFromBuiltInGroups = @(); ServicePrincipalNames = @()
        }
        @{
            Name = 'Alice Brown'; GivenName = 'Alice'; Surname = 'Brown'; SamAccountName = 'alice.brown'
            Department = 'HR'; OU = @('Users', 'HR'); Description = 'HR user'; Enabled = $true
            AccountType = 'StandardUser'; Groups = @('GG_HR'); BuiltInGroups = @(); AbsentFromBuiltInGroups = @(); ServicePrincipalNames = @()
        }
        @{
            Name = 'Bob Taylor'; GivenName = 'Bob'; Surname = 'Taylor'; SamAccountName = 'bob.taylor'
            Department = 'Manufacturing'; OU = @('Users', 'Manufacturing'); Description = 'Manufacturing user'; Enabled = $true
            AccountType = 'StandardUser'; Groups = @('GG_Manufacturing'); BuiltInGroups = @(); AbsentFromBuiltInGroups = @(); ServicePrincipalNames = @()
        }
        @{
            Name = 'Operator 01'; GivenName = 'Operator'; Surname = '01'; SamAccountName = 'operator01'
            Department = 'Manufacturing'; OU = @('Users', 'Manufacturing'); Description = 'Manufacturing operator'; Enabled = $true
            AccountType = 'StandardUser'; Groups = @('GG_Manufacturing'); BuiltInGroups = @(); AbsentFromBuiltInGroups = @(); ServicePrincipalNames = @()
        }
        @{
            Name = 'Ansible Service'; GivenName = 'Ansible'; Surname = 'Service'; SamAccountName = 'svc_ansible'
            Department = 'IT'; OU = @('Service Accounts'); Description = 'Service identity for configuration automation'; Enabled = $true
            AccountType = 'ServiceAccount'; Groups = @(); BuiltInGroups = @(); AbsentFromBuiltInGroups = @('Domain Admins', 'Enterprise Admins'); ServicePrincipalNames = @()
        }
        @{
            Name = 'SQL Service'; GivenName = 'SQL'; Surname = 'Service'; SamAccountName = 'svc_sql'
            Department = 'IT'; OU = @('Service Accounts'); Description = 'Service identity for SQL Server'; Enabled = $true
            AccountType = 'ServiceAccount'; Groups = @(); BuiltInGroups = @(); AbsentFromBuiltInGroups = @('Domain Admins', 'Enterprise Admins'); ServicePrincipalNames = @()
        }
        @{
            Name = 'Backup Service'; GivenName = 'Backup'; Surname = 'Service'; SamAccountName = 'svc_backup'
            Department = 'IT'; OU = @('Service Accounts'); Description = 'Service identity for backup operations'; Enabled = $true
            AccountType = 'ServiceAccount'; Groups = @(); BuiltInGroups = @(); AbsentFromBuiltInGroups = @('Domain Admins', 'Enterprise Admins'); ServicePrincipalNames = @()
        }
        @{
            Name = 'Web Service'; GivenName = 'Web'; Surname = 'Service'; SamAccountName = 'svc_web'
            Department = 'IT'; OU = @('Service Accounts'); Description = 'Service identity for web applications'; Enabled = $true
            AccountType = 'ServiceAccount'; Groups = @(); BuiltInGroups = @(); AbsentFromBuiltInGroups = @('Domain Admins', 'Enterprise Admins'); ServicePrincipalNames = @()
        }
    )

    Computers = @(
        @{ Name = 'CLIENT01'; OU = @('Computers', 'Workstations'); Description = 'Windows client test VM'; Enabled = $true }
        @{ Name = 'FILE01'; OU = @('Computers', 'Servers'); Description = 'File server test VM'; Enabled = $true }
        @{ Name = 'WEB01'; OU = @('Computers', 'Servers'); Description = 'Web server test VM'; Enabled = $true }
    )

    Hosts = @(
        @{ Name = 'CLIENT01'; Role = 'Workstation'; DomainJoin = $true; OUPath = @('Computers', 'Workstations') }
        @{ Name = 'FILE01'; Role = 'Server'; DomainJoin = $true; OUPath = @('Computers', 'Servers') }
        @{ Name = 'WEB01'; Role = 'Server'; DomainJoin = $true; OUPath = @('Computers', 'Servers') }
        @{ Name = 'MGMT01'; Role = 'Management'; DomainJoin = $false; OUPath = @() }
        @{ Name = 'EDGE01'; Role = 'Edge'; DomainJoin = $false; OUPath = @() }
    )

    # Moving existing objects can change GPO scope, so it is opt-in.
    MoveExistingObjects = $false

    Audit = @{
        IncludeProcessCommandLine = $true
        Subcategories = @(
            @{ Name = 'Logon'; Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true; RequiresADCS = $false }
            @{ Name = 'Process Creation'; Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $false; RequiresADCS = $false }
            @{ Name = 'User Account Management'; Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true; RequiresADCS = $false }
            @{ Name = 'Computer Account Management'; Guid = '{0CCE9236-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true; RequiresADCS = $false }
            @{ Name = 'Security Group Management'; Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true; RequiresADCS = $false }
            @{ Name = 'Directory Service Changes'; Guid = '{0CCE923C-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $false; RequiresADCS = $false }
            @{ Name = 'Credential Validation'; Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true; RequiresADCS = $false }
            @{ Name = 'Kerberos Service Ticket Operations'; Guid = '{0CCE9240-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true; RequiresADCS = $false }
            @{ Name = 'Kerberos Authentication Service'; Guid = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true; RequiresADCS = $false }
            @{ Name = 'Certification Services'; Guid = '{0CCE9221-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true; RequiresADCS = $true }
        )
    }

    ADCS = @{
        Install             = $true
        TargetComputerName  = 'DC01'
        CACommonName        = 'LAB-ROOT-CA'
        CAType              = 'EnterpriseRootCA'
        CryptoProviderName  = 'RSA#Microsoft Software Key Storage Provider'
        KeyLength           = 4096
        HashAlgorithmName   = 'SHA256'
        ValidityPeriod      = 'Years'
        ValidityPeriodUnits = 10
        EnableFullAuditing  = $true
    }
}
