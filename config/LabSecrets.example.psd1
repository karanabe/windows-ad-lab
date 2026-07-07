@{
    # Normally use Invoke-ValidatedLabSetup.ps1 without -SecretsPath: it prompts
    # separately for the local Administrator, DSRM, and new-user passwords and
    # builds through checkpoint 06-ADCS-HTTP-CDP. Use this file only for
    # unattended runs.
    #
    # 1. On the Hyper-V host, sign in as the Windows user who will run setup.
    #    Open PowerShell there (not inside DC01) and copy this example to
    #    config\LabSecrets.psd1. The destination is ignored by Git.
    # 2. For each password field below, run this command on that host:
    #
    #    Read-Host 'Password' -AsSecureString | ConvertFrom-SecureString
    #
    #    Type the password at the prompt. Copy the resulting encrypted string
    #    into the corresponding field below, replacing the entire <...> value
    #    but keeping the single quotes. Repeat for different passwords.
    #    When all four passwords are the same, the same encrypted value can be
    #    pasted into all four password fields. The built-in Administrator keeps
    #    its password when the forest is created, so the local and domain
    #    Administrator values are usually the same in a fresh lab.
    # 3. Run .\scripts\host\Invoke-ValidatedLabSetup.ps1 with
    #    -SecretsPath .\config\LabSecrets.psd1 as the same Windows user on
    #    the same host. ConvertTo-SecureString decrypts the values there.
    #
    # ConvertFrom-SecureString without -Key or -SecureKey uses Windows DPAPI.
    # Moving the file to another host or running it as another Windows user
    # will not decrypt it. If that changes, generate new values there.
    # Never paste plaintext passwords into this file or LabConfig.psd1, and
    # never commit LabSecrets.psd1. The interactive prompt needs no secrets file.
    LocalAdministratorUser     = '.\Administrator'
    LocalAdministratorPassword = '<DPAPI encrypted ConvertFrom-SecureString value>'
    DomainAdministratorUser    = 'LAB\Administrator'
    DomainAdministratorPassword = '<DPAPI encrypted ConvertFrom-SecureString value>'
    DsrmPassword               = '<DPAPI encrypted ConvertFrom-SecureString value>'
    DefaultUserPassword        = '<DPAPI encrypted ConvertFrom-SecureString value>'
}
