#Requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path $PSScriptRoot -Parent
$failures = New-Object System.Collections.Generic.List[string]

function Test-IgnoredLabPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $normalized = $Path.Replace('\', '/')
    return ($normalized -match '(^|/)scenarios/rusthound-dev(/|$)' -or
        $normalized -match '(^|/)config/LabSecrets\.psd1$')
}
$requiredFiles = @(
    'config\LabConfig.psd1',
    'config\LabSecrets.example.psd1',
    'scripts\Test-LabConfig.ps1',
    'tests\Assert-ShippedLabInstance.ps1',
    'config\examples\generic-lab.psd1',
    'bootstrap\Invoke-LabBootstrap.ps1',
    'scripts\host\Invoke-ValidatedLabSetup.ps1',
    'scripts\host\New-LabVm.ps1',
    'scripts\host\New-LabBaseCheckpoint.ps1',
    'scripts\host\Test-HyperVPrerequisites.ps1',
    'scripts\host\Set-VMNetwork.ps1',
    'scenarios\Invoke-Scenario.ps1',
    'scenarios\Restore-LabBaseline.ps1',
    'scenarios\adcs\ESC1-CertificateTemplate\Detect.md',
    'scenarios\adcs\ESC1-CertificateTemplate\Detect.ja.md',
    'scenarios\adcs\ESC1-CertificateTemplate\Audit.ps1',
    'scenarios\adcs\ESC1-CertificateTemplate\scenario.psd1',
    'scenarios\credentials\KeyCredentialLink-Observation\Detect.md',
    'scenarios\credentials\KeyCredentialLink-Observation\Audit.ps1',
    'scenarios\credentials\KeyCredentialLink-Observation\scenario.psd1',
    'scenarios\adcs\PKINIT-KDCCertificate\README.md',
    'scenarios\adcs\PKINIT-KDCCertificate\Detect.md',
    'scenarios\adcs\PKINIT-KDCCertificate\Audit.ps1',
    'scenarios\adcs\PKINIT-KDCCertificate\setup.ps1',
    'scenarios\adcs\PKINIT-KDCCertificate\validate.ps1',
    'scenarios\adcs\PKINIT-KDCCertificate\cleanup.ps1',
    'scenarios\adcs\PKINIT-KDCCertificate\scenario.psd1',
    'scenarios\delegation\RBCD\README.md',
    'scenarios\delegation\RBCD\Detect.md',
    'scenarios\delegation\RBCD\Audit.ps1',
    'scenarios\delegation\RBCD\setup.ps1',
    'scenarios\delegation\RBCD\validate.ps1',
    'scenarios\delegation\RBCD\cleanup.ps1',
    'scenarios\delegation\RBCD\scenario.psd1',
    'scenarios\credentials\WindowsLAPS-Delegation\README.md',
    'scenarios\credentials\WindowsLAPS-Delegation\concepts.md',
    'scenarios\credentials\WindowsLAPS-Delegation\Detect.md',
    'scenarios\credentials\WindowsLAPS-Delegation\Audit.ps1',
    'scenarios\credentials\WindowsLAPS-Delegation\setup.ps1',
    'scenarios\credentials\WindowsLAPS-Delegation\validate.ps1',
    'scenarios\credentials\WindowsLAPS-Delegation\cleanup.ps1',
    'scenarios\credentials\WindowsLAPS-Delegation\scenario.psd1',
    'scenarios\adcs\ESC8-Hardening\README.md',
    'scenarios\adcs\ESC8-Hardening\Detect.md',
    'scenarios\adcs\ESC8-Hardening\Audit.ps1',
    'scenarios\adcs\ESC8-Hardening\Esc8Hardening.Common.psm1',
    'scenarios\adcs\ESC8-Hardening\setup.ps1',
    'scenarios\adcs\ESC8-Hardening\validate.ps1',
    'scenarios\adcs\ESC8-Hardening\cleanup.ps1',
    'scenarios\adcs\ESC8-Hardening\scenario.psd1',
    'scenarios\acl\ADACL-GPOAbuse\README.md',
    'scenarios\acl\ADACL-GPOAbuse\Detect.md',
    'scenarios\acl\ADACL-GPOAbuse\Audit.ps1',
    'scenarios\acl\ADACL-GPOAbuse\setup.ps1',
    'scenarios\acl\ADACL-GPOAbuse\validate.ps1',
    'scenarios\acl\ADACL-GPOAbuse\cleanup.ps1',
    'scenarios\acl\ADACL-GPOAbuse\scenario.psd1',
    'scenarios\credentials\gMSA-PasswordRetrieval\README.md',
    'scenarios\credentials\gMSA-PasswordRetrieval\Detect.md',
    'scenarios\credentials\gMSA-PasswordRetrieval\Audit.ps1',
    'scenarios\credentials\gMSA-PasswordRetrieval\setup.ps1',
    'scenarios\credentials\gMSA-PasswordRetrieval\validate.ps1',
    'scenarios\credentials\gMSA-PasswordRetrieval\cleanup.ps1',
    'scenarios\credentials\gMSA-PasswordRetrieval\scenario.psd1',
    'scenarios\adcs\ESC11-RpcEnrollment\README.md',
    'scenarios\adcs\ESC11-RpcEnrollment\Detect.md',
    'scenarios\adcs\ESC11-RpcEnrollment\Audit.ps1',
    'scenarios\adcs\ESC11-RpcEnrollment\Esc11RpcEnrollment.Common.psm1',
    'scenarios\adcs\ESC11-RpcEnrollment\setup.ps1',
    'scenarios\adcs\ESC11-RpcEnrollment\validate.ps1',
    'scenarios\adcs\ESC11-RpcEnrollment\cleanup.ps1',
    'scenarios\adcs\ESC11-RpcEnrollment\scenario.psd1',
    'scenarios\adcs\ESC15-SchemaV1Template\README.md',
    'scenarios\adcs\ESC15-SchemaV1Template\Detect.md',
    'scenarios\adcs\ESC15-SchemaV1Template\Detect.ja.md',
    'scenarios\adcs\ESC15-SchemaV1Template\Audit.ps1',
    'scenarios\adcs\ESC15-SchemaV1Template\setup.ps1',
    'scenarios\adcs\ESC15-SchemaV1Template\validate.ps1',
    'scenarios\adcs\ESC15-SchemaV1Template\cleanup.ps1',
    'scenarios\adcs\ESC15-SchemaV1Template\scenario.psd1',
    'scenarios\adcs\ESC2-AnyPurposeTemplate\README.md',
    'scenarios\adcs\ESC2-AnyPurposeTemplate\Detect.md',
    'scenarios\adcs\ESC2-AnyPurposeTemplate\Detect.ja.md',
    'scenarios\adcs\ESC2-AnyPurposeTemplate\Audit.ps1',
    'scenarios\adcs\ESC2-AnyPurposeTemplate\setup.ps1',
    'scenarios\adcs\ESC2-AnyPurposeTemplate\validate.ps1',
    'scenarios\adcs\ESC2-AnyPurposeTemplate\cleanup.ps1',
    'scenarios\adcs\ESC2-AnyPurposeTemplate\scenario.psd1',
    'scenarios\adcs\ESC3-EnrollmentAgent\README.md',
    'scenarios\adcs\ESC3-EnrollmentAgent\Detect.md',
    'scenarios\adcs\ESC3-EnrollmentAgent\Detect.ja.md',
    'scenarios\adcs\ESC3-EnrollmentAgent\Audit.ps1',
    'scenarios\adcs\ESC3-EnrollmentAgent\setup.ps1',
    'scenarios\adcs\ESC3-EnrollmentAgent\validate.ps1',
    'scenarios\adcs\ESC3-EnrollmentAgent\cleanup.ps1',
    'scenarios\adcs\ESC3-EnrollmentAgent\scenario.psd1',
    'scenarios\adcs\ESC4-TemplateAcl\README.md',
    'scenarios\adcs\ESC4-TemplateAcl\Detect.md',
    'scenarios\adcs\ESC4-TemplateAcl\Detect.ja.md',
    'scenarios\adcs\ESC4-TemplateAcl\Audit.ps1',
    'scenarios\adcs\ESC4-TemplateAcl\setup.ps1',
    'scenarios\adcs\ESC4-TemplateAcl\validate.ps1',
    'scenarios\adcs\ESC4-TemplateAcl\cleanup.ps1',
    'scenarios\adcs\ESC4-TemplateAcl\scenario.psd1',
    'scenarios\adcs\ESC5-PkiObjectAcl\README.md',
    'scenarios\adcs\ESC5-PkiObjectAcl\Detect.md',
    'scenarios\adcs\ESC5-PkiObjectAcl\Detect.ja.md',
    'scenarios\adcs\ESC5-PkiObjectAcl\Audit.ps1',
    'scenarios\adcs\ESC5-PkiObjectAcl\setup.ps1',
    'scenarios\adcs\ESC5-PkiObjectAcl\validate.ps1',
    'scenarios\adcs\ESC5-PkiObjectAcl\cleanup.ps1',
    'scenarios\adcs\ESC5-PkiObjectAcl\scenario.psd1',
    'scenarios\adcs\ESC7-ManageCA\README.md',
    'scenarios\adcs\ESC7-ManageCA\Detect.md',
    'scenarios\adcs\ESC7-ManageCA\Detect.ja.md',
    'scenarios\adcs\ESC7-ManageCA\Audit.ps1',
    'scenarios\adcs\ESC7-ManageCA\setup.ps1',
    'scenarios\adcs\ESC7-ManageCA\validate.ps1',
    'scenarios\adcs\ESC7-ManageCA\cleanup.ps1',
    'scenarios\adcs\ESC7-ManageCA\scenario.psd1',
    'scenarios\adcs\ESC12-CaKeyStorage\README.md',
    'scenarios\adcs\ESC12-CaKeyStorage\Detect.md',
    'scenarios\adcs\ESC12-CaKeyStorage\Detect.ja.md',
    'scenarios\adcs\ESC12-CaKeyStorage\Audit.ps1',
    'scenarios\adcs\ESC12-CaKeyStorage\Esc12CaKeyStorage.Common.psm1',
    'scenarios\adcs\ESC12-CaKeyStorage\setup.ps1',
    'scenarios\adcs\ESC12-CaKeyStorage\validate.ps1',
    'scenarios\adcs\ESC12-CaKeyStorage\cleanup.ps1',
    'scenarios\adcs\ESC12-CaKeyStorage\scenario.psd1',
    'scenarios\adcs\ESC13-IssuancePolicy\README.md',
    'scenarios\adcs\ESC13-IssuancePolicy\Detect.md',
    'scenarios\adcs\ESC13-IssuancePolicy\Detect.ja.md',
    'scenarios\adcs\ESC13-IssuancePolicy\Audit.ps1',
    'scenarios\adcs\ESC13-IssuancePolicy\setup.ps1',
    'scenarios\adcs\ESC13-IssuancePolicy\validate.ps1',
    'scenarios\adcs\ESC13-IssuancePolicy\cleanup.ps1',
    'scenarios\adcs\ESC13-IssuancePolicy\scenario.psd1',
    'scenarios\adcs\ESC14-WeakExplicitMapping\README.md',
    'scenarios\adcs\ESC14-WeakExplicitMapping\Detect.md',
    'scenarios\adcs\ESC14-WeakExplicitMapping\Detect.ja.md',
    'scenarios\adcs\ESC14-WeakExplicitMapping\Audit.ps1',
    'scenarios\adcs\ESC14-WeakExplicitMapping\setup.ps1',
    'scenarios\adcs\ESC14-WeakExplicitMapping\validate.ps1',
    'scenarios\adcs\ESC14-WeakExplicitMapping\cleanup.ps1',
    'scenarios\adcs\ESC14-WeakExplicitMapping\scenario.psd1',
    'scenarios\adcs\ESC16-DisableExtensionList\README.md',
    'scenarios\adcs\ESC16-DisableExtensionList\Detect.md',
    'scenarios\adcs\ESC16-DisableExtensionList\Detect.ja.md',
    'scenarios\adcs\ESC16-DisableExtensionList\Audit.ps1',
    'scenarios\adcs\ESC16-DisableExtensionList\Esc16DisableExtensionList.Common.psm1',
    'scenarios\adcs\ESC16-DisableExtensionList\setup.ps1',
    'scenarios\adcs\ESC16-DisableExtensionList\validate.ps1',
    'scenarios\adcs\ESC16-DisableExtensionList\cleanup.ps1',
    'scenarios\adcs\ESC16-DisableExtensionList\scenario.psd1',
    'scenarios\adcs\ESC17-ServerAuthTemplate\README.md',
    'scenarios\adcs\ESC17-ServerAuthTemplate\Detect.md',
    'scenarios\adcs\ESC17-ServerAuthTemplate\Detect.ja.md',
    'scenarios\adcs\ESC17-ServerAuthTemplate\Audit.ps1',
    'scenarios\adcs\ESC17-ServerAuthTemplate\setup.ps1',
    'scenarios\adcs\ESC17-ServerAuthTemplate\validate.ps1',
    'scenarios\adcs\ESC17-ServerAuthTemplate\cleanup.ps1',
    'scenarios\adcs\ESC17-ServerAuthTemplate\scenario.psd1',
    'scenarios\acl\DCSync-ReplicationRights\README.md',
    'scenarios\acl\DCSync-ReplicationRights\Detect.md',
    'scenarios\acl\DCSync-ReplicationRights\Audit.ps1',
    'scenarios\acl\DCSync-ReplicationRights\setup.ps1',
    'scenarios\acl\DCSync-ReplicationRights\validate.ps1',
    'scenarios\acl\DCSync-ReplicationRights\cleanup.ps1',
    'scenarios\acl\DCSync-ReplicationRights\scenario.psd1',
    'scenarios\acl\AdminSDHolder\README.md',
    'scenarios\acl\AdminSDHolder\Detect.md',
    'scenarios\acl\AdminSDHolder\Audit.ps1',
    'scenarios\acl\AdminSDHolder\AdminSDHolder.Common.psm1',
    'scenarios\acl\AdminSDHolder\setup.ps1',
    'scenarios\acl\AdminSDHolder\validate.ps1',
    'scenarios\acl\AdminSDHolder\cleanup.ps1',
    'scenarios\acl\AdminSDHolder\scenario.psd1',
    'scripts\guest\00-PrepareServer.ps1',
    'scripts\guest\10-NewForest.ps1',
    'scripts\guest\15-EnsureADDns.ps1',
    'scripts\guest\20-BootstrapAD.ps1',
    'scripts\guest\30-InstallADCS.ps1',
    'scripts\guest\40-EnableDefensiveAuditing.ps1',
    'scripts\guest\50-EnableADCSHttpCdp.ps1',
    'scripts\guest\90-ValidateLab.ps1',
    'modules\Lab.Common.psm1',
    'modules\Lab.ActiveDirectory.psm1',
    'modules\Lab.Validation.psm1'
)

foreach ($relativePath in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $relativePath) -PathType Leaf)) {
        $failures.Add("Missing required file: $relativePath")
    }
}

$sourceRootNames = @('bootstrap', 'config', 'modules', 'scenarios', 'scripts', 'tests')
$sourceFiles = @(
    foreach ($sourceRootName in $sourceRootNames) {
        $sourceRootPath = Join-Path $root $sourceRootName
        if (Test-Path -LiteralPath $sourceRootPath -PathType Container) {
            Get-ChildItem -LiteralPath $sourceRootPath -Recurse -File -ErrorAction Stop
        }
    }
) | Where-Object { $_.Extension -in @('.ps1', '.psm1', '.psd1') -and -not (Test-IgnoredLabPath $_.FullName) }
foreach ($file in $sourceFiles) {
    $tokens = $null
    $parseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors)
    foreach ($parseError in @($parseErrors)) {
        $failures.Add("Parse error in $($file.FullName): $($parseError.Message)")
    }
}

try {
    $configPath = Join-Path $root 'config\LabConfig.psd1'
    $schemaResult = & (Join-Path $root 'scripts\Test-LabConfig.ps1') -ConfigPath $configPath
    if ([string]$schemaResult.Kind -ne 'Schema' -or -not [bool]$schemaResult.Valid) {
        $failures.Add('Test-LabConfig.ps1 must report a successful schema validation for the shipped config.')
    }

    Import-Module (Join-Path $root 'modules\Lab.Common.psm1') -Force -ErrorAction Stop
    . (Join-Path $root 'tests\Assert-ShippedLabInstance.ps1')
    $config = Import-PowerShellDataFile -LiteralPath $configPath
    Test-ShippedLabInstance -Config $config -Failures $failures

    $genericConfigPath = Join-Path $root 'config\examples\generic-lab.psd1'
    $genericSchemaResult = & (Join-Path $root 'scripts\Test-LabConfig.ps1') -ConfigPath $genericConfigPath
    if (-not [bool]$genericSchemaResult.Valid -or [string]$genericSchemaResult.DomainName -ne 'ad.lab.example.test') {
        $failures.Add('config/examples/generic-lab.psd1 must pass schema validation as ad.lab.example.test.')
    }

    $genericConfig = Import-PowerShellDataFile -LiteralPath $genericConfigPath
    $genericInstanceFailures = New-Object System.Collections.Generic.List[string]
    Test-ShippedLabInstance -Config $genericConfig -Failures $genericInstanceFailures
    if ($genericInstanceFailures.Count -eq 0) {
        $failures.Add('config/examples/generic-lab.psd1 must remain distinct from the shipped lab instance.')
    }

    $invalidGeneric = Import-PowerShellDataFile -LiteralPath $genericConfigPath
    $invalidGeneric.Network.SwitchType = 'Internal'
    $invalidSchemaRejected = $false
    try {
        Assert-LabConfig -Config $invalidGeneric | Out-Null
    }
    catch {
        if ($_.Exception.Message -match 'SwitchType') {
            $invalidSchemaRejected = $true
        }
        else {
            throw
        }
    }
    if (-not $invalidSchemaRejected) {
        $failures.Add('Assert-LabConfig must reject a non-Private switch even on the generic example.')
    }
}
catch {
    $failures.Add("Configuration validation failed: $($_.Exception.Message)")
}

$implementationFiles = @($sourceFiles | Where-Object { $_.FullName -ne $PSCommandPath })
$allSource = ($implementationFiles | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join [Environment]::NewLine
foreach ($forbiddenCommand in @('Install-Module', 'Invoke-WebRequest', 'Start-BitsTransfer', 'winget.exe', 'choco.exe')) {
    if ($allSource -match [regex]::Escape($forbiddenCommand)) {
        $failures.Add("Offline bootstrap contains forbidden download/install command: $forbiddenCommand")
    }
}

$validatedSetupPath = Join-Path $root 'scripts\host\Invoke-ValidatedLabSetup.ps1'
if (Test-Path -LiteralPath $validatedSetupPath -PathType Leaf) {
    $validatedSetupSource = Get-Content -LiteralPath $validatedSetupPath -Raw
    foreach ($checkpointName in @(
        '01-Updated',
        '02-Baseline',
        '03-Forest',
        '04-AD-Baseline',
        '05-ADCS-Baseline',
        '06-ADCS-HTTP-CDP'
    )) {
        if ($validatedSetupSource -notmatch [regex]::Escape($checkpointName)) {
            $failures.Add("Validated setup is missing checkpoint workflow name: $checkpointName")
        }
    }
    if ($validatedSetupSource -notmatch [regex]::Escape('Checkpoint-VM')) {
        $failures.Add('Validated setup must create successful stage checkpoints with Checkpoint-VM.')
    }
    foreach ($passwordPrompt in @(
        "Read-Host 'Enter the local Administrator password set during Windows installation' -AsSecureString",
        "Read-Host 'Enter the DSRM password' -AsSecureString",
        "Read-Host 'Enter the password for new lab users' -AsSecureString"
    )) {
        if ($validatedSetupSource -notmatch [regex]::Escape($passwordPrompt)) {
            $failures.Add("Validated setup is missing a separate interactive password prompt: $passwordPrompt")
        }
    }
    $newVmSource = Get-Content -LiteralPath (Join-Path $root 'scripts\host\New-LabVm.ps1') -Raw
    foreach ($newVmContract in @(
        'ProcessorCount = 4',
        '8192MB',
        '80GB',
        'DynamicMemoryEnabled $false',
        'AutomaticCheckpointsEnabled $false',
        'CheckpointType Standard',
        'EnableSecureBoot On',
        'Network.SwitchName',
        'SwitchType Private',
        'does not change an existing VM'
    )) {
        if ($newVmSource -notmatch [regex]::Escape($newVmContract)) {
            $failures.Add("New lab VM script is missing required shape: $newVmContract")
        }
    }
    $baseCheckpointSource = Get-Content -LiteralPath (Join-Path $root 'scripts\host\New-LabBaseCheckpoint.ps1') -Raw
    foreach ($baseCheckpointContract in @(
        '01-Updated',
        'Network.SwitchName',
        'must be Private',
        'exactly one NIC'
    )) {
        if ($baseCheckpointSource -notmatch [regex]::Escape($baseCheckpointContract)) {
            $failures.Add("Base checkpoint script is missing required behavior: $baseCheckpointContract")
        }
    }
    $publishedDocRoots = @(
        (Join-Path $root 'README.md'),
        (Join-Path $root 'README.ja.md'),
        (Join-Path $root 'docs'),
        (Join-Path $root 'scenarios')
    )
    $publishedDocs = @(
        foreach ($publishedDocRoot in $publishedDocRoots) {
            if (Test-Path -LiteralPath $publishedDocRoot -PathType Container) {
                Get-ChildItem -LiteralPath $publishedDocRoot -Recurse -File -Filter '*.md' -ErrorAction Stop |
                    Where-Object { -not (Test-IgnoredLabPath $_.FullName) }
            }
            elseif (Test-Path -LiteralPath $publishedDocRoot -PathType Leaf) {
                Get-Item -LiteralPath $publishedDocRoot
            }
        }
    )
    foreach ($publishedDoc in $publishedDocs) {
        $publishedDocSource = Get-Content -LiteralPath $publishedDoc.FullName -Raw
        $relativeDocPath = $publishedDoc.FullName.Substring($root.Length).TrimStart([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
        if ($publishedDocSource -match 'Auth WinUpdate PrivateSwitch') {
            $failures.Add("Published documentation still names the maintainer checkpoint: $relativeDocPath")
        }
        if ($publishedDocSource -match [regex]::Escape("Set-Location 'D:\Lab\windows-ad-lab'")) {
            $failures.Add("Published documentation still uses the maintainer working directory: $relativeDocPath")
        }
    }
    foreach ($checkpointCommand in @(
        'Rename-VMCheckpoint',
        'Restore-VMCheckpoint',
        'Remove-VMCheckpoint'
    )) {
        if ($validatedSetupSource -match [regex]::Escape($checkpointCommand)) {
            $failures.Add("Validated setup must leave checkpoint lifecycle operations manual: $checkpointCommand")
        }
    }
}

$bootstrapSource = Get-Content -LiteralPath (Join-Path $root 'bootstrap\Invoke-LabBootstrap.ps1') -Raw
foreach ($uncCopyContract in @(
    'Copy-LabPayloadFiles',
    "Copy-LabPayloadFiles -Session `$Session -SourceRoot `$repositoryRoot -SourceConfigPath `$ConfigPath",
    "if (-not (`$repositoryRoot.StartsWith('\\') -or `$ConfigPath.StartsWith('\\'))) { throw }",
    '[System.IO.Path]::GetTempPath()',
    'Copy-LabPayloadFiles -Session $Session -SourceRoot $temporaryRoot -SourceConfigPath $temporaryConfigPath'
)) {
    if ($bootstrapSource -notmatch [regex]::Escape($uncCopyContract)) {
        $failures.Add("Bootstrap is missing direct UNC copy or local temporary retry behavior: $uncCopyContract")
    }
}
foreach ($readinessContract in @(
    'Wait-LabActiveDirectoryReady',
    "Get-Service -Name 'ADWS', 'NTDS'",
    'Get-ADDomain -Server $env:COMPUTERNAME',
    "Set-Service -Name 'ADWS' -StartupType Automatic",
    "Start-Service -Name 'ADWS'",
    'if ($isExistingDomainController)',
    'Ensure-LabActiveDirectoryDns',
    '15-EnsureADDns.ps1'
)) {
    if ($bootstrapSource -notmatch [regex]::Escape($readinessContract)) {
        $failures.Add("Bootstrap is missing Active Directory readiness check: $readinessContract")
    }
}

$httpCdpScriptSource = Get-Content -LiteralPath (Join-Path $root 'scripts\guest\50-EnableADCSHttpCdp.ps1') -Raw
foreach ($httpCdpContract in @(
    'ADCSHttpCdp',
    'Web-Server',
    'Web-Static-Content',
    'Web-Filtering',
    'http://%1/CertEnroll/%3%8%9.crl',
    'http://%1/CertEnroll/%1_%3%4.crt',
    'CRLPublicationURLs',
    'CACertPublicationURLs',
    'requestFiltering allowDoubleEscaping="true"',
    'Restart-Service -Name CertSvc',
    'WaitCertSvcRpc',
    'RetryCount 12',
    'certutil.exe',
    "'-crl'"
)) {
    if ($httpCdpScriptSource -notmatch [regex]::Escape($httpCdpContract)) {
        $failures.Add("AD CS HTTP CDP phase is missing required behavior: $httpCdpContract")
    }
}

$validatedBootstrapHttpCdpContracts = @(
    'ADCSHttpCdp',
    '50-EnableADCSHttpCdp.ps1',
    '-ExpectAdcsHttpCdp:$ExpectHttpCdp'
)
foreach ($httpCdpBootstrapContract in $validatedBootstrapHttpCdpContracts) {
    if ($bootstrapSource -notmatch [regex]::Escape($httpCdpBootstrapContract)) {
        $failures.Add("Bootstrap is missing AD CS HTTP CDP workflow: $httpCdpBootstrapContract")
    }
}

$dnsConvergenceSource = Get-Content -LiteralPath (Join-Path $root 'scripts\guest\15-EnsureADDns.ps1') -Raw
foreach ($dnsContract in @(
    'Add-DnsServerPrimaryZone',
    "Scope     = 'Domain'",
    "Scope     = 'Forest'",
    '-DynamicUpdate Secure',
    'Restart-Service -Name Netlogon',
    'nltest.exe /dsregdns',
    'Resolve-DnsName',
    'Select-Object -First 1'
)) {
    if ($dnsConvergenceSource -notmatch [regex]::Escape($dnsContract)) {
        $failures.Add("AD DNS convergence is missing required behavior: $dnsContract")
    }
}
if ($dnsConvergenceSource -match [regex]::Escape('Repl Perform Initial Synchronizations')) {
    $failures.Add('AD DNS convergence must not bypass initial synchronization through the NTDS registry setting.')
}
if ($dnsConvergenceSource -match [regex]::Escape('@(Get-DnsServerZone -Name $Name -ErrorAction SilentlyContinue)[0]')) {
    $failures.Add('AD DNS convergence must not index an empty zone result under StrictMode.')
}

$commonModuleSource = Get-Content -LiteralPath (Join-Path $root 'modules\Lab.Common.psm1') -Raw
if ($commonModuleSource -notmatch [regex]::Escape('Get-ADDomain -Server $env:COMPUTERNAME')) {
    $failures.Add('Get-LabCurrentDomain must target the local domain controller explicitly.')
}

$scenarioRunnerSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\Invoke-Scenario.ps1') -Raw
foreach ($scenarioRunnerContract in @(
    'New-PSSession @sessionParameters',
    'Get-ChildItem -LiteralPath $ScenariosRoot -Recurse -Directory',
    'function Get-LabScenarioManifest',
    'function Get-LabScenarioResolutionNames',
    'function Get-LabScenarioInventory',
    'function Join-LabScenarioRelativePath',
    'ScenarioName must identify one scenario; wildcard characters are not supported',
    'Copy-Item -LiteralPath $Scenario.FullName -Destination $remoteScenarioParentPath -ToSession $Session -Force -Recurse',
    '$guestScenariosRoot = Join-Path $guestRoot ''scenarios''',
    '& $Path @ArgumentHash',
    "'Audit' { 'Audit.ps1' }",
    'AcknowledgeIsolatedLabRisk',
    '[hashtable]$ValidationInputFiles = @{}',
    "Join-Path `$repositoryRoot 'artifacts\scenario-validation'",
    "Join-Path `$guestRoot 'scenario-validation-inputs'",
    'function Assert-LabValidationInputConfiguration',
    'ValidationInputFiles can only be used with -Action Validate.',
    'requires exactly one resolved scenario',
    'cannot be supplied by both ScriptParameters and ValidationInputFiles',
    'function Resolve-LabScenarioValidationInputFiles',
    'must remain under',
    'Get-FileHash -LiteralPath $hostFile.FullName -Algorithm SHA256',
    'function Sync-LabScenarioValidationInputs',
    'Copy-Item -LiteralPath $input.HostPath -Destination $guestPath -ToSession $Session -Force',
    'SHA-256 or length mismatch after copying',
    '$effectiveParameters[[string]$transfer.ParameterName] = [string]$transfer.GuestPath'
)) {
    if ($scenarioRunnerSource -notmatch [regex]::Escape($scenarioRunnerContract)) {
        $failures.Add("Scenario runner is missing required PowerShell Direct workflow: $scenarioRunnerContract")
    }
}

try {
    $runnerTokens = $null
    $runnerParseErrors = $null
    $scenarioRunnerAst = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $root 'scenarios\Invoke-Scenario.ps1'),
        [ref]$runnerTokens,
        [ref]$runnerParseErrors
    )
    if (@($runnerParseErrors).Count -gt 0) {
        throw (@($runnerParseErrors | ForEach-Object { $_.Message }) -join '; ')
    }

    $validationInputHelperNames = @(
        'Get-LabScenarioScriptParameterNames',
        'Assert-LabValidationInputConfiguration',
        'Resolve-LabScenarioValidationInputFiles'
    )
    $validationInputHelperAsts = @($scenarioRunnerAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $validationInputHelperNames -contains $node.Name
    }, $true))
    if ($validationInputHelperAsts.Count -ne $validationInputHelperNames.Count) {
        throw "Expected $($validationInputHelperNames.Count) validation input helpers, found $($validationInputHelperAsts.Count)."
    }
    foreach ($validationInputHelperAst in $validationInputHelperAsts) {
        Invoke-Expression $validationInputHelperAst.Extent.Text
    }

    $validationScenarioRoot = Join-Path $root 'scenarios\adcs\ESC1-CertificateTemplate'
    $validationScenario = [pscustomobject]@{ FullName = $validationScenarioRoot }
    $absoluteValidationInput = Join-Path $validationScenarioRoot 'README.md'
    $hostValidationInputDirectory = Join-Path $root 'artifacts\scenario-validation\adcs\ESC1-CertificateTemplate'
    Assert-LabValidationInputConfiguration `
        -Scenarios @($validationScenario) `
        -CurrentAction Validate `
        -ActionScript validate.ps1 `
        -Files @{ OutputPath = $absoluteValidationInput } `
        -Parameters @{ FailOnValidationError = $true }

    $resolvedValidationInputs = @(Resolve-LabScenarioValidationInputFiles `
        -Files @{ OutputPath = $absoluteValidationInput } `
        -HostDirectory $hostValidationInputDirectory)
    if ($resolvedValidationInputs.Count -ne 1 -or
        $resolvedValidationInputs[0].Length -le 0 -or
        ([string]$resolvedValidationInputs[0].SHA256).Length -ne 64 -or
        [string]$resolvedValidationInputs[0].GuestFileName -ne 'OutputPath.md') {
        $failures.Add('Scenario runner did not resolve an absolute validation input with deterministic guest metadata.')
    }

    $duplicateParameterRejected = $false
    try {
        Assert-LabValidationInputConfiguration `
            -Scenarios @($validationScenario) `
            -CurrentAction Validate `
            -ActionScript validate.ps1 `
            -Files @{ OutputPath = $absoluteValidationInput } `
            -Parameters @{ OutputPath = 'duplicate' }
    }
    catch {
        if ($_.Exception.Message -match 'both ScriptParameters and ValidationInputFiles') {
            $duplicateParameterRejected = $true
        }
        else {
            throw
        }
    }
    if (-not $duplicateParameterRejected) {
        $failures.Add('Scenario runner must reject a validation input parameter supplied through both parameter maps.')
    }

    $relativeEscapeRejected = $false
    try {
        Resolve-LabScenarioValidationInputFiles `
            -Files @{ OutputPath = '../README.md' } `
            -HostDirectory $hostValidationInputDirectory |
            Out-Null
    }
    catch {
        if ($_.Exception.Message -match 'must remain under') {
            $relativeEscapeRejected = $true
        }
        else {
            throw
        }
    }
    if (-not $relativeEscapeRejected) {
        $failures.Add('Scenario runner must reject relative validation input paths that escape the scenario input directory.')
    }
}
catch {
    $failures.Add("Scenario runner validation input helper test failed: $($_.Exception.Message)")
}

try {
    $resolutionHelperNames = @(
        'Normalize-LabScenarioName',
        'ConvertTo-LabScenarioRelativePath',
        'Get-LabScenarioManifest',
        'Get-LabScenarioResolutionNames',
        'Get-LabScenarioInventory',
        'Resolve-LabScenarioDirectory'
    )
    $resolutionHelperAsts = @($scenarioRunnerAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $resolutionHelperNames -contains $node.Name
    }, $true))
    if ($resolutionHelperAsts.Count -ne $resolutionHelperNames.Count) {
        throw "Expected $($resolutionHelperNames.Count) scenario resolution helpers, found $($resolutionHelperAsts.Count)."
    }
    foreach ($resolutionHelperAst in $resolutionHelperAsts) {
        Invoke-Expression $resolutionHelperAst.Extent.Text
    }

    $scenariosRootForTest = Join-Path $root 'scenarios'
    $inventory = @(Get-LabScenarioInventory -ScenariosRoot $scenariosRootForTest -RequiredScript 'setup.ps1')
    if ($inventory.Count -lt 22) {
        throw "Expected at least 22 shipped scenarios, found $($inventory.Count)."
    }

    $ids = @{}
    $aliases = @{}
    foreach ($scenario in $inventory) {
        $manifestPath = Join-Path $scenario.FullName 'scenario.psd1'
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            throw "Scenario '$($scenario.Name)' is missing scenario.psd1."
        }
        if ([string]::IsNullOrWhiteSpace([string]$scenario.Id)) {
            throw "Scenario '$($scenario.Name)' is missing Id."
        }
        if ($ids.ContainsKey([string]$scenario.Id)) {
            throw "Scenario Id '$($scenario.Id)' is used by both '$($ids[[string]$scenario.Id])' and '$($scenario.Name)'."
        }
        $ids[[string]$scenario.Id] = [string]$scenario.Name
        foreach ($alias in @([string]$scenario.Id) + @($scenario.Aliases)) {
            $normalizedAlias = Normalize-LabScenarioName -Name ([string]$alias)
            if ($aliases.ContainsKey($normalizedAlias) -and $aliases[$normalizedAlias] -ne [string]$scenario.Name) {
                throw "Scenario alias '$normalizedAlias' is used by both '$($aliases[$normalizedAlias])' and '$($scenario.Name)'."
            }
            $aliases[$normalizedAlias] = [string]$scenario.Name
        }
    }

    $esc8Matches = @(Resolve-LabScenarioDirectory `
        -Name @('esc8', 'ESC8-Hardening', 'adcs/ESC8-Hardening') `
        -RequiredScript 'setup.ps1' `
        -ScenariosRoot $scenariosRootForTest)
    if ($esc8Matches.Count -ne 1 -or [string]$esc8Matches[0].Name -ne 'adcs/ESC8-Hardening') {
        throw "ESC8 identities did not resolve to adcs/ESC8-Hardening."
    }

    $esc15Matches = @(Resolve-LabScenarioDirectory `
        -Name @('esc15', 'ESC15-SchemaV1Template', 'adcs/ESC15-SchemaV1Template') `
        -RequiredScript 'setup.ps1' `
        -ScenariosRoot $scenariosRootForTest)
    if ($esc15Matches.Count -ne 1 -or [string]$esc15Matches[0].Name -ne 'adcs/ESC15-SchemaV1Template') {
        throw "ESC15 identities did not resolve to adcs/ESC15-SchemaV1Template."
    }

    $esc2Matches = @(Resolve-LabScenarioDirectory `
        -Name @('esc2', 'ESC2-AnyPurposeTemplate', 'adcs/ESC2-AnyPurposeTemplate') `
        -RequiredScript 'setup.ps1' `
        -ScenariosRoot $scenariosRootForTest)
    if ($esc2Matches.Count -ne 1 -or [string]$esc2Matches[0].Name -ne 'adcs/ESC2-AnyPurposeTemplate') {
        throw "ESC2 identities did not resolve to adcs/ESC2-AnyPurposeTemplate."
    }

    $esc3Matches = @(Resolve-LabScenarioDirectory `
        -Name @('esc3', 'ESC3-EnrollmentAgent', 'adcs/ESC3-EnrollmentAgent') `
        -RequiredScript 'setup.ps1' `
        -ScenariosRoot $scenariosRootForTest)
    if ($esc3Matches.Count -ne 1 -or [string]$esc3Matches[0].Name -ne 'adcs/ESC3-EnrollmentAgent') {
        throw "ESC3 identities did not resolve to adcs/ESC3-EnrollmentAgent."
    }

    $esc4Matches = @(Resolve-LabScenarioDirectory `
        -Name @('esc4', 'ESC4-TemplateAcl', 'adcs/ESC4-TemplateAcl') `
        -RequiredScript 'setup.ps1' `
        -ScenariosRoot $scenariosRootForTest)
    if ($esc4Matches.Count -ne 1 -or [string]$esc4Matches[0].Name -ne 'adcs/ESC4-TemplateAcl') {
        throw "ESC4 identities did not resolve to adcs/ESC4-TemplateAcl."
    }

    $esc5Matches = @(Resolve-LabScenarioDirectory `
        -Name @('esc5', 'ESC5-PkiObjectAcl', 'adcs/ESC5-PkiObjectAcl') `
        -RequiredScript 'setup.ps1' `
        -ScenariosRoot $scenariosRootForTest)
    if ($esc5Matches.Count -ne 1 -or [string]$esc5Matches[0].Name -ne 'adcs/ESC5-PkiObjectAcl') {
        throw "ESC5 identities did not resolve to adcs/ESC5-PkiObjectAcl."
    }

    $esc7Matches = @(Resolve-LabScenarioDirectory `
        -Name @('esc7', 'ESC7-ManageCA', 'adcs/ESC7-ManageCA') `
        -RequiredScript 'setup.ps1' `
        -ScenariosRoot $scenariosRootForTest)
    if ($esc7Matches.Count -ne 1 -or [string]$esc7Matches[0].Name -ne 'adcs/ESC7-ManageCA') {
        throw "ESC7 identities did not resolve to adcs/ESC7-ManageCA."
    }

    $esc12Matches = @(Resolve-LabScenarioDirectory `
        -Name @('esc12', 'ESC12-CaKeyStorage', 'adcs/ESC12-CaKeyStorage') `
        -RequiredScript 'setup.ps1' `
        -ScenariosRoot $scenariosRootForTest)
    if ($esc12Matches.Count -ne 1 -or [string]$esc12Matches[0].Name -ne 'adcs/ESC12-CaKeyStorage') {
        throw "ESC12 identities did not resolve to adcs/ESC12-CaKeyStorage."
    }

    $esc13Matches = @(Resolve-LabScenarioDirectory `
        -Name @('esc13', 'ESC13-IssuancePolicy', 'adcs/ESC13-IssuancePolicy') `
        -RequiredScript 'setup.ps1' `
        -ScenariosRoot $scenariosRootForTest)
    if ($esc13Matches.Count -ne 1 -or [string]$esc13Matches[0].Name -ne 'adcs/ESC13-IssuancePolicy') {
        throw "ESC13 identities did not resolve to adcs/ESC13-IssuancePolicy."
    }

    $esc14Matches = @(Resolve-LabScenarioDirectory `
        -Name @('esc14', 'ESC14-WeakExplicitMapping', 'adcs/ESC14-WeakExplicitMapping') `
        -RequiredScript 'setup.ps1' `
        -ScenariosRoot $scenariosRootForTest)
    if ($esc14Matches.Count -ne 1 -or [string]$esc14Matches[0].Name -ne 'adcs/ESC14-WeakExplicitMapping') {
        throw "ESC14 identities did not resolve to adcs/ESC14-WeakExplicitMapping."
    }

    $esc16Matches = @(Resolve-LabScenarioDirectory `
        -Name @('esc16', 'ESC16-DisableExtensionList', 'adcs/ESC16-DisableExtensionList') `
        -RequiredScript 'setup.ps1' `
        -ScenariosRoot $scenariosRootForTest)
    if ($esc16Matches.Count -ne 1 -or [string]$esc16Matches[0].Name -ne 'adcs/ESC16-DisableExtensionList') {
        throw "ESC16 identities did not resolve to adcs/ESC16-DisableExtensionList."
    }

    $esc17Matches = @(Resolve-LabScenarioDirectory `
        -Name @('esc17', 'ESC17-ServerAuthTemplate', 'adcs/ESC17-ServerAuthTemplate') `
        -RequiredScript 'setup.ps1' `
        -ScenariosRoot $scenariosRootForTest)
    if ($esc17Matches.Count -ne 1 -or [string]$esc17Matches[0].Name -ne 'adcs/ESC17-ServerAuthTemplate') {
        throw "ESC17 identities did not resolve to adcs/ESC17-ServerAuthTemplate."
    }

    $rbcdMatch = @(Resolve-LabScenarioDirectory `
        -Name @('RBCD') `
        -RequiredScript 'setup.ps1' `
        -ScenariosRoot $scenariosRootForTest)
    if ($rbcdMatch.Count -ne 1 -or [string]$rbcdMatch[0].Name -ne 'delegation/RBCD') {
        throw "Old RBCD name did not resolve to delegation/RBCD."
    }

    $relativeScenarioMatch = @(Resolve-LabScenarioDirectory `
        -Name @('adcs/ESC1-CertificateTemplate') `
        -RequiredScript 'setup.ps1' `
        -ScenariosRoot $scenariosRootForTest)
    if ($relativeScenarioMatch.Count -ne 1 -or [string]$relativeScenarioMatch[0].Name -ne 'adcs/ESC1-CertificateTemplate') {
        throw "Category-relative scenario path resolution failed."
    }
}
catch {
    $failures.Add("Scenario catalog and identity resolution test failed: $($_.Exception.Message)")
}

$auditScriptFiles = @(Get-ChildItem -LiteralPath (Join-Path $root 'scenarios') -Recurse -File -Filter 'Audit.ps1' |
    Where-Object { -not (Test-IgnoredLabPath $_.FullName) })
foreach ($auditScriptFile in $auditScriptFiles) {
    $auditScriptSource = Get-Content -LiteralPath $auditScriptFile.FullName -Raw
    $relativeAuditPath = $auditScriptFile.FullName.Substring($root.Length).TrimStart([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    if ($auditScriptSource -match 'Add-EventLogMatches[^\r\n]+-EventId\s+(?:\d|@\()') {
        $failures.Add("Audit script must pass named event ID arrays to Add-EventLogMatches: $relativeAuditPath")
    }

    $lineNumber = 0
    foreach ($line in @(Get-Content -LiteralPath $auditScriptFile.FullName)) {
        $lineNumber++
        if ($line -match '^\s*\d{1,4},?\s*(?:#.*)?$' -and $line -notmatch '#') {
            $failures.Add("Audit script event ID line must explain the event meaning: ${relativeAuditPath}:$lineNumber")
        }
    }
}

$esc1SetupSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\adcs\ESC1-CertificateTemplate\setup.ps1') -Raw
foreach ($esc1SetupContract in @(
    'SchemaNamingContext        = [string]$rootDse.schemaNamingContext',
    'function Get-AdAttributeSchema',
    '-Properties lDAPDisplayName, isSingleValued, attributeSyntax, oMSyntax',
    "IsOctetString  = ([string]`$schemaObjects[0].attributeSyntax -eq '2.5.5.10')",
    '-SingleValued ([bool]$schema.IsSingleValued) -OctetString ([bool]$schema.IsOctetString)',
    '$valueObject -is [System.Collections.IEnumerable]',
    'HasValue = $false',
    '$result.Value = [byte[]]$bytes.ToArray()',
    'function ConvertTo-SortedUniqueStringArray',
    'function ConvertTo-SingleStringOrNull',
    'function Test-OidString',
    'function Ensure-AdDrive',
    '$path = "AD:\$TemplateDistinguishedName"',
    'Create certificate template ''$TemplateName'' failed',
    'Create enterprise OID object ''$($oid.Name)'' failed',
    '$attributes[''msPKI-Certificate-Application-Policy''] = [string[]](ConvertTo-SortedUniqueStringArray -Value $applicationPolicies)',
    '$replace[''msPKI-Certificate-Application-Policy''] = [string[]](ConvertTo-SortedUniqueStringArray -Value $applicationPolicies)'
)) {
    if ($esc1SetupSource -notmatch [regex]::Escape($esc1SetupContract)) {
        $failures.Add("ESC1 setup is missing ADCS string-array normalization contract: $esc1SetupContract")
    }
}
if ($esc1SetupSource -match [regex]::Escape('$attributes[''msPKI-Certificate-Application-Policy''] = @($applicationPolicies | Sort-Object -Unique)')) {
    $failures.Add('ESC1 setup must not pass untyped pipeline output to msPKI-Certificate-Application-Policy.')
}
if ($esc1SetupSource -match [regex]::Escape('$items = @($Value)')) {
    $failures.Add('ESC1 setup must enumerate ADPropertyValueCollection values instead of wrapping the collection with @($Value).')
}
$esc1ValidateSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\adcs\ESC1-CertificateTemplate\validate.ps1') -Raw
$mandatoryGenericListPattern = '\[Parameter\(Mandatory\s*=\s*\$true\)\]\s*\[System\.Collections\.Generic\.List\['
$scenarioScriptFiles = @(Get-ChildItem -LiteralPath (Join-Path $root 'scenarios') -Recurse -File -Filter '*.ps1' |
    Where-Object { -not (Test-IgnoredLabPath $_.FullName) })
foreach ($scenarioScriptFile in $scenarioScriptFiles) {
    $scenarioScriptSource = Get-Content -LiteralPath $scenarioScriptFile.FullName -Raw
    if ($scenarioScriptSource -match $mandatoryGenericListPattern) {
        $relativeScenarioPath = $scenarioScriptFile.FullName.Substring($root.Length).TrimStart([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
        $failures.Add("Scenario helper Generic List parameters must accept empty collections: $relativeScenarioPath")
    }
}
foreach ($esc1ScenarioSource in @($esc1SetupSource, $esc1ValidateSource)) {
    if ($esc1ScenarioSource -match [regex]::Escape('ADCSLAB')) {
        $failures.Add('ESC1 scenario must use AD:\DistinguishedName ACL paths instead of custom ADCSLAB PSDrive paths.')
    }
    if ($esc1ScenarioSource -match [regex]::Escape('function New-TemplateProviderDrive')) {
        $failures.Add('ESC1 scenario must not create a custom certificate-template-rooted AD PSDrive.')
    }
    if ($esc1ScenarioSource -match [regex]::Escape('$path = "$DriveName`:\CN=$TemplateName"')) {
        $failures.Add('ESC1 scenario must not use CN-relative ACL paths under a custom AD PSDrive.')
    }
}

$pkinitSetupSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\adcs\PKINIT-KDCCertificate\setup.ps1') -Raw
foreach ($pkinitSetupContract in @(
    'LAB-PKINIT-KDCAuthentication',
    'KerberosAuthentication',
    'windows-ad-lab:PKINIT-KDCCertificate',
    'Domain Controllers',
    'Cert:\LocalMachine\My',
    '1.3.6.1.5.2.3.5',
    '1.3.6.1.4.1.311.21.7',
    'Get-CertificateTemplateOidFromCertificate',
    "'-enroll', '-machine'",
    'Restart-Service -Name KDC',
    'More than one valid PKINIT KDC certificate'
)) {
    if ($pkinitSetupSource -notmatch [regex]::Escape($pkinitSetupContract)) {
        $failures.Add("PKINIT KDC setup is missing required behavior: $pkinitSetupContract")
    }
}
if ($pkinitSetupSource -match [regex]::Escape('NTDS')) {
    $failures.Add('PKINIT KDC scenario must not use the NTDS certificate store in this iteration.')
}
if ($pkinitSetupSource -match [regex]::Escape('LDAPS')) {
    $failures.Add('PKINIT KDC scenario must not include LDAPS setup in this iteration.')
}

$pkinitValidateSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\adcs\PKINIT-KDCCertificate\validate.ps1') -Raw
foreach ($pkinitValidateContract in @(
    'certutil.exe',
    "'-DCInfo'",
    "'Verify'",
    'Test-CertificateChain',
    'Certificate chain and revocation',
    'FailOnValidationError'
)) {
    if ($pkinitValidateSource -notmatch [regex]::Escape($pkinitValidateContract)) {
        $failures.Add("PKINIT KDC validation is missing required behavior: $pkinitValidateContract")
    }
}
if ($pkinitValidateSource -match [regex]::Escape('AS-REQ')) {
    $failures.Add('PKINIT KDC validation must not claim to automate AS-REQ/TGT verification in this iteration.')
}

$pkinitCleanupSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\adcs\PKINIT-KDCCertificate\cleanup.ps1') -Raw
foreach ($pkinitCleanupContract in @(
    'Remove-ScenarioKdcCertificates',
    'Restart-Service -Name KDC',
    'Remove-TemplateFromLocalCa',
    'Remove-ADObject',
    'Refusing to delete it'
)) {
    if ($pkinitCleanupSource -notmatch [regex]::Escape($pkinitCleanupContract)) {
        $failures.Add("PKINIT KDC cleanup is missing required behavior: $pkinitCleanupContract")
    }
}

$rbcdSetupSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\delegation\RBCD\setup.ps1') -Raw
foreach ($rbcdSetupContract in @(
    'RBCD',
    'windows-ad-lab:RBCD',
    'msDS-AllowedToActOnBehalfOfOtherIdentity',
    '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79',
    'New-RbcdSecurityDescriptorBytes',
    'svc_web',
    'FILE01',
    'WEB01',
    'WriteProperty',
    'Refusing to replace a non-scenario RBCD descriptor'
)) {
    if ($rbcdSetupSource -notmatch [regex]::Escape($rbcdSetupContract)) {
        $failures.Add("RBCD setup is missing required behavior: $rbcdSetupContract")
    }
}

$rbcdValidateSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\delegation\RBCD\validate.ps1') -Raw
foreach ($rbcdValidateContract in @(
    'S4U2Proxy metadata',
    'Delegating computer is allowed on resource',
    'Control computer is not allowed',
    'MachineAccountQuota',
    'PrincipalsAllowedToDelegateToAccount',
    'FailOnValidationError'
)) {
    if ($rbcdValidateSource -notmatch [regex]::Escape($rbcdValidateContract)) {
        $failures.Add("RBCD validation is missing required behavior: $rbcdValidateContract")
    }
}

$rbcdCleanupSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\delegation\RBCD\cleanup.ps1') -Raw
foreach ($rbcdCleanupContract in @(
    'Clear-ScenarioRbcdAttribute',
    'Remove-ScenarioRbcdWriteAce',
    'Refusing to clear',
    'BaselineRestored'
)) {
    if ($rbcdCleanupSource -notmatch [regex]::Escape($rbcdCleanupContract)) {
        $failures.Add("RBCD cleanup is missing required behavior: $rbcdCleanupContract")
    }
}

$lapsSetupSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\credentials\WindowsLAPS-Delegation\setup.ps1') -Raw
foreach ($lapsSetupContract in @(
    'WindowsLAPS-Delegation',
    'windows-ad-lab:WindowsLAPS-Delegation',
    'UpdateSchemaIfMissing',
    'Update-LapsADSchema',
    'This is not a conflict with other scenarios',
    'Set-LapsADReadPasswordPermission',
    'msLAPS-Password',
    'msLAPS-PasswordExpirationTime',
    'GG_LAPS_Helpdesk',
    'IncludeFile01Misconfiguration',
    'GenericAll',
    'PasswordValuesLogged          = $false'
)) {
    if ($lapsSetupSource -notmatch [regex]::Escape($lapsSetupContract)) {
        $failures.Add("Windows LAPS delegation setup is missing required behavior: $lapsSetupContract")
    }
}
if ($lapsSetupSource -match [regex]::Escape('Test-ExplicitAceForSid')) {
    $failures.Add('Windows LAPS delegation setup must not treat any explicit principal ACE as a completed LAPS read delegation.')
}

$lapsValidateSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\credentials\WindowsLAPS-Delegation\validate.ps1') -Raw
foreach ($lapsValidateContract in @(
    'Find-LapsADExtendedRights',
    'Get-LapsExtendedRightHoldersForOu',
    'Get-LapsReadCapableAceCount',
    'Get-GenericAllAceCount',
    'Add-EffectiveHelpdeskAccessResult',
    'Effective Helpdesk access',
    'Read LAPS Password',
    'AclMatchCount',
    'AllowSingleRowFallback',
    'ExpectFile01Misconfiguration',
    'ConvertTo-LapsPasswordSummary',
    'PasswordPresent',
    'FailOnValidationError',
    'WEB01 explicit misconfiguration absent'
)) {
    if ($lapsValidateSource -notmatch [regex]::Escape($lapsValidateContract)) {
        $failures.Add("Windows LAPS delegation validation is missing required behavior: $lapsValidateContract")
    }
}

$lapsCleanupSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\credentials\WindowsLAPS-Delegation\cleanup.ps1') -Raw
foreach ($lapsCleanupContract in @(
    'Remove-ScenarioPrincipalAces',
    'Clear-ScenarioLapsAttributes',
    'Remove-ScenarioGroup',
    'WindowsLapsSchemaPresent',
    'Refusing to clear',
    'BaselineRestored'
)) {
    if ($lapsCleanupSource -notmatch [regex]::Escape($lapsCleanupContract)) {
        $failures.Add("Windows LAPS delegation cleanup is missing required behavior: $lapsCleanupContract")
    }
}

$esc8CommonSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\adcs\ESC8-Hardening\Esc8Hardening.Common.psm1') -Raw
foreach ($esc8CommonContract in @(
    'ADCS-Web-Enrollment',
    'Install-AdcsWebEnrollment',
    'Uninstall-AdcsWebEnrollment',
    'extendedProtection',
    'tokenChecking',
    'sslFlags',
    'Get-Esc8AccessSslFlags',
    'Set-WebConfigurationProperty',
    '-Location $script:Esc8CertSrvLocation',
    'windowsAuthentication',
    'providers',
    'Negotiate:Kerberos',
    'System32\inetsrv\Microsoft.Web.Administration.dll',
    'Add-Type -Path $assemblyPath',
    '[void]$webBinding.AddSslCertificate',
    '[void]$providerCollection.Add',
    'New-SelfSignedCertificate',
    'ScenarioCertificateThumbprint'
)) {
    if ($esc8CommonSource -notmatch [regex]::Escape($esc8CommonContract)) {
        $failures.Add("ESC8 hardening common module is missing required behavior: $esc8CommonContract")
    }
}
if ($esc8CommonSource -match [regex]::Escape('Install-AdcsWebEnrollment -CAConfig')) {
    $failures.Add('ESC8 hardening must not pass -CAConfig when configuring Web Enrollment on the local CA.')
}

$esc8SetupSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\adcs\ESC8-Hardening\setup.ps1') -Raw
foreach ($esc8SetupContract in @(
    "ValidateSet('Hardened', 'Vulnerable')",
    "Stage = 'Hardened'",
    'DisableNameChecking',
    'Ensure-Esc8HttpsBinding did not return a single operation result',
    'Ensure-Esc8WebEnrollmentInstalled',
    'Set-Esc8IisSecurityState -RequireSsl $false -TokenChecking None',
    "Set-Esc8IisSecurityState -RequireSsl `$true -TokenChecking Require -Providers @('Negotiate:Kerberos')",
    'Ensure-Esc8HttpsBinding',
    'Ensure-Esc8HttpsFirewallRule',
    'RelayPrerequisitesPresent'
)) {
    if ($esc8SetupSource -notmatch [regex]::Escape($esc8SetupContract)) {
        $failures.Add("ESC8 hardening setup is missing required behavior: $esc8SetupContract")
    }
}

$esc8ValidateSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\adcs\ESC8-Hardening\validate.ps1') -Raw
foreach ($esc8ValidateContract in @(
    'ExpectedState',
    'DisableNameChecking',
    'ESC8 relay preconditions',
    'HTTP enrollment allowed',
    'EPA required',
    'NTLM provider removed',
    'Kerberos-only provider',
    'Export-LabValidationResults',
    'FailOnValidationError'
)) {
    if ($esc8ValidateSource -notmatch [regex]::Escape($esc8ValidateContract)) {
        $failures.Add("ESC8 hardening validation is missing required behavior: $esc8ValidateContract")
    }
}

$esc8CleanupSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\adcs\ESC8-Hardening\cleanup.ps1') -Raw
foreach ($esc8CleanupContract in @(
    'DisableNameChecking',
    'Read-Esc8ScenarioState',
    'Restore-Esc8IisSecurityState',
    'Restore-Esc8HttpsBinding',
    'Remove-Esc8ScenarioCertificate',
    'Uninstall-Esc8WebEnrollment',
    'State file is absent'
)) {
    if ($esc8CleanupSource -notmatch [regex]::Escape($esc8CleanupContract)) {
        $failures.Add("ESC8 hardening cleanup is missing required behavior: $esc8CleanupContract")
    }
}

$adAclGpoSetupSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\acl\ADACL-GPOAbuse\setup.ps1') -Raw
foreach ($adAclGpoSetupContract in @(
    'ADACL-GPOAbuse',
    'windows-ad-lab:ADACL-GPOAbuse',
    'WriteMembers',
    'GG_GPO_WS_Admins',
    'GPO-Workstation-Baseline',
    'GenericWrite',
    'Set-GPRegistryValue',
    'New-GPLink',
    'HKLM\Software\Policies\ExceedsLab\Scenario07',
    'AutomatedEndpointExecution  = $false',
    'Refusing to reuse it'
)) {
    if ($adAclGpoSetupSource -notmatch [regex]::Escape($adAclGpoSetupContract)) {
        $failures.Add("AD ACL GPO abuse setup is missing required behavior: $adAclGpoSetupContract")
    }
}

$adAclGpoValidateSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\acl\ADACL-GPOAbuse\validate.ps1') -Raw
foreach ($adAclGpoValidateContract in @(
    'WriteMembers edge exists',
    'Workstation Admins has GPO AD GenericWrite',
    'Workstation Admins has GPO SYSVOL Modify',
    'GPO registry policy marker exists',
    'GPO SYSVOL registry.pol exists',
    'Security filtering permits default computer scope',
    'Target computer is in linked OU scope',
    'GPO link is enabled',
    'FailOnValidationError'
)) {
    if ($adAclGpoValidateSource -notmatch [regex]::Escape($adAclGpoValidateContract)) {
        $failures.Add("AD ACL GPO abuse validation is missing required behavior: $adAclGpoValidateContract")
    }
}

$adAclGpoCleanupSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\acl\ADACL-GPOAbuse\cleanup.ps1') -Raw
foreach ($adAclGpoCleanupContract in @(
    'Remove-MemberWriteAce',
    'Remove-GpoGenericWriteAce',
    'Remove-GpoSysvolModifyAce',
    'Remove-ScenarioGpoLink',
    'Remove-ScenarioGpo',
    'Remove-ScenarioGroup',
    'BaselineRestored',
    'Refusing cleanup'
)) {
    if ($adAclGpoCleanupSource -notmatch [regex]::Escape($adAclGpoCleanupContract)) {
        $failures.Add("AD ACL GPO abuse cleanup is missing required behavior: $adAclGpoCleanupContract")
    }
}

$gmsaSetupSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\credentials\gMSA-PasswordRetrieval\setup.ps1') -Raw
foreach ($gmsaSetupContract in @(
    'gMSA-PasswordRetrieval',
    'windows-ad-lab:gMSA-PasswordRetrieval',
    'msDS-GroupManagedServiceAccount',
    'msDS-GroupMSAMembership',
    'msDS-ManagedPassword',
    'PrincipalsAllowedToRetrieveManagedPassword',
    'New-ADServiceAccount',
    'Set-ADServiceAccount',
    'CreateKdsRootKeyIfMissing',
    'Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))',
    'GG_gMSA_Readers',
    'WriteProperty',
    'Backup Operators',
    'Refusing to modify it',
    'ManagedPasswordValueLogged              = $false'
)) {
    if ($gmsaSetupSource -notmatch [regex]::Escape($gmsaSetupContract)) {
        $failures.Add("gMSA password retrieval setup is missing required behavior: $gmsaSetupContract")
    }
}

$gmsaValidateSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\credentials\gMSA-PasswordRetrieval\validate.ps1') -Raw
foreach ($gmsaValidateContract in @(
    'msDS-GroupMSAMembership',
    'msDS-ManagedPassword',
    'PrincipalsAllowedToRetrieveManagedPassword',
    'Authorized computer can retrieve gMSA password',
    'Reader group can retrieve gMSA password',
    'Control computer cannot retrieve gMSA password',
    'Group member manager delegation',
    'Backup Operators overprivilege',
    'FailOnValidationError'
)) {
    if ($gmsaValidateSource -notmatch [regex]::Escape($gmsaValidateContract)) {
        $failures.Add("gMSA password retrieval validation is missing required behavior: $gmsaValidateContract")
    }
}

$gmsaCleanupSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\credentials\gMSA-PasswordRetrieval\cleanup.ps1') -Raw
foreach ($gmsaCleanupContract in @(
    'Remove-ScenarioMemberWriteAce',
    'Remove-ADServiceAccount',
    'Remove-ScenarioGroup',
    'KdsRootKeyPreserved',
    'BaselineRestored'
)) {
    if ($gmsaCleanupSource -notmatch [regex]::Escape($gmsaCleanupContract)) {
        $failures.Add("gMSA password retrieval cleanup is missing required behavior: $gmsaCleanupContract")
    }
}

$esc11CommonSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\adcs\ESC11-RpcEnrollment\Esc11RpcEnrollment.Common.psm1') -Raw
foreach ($esc11CommonContract in @(
    'ESC11-RpcEnrollment',
    'CA\InterfaceFlags',
    'IF_ENFORCEENCRYPTICERTREQUEST',
    'IF_NORPCICERTREQUEST',
    '0x00000200',
    '0x00000008',
    'PacketPrivacyEnforced',
    'RelayPrerequisitesPresent',
    'InterfaceFlagsPropertyExistsBefore',
    'Restart-Esc11CertSvc',
    'Restore-Esc11InterfaceFlags'
)) {
    if ($esc11CommonSource -notmatch [regex]::Escape($esc11CommonContract)) {
        $failures.Add("ESC11 RPC enrollment common module is missing required behavior: $esc11CommonContract")
    }
}

$esc11SetupSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\adcs\ESC11-RpcEnrollment\setup.ps1') -Raw
foreach ($esc11SetupContract in @(
    "ValidateSet('Hardened', 'Vulnerable')",
    "Stage = 'Hardened'",
    'DisableNameChecking',
    'Set-Esc11PacketPrivacyRequirement',
    'IF_ENFORCEENCRYPTICERTREQUEST',
    'Restart-Esc11CertSvc',
    'RelayPrerequisitesPresent'
)) {
    if ($esc11SetupSource -notmatch [regex]::Escape($esc11SetupContract)) {
        $failures.Add("ESC11 RPC enrollment setup is missing required behavior: $esc11SetupContract")
    }
}

$esc11ValidateSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\adcs\ESC11-RpcEnrollment\validate.ps1') -Raw
foreach ($esc11ValidateContract in @(
    'ExpectedState',
    'DisableNameChecking',
    'RPC packet privacy required',
    'ESC11 relay preconditions',
    'no NTLM relay or certificate request is executed',
    'Export-LabValidationResults',
    'FailOnValidationError'
)) {
    if ($esc11ValidateSource -notmatch [regex]::Escape($esc11ValidateContract)) {
        $failures.Add("ESC11 RPC enrollment validation is missing required behavior: $esc11ValidateContract")
    }
}

$esc11CleanupSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\adcs\ESC11-RpcEnrollment\cleanup.ps1') -Raw
foreach ($esc11CleanupContract in @(
    'DisableNameChecking',
    'Read-Esc11ScenarioState',
    'Restore-Esc11InterfaceFlags',
    'Restart-Esc11CertSvc',
    'State file is absent',
    'BaselineRestored'
)) {
    if ($esc11CleanupSource -notmatch [regex]::Escape($esc11CleanupContract)) {
        $failures.Add("ESC11 RPC enrollment cleanup is missing required behavior: $esc11CleanupContract")
    }
}

$esc15ScenarioRoot = Join-Path $root 'scenarios\adcs\ESC15-SchemaV1Template'
$esc15SetupSource = Get-Content -LiteralPath (Join-Path $esc15ScenarioRoot 'setup.ps1') -Raw
$esc15ValidateSource = Get-Content -LiteralPath (Join-Path $esc15ScenarioRoot 'validate.ps1') -Raw
$esc15CleanupSource = Get-Content -LiteralPath (Join-Path $esc15ScenarioRoot 'cleanup.ps1') -Raw
$esc15AuditSource = Get-Content -LiteralPath (Join-Path $esc15ScenarioRoot 'Audit.ps1') -Raw
$esc15ReadmeSource = Get-Content -LiteralPath (Join-Path $esc15ScenarioRoot 'README.md') -Raw
$esc15DetectSource = Get-Content -LiteralPath (Join-Path $esc15ScenarioRoot 'Detect.md') -Raw
$esc15Marker = 'windows-ad-lab:ESC15-SchemaV1Template'

foreach ($esc15SetupContract in @(
    '#Requires -Version 5.1',
    '#Requires -RunAsAdministrator',
    '[CmdletBinding(SupportsShouldProcess = $true)]',
    "TemplateName = 'ESC15LabWeb'",
    "TemplateDisplayName = 'ESC15 Lab Schema V1 Web'",
    "`$script:TemplateMarker = '$esc15Marker'",
    "`$script:ServerAuthenticationOid = '1.3.6.1.5.5.7.3.1'",
    'SchemaNamingContext        = [string]$rootDse.schemaNamingContext',
    'function Get-AdAttributeSchema',
    'function ConvertTo-SortedUniqueStringArray',
    'function ConvertTo-SingleStringOrNull',
    'function Test-OidString',
    'function Ensure-AdDrive',
    '$path = "AD:\$TemplateDistinguishedName"',
    "`$attributes['msPKI-Template-Schema-Version'] = 1",
    "`$attributes['msPKI-Certificate-Name-Flag'] = `$script:EnrolleeSuppliesSubject",
    "`$replace['msPKI-Template-Schema-Version'] = 1",
    "`$clear.Add('msPKI-Certificate-Application-Policy')",
    'Update ESC15 template settings',
    'Domain Users'
)) {
    if ($esc15SetupSource -notmatch [regex]::Escape($esc15SetupContract)) {
        $failures.Add("ESC15 setup is missing required contract: $esc15SetupContract")
    }
}
if ($esc15SetupSource -match [regex]::Escape("`$attributes['msPKI-Certificate-Application-Policy']")) {
    $failures.Add('ESC15 setup must not write msPKI-Certificate-Application-Policy on the schema v1 template.')
}
if ($esc15SetupSource -match [regex]::Escape("`$attributes['msPKI-Template-Schema-Version'] = 2")) {
    $failures.Add('ESC15 setup must keep the learning template at schema version 1.')
}

foreach ($esc15ValidateContract in @(
    "TemplateName = 'ESC15LabWeb'",
    "`$script:TemplateMarker = '$esc15Marker'",
    "`$script:ServerAuthenticationOid = '1.3.6.1.5.5.7.3.1'",
    'Schema version',
    'msPKI-Template-Schema-Version = 1',
    'Application Policy',
    'msPKI-Certificate-Application-Policy empty',
    'Authentication EKU absent',
    'CVE-2024-49019',
    'This fixture is not ESC1',
    'FailOnValidationError'
)) {
    if ($esc15ValidateSource -notmatch [regex]::Escape($esc15ValidateContract)) {
        $failures.Add("ESC15 validation is missing required contract: $esc15ValidateContract")
    }
}

foreach ($esc15CleanupContract in @(
    "TemplateName = 'ESC15LabWeb'",
    "`$script:TemplateMarker = '$esc15Marker'",
    'Refusing to delete it.',
    'Remove-TemplateFromLocalCa',
    'Remove-ADObject'
)) {
    if ($esc15CleanupSource -notmatch [regex]::Escape($esc15CleanupContract)) {
        $failures.Add("ESC15 cleanup is missing required contract: $esc15CleanupContract")
    }
}

foreach ($esc15AuditContract in @(
    "`$script:ScenarioName = 'ESC15-SchemaV1Template'",
    "`$script:TemplateName = 'ESC15LabWeb'",
    $esc15Marker,
    'msPKI-Template-Schema-Version',
    'SchemaVersion',
    'ServerAuthenticationEkuPresent',
    'ApplicationPolicyPresent',
    'CertificateRequestExecutedByScript        = $false',
    'PrivateKeyMaterialRead                    = $false'
)) {
    if ($esc15AuditSource -notmatch [regex]::Escape($esc15AuditContract)) {
        $failures.Add("ESC15 audit is missing required contract: $esc15AuditContract")
    }
}
if ($esc15AuditSource -match '(?m)^\s*(?:New|Set|Remove)-ADObject\b|^\s*Set-Acl\b') {
    $failures.Add('ESC15 Audit.ps1 must remain read-only.')
}

foreach ($esc15ReadmeContract in @(
    'ESC15LabWeb',
    'schema v1',
    'CVE-2024-49019',
    'does not request certificates',
    'Application Policies'
)) {
    if ($esc15ReadmeSource -notmatch [regex]::Escape($esc15ReadmeContract)) {
        $failures.Add("ESC15 README is missing safety or usage contract: $esc15ReadmeContract")
    }
}
if ($esc15DetectSource -notmatch [regex]::Escape('Microsoft-Windows-PowerShell/Operational')) {
    $failures.Add('ESC15 detection guide is missing the default Windows PowerShell log.')
}
if ($esc15DetectSource -match [regex]::Escape('PowerShellCore/Operational')) {
    $failures.Add('ESC15 detection guide must not describe the optional PowerShell 7 log as a default audit source.')
}

foreach ($prohibitedEsc15Action in @(
    '\bcertreq(?:\.exe)?\b',
    '\bGet-Certificate\b',
    '\bNew-SelfSignedCertificate\b',
    '\bExport-PfxCertificate\b'
)) {
    $esc15ScenarioSources = $esc15SetupSource + $esc15ValidateSource + $esc15CleanupSource
    if ($esc15ScenarioSources -match $prohibitedEsc15Action) {
        $failures.Add("ESC15 scenario must not request, issue, generate, or export certificates: $prohibitedEsc15Action")
    }
}

$newEscScenarioSpecs = @(
    [pscustomobject]@{
        Directory = 'ESC2-AnyPurposeTemplate'
        Id = 'esc2'
        Marker = 'windows-ad-lab:ESC2-AnyPurposeTemplate'
        SetupContracts = @(
            "TemplateName = 'ESC2LabAnyPurpose'",
            "`$script:AnyPurposeOid = '2.5.29.37.0'",
            'Update ESC2 template settings',
            'Domain Users'
        )
        ValidateContracts = @(
            'Any Purpose EKU',
            'Client Authentication absent',
            'CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT not set',
            'This fixture is not ESC1 or ESC3.'
        )
        ReadmeContracts = @(
            'ESC2LabAnyPurpose',
            'does not request certificates',
            'This fixture is not ESC1'
        )
    },
    [pscustomobject]@{
        Directory = 'ESC3-EnrollmentAgent'
        Id = 'esc3'
        Marker = 'windows-ad-lab:ESC3-EnrollmentAgent'
        SetupContracts = @(
            "AgentTemplateName = 'ESC3LabAgent'",
            "OnBehalfTemplateName = 'ESC3LabOnBehalf'",
            "`$script:CertificateRequestAgentOid = '1.3.6.1.4.1.311.20.2.1'",
            'windows-ad-lab:ESC3-OnBehalf',
            "`$attributes['msPKI-RA-Signature'] = [int]`$Specification.RaSignature"
        )
        ValidateContracts = @(
            'Enrollment agent EKU',
            'On-behalf RA signature',
            'msPKI-RA-Signature = 1',
            'Certificate Request Agent'
        )
        ReadmeContracts = @(
            'ESC3LabAgent',
            'ESC3LabOnBehalf',
            'does not request certificates',
            'Enrollee-supplied subject is not required'
        )
    },
    [pscustomobject]@{
        Directory = 'ESC4-TemplateAcl'
        Id = 'esc4'
        Marker = 'windows-ad-lab:ESC4-TemplateAcl'
        SetupContracts = @(
            "TemplateName = 'ESC4LabUser'",
            "ControlPrincipal = 'alice.brown'",
            'Grant GenericAll to',
            'EnrolleeSuppliesSubject'
        )
        ValidateContracts = @(
            'GenericAll permission',
            'CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT not set',
            'This fixture is not already ESC1'
        )
        ReadmeContracts = @(
            'ESC4LabUser',
            'alice.brown',
            'does not rewrite the template into ESC1'
        )
    },
    [pscustomobject]@{
        Directory = 'ESC5-PkiObjectAcl'
        Id = 'esc5'
        Marker = 'NTAuthCertificates'
        SetupContracts = @(
            "ControlPrincipal = 'bob.taylor'",
            'NTAuthCertificates',
            'Grant GenericAll to'
        )
        ValidateContracts = @(
            'NTAuthCertificates exists',
            'GenericAll permission',
            'This fixture does not grant Manage CA'
        )
        ReadmeContracts = @(
            'NTAuthCertificates',
            'bob.taylor',
            'does not write a CA certificate into NTAuth'
        )
    },
    [pscustomobject]@{
        Directory = 'ESC7-ManageCA'
        Id = 'esc7'
        Marker = 'ManageCA'
        SetupContracts = @(
            "ControlPrincipal = 'operator01'",
            '$script:CaAccessManageCa = 0x00000001',
            'Grant ManageCA to',
            'EDITF_ATTRIBUTESUBJECTALTNAME2'
        )
        ValidateContracts = @(
            'Registry ManageCA',
            'AD ManageCA',
            'Registry GenericAll absent',
            'This fixture is ESC7, not ESC5.'
        )
        ReadmeContracts = @(
            'operator01',
            'does not enable `EDITF_ATTRIBUTESUBJECTALTNAME2`',
            'Manage CA'
        )
    },
    [pscustomobject]@{
        Directory = 'ESC12-CaKeyStorage'
        Id = 'esc12'
        Marker = 'YubiHSM Key Storage Provider'
        SetupContracts = @(
            'Get-Esc12CaKeyStorageState',
            'Initialize-Esc12ScenarioState',
            'PrivateKeyExported'
        )
        ValidateContracts = @(
            'Software Key Storage Provider',
            'YubiHSM Key Storage Provider absent',
            'Private key not exported'
        )
        ReadmeContracts = @(
            'YubiHSM',
            'does not export the CA private key',
            'Microsoft software Key Storage Provider'
        )
    },
    [pscustomobject]@{
        Directory = 'ESC13-IssuancePolicy'
        Id = 'esc13'
        Marker = 'windows-ad-lab:ESC13-IssuancePolicy'
        SetupContracts = @(
            "TemplateName = 'ESC13LabAma'",
            "GroupName = 'UG_ESC13_AMA'",
            'msDS-OIDToGroupLink',
            "`$script:ClientAuthenticationOid = '1.3.6.1.5.5.7.3.2'"
        )
        ValidateContracts = @(
            'Client Authentication EKU',
            'OID group link',
            'AMA group is empty',
            'This fixture is not ESC1'
        )
        ReadmeContracts = @(
            'ESC13LabAma',
            'UG_ESC13_AMA',
            'does not request certificates',
            'This fixture is not ESC1'
        )
    },
    [pscustomobject]@{
        Directory = 'ESC14-WeakExplicitMapping'
        Id = 'esc14'
        Marker = 'altSecurityIdentities'
        SetupContracts = @(
            "ControlPrincipal = 'alice.brown'",
            "TargetUser = 'operator01'",
            'X509:<RFC822>',
            'Grant WriteProperty(altSecurityIdentities) to'
        )
        ValidateContracts = @(
            'WriteProperty altSecurityIdentities',
            'Weak RFC822 mapping',
            'This fixture is ESC14, not ESC9 or ESC10.'
        )
        ReadmeContracts = @(
            'alice.brown',
            'operator01',
            'does not request certificates',
            'This fixture is not ESC9 or ESC10'
        )
    },
    [pscustomobject]@{
        Directory = 'ESC16-DisableExtensionList'
        Id = 'esc16'
        Marker = 'DisableExtensionList'
        SetupContracts = @(
            "Stage = 'Hardened'",
            'Set-Esc16SidSecurityExtensionDisabled',
            'policy\DisableExtensionList'
        )
        ValidateContracts = @(
            'SID security extension enabled',
            'This scenario is ESC16, not ESC9',
            'szOID_NTDS_CA_SECURITY_EXT'
        )
        ReadmeContracts = @(
            'Stage = Hardened',
            '1.3.6.1.4.1.311.25.2',
            'does not request certificates'
        )
    },
    [pscustomobject]@{
        Directory = 'ESC17-ServerAuthTemplate'
        Id = 'esc17'
        Marker = 'windows-ad-lab:ESC17-ServerAuthTemplate'
        SetupContracts = @(
            "TemplateName = 'ESC17LabServerAuth'",
            "`$script:ServerAuthenticationOid = '1.3.6.1.5.5.7.3.1'",
            'Update ESC17 template settings',
            'Domain Users'
        )
        ValidateContracts = @(
            'Server Authentication EKU',
            'Client Authentication absent',
            'CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT set',
            'This fixture is not ESC1 or ESC3.'
        )
        ReadmeContracts = @(
            'ESC17LabServerAuth',
            'does not request certificates',
            'This fixture is not ESC1'
        )
    }
)

$prohibitedCertificateActions = @(
    '\bcertreq(?:\.exe)?\b',
    '\bGet-Certificate\b',
    '\bNew-SelfSignedCertificate\b',
    '\bExport-PfxCertificate\b'
)

foreach ($escSpec in $newEscScenarioSpecs) {
    $escScenarioRoot = Join-Path $root "scenarios\adcs\$($escSpec.Directory)"
    $escSetupSource = Get-Content -LiteralPath (Join-Path $escScenarioRoot 'setup.ps1') -Raw
    $escValidateSource = Get-Content -LiteralPath (Join-Path $escScenarioRoot 'validate.ps1') -Raw
    $escCleanupSource = Get-Content -LiteralPath (Join-Path $escScenarioRoot 'cleanup.ps1') -Raw
    $escAuditSource = Get-Content -LiteralPath (Join-Path $escScenarioRoot 'Audit.ps1') -Raw
    $escReadmeSource = Get-Content -LiteralPath (Join-Path $escScenarioRoot 'README.md') -Raw
    $escDetectSource = Get-Content -LiteralPath (Join-Path $escScenarioRoot 'Detect.md') -Raw

    foreach ($escSetupContract in @($escSpec.SetupContracts)) {
        if ($escSetupSource -notmatch [regex]::Escape($escSetupContract)) {
            $failures.Add("$($escSpec.Id) setup is missing required contract: $escSetupContract")
        }
    }
    foreach ($escValidateContract in @($escSpec.ValidateContracts)) {
        if ($escValidateSource -notmatch [regex]::Escape($escValidateContract)) {
            $failures.Add("$($escSpec.Id) validation is missing required contract: $escValidateContract")
        }
    }
    if ($escCleanupSource -notmatch [regex]::Escape('Remove-ADObject') -and $escSpec.Id -in @('esc2', 'esc3', 'esc4', 'esc13', 'esc17')) {
        $failures.Add("$($escSpec.Id) cleanup must delete lab-owned template objects.")
    }
    if ($escCleanupSource -notmatch [regex]::Escape('RemoveAccessRuleSpecific') -and $escSpec.Id -in @('esc5', 'esc7', 'esc14')) {
        if ($escSpec.Id -eq 'esc5' -or $escSpec.Id -eq 'esc14' -or $escCleanupSource -notmatch [regex]::Escape('RemoveAccess')) {
            $failures.Add("$($escSpec.Id) cleanup must remove the scenario ACE.")
        }
    }
    if ($escAuditSource -notmatch [regex]::Escape("ScenarioName = '$($escSpec.Directory)'")) {
        $failures.Add("$($escSpec.Id) audit is missing scenario name $($escSpec.Directory).")
    }
    if ($escAuditSource -match '(?m)^\s*(?:New|Set|Remove)-ADObject\b|^\s*Set-Acl\b') {
        $failures.Add("$($escSpec.Id) Audit.ps1 must remain read-only.")
    }
    if ($escAuditSource -notmatch [regex]::Escape('CertificateRequestExecutedByScript')) {
        $failures.Add("$($escSpec.Id) audit must record that certificate requests are not executed by the script.")
    }
    foreach ($escReadmeContract in @($escSpec.ReadmeContracts)) {
        if ($escReadmeSource -notmatch [regex]::Escape($escReadmeContract)) {
            $failures.Add("$($escSpec.Id) README is missing safety or usage contract: $escReadmeContract")
        }
    }
    if ($escDetectSource -notmatch [regex]::Escape('Microsoft-Windows-PowerShell/Operational')) {
        $failures.Add("$($escSpec.Id) detection guide is missing the default Windows PowerShell log.")
    }
    if ($escDetectSource -match [regex]::Escape('PowerShellCore/Operational')) {
        $failures.Add("$($escSpec.Id) detection guide must not describe the optional PowerShell 7 log as a default audit source.")
    }
    $escScenarioSources = $escSetupSource + $escValidateSource + $escCleanupSource
    foreach ($prohibitedCertificateAction in $prohibitedCertificateActions) {
        if ($escScenarioSources -match $prohibitedCertificateAction) {
            $failures.Add("$($escSpec.Id) scenario must not request, issue, generate, or export certificates: $prohibitedCertificateAction")
        }
    }
}

$credentialReplicationToolPattern = ('Invoke-Mimi' + 'katz|secrets' + 'dump|lsa' + 'dump|DCSync::|lsa' + 'dump::dcsync')

$dcsyncSetupSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\acl\DCSync-ReplicationRights\setup.ps1') -Raw
foreach ($dcsyncSetupContract in @(
    'DCSync-ReplicationRights',
    'windows-ad-lab:DCSync-ReplicationRights',
    'DS-Replication-Get-Changes',
    'DS-Replication-Get-Changes-All',
    'DS-Replication-Get-Changes-In-Filtered-Set',
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
    '89e95b76-444d-4c62-991a-0facbeda640c',
    'controlAccessRight',
    'GG_DCSync_Readers',
    'GG_DCSync_Ops',
    'svc_backup',
    'ExtendedRight',
    'CredentialReplicationExecuted    = $false',
    'Refusing to modify it'
)) {
    if ($dcsyncSetupSource -notmatch [regex]::Escape($dcsyncSetupContract)) {
        $failures.Add("DCSync replication rights setup is missing required behavior: $dcsyncSetupContract")
    }
}
if ($dcsyncSetupSource -match $credentialReplicationToolPattern) {
    $failures.Add('DCSync replication rights setup must not invoke credential replication or external offensive tools.')
}

$dcsyncValidateSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\acl\DCSync-ReplicationRights\validate.ps1') -Raw
foreach ($dcsyncValidateContract in @(
    'Reader group is nested into rights group',
    'Delegated user is not a privileged admin',
    '-Name "Rights group has $($right.DisplayName)"',
    'Replicating Directory Changes',
    'Replicating Directory Changes All',
    'Replicating Directory Changes In Filtered Set',
    'Delegated user has no direct domain root DCSync ACE',
    'Control user remains outside DCSync path',
    'Credential replication is not automated',
    'Static ACL validation only',
    'FailOnValidationError'
)) {
    if ($dcsyncValidateSource -notmatch [regex]::Escape($dcsyncValidateContract)) {
        $failures.Add("DCSync replication rights validation is missing required behavior: $dcsyncValidateContract")
    }
}
if ($dcsyncValidateSource -match $credentialReplicationToolPattern) {
    $failures.Add('DCSync replication rights validation must not invoke credential replication or external offensive tools.')
}

$dcsyncCleanupSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\acl\DCSync-ReplicationRights\cleanup.ps1') -Raw
foreach ($dcsyncCleanupContract in @(
    'Remove-DcsyncRightAces',
    'Remove-GroupMemberIfPresent',
    'Remove-ScenarioGroup',
    'Refusing cleanup',
    'BaselineRestored',
    'GG_DCSync_Readers',
    'GG_DCSync_Ops'
)) {
    if ($dcsyncCleanupSource -notmatch [regex]::Escape($dcsyncCleanupContract)) {
        $failures.Add("DCSync replication rights cleanup is missing required behavior: $dcsyncCleanupContract")
    }
}

$adminSdHolderCommonSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\acl\AdminSDHolder\AdminSDHolder.Common.psm1') -Raw
foreach ($adminSdHolderCommonContract in @(
    'AdminSDHolder',
    'windows-ad-lab:AdminSDHolder',
    '00299570-246d-11d0-a768-00aa006e0529',
    'RunProtectAdminGroupsTask',
    'adminCount=1',
    'GG_AdminSD_Resetters',
    'Get-AdminSdHolderScenarioPosture',
    'Remove-AdminSdHolderResetPasswordAces',
    'PasswordResetExecuted            = $false'
)) {
    if ($adminSdHolderCommonSource -notmatch [regex]::Escape($adminSdHolderCommonContract)) {
        $failures.Add("AdminSDHolder common module is missing required behavior: $adminSdHolderCommonContract")
    }
}
if ($adminSdHolderCommonSource -match ($credentialReplicationToolPattern + '|Set-ADAccountPassword')) {
    $failures.Add('AdminSDHolder common module must not reset passwords or invoke external offensive tools.')
}

$adminSdHolderSetupSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\acl\AdminSDHolder\setup.ps1') -Raw
foreach ($adminSdHolderSetupContract in @(
    'Set-AdminSdHolderScenario',
    'RequireDelegateMemberNonPrivileged',
    'TriggerSdProp',
    'GG_AdminSD_Resetters',
    'john.smith',
    'yagami_adm',
    'PasswordResetExecuted'
)) {
    if ($adminSdHolderSetupSource -notmatch [regex]::Escape($adminSdHolderSetupContract)) {
        $failures.Add("AdminSDHolder setup is missing required behavior: $adminSdHolderSetupContract")
    }
}

$adminSdHolderAuditSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\acl\AdminSDHolder\Audit.ps1') -Raw
foreach ($adminSdHolderAuditContract in @(
    "[ValidateSet('All', 'SetupAudit', 'AbuseDetection')]",
    'EvidenceClass',
    'SetupAudit',
    'AbuseDetection',
    'TelemetryGap',
    'CollectionWarning',
    'ConvertTo-AuditEventData',
    'TargetUserName',
    'SubjectUserName',
    'ObjectDN',
    'AttributeLDAPDisplayName',
    'ObjectType',
    'Assessment',
    'AbuseDetected',
    'EvidenceFindingCount',
    'SetupAuditFindingCount',
    'AbuseDetectionFindingCount',
    'TelemetryGapCount',
    'CollectionWarningCount',
    'Directory Service Access'
)) {
    if ($adminSdHolderAuditSource -notmatch [regex]::Escape($adminSdHolderAuditContract)) {
        $failures.Add("AdminSDHolder audit is missing required classification behavior: $adminSdHolderAuditContract")
    }
}

$adminSdHolderValidateSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\acl\AdminSDHolder\validate.ps1') -Raw
foreach ($adminSdHolderValidateContract in @(
    'ExpectPropagatedAce',
    'RequireDelegateMemberNonPrivileged',
    'Delegate member privilege context observed',
    'Protected user has adminCount=1',
    'AdminSDHolder has delegate Reset Password ACE',
    'Protected user has propagated Reset Password ACE',
    'Password reset is not automated',
    'FailOnValidationError'
)) {
    if ($adminSdHolderValidateSource -notmatch [regex]::Escape($adminSdHolderValidateContract)) {
        $failures.Add("AdminSDHolder validation is missing required behavior: $adminSdHolderValidateContract")
    }
}

$adminSdHolderCleanupSource = Get-Content -LiteralPath (Join-Path $root 'scenarios\acl\AdminSDHolder\cleanup.ps1') -Raw
foreach ($adminSdHolderCleanupContract in @(
    'Clear-AdminSdHolderScenario',
    'TriggerSdProp',
    'AdminSDHolderAcesRemoved',
    'ProtectedObjectAcesRemoved',
    'BaselineRestored'
)) {
    if ($adminSdHolderCleanupSource -notmatch [regex]::Escape($adminSdHolderCleanupContract)) {
        $failures.Add("AdminSDHolder cleanup is missing required behavior: $adminSdHolderCleanupContract")
    }
}

$validationScriptSource = Get-Content -LiteralPath (Join-Path $root 'scripts\guest\90-ValidateLab.ps1') -Raw
if ($validationScriptSource -match [regex]::Escape('@($results)')) {
    $failures.Add('Validation must not array-expand Generic List[object] with @($results) on Windows PowerShell 5.1.')
}
if ($validationScriptSource -notmatch [regex]::Escape('$results.ToArray()')) {
    $failures.Add('Validation must convert Generic List[object] with ToArray() for Windows PowerShell 5.1.')
}
foreach ($progressContract in @(
    'function Write-ValidationProgress',
    "Write-ValidationProgress -Target 'DCDiag'",
    '[System.Diagnostics.Stopwatch]::StartNew()'
)) {
    if ($validationScriptSource -notmatch [regex]::Escape($progressContract)) {
        $failures.Add("Validation is missing progress logging contract: $progressContract")
    }
}
foreach ($failedValidationContract in @(
    "Where-Object Status -eq 'Failed'",
    'Write-LabLog -Phase $phase -Action ''FailedChecks''',
    'Write-LabLog -Phase $phase -Action ''FailedCheck''',
    'ConvertTo-ValidationLogValue',
    'validation check(s) failed: $($failedNames -join ''; '')'
)) {
    if ($validationScriptSource -notmatch [regex]::Escape($failedValidationContract)) {
        $failures.Add("Validation is missing failed-check reporting contract: $failedValidationContract")
    }
}
foreach ($httpCdpValidationContract in @(
    'IIS encoded plus handling',
    '/configuration/system.webServer/security/requestFiltering',
    'allowDoubleEscaping=true',
    '[Uri]::EscapeDataString($crlFile[0].Name)'
)) {
    if ($validationScriptSource -notmatch [regex]::Escape($httpCdpValidationContract)) {
        $failures.Add("Validation is missing AD CS HTTP CDP check: $httpCdpValidationContract")
    }
}
foreach ($dnsValidationContract in @(
    'ForestLocatorZone',
    'IsDsIntegrated',
    'DynamicUpdate=Secure'
)) {
    if ($validationScriptSource -notmatch [regex]::Escape($dnsValidationContract)) {
        $failures.Add("Validation is missing AD DNS check: $dnsValidationContract")
    }
}

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ }
    throw "Static validation failed with $($failures.Count) error(s)."
}

[pscustomobject]@{
    Status      = 'Passed'
    FilesParsed = $sourceFiles.Count
    ConfigValid = $true
    OfflineOnly = $true
}
