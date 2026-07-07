# ESC17 Server Authentication Template

[日本語](README.ja.md)

Teaching fixture for the difference between an ESC1 client-auth template and an ESC17-capable Server Authentication template. Default templates are not changed. Only `ESC17LabServerAuth`, cloned from `User`, is added.

This is a design and configuration scenario. It does not request certificates, export PFX files, impersonate WSUS, or authenticate with a certificate. This lab does not run WSUS.

Run these commands from the repository clone on the Hyper-V host. `Invoke-Scenario.ps1` copies this scenario from that clone to `C:\LabBootstrap\scenarios`.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc17' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc17' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc17' `
    -Action Cleanup
```

ESC17 holds when a low-privilege principal can enroll, the template EKU is Server Authentication (`1.3.6.1.5.5.7.3.1`) or Any Purpose, enrollee-supplied subject is on, manager approval is off, authorized signatures are 0, and an Enterprise CA publishes the template. This fixture is not ESC1: Client Authentication is not present.

Detection notes are in [Detect.md](Detect.md).
