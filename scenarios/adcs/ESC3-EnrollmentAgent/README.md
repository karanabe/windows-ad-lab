# ESC3 Enrollment Agent

[日本語](README.ja.md)

Teaching fixture for the two-template ESC3 condition set. Default templates are not changed. The scenario adds `ESC3LabAgent` (Certificate Request Agent) and `ESC3LabOnBehalf` (Client Authentication that requires an enrollment-agent signature).

This is a design and configuration scenario. It does not request certificates, enroll on behalf of another account, export PFX files, or authenticate with a certificate.

Run these commands from the repository clone on the Hyper-V host. `Invoke-Scenario.ps1` copies this scenario from that clone to `C:\LabBootstrap\scenarios`.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc3' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc3' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc3' `
    -Action Cleanup
```

ESC3 holds when a low-privilege principal can enroll in an enrollment-agent template and in a second published authentication template that requires one Certificate Request Agent signature, with manager approval off. Enrollee-supplied subject is not required.

Detection notes are in [Detect.md](Detect.md).
