# ESC2 Any Purpose Template

[日本語](README.ja.md)

Teaching fixture for the difference between a purpose-constrained template and an ESC2-capable Any Purpose template. Default templates are not changed. Only `ESC2LabAnyPurpose`, cloned from `User`, is added.

This is a design and configuration scenario. It does not request certificates, export PFX files, or authenticate with a certificate.

Run these commands from the repository clone on the Hyper-V host. `Invoke-Scenario.ps1` copies this scenario from that clone to `C:\LabBootstrap\scenarios`.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc2' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc2' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc2' `
    -Action Cleanup
```

ESC2 holds when a low-privilege principal can enroll, the template EKU is Any Purpose (`2.5.29.37.0`) or empty, manager approval is off, authorized signatures are 0, and an Enterprise CA publishes the template. Enrollee-supplied subject is not required. This fixture is not ESC1: Client Authentication is not present and `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` is not set.

Detection notes are in [Detect.md](Detect.md).
