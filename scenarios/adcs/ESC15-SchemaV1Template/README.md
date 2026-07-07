# ESC15 Schema V1 Template

[日本語](README.ja.md)

Teaching fixture for the difference between a schema v2+ template and an ESC15-capable schema v1 template. Default templates are not changed. Only `ESC15LabWeb`, cloned from `User`, is added.

This is a design and configuration scenario. It does not request certificates, inject Application Policies, export PFX files, or authenticate with a certificate.

Run these commands from the repository clone on the Hyper-V host. `Invoke-Scenario.ps1` copies this scenario from that clone to `C:\LabBootstrap\scenarios`.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc15' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc15' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc15' `
    -Action Cleanup
```

ESC15 (EKUwu / CVE-2024-49019) holds when a schema v1 template lets a low-privilege principal enroll, the subject is supplied in the request, manager approval is off, authorized signatures are 0, Application Policy is not defined on the template, and an Enterprise CA publishes it. The template EKU itself does not need to be an authentication EKU.

This lab runs Windows Server 2025, which includes the November 2024 CA change. Validation checks the template conditions. It does not prove that a request-specified Application Policy would be issued.

Detection notes are in [Detect.md](Detect.md).
