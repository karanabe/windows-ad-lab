# ESC1 Certificate Template

[日本語](README.ja.md)

Teaching fixture for the difference between default Microsoft Certificate Templates and an ESC1-capable template. Default templates are not changed. Only `ESC1LabUser`, cloned from `User`, is added.

This is a design and configuration scenario. It does not walk through GUI enrollment or attack steps.

Run these commands from the repository clone on the Hyper-V host. `Invoke-Scenario.ps1` copies this scenario from that clone to `C:\LabBootstrap\scenarios`.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc1' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc1' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc1' `
    -Action Cleanup
```

A Certificate Template is an AD DS policy object under `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`. Creating it is not enough; the CA must also publish it.

ESC1 holds when a low-privilege principal can enroll, the subject is supplied in the request, an authentication EKU is present, manager approval is off, authorized signatures are 0, and an Enterprise CA publishes the template.

Detection notes are in [Detect.md](Detect.md).
