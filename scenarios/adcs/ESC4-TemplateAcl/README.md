# ESC4 Template ACL

[日本語](README.ja.md)

Teaching fixture for dangerous access control on a Certificate Template. Default templates are not changed. Only `ESC4LabUser`, cloned from `User`, is added, and `alice.brown` is granted GenericAll on that lab template.

This is a design and configuration scenario. It does not rewrite the template into ESC1, request certificates, export PFX files, or authenticate with a certificate.

Run these commands from the repository clone on the Hyper-V host. `Invoke-Scenario.ps1` copies this scenario from that clone to `C:\LabBootstrap\scenarios`.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc4' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc4' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc4' `
    -Action Cleanup
```

ESC4 holds when a low-privilege principal can modify a published certificate template (GenericAll, WriteDacl, WriteOwner, or equivalent write rights). The learning template itself is not an ESC1 template: enrollee-supplied subject stays off. The ACL is the condition under test.

Detection notes are in [Detect.md](Detect.md).
