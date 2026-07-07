# ESC5 PKI Object ACL

[日本語](README.ja.md)

Teaching fixture for dangerous access control on a PKI object that is not a certificate template. Default templates and CA flags are not changed. The scenario grants GenericAll on `CN=NTAuthCertificates` to `bob.taylor`.

This is a design and configuration scenario. It does not write a CA certificate into NTAuth, create a rogue CA, request certificates, or authenticate.

Run these commands from the repository clone on the Hyper-V host. `Invoke-Scenario.ps1` copies this scenario from that clone to `C:\LabBootstrap\scenarios`.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc5' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc5' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc5' `
    -Action Cleanup
```

ESC5 holds when a low-privilege principal can control PKI objects such as NTAuthCertificates, the CA AD object, or Public Key Services containers. This fixture uses NTAuthCertificates so the condition is distinct from ESC4 (template ACL) and ESC7 (Manage CA).

Detection notes are in [Detect.md](Detect.md).
