# ESC13 Issuance Policy

[日本語](README.ja.md)

Teaching fixture for Authentication Mechanism Assurance. The scenario adds empty universal group `UG_ESC13_AMA`, an issuance-policy OID with `msDS-OIDToGroupLink`, and template `ESC13LabAma` with Client Authentication plus that issuance policy. `Domain Users` can enroll. The group gets GenericWrite on `CLIENT01`.

This is a design and configuration scenario. It does not request certificates, export PFX files, or authenticate with a certificate.

Run these commands from the repository clone on the Hyper-V host. `Invoke-Scenario.ps1` copies this scenario from that clone to `C:\LabBootstrap\scenarios`.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc13' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc13' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc13' `
    -Action Cleanup
```

ESC13 holds when a low-privilege principal can enroll a Client Authentication template whose issuance policy OID is linked to an AD group. The KDC can then add that group's SID to the PAC. The linked group must be empty and universal. This fixture is not ESC1: enrollee-supplied subject stays off.

Detection notes are in [Detect.md](Detect.md).
