# ESC7 Manage CA

[日本語](README.ja.md)

Teaching fixture for a low-privilege Manage CA grant on the lab Certification Authority. Default templates are not changed. The scenario grants Manage CA (`0x1`) to `operator01` on the CA security descriptor. It does not enable `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6) and does not grant GenericAll on PKI objects (ESC5).

This is a design and configuration scenario. It does not change CA policy flags, approve pending requests, request certificates, or authenticate.

Run these commands from the repository clone on the Hyper-V host. `Invoke-Scenario.ps1` copies this scenario from that clone to `C:\LabBootstrap\scenarios`.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc7' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc7' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc7' `
    -Action Cleanup
```

ESC7 holds when a principal has Manage CA or Manage Certificates on a Certification Authority. Manage CA can later change CA flags, including enabling SAN on any request. This fixture only grants the right.

Detection notes are in [Detect.md](Detect.md).
