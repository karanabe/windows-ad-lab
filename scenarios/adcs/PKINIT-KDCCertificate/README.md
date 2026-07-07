# PKINIT KDC certificate

[日本語](README.ja.md)

Issues a PKINIT-ready KDC certificate to DC01 and validates it with built-in tools. It does not automate AS-REQ/TGT proof or LDAPS.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'pkinit' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'pkinit' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'pkinit' `
    -Action Cleanup
```

The scenario copies a lab template from `KerberosAuthentication`, enrolls a machine certificate into `Cert:\LocalMachine\My`, and restarts KDC. Detection notes are in [Detect.md](Detect.md).
