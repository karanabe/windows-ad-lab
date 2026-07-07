# ESC16 Disable Extension List

[日本語](README.ja.md)

Compares the CA-global SID security extension. Default setup is `Stage = Hardened`. It does not request certificates, change a template `CT_FLAG_NO_SECURITY_EXTENSION` flag (ESC9), or enable `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6).

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc16' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc16' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }
```

Hardened state keeps `szOID_NTDS_CA_SECURITY_EXT` (`1.3.6.1.4.1.311.25.2`) out of `policy\DisableExtensionList`. `ExpectedState = 'Vulnerable'` is a configuration check, not proof that UPN-based mapping would succeed.

Detection notes are in [Detect.md](Detect.md).
