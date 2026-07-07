# ESC11 RPC enrollment

[日本語](README.ja.md)

Compares AD CS RPC enrollment packet-privacy flags. Default setup is `Stage = Hardened`. It does not run NTLM relay or create a new vulnerable template.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc11' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc11' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }
```

Hardened state requires `IF_ENFORCEENCRYPTICERTREQUEST` and leaves RPC enrollment enabled (`IF_NORPCICERTREQUEST` unset). `ExpectedState = 'Vulnerable'` is a configuration check, not proof of relay success.

Detection notes are in [Detect.md](Detect.md).
