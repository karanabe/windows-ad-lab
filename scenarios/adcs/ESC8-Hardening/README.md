# ESC8 hardening

[日本語](README.ja.md)

Compares AD CS Web Enrollment `/CertSrv` conditions. It does not run NTLM relay. Default setup is `Stage = Hardened`. The baseline's `/CertEnroll` endpoint publishes CRLs and CA certificates; it is not the Web Enrollment endpoint under test.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc8' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc8' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }
```

Use `-ScriptParameters @{ Stage = 'Vulnerable' }` only to inspect the unsafe comparison state, and validate with `ExpectedState = 'Vulnerable'`.

Hardened checks include Windows Authentication on, anonymous off, HTTPS binding, Require SSL, EPA `tokenChecking=Require`, and `Negotiate:Kerberos` only.

Detection notes are in [Detect.md](Detect.md).
