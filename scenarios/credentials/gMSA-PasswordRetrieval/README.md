# gMSA password retrieval

[日本語](README.ja.md)

Compares a gMSA password-retrieval policy, a reader group, and an over-grant.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'gmsa-password' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'gmsa-password' `
    -Action Validate

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'gmsa-password' `
    -Action Cleanup
```

Detection notes are in [Detect.md](Detect.md).
