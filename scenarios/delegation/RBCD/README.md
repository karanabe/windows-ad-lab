# Resource-based constrained delegation

[日本語](README.ja.md)

Configures `FILE01` RBCD and write delegation for `svc_web` so the attribute and ACL can be observed. It does not request S4U tickets.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'rbcd' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'rbcd' `
    -Action Validate

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'rbcd' `
    -Action Cleanup
```

Detection notes are in [Detect.md](Detect.md).
