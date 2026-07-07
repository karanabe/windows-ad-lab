# AD ACL to GPO abuse

[日本語](README.ja.md)

Builds a composite path from `john.smith` through group membership, GPO ACL, SYSVOL ACL, and OU link. It does not drop a malicious GPO payload.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'gpo-abuse' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'gpo-abuse' `
    -Action Validate

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'gpo-abuse' `
    -Action Cleanup
```

Detection notes are in [Detect.md](Detect.md).
