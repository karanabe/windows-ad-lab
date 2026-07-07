# DCSync replication rights

[日本語](README.ja.md)

Gives non-Domain-Admin `svc_backup` directory replication rights through a nested group so the path can be observed. It does not run DCSync.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'dcsync' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'dcsync' `
    -Action Validate

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'dcsync' `
    -Action Cleanup
```

Detection notes are in [Detect.md](Detect.md).
