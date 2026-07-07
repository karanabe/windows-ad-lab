# Windows LAPS delegation

[日本語](README.ja.md)

Compares an OU-scoped Windows LAPS read delegation with a FILE01 computer ACL mistake. See [concepts.md](concepts.md) for what the scenario does and does not prove.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'laps-delegation' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'laps-delegation' `
    -Action Validate

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'laps-delegation' `
    -Action Cleanup
```

Detection notes are in [Detect.md](Detect.md).
