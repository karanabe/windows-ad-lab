# AdminSDHolder

[日本語](README.ja.md)

Observes AdminSDHolder ACL and SDProp propagation onto a protected account. It does not disable SDProp or attack protected groups.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'adminsdholder' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'adminsdholder' `
    -Action Validate

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'adminsdholder' `
    -Action Cleanup
```

Detection notes are in [Detect.md](Detect.md).
