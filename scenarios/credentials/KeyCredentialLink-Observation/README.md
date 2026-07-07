# Key credential link observation

[日本語](README.ja.md)

Adds a user for observing `msDS-KeyCredentialLink` differences. It does not write a real key credential or run Shadow Credentials.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'key-credential-link' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'key-credential-link' `
    -Action Validate

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'key-credential-link' `
    -Action Cleanup
```

See [diff.ja.md](diff.ja.md) for the attribute-level comparison notes and [Detect.md](Detect.md) for audit views.
