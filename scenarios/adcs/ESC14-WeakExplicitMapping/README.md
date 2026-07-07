# ESC14 Weak Explicit Mapping

[日本語](README.ja.md)

Teaching fixture for weak explicit certificate mapping. `alice.brown` is granted WriteProperty on `altSecurityIdentities` of `operator01`, and a weak `X509:<RFC822>` mapping for `alice.brown` is written on that account.

This is a design and configuration scenario. It does not request certificates, export PFX files, or authenticate with a certificate.

Run these commands from the repository clone on the Hyper-V host. `Invoke-Scenario.ps1` copies this scenario from that clone to `C:\LabBootstrap\scenarios`.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc14' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc14' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc14' `
    -Action Cleanup
```

ESC14 holds when a low-privilege principal can write `altSecurityIdentities`, or when a privileged account already has a weak explicit mapping such as `X509:<RFC822>` or `X509:<S>`. Strong mappings use `X509:<SKI>`, `X509:<SHA1-PUKEY>`, or issuer plus serial. This fixture is not ESC9 or ESC10: no template SID-extension flag is changed.

Detection notes are in [Detect.md](Detect.md).
