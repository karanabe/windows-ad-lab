# ESC12 CA key storage

[日本語](README.ja.md)

Observation fixture for CA private-key storage. Published ESC12 is YubiHSM-specific: a file-backed YubiHSM authkey can let a local shell use the CA key. This lab does not install YubiHSM. The scenario records the lab CA CSP/KSP instead.

This is a design and configuration scenario. It does not export the CA private key, forge certificates, or install HSM software.

Run these commands from the repository clone on the Hyper-V host. `Invoke-Scenario.ps1` copies this scenario from that clone to `C:\LabBootstrap\scenarios`.

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc12' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc12' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc12' `
    -Action Cleanup
```

The lab CA uses a Microsoft software Key Storage Provider. Shell access to DC01, which also hosts the CA, therefore includes CA-key use. That is a stronger host-compromise outcome than the YubiHSM authkey case, but it is not the published ESC12 hardware class.

Detection notes are in [Detect.md](Detect.md).
