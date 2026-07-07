# Contributing

[日本語](CONTRIBUTING.ja.md)

This repository is an isolated Windows Server 2025 Active Directory lab. Changes should keep the existing bootstrap, checkpoint, and scenario contracts working.

## Working tree

Keep the lab scripts and scenarios in one clone on the Hyper-V host. Edit and validate the same working tree, whether it is on a Windows drive or in WSL.

Do not commit `config/LabSecrets.psd1`, `logs/`, `artifacts/`, or generated `BUILD_*` files.

## Validation

After changing PowerShell or configuration, run these from the repository root in PowerShell on Windows:

```powershell
.\scripts\Test-LabConfig.ps1
.\tests\Invoke-StaticValidation.ps1
```

From the repository root in WSL, run the same files with PowerShell 7.2+ for Windows:

```bash
pwsh.exe -ExecutionPolicy Bypass -File "$(wslpath -w "$PWD/scripts/Test-LabConfig.ps1")"
pwsh.exe -ExecutionPolicy Bypass -File "$(wslpath -w "$PWD/tests/Invoke-StaticValidation.ps1")"
```

Use `powershell.exe -ExecutionPolicy Bypass` in place of `pwsh.exe -ExecutionPolicy Bypass` for Windows PowerShell 5.1. Windows executables launched from WSL use the current Windows user's permissions; run Hyper-V commands from an elevated Windows session.

`Test-LabConfig.ps1` is schema validation only. It accepts any isolated-lab config, including `config/examples/generic-lab.psd1`. The shipped `ad.lab.exceeds.test` values are checked by `tests/Assert-ShippedLabInstance.ps1` through static validation.

Inspect a bootstrap plan without changing the VM:

```powershell
.\bootstrap\Invoke-LabBootstrap.ps1 -WhatIf
```

## Adding a scenario

1. Choose a category under `scenarios/` (`adcs`, `credentials`, `delegation`, or `acl`).
2. Create an unnumbered `ShortName/` directory in that category.
3. Include `README.md`, `setup.ps1`, `validate.ps1`, `cleanup.ps1`, and `scenario.psd1`.
4. Add `Detect.md` and `Audit.ps1` when the scenario needs detection notes or log queries.
5. Keep English as the canonical document. Put Japanese in `README.ja.md` and `Detect.ja.md`.
6. Keep the `Id` stable when renaming or moving a scenario. Any optional `Aliases` must also be unnumbered.
7. Branch from the completed `06-ADCS-HTTP-CDP` checkpoint. Confirm the target with `Restore-LabBaseline.ps1 -WhatIf` before discarding VM state.

`scenario.psd1` shape:

```powershell
@{
    Id                 = 'esc1'
    Title              = 'ESC1 Certificate Template'
    Category           = 'adcs'
    BaselineCheckpoint = '06-ADCS-HTTP-CDP'
}
```

Do not paste secrets, passwords, tokens, or full execution logs into documentation.
