# AGENT.md

This file is an operating note for agents working in this repository.

## Purpose

- This repository builds the Windows Server 2025 Hyper-V VM `DC01` as an isolated Windows AD lab.
- It is not a template for production AD configuration management, security baselines, or commercial operations.
- The repository intentionally includes lab-only assumptions such as colocating the DC and Enterprise Root CA, shared initial passwords, and weak permissions used for validation scenarios.

## Working Rules

- The public lab is one clone on the Hyper-V host. Setup scripts and `scenarios/` stay in that clone. Do not document `D:\Lab\windows-ad-lab` as the user working directory.
- Contributors who keep Git on WSL can run PowerShell for Windows against the same working tree. The commands are in `CONTRIBUTING.md`.
- Do not add `config/LabSecrets.psd1`, `logs/`, `artifacts/`, or generated `BUILD_*` files to Git.
- If the working tree already has uncommitted changes, do not revert or reformat changes outside the requested scope.

## Main Validation

When changing PowerShell syntax or configuration, run these checks with PowerShell on Windows against the working tree.

```powershell
.\scripts\Test-LabConfig.ps1
.\tests\Invoke-StaticValidation.ps1
```

`Test-LabConfig.ps1` validates schema only. Shipped instance values (`ad.lab.exceeds.test`, the host time zone setting, the current user set) are asserted by `tests/Assert-ShippedLabInstance.ps1`.

To inspect the bootstrap plan without changing the VM, run this from an elevated PowerShell session. Credential prompts and read-only prerequisite checks still run.

```powershell
.\bootstrap\Invoke-LabBootstrap.ps1 -WhatIf
```

`.\scripts\host\Invoke-ValidatedLabSetup.ps1` is the real setup wrapper. It runs static validation, Hyper-V prerequisite checks, the bootstrap `-WhatIf` plan, all phases, checkpoint creation, and final validation.

## Scenario Work

- Each scenario under `scenarios/<category>/` is validated by branching from the completed `06-ADCS-HTTP-CDP` checkpoint.
- When adding a scenario, include `README.md`, `setup.ps1`, `validate.ps1`, `cleanup.ps1`, and `scenario.psd1` by default. Add `Detect.md` and `Audit.ps1` when the scenario needs them.
- Keep English documents as the canonical files. Put Japanese translations in `*.ja.md`.
- Before discarding VM state, run `Restore-LabBaseline.ps1 -WhatIf` and confirm the target checkpoint.

## Safety Notes

- Do not connect this lab VM to an external network.
- Only run operations requiring `-AcknowledgeIsolatedLabRisk` or `-AcknowledgeDataLoss` when the isolated-lab and checkpoint-discard assumptions are understood.
- Do not paste secrets, passwords, tokens, or full execution logs into README files or scenario documentation.
