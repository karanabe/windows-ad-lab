<br />
<h1 align="center">Windows Active Directory Lab</h1>
<h3 align="center">
From zero to a reusable Active Directory lab in about 20 minutes — build scenarios, break things, and reset with confidence.
</h3>
<br />
<br />

[日本語](README.ja.md)

Build an isolated Windows Server 2025 Active Directory lab on a Hyper-V VM named `DC01`. The Hyper-V host uses PowerShell Direct to configure the guest. This is a fixed lab for learning and validation, not a production AD or PKI template.

The shipped forest is `ad.lab.exceeds.test` (NetBIOS `LAB`) with the `exceeds.test` UPN suffix. The DC uses `10.10.6.10/28` on the private `AD-Internal` switch, with no default gateway. The build adds users and groups, auditing, an Enterprise Root CA, and HTTP CDP/AIA. Scenarios start from checkpoint `06-ADCS-HTTP-CDP`.

## Requirements

- A Windows 11 Pro, Enterprise, or Education host, or Windows Server with Hyper-V; administrator PowerShell 7.2+ or Windows PowerShell 5.1.
- A Windows Server 2025 Standard Evaluation (Desktop Experience) ISO obtained from Microsoft.
- Capacity for a Generation 2 VM with 4 vCPU, 8 GiB memory, and an 80 GiB VHDX.
- An existing switch with connectivity for installation and Windows Update. The lab script creates the private `AD-Internal` switch.

## Build the lab

A clone on a local drive of the Hyper-V host is recommended. When using a WSL clone through `\\wsl.localhost`, a failed direct guest transfer is retried through a temporary local host copy. Run commands in an elevated PowerShell session:

```powershell
git clone https://github.com/karanabe/windows-ad-lab.git
Set-Location .\windows-ad-lab
Set-ExecutionPolicy -Scope Process Bypass

.\scripts\host\New-LabVm.ps1 `
    -IsoPath '<path-to-Windows-Server-2025-evaluation.iso>' `
    -ExternalSwitchName '<existing-switch-for-Windows-Update>'
```

In the VM console, install Windows Server, set and save the local Administrator password, complete activation or evaluation checks and Windows Update, restart as needed, and sign in once as Administrator. Then run:

```powershell
.\scripts\host\Set-VMNetwork.ps1
.\scripts\host\New-LabBaseCheckpoint.ps1
.\scripts\host\Invoke-ValidatedLabSetup.ps1
```

The last command asks separately for the **local Administrator password set during installation**, the DSRM password, and the password for new lab users. After forest promotion, `LAB\Administrator` retains the local Administrator password. The wrapper validates the lab and creates checkpoints `02-Baseline` through `06-ADCS-HTTP-CDP`. The shipped configuration uses the host's `(Get-TimeZone).Id` for the guest. Use ignored `config/LabSecrets.psd1` only for unattended runs.

## Update and run scenarios

```powershell
git pull --ff-only
.\scenarios\Restore-LabBaseline.ps1 -WhatIf
.\scenarios\Invoke-Scenario.ps1 -ScenarioName 'esc1' -AcknowledgeIsolatedLabRisk
```

`git pull` updates this host clone. The scenario runner copies the selected scenario into the guest on each run. The bootstrap copies its guest scripts when setup is rerun; pulling code alone does not reconfigure an existing forest. A lab built with an older domain name must be rebuilt from the pre-forest `01-Updated` checkpoint.

See [setup and recovery](docs/setup.md), the [scenario catalog](scenarios/README.md), and the optional [Debian client](docs/debian-client-network.md) and [LDAP](docs/ldap.md) guides. Contributor workflows are in [CONTRIBUTING.md](CONTRIBUTING.md).

Keep `DC01` on the private switch after installation. Checkpoints are not backups. Lab-only settings include a DC and CA on one VM, a common initial password for new lab users, and deliberately weak permissions in scenarios.

## License

This project is licensed under the [MIT License](LICENSE).
