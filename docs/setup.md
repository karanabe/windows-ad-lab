# Build and recover the lab

[日本語](setup.ja.md)

The [README](../README.md) is the shortest setup path. A clone on a local drive of the Hyper-V host is recommended for host commands. The shipped configuration is fixed at `ad.lab.exceeds.test`, `DC01`, and `10.10.6.10/28`. The scenario runner uses the same clone.

## Before automation

1. Obtain the Windows Server 2025 Standard Evaluation (Desktop Experience) ISO from the [Microsoft Evaluation Center](https://www.microsoft.com/evalcenter). The repository does not download or redistribute Windows.
2. Use an elevated PowerShell 7.2+ or Windows PowerShell 5.1 session. Confirm that Hyper-V is available and choose an existing switch with connectivity for Windows Update.
3. Create the VM from the clone:

```powershell
.\scripts\host\New-LabVm.ps1 `
    -IsoPath '<path-to-evaluation.iso>' `
    -ExternalSwitchName '<existing-switch-for-Windows-Update>'
```

The script creates a Generation 2 `DC01` with 4 vCPU, 8 GiB fixed memory, an 80 GiB expanding VHDX, one NIC, Secure Boot, Standard checkpoints, and automatic checkpoints disabled. It creates the private `AD-Internal` switch if needed, then starts the VM from the ISO. It refuses an existing VM or VHD.

4. In the VM console, install Windows Server, set and save the local Administrator password, finish activation or evaluation checks and Windows Update, restart as needed, and sign in once as Administrator. Finish all online work before moving the NIC.
5. Move the NIC to the private switch and create the pre-forest checkpoint:

```powershell
.\scripts\host\Set-VMNetwork.ps1
.\scripts\host\New-LabBaseCheckpoint.ps1
```

The checkpoint is named `01-Updated`. These scripts require a running VM with one NIC. After creation, the script waits 10 seconds and checks that the checkpoint is visible in Hyper-V. PowerShell Direct subsequently works without a guest IP address, WinRM, or a default gateway.

## Build and verify

Run the full setup from the same clone:

```powershell
.\scripts\host\Invoke-ValidatedLabSetup.ps1
```

With no additional arguments, the interactive run asks separately for the local Administrator password set during Windows installation, the DSRM password, and the password for new AD users. After promotion, `LAB\Administrator` retains the local Administrator password. This run builds through `06-ADCS-HTTP-CDP`. The wrapper validates the configuration and scripts, checks Hyper-V and PowerShell Direct, previews the bootstrap, builds the forest and AD CS, validates the result, and creates checkpoints `02-Baseline` through `06-ADCS-HTTP-CDP`. After creating each checkpoint, it waits 10 seconds and checks for Hyper-V visibility for up to 120 seconds. An existing checkpoint with the expected name is left unchanged. The shipped configuration takes the Hyper-V host's `(Get-TimeZone).Id` at runtime and uses that ID for guest setup and final validation. You can also supply `-LocalCredential`, `-DsrmPassword`, and `-DefaultUserPassword` separately.

Only for unattended runs, follow the comments in [LabSecrets.example.psd1](../config/LabSecrets.example.psd1) to create ignored `config/LabSecrets.psd1`, then use `-SecretsPath .\config\LabSecrets.psd1`.

Check the checkpoints and run a scenario from the completed baseline:

```powershell
Get-VMCheckpoint -VMName 'DC01' | Sort-Object CreationTime | Format-Table Name, CreationTime
.\scenarios\Invoke-Scenario.ps1 -ScenarioName 'esc1' -AcknowledgeIsolatedLabRisk
```

Host logs are under `logs/`. Guest transcripts and validation JSON are under `C:\ProgramData\ADLabBootstrap\Logs`.

## Failure, restore, and updates

If setup fails, check the host log in `logs/`, `FailedPhase` in `logs/*-host-summary-failed.json`, and the guest log for that stage. Fix the cause, wait for DC01 to finish booting if it was just promoted, then rerun `scripts/host/Invoke-ValidatedLabSetup.ps1`. The existing forest and same-named checkpoints are reused.

If a scenario fails or you want to discard its changes, preview and restore `06-ADCS-HTTP-CDP` from an elevated host PowerShell session. This requires that setup completed that checkpoint:

```powershell
.\scenarios\Restore-LabBaseline.ps1 -WhatIf
.\scenarios\Restore-LabBaseline.ps1 -AcknowledgeDataLoss -StartVM
```

To rebuild the forest and CA, restore the pre-forest `01-Updated` checkpoint on the same VM. `Restore-LabBaseline.ps1` does not support this checkpoint, so use elevated host PowerShell:

```powershell
$base = @(Get-VMCheckpoint -VMName 'DC01' -Name '01-Updated')
if ($base.Count -ne 1) { throw "Expected exactly one 01-Updated checkpoint; found $($base.Count)." }
$base[0] | Format-List Name, Id, CreationTime
$base[0] | Restore-VMCheckpoint -WhatIf
$base[0] | Restore-VMCheckpoint -Confirm:$false
if ((Get-VM -Name 'DC01').State -eq 'Off') { Start-VM -Name 'DC01' }
```

Restoring a checkpoint discards later guest changes and logs. Restoring `01-Updated` also removes the forest and CA. Checkpoints are not backups.

For updates, run `git pull --ff-only` in the host clone. Scenarios are copied to the guest on each run; bootstrap scripts are copied when setup is rerun. Git updates do not rename an existing forest. Rebuild a VM with an older domain from `01-Updated`, or use its matching older code.

Keep `DC01` on `AD-Internal` after setup. The lab has no gateway, and its DC/CA colocation, common initial password for new lab users, and scenario permissions are for isolated validation only.
