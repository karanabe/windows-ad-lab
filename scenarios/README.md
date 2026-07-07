# Scenario catalog

[日本語](README.ja.md)

Run scenarios from the same Hyper-V host clone that built the lab. Each starts from the `06-ADCS-HTTP-CDP` baseline; there is no required order between scenarios. The runner copies the selected directory to the guest unless `-SkipSync` is specified. If a direct transfer from a UNC clone fails, it retries through a temporary local host copy. The same applies to validation input files. Each scenario's README explains its behavior and limitations; `Detect.md` and `Audit.ps1` are present where needed.

| ID | Scenario |
|---|---|
| `esc1` | [ESC1 certificate template](adcs/ESC1-CertificateTemplate/README.md) |
| `esc2` | [ESC2 Any Purpose template](adcs/ESC2-AnyPurposeTemplate/README.md) |
| `esc3` | [ESC3 enrollment agent](adcs/ESC3-EnrollmentAgent/README.md) |
| `esc4` | [ESC4 template ACL](adcs/ESC4-TemplateAcl/README.md) |
| `esc5` | [ESC5 PKI object ACL](adcs/ESC5-PkiObjectAcl/README.md) |
| `esc7` | [ESC7 Manage CA](adcs/ESC7-ManageCA/README.md) |
| `esc8` | [ESC8 Web Enrollment hardening](adcs/ESC8-Hardening/README.md) |
| `esc11` | [ESC11 RPC enrollment](adcs/ESC11-RpcEnrollment/README.md) |
| `esc12` | [ESC12 CA key storage observation](adcs/ESC12-CaKeyStorage/README.md) |
| `esc13` | [ESC13 issuance policy](adcs/ESC13-IssuancePolicy/README.md) |
| `esc14` | [ESC14 weak explicit mapping](adcs/ESC14-WeakExplicitMapping/README.md) |
| `esc15` | [ESC15 schema v1 template](adcs/ESC15-SchemaV1Template/README.md) |
| `esc16` | [ESC16 SID extension list](adcs/ESC16-DisableExtensionList/README.md) |
| `esc17` | [ESC17 Server Authentication template](adcs/ESC17-ServerAuthTemplate/README.md) |
| `pkinit` | [PKINIT KDC certificate](adcs/PKINIT-KDCCertificate/README.md) |
| `key-credential-link` | [KeyCredentialLink observation](credentials/KeyCredentialLink-Observation/README.md) |
| `laps-delegation` | [Windows LAPS delegation](credentials/WindowsLAPS-Delegation/README.md) |
| `gmsa-password` | [gMSA password retrieval](credentials/gMSA-PasswordRetrieval/README.md) |
| `rbcd` | [Resource-based constrained delegation](delegation/RBCD/README.md) |
| `gpo-abuse` | [GPO ACL path](acl/ADACL-GPOAbuse/README.md) |
| `dcsync` | [Replication rights](acl/DCSync-ReplicationRights/README.md) |
| `adminsdholder` | [AdminSDHolder propagation](acl/AdminSDHolder/README.md) |

Inspect the restore target before discarding VM changes, then run a scenario:

```powershell
.\scenarios\Restore-LabBaseline.ps1 -WhatIf
.\scenarios\Restore-LabBaseline.ps1 -AcknowledgeDataLoss -StartVM
.\scenarios\Invoke-Scenario.ps1 -ScenarioName 'esc1' -AcknowledgeIsolatedLabRisk
.\scenarios\Invoke-Scenario.ps1 -ScenarioName 'esc1' -Action Validate
.\scenarios\Invoke-Scenario.ps1 -ScenarioName 'esc1' -Action Cleanup
```

The runner accepts IDs, unnumbered category-relative paths, and scenario names. Former numbered scenario names are no longer accepted. If a scenario was applied under its former name, restore `06-ADCS-HTTP-CDP` before using the renamed scripts because their guest state paths changed too. Use `-Action Audit` when the scenario provides `Audit.ps1`. `-ScriptParameters` passes a hashtable to the selected guest script. For a single `Validate` action, `-ValidationInputFiles` maps declared path parameters to host files; relative file names resolve under `artifacts/scenario-validation/<scenario path>` and are copied with size and SHA-256 checks.

`Invoke-Scenario.ps1 -WhatIf` shows the intended script and sync path without connecting to the VM. Restoration discards later guest state and logs. Keep the VM isolated while a scenario is applied.
