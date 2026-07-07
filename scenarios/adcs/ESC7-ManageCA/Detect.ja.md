# Detect

[English](Detect.md)


この文書は `ESC7-ManageCA` の痕跡を探すための調査メモです。シナリオは ESC6 フラグ変更、要求承認、証明書発行を自動化しません。

## Event log

| Log | Event ID | 見る痕跡 |
|---|---:|---|
| Security | 5136 | CA の `pKIEnrollmentService` の `nTSecurityDescriptor` |
| Security | 4670 | CA AD オブジェクトの権限変更 |
| Security | 4688 | `setup.ps1`、レジストリ書き込み、`Restart-Service CertSvc` |
| Security | 4891, 4892 | Certificate Services の構成変更 |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `operator01`、`ManageCA`、`CA\Security` |

## 現在状態

- `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA>\Security` に `operator01` の Allow ACE（マスク `0x1`）がある
- CA enrollment service オブジェクトにも同じ主体の Manage CA 相当 ACE がある
- `EDITF_ATTRIBUTESUBJECTALTNAME2` はこのシナリオでは有効化しない

## Audit script

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc7' `
    -Action Audit `
    -ScriptParameters @{ StartTime = (Get-Date).AddHours(-6) }
```
