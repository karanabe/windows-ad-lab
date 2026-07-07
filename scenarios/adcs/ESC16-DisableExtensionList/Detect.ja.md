# Detect

[English](Detect.md)


この文書は `ESC16-DisableExtensionList` の痕跡を探すための調査メモです。シナリオは証明書要求を自動化しません。主な痕跡は CA policy module の `DisableExtensionList` 変更です。

## Event log

| Log | Event ID | 見る痕跡 |
|---|---:|---|
| Security | 4657 | `DisableExtensionList` |
| Security | 4688 | `certutil`、PowerShell |
| Security | 4891, 4892 | Certificate Services の構成変更 |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `1.3.6.1.4.1.311.25.2`、`DisableExtensionList` |
| Microsoft-Windows-Sysmon/Operational | 1, 13 | Sysmon がある場合の process / registry |

## 現在状態

- `HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA>\PolicyModules\<Policy>\DisableExtensionList`
  - Hardened: `1.3.6.1.4.1.311.25.2` が無い
  - Vulnerable: `1.3.6.1.4.1.311.25.2` がある
- テンプレートの `CT_FLAG_NO_SECURITY_EXTENSION` は見ない。それは ESC9 です。

## Audit script

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc16' `
    -Action Audit `
    -ScriptParameters @{ StartTime = (Get-Date).AddHours(-6) }
```
