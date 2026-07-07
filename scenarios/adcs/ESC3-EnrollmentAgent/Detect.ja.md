# Detect

[English](Detect.md)


この文書は `ESC3-EnrollmentAgent` の痕跡を探すための調査メモです。シナリオは証明書要求、代理発行、PFX 保存を自動化しません。

## 前提

- Baseline 06 では `Directory Service Changes`、`Process Creation`、`Certification Services` 監査が有効です。
- このシナリオは既定テンプレートを変更しません。`ESC3LabAgent` と `ESC3LabOnBehalf` だけを見ます。

## Event log

| Log | Event ID | 見る痕跡 |
|---|---:|---|
| Security | 5137, 5141 | 2 つの `pKICertificateTemplate` と enterprise OID の作成/削除 |
| Security | 5136 | `pKIExtendedKeyUsage`、`msPKI-RA-Signature`、`msPKI-RA-Application-Policies`、`certificateTemplates` |
| Security | 4662 | template / CA object への directory access |
| Security | 4688 | `setup.ps1`、`New-ADObject`、`Set-ADObject`、`Add-CATemplate` |
| Security | 4898, 4899 | Certificate Services の template 読み込みまたは更新 |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `ESC3LabAgent`、`ESC3LabOnBehalf`、`1.3.6.1.4.1.311.20.2.1` |

## LDAP changes

- `CN=ESC3LabAgent` の Certificate Request Agent EKU と `windows-ad-lab:ESC3-EnrollmentAgent`
- `CN=ESC3LabOnBehalf` の Client Authentication、`msPKI-RA-Signature=1`、`windows-ad-lab:ESC3-OnBehalf`
- CA の `certificateTemplates` に両方の短名が含まれること

## Audit script

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc3' `
    -Action Audit `
    -ScriptParameters @{ StartTime = (Get-Date).AddHours(-6) }
```
