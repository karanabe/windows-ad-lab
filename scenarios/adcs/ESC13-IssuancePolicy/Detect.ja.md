# Detect

[English](Detect.md)


この文書は `ESC13-IssuancePolicy` の痕跡を探すための調査メモです。シナリオは証明書要求や PFX 保存を自動化しません。主な痕跡は AMA グループ、issuance policy OID、テンプレート、`CLIENT01` の ACL です。

## Event log

| Log | Event ID | 見る痕跡 |
|---|---:|---|
| Security | 5137, 5141 | グループ、`msPKI-Enterprise-Oid`、`pKICertificateTemplate` の作成/削除 |
| Security | 5136 | `msDS-OIDToGroupLink`、`msPKI-Certificate-Policy`、`nTSecurityDescriptor` |
| Security | 4688 | `setup.ps1`、`New-ADGroup`、`New-ADObject` を含む PowerShell |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `ESC13LabAma`、`UG_ESC13_AMA`、`msDS-OIDToGroupLink` |

## LDAP changes

- `UG_ESC13_AMA` が空の Universal グループ
- issuance policy OID の `msDS-OIDToGroupLink` がそのグループを指す
- `ESC13LabAma` が Client Authentication とその OID を持つ
- `CLIENT01` に `UG_ESC13_AMA` の GenericWrite がある

## Audit script

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc13' `
    -Action Audit `
    -ScriptParameters @{ StartTime = (Get-Date).AddHours(-6) }
```
