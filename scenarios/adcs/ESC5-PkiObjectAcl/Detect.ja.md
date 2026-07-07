# Detect

[English](Detect.md)


この文書は `ESC5-PkiObjectAcl` の痕跡を探すための調査メモです。シナリオは `cACertificate` の書き込みや rogue CA 作成を自動化しません。

## Event log

| Log | Event ID | 見る痕跡 |
|---|---:|---|
| Security | 5136 | `CN=NTAuthCertificates` の `nTSecurityDescriptor` |
| Security | 4670 | NTAuth オブジェクトの権限変更 |
| Security | 4662 | NTAuthCertificates への directory access |
| Security | 4688 | `setup.ps1` または `Set-Acl` |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `NTAuthCertificates`、`bob.taylor`、`GenericAll` |

## LDAP changes

`CN=NTAuthCertificates,CN=Public Key Services,CN=Services,...` に、`bob.taylor` 向けの非継承 GenericAll ACE があること。CA の Manage CA 権限は ESC7 として別扱いです。

## Audit script

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc5' `
    -Action Audit `
    -ScriptParameters @{ StartTime = (Get-Date).AddHours(-6) }
```
