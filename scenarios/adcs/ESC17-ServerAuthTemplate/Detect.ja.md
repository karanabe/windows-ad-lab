# Detect

[English](Detect.md)


この文書は `ESC17-ServerAuthTemplate` の痕跡を探すための調査メモです。シナリオは証明書要求や PFX 保存を自動化しません。主な痕跡は Certificate Template、Enterprise OID、CA 公開一覧の変更です。

## Event log

| Log | Event ID | 見る痕跡 |
|---|---:|---|
| Security | 5137, 5141 | `pKICertificateTemplate` と enterprise OID の作成/削除 |
| Security | 5136 | `pKIExtendedKeyUsage`、`msPKI-Certificate-Name-Flag`、CA の `certificateTemplates` |
| Security | 4688 | `setup.ps1`、`New-ADObject`、`Set-ADObject`、`Add-CATemplate` を含む PowerShell |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `ESC17LabServerAuth`、`Domain Users`、`1.3.6.1.5.5.7.3.1` |

## LDAP changes

- `CN=ESC17LabServerAuth,CN=Certificate Templates,...`
  - `adminDescription=windows-ad-lab:ESC17-ServerAuthTemplate`
  - Server Authentication EKU `1.3.6.1.5.5.7.3.1`
  - Client Authentication EKU が無い
  - `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` がある
  - `Domain Users` の Certificate-Enrollment ACE
- CA の `certificateTemplates` に `ESC17LabServerAuth` が含まれる

## Audit script

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc17' `
    -Action Audit `
    -ScriptParameters @{ StartTime = (Get-Date).AddHours(-6) }
```
