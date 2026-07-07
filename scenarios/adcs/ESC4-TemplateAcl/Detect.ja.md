# Detect

[English](Detect.md)


この文書は `ESC4-TemplateAcl` の痕跡を探すための調査メモです。シナリオはテンプレート書き換え、証明書要求、PFX 保存を自動化しません。

## 前提

- Baseline 06 では `Directory Service Changes`、`Process Creation`、`Certification Services` 監査が有効です。
- このシナリオは既定テンプレートを変更しません。`ESC4LabUser` だけを見ます。

## Event log

| Log | Event ID | 見る痕跡 |
|---|---:|---|
| Security | 5137, 5141 | `pKICertificateTemplate` と enterprise OID の作成/削除 |
| Security | 5136 | `nTSecurityDescriptor`、CA `certificateTemplates` |
| Security | 4670 | テンプレート ACL 変更 |
| Security | 4662 | template object への directory access |
| Security | 4688 | `setup.ps1`、`New-ADObject`、`Set-Acl`、`Add-CATemplate` |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `ESC4LabUser`、`alice.brown`、`GenericAll` |

## LDAP changes

- `CN=ESC4LabUser` の marker `windows-ad-lab:ESC4-TemplateAcl`
- 非継承の GenericAll ACE が `alice.brown` にある
- `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` が無い（ESC1 ではない）
- CA の `certificateTemplates` に `ESC4LabUser` が含まれる

## Audit script

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc4' `
    -Action Audit `
    -ScriptParameters @{ StartTime = (Get-Date).AddHours(-6) }
```
