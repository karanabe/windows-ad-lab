# Detect

[English](Detect.md)


この文書は `ESC14-WeakExplicitMapping` の痕跡を探すための調査メモです。シナリオは証明書要求や PFX 保存を自動化しません。主な痕跡は `operator01` の `altSecurityIdentities` と ACL です。

## Event log

| Log | Event ID | 見る痕跡 |
|---|---:|---|
| Security | 5136 | `operator01` の `altSecurityIdentities`、`nTSecurityDescriptor` |
| Security | 4670 | `operator01` の権限変更 |
| Security | 4688 | `setup.ps1`、`Set-ADUser`、`Set-Acl` を含む PowerShell |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `alice.brown`、`operator01`、`X509:<RFC822>` |

## LDAP changes

- `operator01`
  - `altSecurityIdentities` に `X509:<RFC822>alice.brown@...`
  - `alice.brown` 向けの非継承 WriteProperty ACE（`altSecurityIdentities`）
- テンプレートの `CT_FLAG_NO_SECURITY_EXTENSION` は見ない。それは ESC9 です。

## Audit script

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc14' `
    -Action Audit `
    -ScriptParameters @{ StartTime = (Get-Date).AddHours(-6) }
```
