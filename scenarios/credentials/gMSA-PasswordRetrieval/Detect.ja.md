# Detect

[English](Detect.md)


この文書は `gMSA-PasswordRetrieval` の痕跡を、イベントログ、LDAP変更、監査イベント、EDR観点で探すための調査メモです。シナリオは gMSA password blob の復号や外部 offensive tool の実行を自動化しないため、主な痕跡は gMSA object、retrieval policy、group membership、ACL 変更です。

## 前提

- Baseline 06 の `DefensiveAuditing` により `Directory Service Changes`、`Security Group Management`、`Process Creation` が有効です。
- `msDS-ManagedPassword` の読み取りを 4662 で安定して取るには、`Directory Service Access` と対象属性/オブジェクトの SACL が必要です。
- `Audit.ps1` は `msDS-ManagedPassword` の値を読みません。現在状態では retrieval policy、SPN、group membership、ACL だけを確認します。

## Event log

| Log | Event ID | 見る痕跡 |
|---|---:|---|
| Security | 4727, 4728, 4729, 4730, 4737 | `GG_gMSA_Readers` の作成、`john.smith` の追加、cleanup |
| Security | 4732, 4733 | `Backup Operators` への `gmsa_web$` 追加/削除 |
| Security | 4741, 4743 | gMSA が computer-class account として記録される環境での作成/削除 |
| Security | 5137, 5141 | `msDS-GroupManagedServiceAccount` object と KDS root key の作成/削除 |
| Security | 5136 | `msDS-GroupMSAMembership`、`servicePrincipalName`、`member`、`nTSecurityDescriptor`、`adminDescription` の変更 |
| Security | 4662 | `msDS-ManagedPassword` や `msDS-GroupMSAMembership` への read/control access。SACL がある場合に確認 |
| Security | 4688 | `New-ADServiceAccount`、`Set-ADServiceAccount`、`Add-KdsRootKey`、`Add-ADGroupMember` を含む PowerShell 実行 |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | gMSA / KDS / AD group 操作の script block と module logging |
| Microsoft-Windows-Sysmon/Operational | 1, 13 | Sysmon がある場合の PowerShell process と registry/script activity |

## LDAP changes

現在状態の確認では次を見ます。

- `CN=gmsa_web,OU=Service Accounts,OU=LAB,...`
  - `adminDescription=windows-ad-lab:gMSA-PasswordRetrieval`
  - `servicePrincipalName` に `HTTP/WEB01` と FQDN SPN がある
  - `PrincipalsAllowedToRetrieveManagedPassword` / `msDS-GroupMSAMembership` に `WEB01$` と、誤設定状態では `GG_gMSA_Readers` が含まれる
  - `Backup Operators` membership が残っていないか
- `CN=GG_gMSA_Readers,OU=Groups,OU=LAB,...`
  - `john.smith` membership
  - `operator01` に `member` 属性の `WriteProperty` explicit ACE
- KDS root key
  - `CreateKdsRootKeyIfMissing` を使った場合、`CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,...` に作成痕跡が出る

## Audit events

優先して相関する順序は次です。

1. `5137` / `4741` で `gmsa_web$` が作成される。
2. `5136` で `servicePrincipalName` と `msDS-GroupMSAMembership` が変更される。
3. `4727` / `4728` で `GG_gMSA_Readers` 作成と `john.smith` 追加を確認する。
4. `5136` で `GG_gMSA_Readers` の `nTSecurityDescriptor` に `operator01` の `member` 書き込み ACE が入る。
5. `4732` で `Backup Operators` に `gmsa_web$` が追加されたか確認する。
6. SACL がある場合、`4662` で `msDS-ManagedPassword` read を確認する。

## EDR viewpoint

EDR では `Add-KdsRootKey`、`New-ADServiceAccount`、`Set-ADServiceAccount`、`Add-ADGroupMember`、`Add-ADPrincipalGroupMembership` 相当の PowerShell 操作を見ます。実際の悪用では、DC への LDAP read、`msDS-ManagedPassword` blob の取得、gMSA identity を使った network logon が続くため、非許可 host からの retrieval や `GG_gMSA_Readers` 経由の読み取りを重点的に見ます。

## Audit script

`Audit.ps1` はイベントログを時刻範囲で検索し、現在の gMSA / group / Backup Operators 姿勢も補助的に返します。managed password の値は出力しません。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'gMSA-PasswordRetrieval' `
    -Action Audit `
    -ScriptParameters @{ StartTime = (Get-Date).AddHours(-6) }
```

JSON で保存する場合:

```powershell
.\scenarios\credentials\gMSA-PasswordRetrieval\Audit.ps1 `
    -StartTime (Get-Date).AddHours(-6) |
    ConvertTo-Json -Depth 8
```
