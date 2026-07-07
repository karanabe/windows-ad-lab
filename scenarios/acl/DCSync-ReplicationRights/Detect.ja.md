# Detect

[English](Detect.md)


この文書は `DCSync-ReplicationRights` の痕跡を、イベントログ、LDAP変更、監査イベント、EDR観点で探すための調査メモです。シナリオは資格情報複製や password hash dump を自動化しません。主な痕跡は domain root ACL への replication extended right 付与と group nesting です。

## 前提

- Baseline 06 の `DefensiveAuditing` により `Directory Service Changes`、`Security Group Management`、`Process Creation` が有効です。
- DCSync 実行そのものを 4662 で安定して取るには、domain root への SACL と `Directory Service Access` が必要です。
- このシナリオは DRS replication request を発生させません。4662 の DCSync 実行痕跡が出た場合はシナリオ外の手動操作または別ツールを疑います。

## Event log

| Log | Event ID | 見る痕跡 |
|---|---:|---|
| Security | 4727, 4728, 4729, 4730, 4737 | `GG_DCSync_Readers` / `GG_DCSync_Ops` の作成、nested membership、cleanup |
| Security | 5137, 5141 | scenario group object の作成/削除 |
| Security | 5136 | domain root の `nTSecurityDescriptor` 変更、group `member` 変更 |
| Security | 4662 | DCSync 実行時の replication control access。SACL がある場合に確認 |
| Security | 4688 | `setup.ps1`、`Set-Acl`、`Add-ADGroupMember`、DCSync 系外部ツールの process |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | DCSync rights GUID、`GG_DCSync_Ops`、`ExtendedRight` を含む script block |
| Microsoft-Windows-Sysmon/Operational | 1, 3 | Sysmon がある場合の DCSync tool process と DRSUAPI/RPC network activity |

DCSync rights の GUID は次です。

| Right | GUID |
|---|---|
| `DS-Replication-Get-Changes` | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` |
| `DS-Replication-Get-Changes-All` | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` |
| `DS-Replication-Get-Changes-In-Filtered-Set` | `89e95b76-444d-4c62-991a-0facbeda640c` |

## LDAP changes

現在状態の確認では次を見ます。

- `CN=GG_DCSync_Readers,OU=Groups,OU=LAB,...`
  - `adminDescription=windows-ad-lab:DCSync-ReplicationRights`
  - `svc_backup` membership
- `CN=GG_DCSync_Ops,OU=Groups,OU=LAB,...`
  - `adminDescription=windows-ad-lab:DCSync-ReplicationRights`
  - `GG_DCSync_Readers` nested membership
- `DC=ad,DC=lab,DC=exceeds,DC=jp`
  - `GG_DCSync_Ops` に対する 3 つの replication `ExtendedRight` explicit ACE
  - `svc_backup` に direct replication ACE がないこと

## Audit events

優先して相関する順序は次です。

1. `4727` / `5137` で scenario group が作成される。
2. `4728` / `5136` で `svc_backup -> GG_DCSync_Readers -> GG_DCSync_Ops` の membership が成立する。
3. `5136` で domain root の `nTSecurityDescriptor` が変更される。
4. SACL がある場合、`4662` で replication GUID を含む control access を確認する。
5. `4688` / EDR process telemetry で DCSync tool の実行がないか確認する。

## EDR viewpoint

EDR では、AD ACL 変更に加えて、非 DC host から DC への DRSUAPI / `IDL_DRSGetNCChanges` 相当の RPC、`lsadump::dcsync`、`secretsdump`、`mimikatz` などの process / command line、LSASS dump ではなく replication protocol を使う credential access を見ます。このシナリオは credential replication を実行しないため、これらの runtime signal は本来出ません。

## Audit script

`Audit.ps1` はイベントログを時刻範囲で検索し、現在の group nesting と domain root replication ACE も補助的に返します。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'DCSync-ReplicationRights' `
    -Action Audit `
    -ScriptParameters @{ StartTime = (Get-Date).AddHours(-6) }
```

JSON で保存する場合:

```powershell
.\scenarios\acl\DCSync-ReplicationRights\Audit.ps1 `
    -StartTime (Get-Date).AddHours(-6) |
    ConvertTo-Json -Depth 8
```
