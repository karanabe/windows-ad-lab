# Detect

[English](Detect.md)


この文書は `AdminSDHolder` の痕跡を、イベントログ、LDAP変更、監査イベント、EDR観点で探すための調査メモです。シナリオは protected account の password reset や権限昇格を自動化しません。主な痕跡は AdminSDHolder ACL 変更、SDProp による protected object への ACE 伝播、delegate group membership です。

## 前提

- Baseline 06 の `DefensiveAuditing` により `Directory Service Changes`、`Security Group Management`、`Process Creation` が有効です。
- AdminSDHolder と protected object の `nTSecurityDescriptor` 変更を 5136 で安定して取るには、対象 object への SACL が必要です。
- 4662 の control access を安定して取るには、`Directory Service Access` 成功監査と対象 object への SACL が必要です。
- `RunProtectAdminGroupsTask` は rootDSE modify で SDProp を手動トリガーします。イベントログ上では PowerShell script block と、その後の protected object ACL 変更を相関します。

## Event log

| Log | Event ID | 見る痕跡 |
|---|---:|---|
| Security | 4727, 4728, 4729, 4730, 4737 | `GG_AdminSD_Resetters` の作成、`john.smith` 追加、cleanup |
| Security | 5137, 5141 | scenario group object の作成/削除 |
| Security | 5136 | `CN=AdminSDHolder,CN=System,...` と protected user の `nTSecurityDescriptor` 変更 |
| Security | 4662, 4670 | AdminSDHolder / protected object への control access / permission change。SACL がある場合に確認 |
| Security | 4688 | `setup.ps1`、`RunProtectAdminGroupsTask`、`Set-Acl` を含む PowerShell 実行 |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `RunProtectAdminGroupsTask`、`00299570-246d-11d0-a768-00aa006e0529`、`GG_AdminSD_Resetters` |
| Microsoft-Windows-Sysmon/Operational | 1 | Sysmon がある場合の PowerShell process と command line |

Reset Password control access right の GUID は `00299570-246d-11d0-a768-00aa006e0529` です。

## LDAP changes

現在状態の確認では次を見ます。

- `CN=GG_AdminSD_Resetters,OU=Groups,OU=LAB,...`
  - `adminDescription=windows-ad-lab:AdminSDHolder`
  - `john.smith` membership
- `CN=AdminSDHolder,CN=System,DC=ad,DC=lab,DC=exceeds,DC=jp`
  - `GG_AdminSD_Resetters` に対する Reset Password explicit ACE
- `CN=Yagami Admin,OU=Admin,OU=LAB,...`
  - `adminCount=1`
  - inheritance disabled
  - SDProp 後に同じ Reset Password explicit ACE
- domain 全体の `adminCount=1` object
  - 同じ delegate group SID の ACE がどの protected object に伝播しているか

## Setup audit

`Audit.ps1 -Mode SetupAudit` は、シナリオ setup / cleanup と現在の構成姿勢を `EvidenceClass=SetupAudit` として返します。これは「ラボで意図的に作った状態が、ログと LDAP / ACL にどう見えるか」を確認するための分類です。

主に次を確認します。

- `4727` / `4728` / `4737` で `GG_AdminSD_Resetters` の作成、変更、`john.smith` の追加を見る。
- `5136` / `5137` / `5141` で scenario group と AdminSDHolder / protected object の変更を見る。
- `4670` で AdminSDHolder や protected object の permission change を見る。これは SACL 設定に依存します。
- `4688` と PowerShell `4103` / `4104` で `setup.ps1`、`Set-Acl`、`RunProtectAdminGroupsTask` を見る。
- 現在状態として、delegate group、membership、AdminSDHolder の Reset Password ACE、protected object への伝播を確認する。

`SetupAudit` は setup の痕跡確認であり、これだけで悪用実行を意味しません。

## Post-abuse review

手動で悪用検証を行った後は、`Audit.ps1 -Mode AbuseDetection` を同じ時刻範囲で実行します。`EvidenceClass=AbuseDetection` は、setup では自動実行しない操作の痕跡だけを優先して見ます。

runner の `Status=Succeeded` は監査 script が正常終了したという意味です。悪用を検知したかどうかは `Assessment`、`AbuseDetected`、`AbuseDetectionFindingCount` を見ます。`FindingCount` には `CollectionWarning` や `TelemetryGap` も含まれるため、これだけで悪用ありとは判断しません。

優先して確認する順序は次です。

1. `4724` で `yagami_adm` など protected account の password reset attempt を確認する。
2. `4662` で Reset Password control access right `00299570-246d-11d0-a768-00aa006e0529` を確認する。出ない場合でも、`Directory Service Access` や SACL が不足していれば未悪用とは断定しない。
3. `4688`、PowerShell `4103` / `4104`、Sysmon `1` で `Set-ADAccountPassword` や protected user 名を含む process / script block を確認する。
4. `5136` / `4670` で新たな ACL 変更が同じ時間帯に増えていないか確認する。AdminSDHolder への変更は、protected user 側だけを見ると原因を見落とします。

LDAP search や `adminCount=1` の探索は、既定の Security log だけでは十分に見えないことがあります。必要に応じて AD DS diagnostic logging、EDR、またはネットワーク側の LDAP / RPC telemetry と相関します。

## Audit events

優先して相関する順序は次です。

1. `4727` / `5137` で `GG_AdminSD_Resetters` が作成される。
2. `4728` / `5136` で `john.smith` が delegate group に追加される。
3. `5136` で AdminSDHolder の `nTSecurityDescriptor` が変更される。
4. `4104` で `RunProtectAdminGroupsTask` が実行される。
5. `5136` で `adminCount=1` protected object の `nTSecurityDescriptor` が変更される。
6. Password reset そのものはこのシナリオでは行わないため、4724 などが出た場合は別操作として扱う。

## EDR viewpoint

EDR では、PowerShell による AdminSDHolder ACL 変更、rootDSE modify、`adminCount=1` object の探索、password reset 試行を見ます。AdminSDHolder は伝播元なので、protected user だけを見ると原因を見落とします。`john.smith` が直接 privileged group に入っていなくても、delegate group 経由で protected account の password reset right を持つ点を相関します。

## Audit script

`Audit.ps1` はイベントログを時刻範囲で検索し、既存の `AdminSDHolder.Common.psm1` で現在の posture も返します。`Mode` により setup 監査と悪用後確認を分けられます。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'AdminSDHolder' `
    -Action Audit `
    -ScriptParameters @{ StartTime = (Get-Date).AddHours(-6) }
```

JSON で保存する場合:

```powershell
.\scenarios\acl\AdminSDHolder\Audit.ps1 `
    -StartTime (Get-Date).AddHours(-6) |
    ConvertTo-Json -Depth 8
```

setup の痕跡だけを見る場合:

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'AdminSDHolder' `
    -Action Audit `
    -ScriptParameters @{
        Mode = 'SetupAudit'
        StartTime = (Get-Date).AddHours(-6)
    }
```

結果の読み方:

- `Assessment=NoAbuseEvidenceFound` または `AbuseDetected=False` / `AbuseDetectionFindingCount=0` は、指定した時刻範囲で悪用痕跡が見つからなかったことを示します。
- `Assessment=NoAbuseEvidenceFoundWithWarnings` は、悪用痕跡は見つからなかったが、一部ログの取得失敗や監査前提の不足があることを示します。
- `CollectionWarning` は Sysmon log が存在しないなどの収集上の警告です。

悪用後の痕跡だけを見る場合:

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'AdminSDHolder' `
    -Action Audit `
    -ScriptParameters @{
        Mode = 'AbuseDetection'
        StartTime = (Get-Date).AddHours(-1)
    }
```
