# Detect

[English](Detect.md)


この文書は `ADACL-GPOAbuse` の痕跡を、イベントログ、LDAP変更、監査イベント、EDR観点で探すための調査メモです。シナリオは endpoint 上の実行を自動化しないため、主な痕跡は DC01 上の AD / GPO / SYSVOL 変更です。

## 前提

- Baseline 06 の `DefensiveAuditing` により `Directory Service Changes`、`Security Group Management`、`Process Creation` が有効です。
- 5136 の属性値や 4662/4663 の詳細を確実に残すには、対象 AD object、AdminSDHolder、domain root、SYSVOL folder などへ SACL が必要です。
- GPO の実適用、端末上のプロセス生成、サービス作成、タスク作成はこのシナリオでは発生しません。

## Event log

| Log | Event ID | 見る痕跡 |
|---|---:|---|
| Security | 4727, 4730, 4737 | `GG_GPO_WS_Admins` の作成、削除、属性変更 |
| Security | 5137, 5141 | scenario group と `groupPolicyContainer` の作成、削除 |
| Security | 5136 | `nTSecurityDescriptor`、`gPLink`、`gPCFileSysPath`、`gPCMachineExtensionNames`、`versionNumber` の変更 |
| Security | 4670, 4663 | SYSVOL の GPO folder / `registry.pol` ACL や file access。SACL がある場合だけ安定して出る |
| Security | 4688 | `powershell.exe` / `pwsh.exe` で `setup.ps1`、`Set-GPRegistryValue`、`New-GPLink` などを実行した痕跡 |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | GroupPolicy / ActiveDirectory cmdlet、`ADACL-GPOAbuse` marker、`GPO-Workstation-Baseline` |
| Microsoft-Windows-Sysmon/Operational | 1, 11, 13 | Sysmon がある場合の PowerShell process、`registry.pol` 作成、registry value 書き込み |

Security log の 5136 は `ObjectDN` と `AttributeLDAPDisplayName` を軸に見ます。特に `OU=Workstations,OU=Computers,OU=LAB,...` の `gPLink` と、`CN={GPO-GUID},CN=Policies,CN=System,...` の `nTSecurityDescriptor` を優先します。

## LDAP changes

現在状態の確認では次を見ます。

- `CN=GG_GPO_WS_Admins,OU=Groups,OU=LAB,...`
  - `adminDescription=windows-ad-lab:ADACL-GPOAbuse`
  - `member` 属性に対する `john.smith` の `WriteProperty` explicit ACE
- `CN={GPO-GUID},CN=Policies,CN=System,DC=ad,DC=lab,DC=exceeds,DC=jp`
  - `displayName=GPO-Workstation-Baseline`
  - `adminDescription=windows-ad-lab:ADACL-GPOAbuse`
  - `GG_GPO_WS_Admins` の `GenericWrite` explicit ACE
- `C:\Windows\SYSVOL\domain\Policies\{GPO-GUID}`
  - `GG_GPO_WS_Admins` の `Modify` explicit ACE
  - `Machine\registry.pol` の存在
- `OU=Workstations,OU=Computers,OU=LAB,...`
  - `gPLink` に `GPO-Workstation-Baseline` の GUID が含まれ、link が disabled ではないこと

## Audit events

優先して相関する順序は次です。

1. `4727` または `5137` で `GG_GPO_WS_Admins` が作成される。
2. `5136` で同 group の `nTSecurityDescriptor` に `john.smith` の ACE が入る。
3. `5137` で `groupPolicyContainer` が作成される。
4. `5136` で GPO container の `nTSecurityDescriptor`、Workstations OU の `gPLink`、GPO の `versionNumber` が変わる。
5. SACL がある場合、`4670` / `4663` で SYSVOL folder と `registry.pol` が変わる。

## EDR viewpoint

EDR では、PowerShell が `ActiveDirectory` / `GroupPolicy` module をロードし、`Set-Acl`、`New-GPO`、`Set-GPRegistryValue`、`New-GPLink`、SYSVOL 書き込みを行った時系列を見ます。端末側の実行は自動化していないため、`CLIENT01` 上のサービス作成、タスク作成、`gpupdate` 起因の実行が出た場合はシナリオ外の手動操作として扱います。

## Audit script

`Audit.ps1` はイベントログを時刻範囲で検索し、現在の LDAP / GPO / SYSVOL 姿勢も補助的に返します。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ADACL-GPOAbuse' `
    -Action Audit `
    -ScriptParameters @{ StartTime = (Get-Date).AddHours(-6) }
```

JSON で保存する場合:

```powershell
.\scenarios\acl\ADACL-GPOAbuse\Audit.ps1 `
    -StartTime (Get-Date).AddHours(-6) |
    ConvertTo-Json -Depth 8
```
