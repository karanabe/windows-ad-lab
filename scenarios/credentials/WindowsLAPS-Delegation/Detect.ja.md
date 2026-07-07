# Detect

[English](Detect.md)


この文書は `WindowsLAPS-Delegation` の痕跡を、イベントログ、LDAP変更、監査イベント、EDR観点で探すための調査メモです。シナリオは端末側LAPS policyや実パスワードローテーションを自動化せず、主な痕跡は LAPS schema/value、委任ACE、Helpdesk group です。

## 前提

- Baseline 06 では `Directory Service Changes`、`Security Group Management`、`Process Creation` が有効です。
- `msLAPS-Password` の読み取りを 4662 で安定して取るには、対象 computer object への SACL が必要です。
- `Audit.ps1` は synthetic LAPS password の値を出力しません。値が存在するかだけを返します。

## Event log

| Log | Event ID | 見る痕跡 |
|---|---:|---|
| Security | 4727, 4728, 4729, 4730, 4737 | `GG_LAPS_Helpdesk` の作成、`john.smith` 追加、cleanup |
| Security | 4742 | `CLIENT01` / `FILE01` / `WEB01` computer account の LAPS 属性変更 |
| Security | 5136 | `msLAPS-Password`、`msLAPS-PasswordExpirationTime`、OU/computer ACL の変更 |
| Security | 4662 | LAPS password read。SACL がある場合に確認 |
| Security | 4688 | `Update-LapsADSchema`、`Set-LapsADReadPasswordPermission`、`Set-ADComputer`、`Set-Acl` |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | LAPS cmdlet と `WindowsLAPS-Delegation` marker |
| Microsoft-Windows-Sysmon/Operational | 1 | Sysmon がある場合の PowerShell process |

## LDAP changes

現在状態の確認では次を見ます。

- `GG_LAPS_Helpdesk`
  - scenario marker
  - `john.smith` membership
- Workstations OU
  - Helpdesk read holder / password read ACE
- `FILE01`
  - synthetic LAPS 値の存在
  - Helpdesk `GenericAll` explicit ACE の有無
- `WEB01`
  - synthetic LAPS 値はあるが Helpdesk `GenericAll` がないこと

## Audit events

優先して相関する順序は次です。

1. `4727` / `4728` で Helpdesk group と membership を確認する。
2. `5136` で OU/computer object の ACL と `msLAPS-*` 属性変更を確認する。
3. SACL がある場合、`4662` で `msLAPS-Password` read を確認する。
4. `UpdateSchemaIfMissing` を使った場合は schema object の作成/変更も確認する。

## EDR viewpoint

EDR では、LAPS module load、schema update、LDAP modify、password read cmdlet、Helpdesk identity のアクセスを相関します。このシナリオは実端末LAPSを動かさないため、端末側のLAPS rotation event が出た場合はシナリオ外の操作です。

## Audit script

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'WindowsLAPS-Delegation' `
    -Action Audit `
    -ScriptParameters @{ StartTime = (Get-Date).AddHours(-6) }
```
