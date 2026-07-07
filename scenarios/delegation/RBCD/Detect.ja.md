# Detect

[English](Detect.md)


この文書は `RBCD` の痕跡を、イベントログ、LDAP変更、監査イベント、EDR観点で探すための調査メモです。シナリオは S4U2Self / S4U2Proxy やチケット取得を自動化せず、主な痕跡は `FILE01` の RBCD 属性と属性書き込み ACE です。

## 前提

- Baseline 06 では `Directory Service Changes`、`Computer Account Management`、`Process Creation` が有効です。
- `msDS-AllowedToActOnBehalfOfOtherIdentity` の属性値やACL変更を確実に残すには、`FILE01` computer object への SACL が必要です。
- Kerberos S4U 実行はこのシナリオでは発生しません。

## Event log

| Log | Event ID | 見る痕跡 |
|---|---:|---|
| Security | 4742 | `FILE01` computer account の属性変更 |
| Security | 5136 | `msDS-AllowedToActOnBehalfOfOtherIdentity`、`nTSecurityDescriptor` の変更 |
| Security | 4662 | computer object への directory access。SACL がある場合に確認 |
| Security | 4769 | S4U/サービスチケット取得を手動で行った場合の Kerberos service ticket |
| Security | 4688 | `setup.ps1`、`Set-ADComputer`、`Set-Acl` を含む PowerShell 実行 |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `msDS-AllowedToActOnBehalfOfOtherIdentity`、`FILE01`、`WEB01`、`svc_web` |
| Microsoft-Windows-Sysmon/Operational | 1, 3 | Sysmon がある場合の process と Kerberos/RPC network activity |

## LDAP changes

現在状態の確認では次を見ます。

- `FILE01`
  - `msDS-AllowedToActOnBehalfOfOtherIdentity` が設定されている
  - descriptor に `WEB01$` SID が含まれる
  - `svc_web` に RBCD 属性 `WriteProperty` explicit ACE
- `WEB01`
  - 許可された delegating computer
- `CLIENT01`
  - control computer として descriptor に含まれないこと

## Audit events

優先して相関する順序は次です。

1. `5136` / `4742` で `FILE01` の RBCD 属性が変更される。
2. `5136` で `FILE01` の `nTSecurityDescriptor` に `svc_web` の属性書き込み ACE が入る。
3. 手動で委任を試した場合は `4769` の service ticket と要求元 host を確認する。

## EDR viewpoint

EDR では、AD attribute modify、`Set-Acl`、Kerberos S4U tool/process、非標準ホストからのLDAP/RPCを相関します。このシナリオは属性姿勢だけを作るため、チケット要求やサービスアクセスが出た場合は手動検証です。

## Audit script

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'RBCD' `
    -Action Audit `
    -ScriptParameters @{ StartTime = (Get-Date).AddHours(-6) }
```
