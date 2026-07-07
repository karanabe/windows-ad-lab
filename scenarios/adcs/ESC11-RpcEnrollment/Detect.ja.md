# Detect

[English](Detect.md)


この文書は `ESC11-RpcEnrollment` の痕跡を、イベントログ、LDAP変更、監査イベント、EDR観点で探すための調査メモです。シナリオは NTLM relay、強制認証、証明書要求、PFX 保存を自動化しません。主な痕跡は CA registry の `InterfaceFlags` 変更と `CertSvc` restart です。

## 前提

- ESC11 の中心は `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA>\InterfaceFlags` の `IF_ENFORCEENCRYPTICERTREQUEST` です。
- このシナリオは AD object を変更しません。LDAP ではなく CA local registry と service state を確認します。
- registry 変更を Security log で確実に取るには、対象 registry key への SACL と `Audit Registry` が必要です。
- Certification Services 監査イベントは、実際の certificate request が発生した場合の確認点です。このシナリオ単体では certificate request は出ません。

## Event log

| Log | Event ID | 見る痕跡 |
|---|---:|---|
| Security | 4657, 4663 | `CA\InterfaceFlags` registry value の変更。SACL がある場合に確認 |
| Security | 4688 | `setup.ps1`、`Set-ItemProperty`、`Restart-Service CertSvc` を含む PowerShell 実行 |
| System | 7035, 7036, 7040 | `CertSvc` の停止/起動、start type 変更 |
| Security | 4886-4899 | 実際の enrollment / issuance / denial / CA operation。シナリオ単体では通常出ない |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `Set-Esc11PacketPrivacyRequirement`、`IF_ENFORCEENCRYPTICERTREQUEST`、`InterfaceFlags` |
| Microsoft-Windows-Sysmon/Operational | 1, 13 | Sysmon がある場合の PowerShell process と `InterfaceFlags` registry value set |

## LDAP changes

このシナリオの setup / cleanup は LDAP object を変更しません。LDAP 側では、AD CS enrollment service object や certificate template の変更ではなく、CA host 上の registry posture を見ます。

現在状態の確認では次を見ます。

- Active CA name
- `CA\InterfaceFlags` の整数値と flag 名
- `IF_ENFORCEENCRYPTICERTREQUEST` が有効か
- `IF_NORPCICERTREQUEST` で RPC enrollment が無効化されていないか
- `CertSvc` が動作しているか

## Audit events

優先して相関する順序は次です。

1. `4688` / `4104` で `ESC11-RpcEnrollment` の `setup.ps1` が実行される。
2. SACL がある場合、`4657` で `InterfaceFlags` が変更される。
3. `System` log の `7035` / `7036` で `CertSvc` restart を確認する。
4. 実際の悪用検証を手動で行った場合は、`4886-4899` と RPC / NTLM signal を追加で確認する。

## EDR viewpoint

EDR では、CA host 上の registry set、`CertSvc` restart、PowerShell script block、`certsrv.exe` 周辺の RPC 接続を見ます。ESC11 の悪用調査では、MS-ICPR / RPC enrollment への NTLM 認証、relay 元 host、certificate request 結果、発行 certificate の subject / requester を相関します。このシナリオは relay と certificate request を自動化しないため、発行イベントが出た場合は手動操作か別ツールの痕跡です。

## Audit script

`Audit.ps1` はイベントログを時刻範囲で検索し、既存の `Esc11RpcEnrollment.Common.psm1` で現在の CA posture も返します。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ESC11-RpcEnrollment' `
    -Action Audit `
    -ScriptParameters @{ StartTime = (Get-Date).AddHours(-6) }
```

JSON で保存する場合:

```powershell
.\scenarios\adcs\ESC11-RpcEnrollment\Audit.ps1 `
    -StartTime (Get-Date).AddHours(-6) |
    ConvertTo-Json -Depth 8
```
