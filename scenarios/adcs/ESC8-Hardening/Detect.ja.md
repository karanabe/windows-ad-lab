# Detect

[English](Detect.md)


この文書は `ESC8-Hardening` の痕跡を、イベントログ、LDAP変更、監査イベント、EDR観点で探すための調査メモです。シナリオは NTLM relay、強制認証、証明書要求、PFX保存を自動化せず、主な痕跡は AD CS Web Enrollment role、IIS `/CertSrv` 設定、HTTPS binding、state file です。

## 前提

- ESC8 の中心は `/CertSrv` が HTTP、NTLM、EPAなしで利用できるかです。
- このシナリオの setup / cleanup は LDAP object を主対象にしません。IIS / Windows feature / certificate store / service state を見ます。
- IIS設定変更や registry/file access をSecurity logで確実に取るには、対象pathやregistryへのSACLが必要です。

## Event log

| Log | Event ID | 見る痕跡 |
|---|---:|---|
| Security | 4688 | `Install-AdcsWebEnrollment`、`New-WebBinding`、`New-SelfSignedCertificate`、IIS設定変更を含む PowerShell 実行 |
| Security | 4886, 4887 | Web Enrollment で証明書要求を手動実行した場合の要求/発行 |
| System | 7035, 7036, 7040 | `W3SVC` / `CertSvc` の service control |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `Set-Esc8IisSecurityState`、`tokenChecking`、`NTLM`、`Negotiate:Kerberos` |
| Microsoft-Windows-IIS-Configuration/Operational | provider specific | IIS configuration が記録される環境で `/CertSrv` 設定変更 |
| Microsoft-Windows-Sysmon/Operational | 1, 11, 13 | Sysmon がある場合の process、state file、registry/config write |

## LDAP changes

このシナリオの setup / cleanup は LDAP object を主対象にしません。現在状態の確認では次を見ます。

- Web Enrollment feature が入っているか
- `Default Web Site/CertSrv` が存在するか
- Require SSL、EPA `tokenChecking`、Windows Authentication provider
- HTTPS `:443` binding と証明書
- `RelayPrerequisitesPresent` と `Hardened`

## Audit events

優先して相関する順序は次です。

1. `4688` / `4104` で `ESC8-Hardening` の `setup.ps1` が実行される。
2. Windows feature と IIS `/CertSrv` 設定が変更される。
3. Hardened では HTTPS binding と証明書作成、Vulnerable では HTTP allowed / NTLM / EPA None を確認する。
4. 実際にWeb Enrollment要求を手動実行した場合は `4886` / `4887` を確認する。

## EDR viewpoint

EDR では、IIS/AD CS role変更、PowerShell script block、`w3wp.exe` へのHTTP/NTLM access、certificate request の requester、PFX保存の有無を相関します。このシナリオは relay と発行要求を自動化しないため、発行イベントや外部からのHTTPアクセスが出た場合は手動検証です。

## Audit script

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ESC8-Hardening' `
    -Action Audit `
    -ScriptParameters @{ StartTime = (Get-Date).AddHours(-6) }
```
