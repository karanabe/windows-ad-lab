# Detect

[English](Detect.md)


この文書は `PKINIT-KDCCertificate` の痕跡を、イベントログ、LDAP変更、監査イベント、EDR観点で探すための調査メモです。シナリオはユーザー証明書によるAS-REQ/TGT取得を自動化せず、主な痕跡は KDC certificate template、CA公開、DC01 machine enrollment、KDC restart です。

## 前提

- Baseline 06 では `Directory Service Changes`、`Process Creation`、`Certification Services`、Kerberos監査が有効です。
- template / CA publish の 5136 詳細には Configuration NC への SACL が必要です。
- 証明書秘密鍵は `Cert:\LocalMachine\My` に入り、PFX保存は行いません。

## Event log

| Log | Event ID | 見る痕跡 |
|---|---:|---|
| Security | 5137, 5141 | `LAB-PKINIT-KDCAuthentication` template と OID object の作成/削除 |
| Security | 5136 | template 属性、Enroll ACE、CA の `certificateTemplates` 変更 |
| Security | 4886, 4887 | machine enrollment request と証明書発行 |
| Security | 4768 | 実PKINIT認証を手動で行った場合の Kerberos AS request |
| Security | 4688 | `certreq.exe -enroll -machine`、`certutil.exe -DCInfo Verify`、PowerShell 実行 |
| System | 7035, 7036 | `KDC` service restart |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `LAB-PKINIT-KDCAuthentication`、`KerberosAuthentication` |
| Microsoft-Windows-Sysmon/Operational | 1, 11 | Sysmon がある場合の process と certificate/state file creation |

## LDAP changes

現在状態の確認では次を見ます。

- `CN=LAB-PKINIT-KDCAuthentication,CN=Certificate Templates,...`
  - `adminDescription=windows-ad-lab:PKINIT-KDCCertificate`
  - KDC Authentication EKU `1.3.6.1.5.2.3.5`
  - `Domain Controllers` の Enroll ACE
  - request-supplied subject になっていないこと
- CA enrollment service object
  - `certificateTemplates` に lab template が含まれる
- `C:\ProgramData\ADLabBootstrap\Scenarios\PKINIT-KDCCertificate\state.json`
  - 発行証明書 thumbprint と template OID

## Audit events

優先して相関する順序は次です。

1. `5137` で template / OID object が作成される。
2. `5136` で template ACL と CA publish が更新される。
3. `4688` で `certreq.exe -enroll -machine LAB-PKINIT-KDCAuthentication` が実行される。
4. `4886` / `4887` で証明書要求と発行を確認する。
5. `7035` / `7036` で KDC restart を確認する。

## EDR viewpoint

EDR では、DC上の machine certificate enrollment、LocalMachine certificate store の増加、KDC restart、`certutil -DCInfo Verify` を見ます。ユーザー証明書によるTGT取得は自動化しないため、PKINIT由来の認証イベントはシナリオ外の手動検証です。

## Audit script

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'PKINIT-KDCCertificate' `
    -Action Audit `
    -ScriptParameters @{ StartTime = (Get-Date).AddHours(-6) }
```
