# Detect

[English](Detect.md)


この文書は `ESC1-CertificateTemplate` の痕跡を、イベントログ、LDAP変更、監査イベント、EDR観点で探すための調査メモです。シナリオは証明書要求やPFX保存を自動化せず、主な痕跡は Certificate Template、Enterprise OID、CA公開一覧の変更です。

## 前提

- Baseline 06 では `Directory Service Changes`、`Process Creation`、`Certification Services` 監査が有効です。
- 5136 の属性値や 4662 の詳細を確実に残すには、Configuration NC の Certificate Templates / Enrollment Services / OID container へ SACL が必要です。
- このシナリオは既定テンプレートを変更しません。`ESC1LabUser` だけを見ます。

## Event log

| Log | Event ID | 見る痕跡 |
|---|---:|---|
| Security | 5137, 5141 | `pKICertificateTemplate` と enterprise OID object の作成/削除 |
| Security | 5136 | `msPKI-Certificate-Name-Flag`、`pKIExtendedKeyUsage`、`nTSecurityDescriptor`、CA の `certificateTemplates` 変更 |
| Security | 4662 | template / CA object への directory access。SACL がある場合に確認 |
| Security | 4688 | `setup.ps1`、`New-ADObject`、`Set-ADObject`、`Add-CATemplate` を含む PowerShell 実行 |
| Security | 4898, 4899 | Certificate Services が template を読み込む、または template が更新される |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `ESC1LabUser`、`Domain Users`、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` |
| Microsoft-Windows-Sysmon/Operational | 1 | Sysmon がある場合の PowerShell / certutil / AD CS 管理 process |

## LDAP changes

現在状態の確認では次を見ます。

- `CN=ESC1LabUser,CN=Certificate Templates,CN=Public Key Services,CN=Services,...`
  - `adminDescription=windows-ad-lab:ESC1-CertificateTemplate`
  - `msPKI-Certificate-Name-Flag` に `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` がある
  - Client Authentication EKU `1.3.6.1.5.5.7.3.2`
  - `Domain Users` の Certificate-Enrollment ACE
- `CN=<CA>,CN=Enrollment Services,CN=Public Key Services,CN=Services,...`
  - `certificateTemplates` に `ESC1LabUser` が含まれる
- Enterprise OID object
  - scenario marker と `msPKI-Cert-Template-OID`

## Audit events

優先して相関する順序は次です。

1. `5137` で enterprise OID object と `ESC1LabUser` template が作成される。
2. `5136` で template の `nTSecurityDescriptor`、EKU、Subject Name flag が変更される。
3. `5136` で CA enrollment service object の `certificateTemplates` に `ESC1LabUser` が追加される。
4. 実際の証明書要求を手動で行った場合は `4886` / `4887` を確認する。

## EDR viewpoint

EDR では、AD CS 管理 module のロード、Configuration NC へのLDAP modify、`Add-CATemplate`、`certutil` 実行、証明書要求 process を相関します。ESC1 は template 設計の問題なので、証明書発行イベントだけでなく、template 作成と公開の時点を重点的に見ます。

## Audit script

`Audit.ps1` はイベントログを時刻範囲で検索し、現在の template / CA publish posture も補助的に返します。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ESC1-CertificateTemplate' `
    -Action Audit `
    -ScriptParameters @{ StartTime = (Get-Date).AddHours(-6) }
```
