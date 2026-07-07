# Detect

[English](Detect.md)


この文書は `KeyCredentialLink-Observation` の痕跡を、イベントログ、LDAP変更、監査イベント、EDR観点で探すための調査メモです。シナリオは秘密鍵保存や認証を自動化せず、主な痕跡は専用OU、無効ユーザー、`msDS-KeyCredentialLink` 追加です。

## 前提

- Baseline 06 では `Directory Service Changes` と `Process Creation` が有効です。
- 属性単位の 5136 を確実に残すには対象 user / OU への SACL が必要です。
- `Audit.ps1` は `msDS-KeyCredentialLink` の値を出力せず、値の個数だけを返します。

## Event log

| Log | Event ID | 見る痕跡 |
|---|---:|---|
| Security | 4720, 4722, 4725, 4726 | `kcl.sample` / `kcl.control` の作成、無効化、削除 |
| Security | 5136 | `msDS-KeyCredentialLink`、`adminDescription`、`description` の変更 |
| Security | 5137, 5141 | 専用 OU と学習ユーザーの作成/削除 |
| Security | 4662 | 対象 user object への directory access。SACL がある場合に確認 |
| Security | 4688 | `setup.ps1`、`Set-ADObject -Add msDS-KeyCredentialLink` を含む PowerShell 実行 |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `msDS-KeyCredentialLink`、`KeyCredentialLink-Observation`、`kcl.sample` |
| Microsoft-Windows-Sysmon/Operational | 1 | Sysmon がある場合の PowerShell process |

## LDAP changes

現在状態の確認では次を見ます。

- `OU=KeyCredentialLink-Lab,OU=LAB,...`
  - `adminDescription=windows-ad-lab:KeyCredentialLink-Observation`
- `kcl.sample`
  - disabled account
  - `msDS-KeyCredentialLink` の値が1つ
  - scenario marker
- `kcl.control`
  - disabled account
  - `msDS-KeyCredentialLink` の値なし

## Audit events

優先して相関する順序は次です。

1. `5137` で専用 OU と user object が作成される。
2. `4720` / `4725` で学習ユーザーが作成され、無効化される。
3. `5136` で `kcl.sample` の `msDS-KeyCredentialLink` に value added が残る。
4. cleanup では `5141` / `4726` を確認する。

## EDR viewpoint

EDR では、PowerShell による公開鍵生成、LDAP modify、`msDS-KeyCredentialLink` 変更を相関します。通常の悪用では、その後にPKINIT/Key Trust 認証やTGT取得が続きます。このシナリオは認証を行わないため、Kerberos認証の異常イベントが出た場合は手動操作として扱います。

## Audit script

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'KeyCredentialLink-Observation' `
    -Action Audit `
    -ScriptParameters @{ StartTime = (Get-Date).AddHours(-6) }
```
