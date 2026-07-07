# ESC3 Enrollment Agent 設計書

[English](README.md)

このシナリオは、隔離された Windows Server 2025 Active Directory / AD CS ラボで、Enrollment Agent テンプレートと、エージェント署名を要求する認証テンプレートの組み合わせである ESC3 を理解するための教材である。既定テンプレートは変更せず、`ESC3LabAgent` と `ESC3LabOnBehalf` だけを追加する。

この文書は設計説明であり、GUI手順や攻撃手順は扱わない。証明書要求、代理発行、PFX 保存、証明書による認証は自動化しない。

## 使い方

Hyper-V ホスト上のリポジトリ clone をカレントにして実行します。`Invoke-Scenario.ps1` はこの clone から guest の `C:\LabBootstrap\scenarios` へ同期します。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc3' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc3' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc3' `
    -Action Cleanup
```

## ESC3 成立条件

ESC3 は 2 つのテンプレートが同時に揃うと成立する。

1. Enrollment Agent テンプレート
   - Certificate Request Agent EKU `1.3.6.1.4.1.311.20.2.1`
   - 低権限主体が Enroll できる
   - manager approval が不要
   - authorized signatures が 0
   - Enterprise CA が公開している
2. 代理発行先テンプレート
   - Client Authentication などの認証 EKU
   - `msPKI-RA-Signature` が 1
   - `msPKI-RA-Application-Policies` に Certificate Request Agent がある
   - 低権限主体が Enroll できる
   - manager approval が不要
   - Enterprise CA が公開している

要求者指定 Subject は不要である。エージェントが対象アカウントの代わりに要求するためである。

## 学習用テンプレート

| テンプレート | 役割 | 主な設定 |
|---|---|---|
| `ESC3LabAgent` | Enrollment Agent | Certificate Request Agent EKU、`Domain Users` Enroll、RA signature 0 |
| `ESC3LabOnBehalf` | 代理発行先 | Client Authentication、RA signature 1、RA application policy が Certificate Request Agent |

参考資料:

- Microsoft Learn: Certificate templates concepts
  https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts
- BloodHound: ADCSESC3
  https://bloodhound.specterops.io/resources/edges/adcs-esc3

## ESC1 / ESC2 との違い

ESC1 は 1 つのテンプレートで要求者指定 Subject と認証 EKU が揃う問題である。ESC2 は Any Purpose または空の EKU である。ESC3 は Enrollment Agent 証明書を使って、別テンプレートで他アカウント名義の認証証明書を要求できることが中心である。

## Microsoft Best Practice

Enrollment Agent は専用グループへ限定し、manager approval や Enrollment Agent Restrictions を併用する。Client Authentication テンプレートに authorized signature を付ける場合も、署名に使えるエージェントテンプレートの Enroll 範囲を狭くする。
