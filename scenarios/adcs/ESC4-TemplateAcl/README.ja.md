# ESC4 Template ACL 設計書

[English](README.md)

このシナリオは、隔離された Windows Server 2025 Active Directory / AD CS ラボで、Certificate Template 自体の ACL が危険である ESC4 を理解するための教材である。既定テンプレートは変更せず、`User` から複製した `ESC4LabUser` だけを追加し、`alice.brown` に GenericAll を付与する。

この文書は設計説明であり、GUI手順や攻撃手順は扱わない。テンプレートを ESC1 へ書き換える処理、証明書要求、PFX 保存は自動化しない。

## 使い方

Hyper-V ホスト上のリポジトリ clone をカレントにして実行します。`Invoke-Scenario.ps1` はこの clone から guest の `C:\LabBootstrap\scenarios` へ同期します。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc4' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc4' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc4' `
    -Action Cleanup
```

## ESC4 成立条件

ESC4 はテンプレートの現在の EKU や Subject Name ではなく、テンプレートを変更できる権限が中心である。

- 低権限主体が Certificate Template に GenericAll、WriteDacl、WriteOwner、または同等の書き込み権限を持つ。
- そのテンプレートが Enterprise CA で公開されている。
- 権限があれば `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` や EKU、Enroll ACE を後から ESC1 / ESC3 条件へ変えられる。

この学習用テンプレートは、意図的に ESC1 にしない。要求者指定 Subject はオフのままである。観察対象は `alice.brown` の GenericAll ACE である。

参考資料:

- BloodHound: ADCSESC4
  https://bloodhound.specterops.io/resources/edges/adcs-esc4
- Microsoft Learn: Manage certificate templates
  https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/manage-certificate-templates

## ESC1 との違い

ESC1 は既に危険な発行条件が揃っている状態である。ESC4 は「まだ揃っていないが、揃える権限がある」状態である。同じテンプレートでも、ACL を直せば ESC4 は消え、発行フラグを変えれば ESC1 になる。

## Microsoft Best Practice

テンプレートの作成、ACL 変更、CA 公開は PKI 管理者へ限定する。Domain Users や部門ユーザーへ GenericAll / WriteDacl を付けない。テンプレート棚卸しでは、発行フラグだけでなく `nTSecurityDescriptor` を見る。
