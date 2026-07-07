# ESC2 Any Purpose Template 設計書

[English](README.md)

このシナリオは、隔離された Windows Server 2025 Active Directory / AD CS ラボで、用途を限定した Certificate Template と ESC2 が成立する Any Purpose テンプレートの差分を理解するための教材である。既定テンプレートは変更せず、`User` テンプレートを基準にした学習用テンプレート `ESC2LabAnyPurpose` だけを追加する。

この文書は設計説明であり、GUI手順や攻撃手順は扱わない。証明書要求、PFX 保存、証明書による認証は自動化しない。

## 使い方

Hyper-V ホスト上のリポジトリ clone をカレントにして実行します。`Invoke-Scenario.ps1` はこの clone から guest の `C:\LabBootstrap\scenarios` へ同期します。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc2' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc2' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc2' `
    -Action Cleanup
```

## ESC2 成立条件

ESC2 は、1つの証明書テンプレートに次の条件が同時に揃うと成立する。

- 低権限ユーザーまたは広いグループが、そのテンプレートに対する Enroll 権限を持つ。
- EKU が Any Purpose `2.5.29.37.0` であるか、EKU が空である。
- CA manager approval が不要である。
- authorized signatures が 0 である。
- Enterprise CA がそのテンプレートを発行対象として公開している。

ESC1 と違い、要求者指定 Subject は不要である。Any Purpose または空の EKU は、発行された証明書を認証用途や Enrollment Agent 用途として扱える余地を残す。この学習用テンプレートは Client Authentication EKU を持たず、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` も設定しない。差分は新規テンプレート、新規OID、学習用テンプレートACL、CA公開一覧への追加に閉じる。

## 各 Template 設定の意味

`pKIExtendedKeyUsage` と `msPKI-Certificate-Application-Policy` は証明書の利用目的を表す。Any Purpose は「この証明書は任意の用途に使える」という意味であり、Client Authentication や Certificate Request Agent をテンプレート側で明示しなくても、用途の制約が残らない。

`nTSecurityDescriptor` 上の Certificate-Enrollment extended right は、誰がそのテンプレートで証明書を要求できるかを決める。広いグループに Enroll を与えると、攻撃可能な利用者の範囲も広がる。

`msPKI-Enrollment-Flag` の `CT_FLAG_PEND_ALL_REQUESTS` が無い場合、ほかの制約がなければ要求は自動処理される。`msPKI-RA-Signature` が 0 であれば登録エージェント署名を要求しない。

CA Publish 状態は、CA の `pKIEnrollmentService` オブジェクトの `certificateTemplates` にテンプレート名が含まれるかで判断できる。

参考資料:

- Microsoft Learn: Certificate templates concepts
  https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts
- BloodHound: ADCSESC2
  https://bloodhound.specterops.io/resources/edges/adcs-esc2

## なぜ既定設定では成立しないのか

Microsoft 既定の `User` テンプレートは Client Authentication、Secure Email、EFS など用途が列挙されている。低権限ユーザーが enrollment できる構成であっても、EKU は Any Purpose ではない。ESC2 は単一設定の問題ではなく、広い Enroll、制約のない EKU、自動発行、CA公開状態が同じテンプレート上で揃うことが条件である。

## Microsoft Best Practice

本番ではテンプレートを用途単位で分離し、EKU は必要最小限にする。Any Purpose や空の EKU は認証テンプレートに使わない。Enroll は専用グループへ限定し、Domain Users や Authenticated Users への広い Enroll と組み合わせない。

## ESC1 / ESC3 との違い

ESC1 は要求者指定 Subject と認証 EKU の組み合わせである。中心属性は `msPKI-Certificate-Name-Flag` の `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` である。

ESC2 は EKU が制約されないことが中心である。この教材は Any Purpose のみを設定し、Client Authentication と enrollee-supplies-subject を入れない。

ESC3 は Certificate Request Agent EKU と、そのエージェント署名を要求する別テンプレートの組み合わせである。ESC2 の Any Purpose 証明書が Enrollment Agent として使える余地はあるが、このシナリオはエージェント用テンプレートを別途作らない。

## Microsoft 既定 Template と学習用 Template の差分

| 項目 | Microsoft既定Template `User` | 学習用Template `ESC2LabAnyPurpose` | ESC2への意味 |
|---|---|---|---|
| EKU | Client Authentication などを列挙 | Any Purpose `2.5.29.37.0` のみ | 用途制約が残らない |
| Subject Name | AD から構成 | 要求者指定 Subject は設定しない | ESC1 条件を混ぜない |
| Enroll ACE | 既定テンプレート自体には新しいACEを追加しない | `Domain Users` に Certificate-Enrollment を明示付与 | 低権限ユーザーが enrollment できる |
| CA発行テンプレート一覧 | 既定の公開状態はそのまま | CA の `certificateTemplates` に `ESC2LabAnyPurpose` を追加 | 学習用テンプレートが発行対象になる |
