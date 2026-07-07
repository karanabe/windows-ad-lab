# ESC7 Manage CA 設計書

[English](README.md)

このシナリオは、隔離された Windows Server 2025 Active Directory / AD CS ラボで、Certification Authority の Manage CA 権限が低権限主体へ付与された ESC7 を理解するための教材である。既定テンプレートは変更せず、`operator01` に Manage CA（アクセスマスク `0x1`）だけを付与する。

この文書は設計説明であり、GUI手順や攻撃手順は扱わない。`EDITF_ATTRIBUTESUBJECTALTNAME2`（ESC6）の有効化、保留要求の承認、証明書要求は自動化しない。

## 使い方

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc7' `
    -AcknowledgeIsolatedLabRisk
```

## ESC7 成立条件

ESC7 は CA のセキュリティ記述子上の権限が中心である。

- Manage CA（CA Administrator、アクセスマスク `0x1`）がある場合、CA フラグや発行テンプレート一覧を変更できる。
- Manage Certificates（Certificate Manager、`0x2`）がある場合、保留中の要求を承認できる。

この教材は Manage CA のみを付与する。NTAuthCertificates への GenericAll（ESC5）や Certificate Template の GenericAll（ESC4）とは対象が違う。Manage CA があれば後から ESC6 の CA フラグを有効化できるが、このシナリオはその権限があることだけを確認する。

設定箇所は次の 2 つである。

- レジストリ `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA>\Security`
- AD の `pKIEnrollmentService` オブジェクト ACL（BloodHound 等が読む側）

参考資料:

- BloodHound: ADCSESC7
  https://bloodhound.specterops.io/resources/edges/adcs-esc7

## Microsoft Best Practice

Manage CA と Manage Certificates は専用の PKI 管理者グループへ限定する。部門ユーザーやサービスアカウントへ付けない。CA ACL の変更は Directory Service Changes と Certification Services 監査の両方で追う。
