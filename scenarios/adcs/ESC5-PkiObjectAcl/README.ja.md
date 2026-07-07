# ESC5 PKI Object ACL 設計書

[English](README.md)

このシナリオは、隔離された Windows Server 2025 Active Directory / AD CS ラボで、Certificate Template 以外の PKI オブジェクト ACL が危険である ESC5 を理解するための教材である。既定テンプレートと CA フラグは変更せず、`CN=NTAuthCertificates` へ `bob.taylor` の GenericAll を付与するだけである。

この文書は設計説明であり、GUI手順や攻撃手順は扱わない。NTAuth への CA 証明書追加、rogue CA 作成、証明書要求は自動化しない。

## 使い方

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc5' `
    -AcknowledgeIsolatedLabRisk
```

## ESC5 成立条件

ESC5 は PKI 関連 AD オブジェクトへの危険な制御権限である。対象は次のようなオブジェクトである。

- `CN=NTAuthCertificates`
- CA の AD オブジェクトや Enrollment Services コンテナ
- Certificate Templates コンテナ
- AIA / CDP / OID コンテナ
- CA コンピュータオブジェクト

この教材は NTAuthCertificates に限定する。テンプレート ACL は ESC4、CA の Manage CA 権限は ESC7 として分ける。

NTAuth を書けると、rogue CA 証明書を NT 認証の信頼ストアへ入れられる。このシナリオはその権限があることだけを静的に確認する。

参考資料:

- BloodHound: ADCSESC5
  https://bloodhound.specterops.io/resources/edges/adcs-esc5

## Microsoft Best Practice

Public Key Services 配下は tier-0 として扱い、書き込み権限を PKI 管理者へ限定する。NTAuth、Enrollment Services、Certificate Templates コンテナの ACL を定期的に棚卸しする。
