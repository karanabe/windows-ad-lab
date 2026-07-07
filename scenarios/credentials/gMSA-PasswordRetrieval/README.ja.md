# gMSA Password Retrieval

[English](README.md)

このシナリオは `06-ADCS-HTTP-CDP` から分岐して、gMSA のパスワード取得許可と AD ACL の組み合わせを観察する教材です。`gmsa_web$` を作成し、正規ホスト `WEB01$` にだけ取得を許可する設計と、`GG_gMSA_Readers` を取得許可に入れてしまう誤設定を比較します。

gMSA の実サービス登録、`Install-ADServiceAccount`、サービス起動、`msDS-ManagedPassword` blob の復号、外部 offensive tool の実行は自動化しません。DC01 上で KDS root key、`msDS-GroupMSAMembership`、`PrincipalsAllowedToRetrieveManagedPassword`、SPN、group membership、`member` 属性の WriteProperty 委任を確認するためのシナリオです。

## 使い方

Hyper-V ホスト上のリポジトリ clone をカレントにして実行します。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'gMSA-PasswordRetrieval' `
    -AcknowledgeIsolatedLabRisk

# KDS root key がまだない単一 DC checkpoint でのみ明示的に指定する
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'gMSA-PasswordRetrieval' `
    -AcknowledgeIsolatedLabRisk `
    -ScriptParameters @{ CreateKdsRootKeyIfMissing = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'gMSA-PasswordRetrieval' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

# Reader group を gMSA password retrieval policy から外し、WEB01 だけ許可する状態へ比較
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'gMSA-PasswordRetrieval' `
    -AcknowledgeIsolatedLabRisk `
    -ScriptParameters @{ IncludeReaderGroupMisconfiguration = $false }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'gMSA-PasswordRetrieval' `
    -Action Validate `
    -ScriptParameters @{
        ExpectReaderGroupMisconfiguration = $false
        FailOnValidationError = $true
    }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'gMSA-PasswordRetrieval' `
    -Action Cleanup
```

既定値は次のとおりです。

| 項目 | 値 |
|---|---|
| Scenario | `gMSA-PasswordRetrieval` |
| gMSA | `LAB\gmsa_web$` |
| Authorized computer | `LAB\WEB01$` |
| Control computer | `LAB\FILE01$` |
| Reader group | `LAB\GG_gMSA_Readers` |
| Reader group member | `john.smith` |
| Group member manager | `operator01` |
| Default misconfiguration | Reader group can retrieve the gMSA password |
| Overprivilege | `gmsa_web$` is a member of built-in `Backup Operators` |

## 構成内容

`setup.ps1` は次を行います。

- gMSA schema class と `msDS-GroupMSAMembership` / `msDS-ManagedPassword` / `msDS-ManagedPasswordInterval` schema attributes の存在を確認する
- KDS root key が存在することを確認する
- `-CreateKdsRootKeyIfMissing` が指定された場合だけ、単一 DC ラボ向けに `Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))` を実行する
- `OU=Groups,OU=LAB,...` に marker 付きの `GG_gMSA_Readers` を作成し、`john.smith` を追加する
- `operator01` に `GG_gMSA_Readers` の `member` 属性 `WriteProperty` ACE を追加する
- `OU=Service Accounts,OU=LAB,...` に marker 付きの `gmsa_web$` を作成する
- `gmsa_web$` の SPN に `HTTP/WEB01` と `HTTP/WEB01.ad.lab.exceeds.test` を設定する
- `PrincipalsAllowedToRetrieveManagedPassword` を使い、`WEB01$` と、既定では `GG_gMSA_Readers` に password retrieval を許可する
- 既定では `gmsa_web$` を built-in `Backup Operators` に追加し、取得できる資格情報の権限が過剰な状態を作る

既に対象 gMSA や reader group が存在し、scenario marker が一致しない場合、`setup.ps1` は上書きせず停止します。

KDS root key は forest-wide な前提条件です。既存 key があればそれを利用します。key がない場合に `CreateKdsRootKeyIfMissing` を指定すると、この単一 DC ラボ用に過去時刻で key を作成して 10 時間待機を回避します。cleanup は KDS root key を削除しません。Baseline 06 と完全に同じ KDS 状態へ戻す必要がある場合は checkpoint から復元してください。

## Validation

`validate.ps1` は次を確認します。

- KDS root key が存在する
- gMSA schema class と関連 attributes が存在する
- `gmsa_web$` が scenario marker を持ち、Service Accounts OU にある
- `gmsa_web$` の SPN と managed password interval が想定どおりである
- `WEB01$` が gMSA password retrieval policy に含まれる
- `FILE01$` が gMSA password retrieval policy に含まれない
- `GG_gMSA_Readers` が既定では retrieval policy に含まれる、修正後は含まれない
- `GG_gMSA_Readers` が scenario marker を持ち、`john.smith` を含む
- `operator01` が `GG_gMSA_Readers` の `member` 属性を書ける explicit ACE を持つ
- `gmsa_web$` が built-in `Backup Operators` に含まれる、または修正後は含まれない

`-IncludeAcl` を付けると、`operator01` SID に一致する `GG_gMSA_Readers` 上の ACE 要約も表示します。`msDS-ManagedPassword` の値は validate 出力に出しません。

## Cleanup

`cleanup.ps1` は、次だけを削除または消去します。

- `gmsa_web$` の built-in `Backup Operators` membership
- marker 付きの `gmsa_web$`
- `GG_gMSA_Readers` 上の `operator01` に対する scenario の `member` 属性 `WriteProperty` ACE
- marker 付きの `GG_gMSA_Readers`

KDS root key は削除しません。Microsoft は KDS root key の削除と再作成では cache による問題が起こり得ると説明しているため、このシナリオでは checkpoint 復元を exact baseline の戻し方にします。

## 観察ポイント

gMSA のパスワードは人が知る前提ではなく、許可されたホストが KDS 経由で取得してサービスに使う前提です。このシナリオでは、危険なのは gMSA そのものではなく、次の組み合わせであることを確認します。

- `PrincipalsAllowedToRetrieveManagedPassword` / `msDS-GroupMSAMembership` に含まれる principal
- その principal、特に group の membership を誰が変更できるか
- gMSA に設定された SPN
- gMSA に付与された domain/local privilege
- `msDS-ManagedPassword` の値を読める経路を監査できるか

## 参考資料

- Microsoft Learn: Create a Key Distribution Service (KDS) root key
  https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key
- Microsoft Learn: New-ADServiceAccount
  https://learn.microsoft.com/powershell/module/activedirectory/new-adserviceaccount
- Microsoft Learn: Set-ADServiceAccount
  https://learn.microsoft.com/powershell/module/activedirectory/set-adserviceaccount
- Microsoft Learn: Class msDS-GroupManagedServiceAccount
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/219549d4-39eb-4771-bb8c-b3593ff6be48
