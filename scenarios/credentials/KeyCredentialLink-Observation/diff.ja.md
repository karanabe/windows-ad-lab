# Baseline 06 との差分

[English](diff.md)


このファイルは `KeyCredentialLink-Observation` が `06-ADCS-HTTP-CDP` に加える差分だけを定義します。既存ユーザー、既存グループ、証明書 Template、CA 公開設定は変更対象外です。

| 区分 | 対象 | Baseline 06 | setup.ps1 後 | cleanup.ps1 後 |
| --- | --- | --- | --- | --- |
| OU | `OU=KeyCredentialLink-Lab,OU=LAB,DC=ad,DC=lab,DC=exceeds,DC=jp` | 存在しない | 存在する | 存在しない |
| User | `kcl.sample` | 存在しない | `CN=KCL Sample User,...` として存在。無効化済み | 存在しない |
| User | `kcl.control` | 存在しない | `CN=KCL Control User,...` として存在。無効化済み | 存在しない |
| `msDS-KeyCredentialLink` | `kcl.sample` | 対象ユーザーなし | 観察用 DN-Binary 値を 1 つ保持 | 対象ユーザーごと削除 |
| `msDS-KeyCredentialLink` | `kcl.control` | 対象ユーザーなし | 値なし。比較対象 | 対象ユーザーごと削除 |
| ACL / Owner | 追加 OU と追加ユーザー | 対象オブジェクトなし | 実行アカウントと AD 既定継承に基づく ACL / owner を観察 | 対象オブジェクトなし |
| 既存ユーザー | Baseline の全ユーザー | Baseline 06 のまま | 変更なし | Baseline 06 のまま |
| 既存グループ | Baseline の全グループ | Baseline 06 のまま | 変更なし | Baseline 06 のまま |
| Certificate Template | Baseline の Template | Baseline 06 のまま | 変更なし | Baseline 06 のまま |

`validate.ps1` は上記の差分対象だけを出力します。cleanup 後に差分対象が残っていない場合は、Baseline 06 との差分なしとして表示されます。
