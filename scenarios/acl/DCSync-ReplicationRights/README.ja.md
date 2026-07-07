# DCSync Replication Rights

[English](README.md)

このシナリオは `06-ADCS-HTTP-CDP` から分岐して、DCSync の前提になる directory replication rights を domain root ACL 上で観察する教材です。

`svc_backup` を `GG_DCSync_Readers` に追加し、`GG_DCSync_Readers` を `GG_DCSync_Ops` にネストします。`GG_DCSync_Ops` には domain naming context root で次の extended rights を付与します。

- `DS-Replication-Get-Changes`
- `DS-Replication-Get-Changes-All`
- `DS-Replication-Get-Changes-In-Filtered-Set`

このシナリオは資格情報の複製、password hash dump、外部 offensive tool の実行を自動化しません。`validate.ps1` は ACL と group nesting の静的条件だけを確認します。

実行先の DC01 では `ActiveDirectory` PowerShell module が必要です。

## 使い方

Hyper-V ホスト上のリポジトリ clone をカレントにして実行します。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'DCSync-ReplicationRights' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'DCSync-ReplicationRights' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'DCSync-ReplicationRights' `
    -Action Cleanup
```

既定値は次のとおりです。

| 項目 | 値 |
|---|---|
| Scenario | `DCSync-ReplicationRights` |
| Delegated user | `svc_backup` |
| Control user | `operator01` |
| Reader group | `GG_DCSync_Readers` |
| Rights group | `GG_DCSync_Ops` |
| Rights target | `DC=ad,DC=lab,DC=exceeds,DC=jp` |
| Filtered set right | enabled |

## 構成内容

`setup.ps1` は次を行います。

- baseline の `svc_backup`、`operator01`、`OU=Groups,OU=LAB,...` が存在することを確認する
- scenario group `GG_DCSync_Readers` と `GG_DCSync_Ops` を `OU=Groups` に作成し、`adminDescription` へ scenario marker を設定する
- `svc_backup` を `GG_DCSync_Readers` の member にする
- `GG_DCSync_Readers` を `GG_DCSync_Ops` の member にする
- domain root ACL で `GG_DCSync_Ops` に DCSync に必要な replication extended rights を付与する

同名の group が既に存在し、scenario marker が付いていない場合、`setup.ps1` は停止します。既存の運用資産を教材として再利用しないためです。

## Validation

`validate.ps1` は次を確認します。

- `svc_backup`、`operator01`、`GG_DCSync_Readers`、`GG_DCSync_Ops` が存在する
- scenario groups が scenario marker を持つ
- `svc_backup -> GG_DCSync_Readers -> GG_DCSync_Ops` の nested group path が成立している
- `svc_backup` が Domain Admins、Enterprise Admins、Administrators、Account Operators、Backup Operators、Server Operators に所属していない
- `GG_DCSync_Ops` が domain root に3つの DCSync extended rights を持つ
- `svc_backup` には direct DCSync ACE がない
- `operator01` が direct ACE と scenario group membership のどちらも持たない
- 資格情報複製や password hash dump は自動化していない

`-IncludeAcl` を付けると、`GG_DCSync_Ops` に一致する domain root の explicit ACE 要約も出力します。

## Cleanup

`cleanup.ps1` は scenario marker を確認してから次を削除します。

- domain root ACL 上の `GG_DCSync_Ops` 向け DCSync replication ACE
- `GG_DCSync_Ops` から `GG_DCSync_Readers` の nested membership
- `GG_DCSync_Readers` から `svc_backup` の membership
- scenario groups `GG_DCSync_Readers` と `GG_DCSync_Ops`

同名の group が存在しても scenario marker がない場合、cleanup は停止します。

## 観察ポイント

このシナリオの経路は次の形です。

```text
svc_backup
  -> GG_DCSync_Readers
      -> GG_DCSync_Ops
          -> DS-Replication-Get-Changes
          -> DS-Replication-Get-Changes-All
          -> DS-Replication-Get-Changes-In-Filtered-Set
              -> domain naming context root
```

DCSync の本質は Domain Admins membership ではなく、domain root 上の replication control access rights です。したがって、監視では DCSync 実行だけでなく、これらの extended rights が付与された時点も追う必要があります。

## Baseline との差分

| 種別 | DN / 名前 | Baseline 06 | シナリオ適用後 |
|---|---|---|---|
| Group | `CN=GG_DCSync_Readers,OU=Groups,OU=LAB,DC=ad,DC=lab,DC=exceeds,DC=jp` | なし | scenario marker 付き group |
| Group | `CN=GG_DCSync_Ops,OU=Groups,OU=LAB,DC=ad,DC=lab,DC=exceeds,DC=jp` | なし | scenario marker 付き group |
| Membership | `svc_backup -> GG_DCSync_Readers` | なし | 追加 |
| Membership | `GG_DCSync_Readers -> GG_DCSync_Ops` | なし | 追加 |
| Domain root ACL | `DC=ad,DC=lab,DC=exceeds,DC=jp` | Baseline 06 のまま | `GG_DCSync_Ops` に replication extended rights |

## 参考資料

- Microsoft Learn: Control access rights
  https://learn.microsoft.com/en-us/windows/win32/ad/control-access-rights
- Microsoft Learn: Extended rights
  https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights
