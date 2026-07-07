# Resource-Based Constrained Delegation

[English](README.md)

このシナリオは `06-ADCS-HTTP-CDP` から分岐して、RBCD の AD 側設定を観察する教材です。`FILE01` の `msDS-AllowedToActOnBehalfOfOtherIdentity` に `WEB01$` を許可する security descriptor を設定し、低権限サービスアカウント `svc_web` に `FILE01` computer object 上の同属性だけを書ける explicit ACE を追加します。

Kerberos ticket の取得、S4U2Self/S4U2Proxy の実行、CIFS/LDAP/HTTP へのアクセス検証、外部 offensive tool の実行は自動化しません。DC01 上で RBCD の成立条件、SPN 面、ACL、監査対象を確認するためのシナリオです。

## 使い方

Hyper-V ホスト上のリポジトリ clone をカレントにして実行します。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'RBCD' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'RBCD' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'RBCD' `
    -Action Cleanup
```

既定値は次のとおりです。

| 項目 | 値 |
|---|---|
| Scenario | `RBCD` |
| Resource computer | `FILE01` |
| Delegating computer | `WEB01` |
| Control computer | `CLIENT01` |
| Delegated writer | `svc_web` |
| RBCD attribute | `msDS-AllowedToActOnBehalfOfOtherIdentity` |

## 構成内容

`setup.ps1` は次を行います。

- `msDS-AllowedToActOnBehalfOfOtherIdentity` schema attribute が、想定 GUID `3f78c3e5-f79a-46bd-a0b8-9d18116ddc79` と security descriptor syntax で存在することを確認する
- baseline の `FILE01`、`WEB01`、`CLIENT01`、`svc_web` が存在することを確認する
- `FILE01` の RBCD security descriptor を作成し、`WEB01$` SID を許可する
- `FILE01` computer object の DACL に、`svc_web` へ `msDS-AllowedToActOnBehalfOfOtherIdentity` の `WriteProperty` を許可する explicit ACE を追加する
- domain の `ms-DS-MachineAccountQuota` は読み取り対象として残し、値は変更しない

既に `FILE01` に別の RBCD descriptor がある場合、`setup.ps1` は上書きせず停止します。既存の委任設定を壊さないためです。

## Validation

`validate.ps1` は次を確認します。

- `FILE01`、`WEB01`、`CLIENT01`、`svc_web` が存在する
- `FILE01` の `msDS-AllowedToActOnBehalfOfOtherIdentity` が設定されている
- `WEB01$` SID が RBCD descriptor に含まれる
- `CLIENT01$` SID が RBCD descriptor に含まれない
- `svc_web` が `FILE01` 上で RBCD 属性の explicit `WriteProperty` ACE を持つ
- `PrincipalsAllowedToDelegateToAccount` からも `WEB01` が解決できる
- `FILE01` / `WEB01` の SPN surface と domain の `ms-DS-MachineAccountQuota` を表示する

`-IncludeAcl` を付けると、`svc_web` SID に一致する `FILE01` 上の explicit ACE 要約も出力します。

## Cleanup

`cleanup.ps1` は次だけを削除または消去します。

- `FILE01` の RBCD descriptor が `WEB01$` だけを許可する scenario 値である場合、その属性を clear する
- `FILE01` 上の `svc_web` に対する RBCD 属性 `WriteProperty` ACE を削除する

`FILE01` の RBCD descriptor に `WEB01$` 以外の SID が含まれている場合、cleanup は停止します。別の検証や手作業で追加された RBCD 設定を消さないためです。

## 観察ポイント

RBCD は委任先リソース側が「誰に自分への代理アクセスを許すか」を保持する点が重要です。従来型の constrained delegation と違い、設定の中心は委任元サービスアカウントではなく、アクセスされる computer object の `msDS-AllowedToActOnBehalfOfOtherIdentity` です。

このシナリオでは、RBCD が次の要素の組み合わせで成立することを確認します。

- リソース側 computer object の RBCD security descriptor
- その属性を書ける ACL 委任
- 委任元 computer/service principal と SPN
- S4U2Self / S4U2Proxy のプロトコル遷移
- sensitive account、Protected Users、要求 SPN の違いによる制約

## Baseline との差分

| 種別 | DN / 名前 | Baseline 06 | シナリオ適用後 |
|---|---|---|---|
| Computer attribute | `CN=FILE01,OU=Servers,OU=Computers,OU=LAB,DC=ad,DC=lab,DC=exceeds,DC=jp` / `msDS-AllowedToActOnBehalfOfOtherIdentity` | 未設定 | `WEB01$` SID を許可する RBCD security descriptor |
| Computer ACL | `CN=FILE01,OU=Servers,OU=Computers,OU=LAB,DC=ad,DC=lab,DC=exceeds,DC=jp` | Baseline 06 の DACL | `svc_web` に RBCD 属性 `WriteProperty` の explicit ACE |
| Computer | `WEB01` / `CLIENT01` | Baseline 06 のまま | 属性変更なし。`WEB01` は許可対象、`CLIENT01` は control |
| User | `svc_web` | Baseline 06 のまま | 属性変更なし。`FILE01` 側 ACL にだけ登場 |
| Domain | `ms-DS-MachineAccountQuota` | Baseline 06 のまま | 変更なし |

## 参考資料

- Microsoft Learn: Attribute msDS-AllowedToActOnBehalfOfOtherIdentity
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/cea4ac11-a4b2-4f2d-84cc-aebb4a4ad405
- Microsoft Learn: MS-SFU S4U2proxy
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9f44-e1453be7af5a
- Microsoft Learn: Making the second hop in PowerShell Remoting
  https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ps-remoting-second-hop
