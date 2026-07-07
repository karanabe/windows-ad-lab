# AD ACL to GPO Abuse Path

[English](README.md)

このシナリオは `06-ADCS-HTTP-CDP` から分岐して、AD ACL を数段たどると GPO 編集権限へ到達する経路を観察する教材です。

`john.smith` に `GG_GPO_WS_Admins` グループの `member` 属性を書ける explicit ACE を付け、同グループに `GPO-Workstation-Baseline` の AD 側 `GenericWrite` と SYSVOL 側 `Modify` を付与します。GPO は `OU=Workstations,OU=Computers,OU=LAB,...` にリンクし、`CLIENT01` が scope に入るようにします。

実端末上の `gpupdate` 実行、プロセス生成、サービス作成、タスク作成、ログオンスクリプト実行、外部 offensive tool の実行は自動化しません。GPO content としては、無害な registry policy marker だけを作ります。

実行先の DC01 では `ActiveDirectory` と `GroupPolicy` PowerShell module が必要です。

## 使い方

Hyper-V ホスト上のリポジトリ clone をカレントにして実行します。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ADACL-GPOAbuse' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ADACL-GPOAbuse' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ADACL-GPOAbuse' `
    -Action Cleanup
```

既定値は次のとおりです。

| 項目 | 値 |
|---|---|
| Scenario | `ADACL-GPOAbuse` |
| Helpdesk user | `john.smith` |
| Workstation admins group | `GG_GPO_WS_Admins` |
| Target GPO | `GPO-Workstation-Baseline` |
| Target OU | `OU=Workstations,OU=Computers,OU=LAB,DC=ad,DC=lab,DC=exceeds,DC=jp` |
| Target computer | `CLIENT01` |
| Registry marker | `HKLM\Software\Policies\ExceedsLab\Scenario07\Marker = ADACL-GPOAbuse` |

## 構成内容

`setup.ps1` は次を行います。

- baseline の `john.smith`、`CLIENT01`、`OU=Groups`、`OU=Workstations` が存在することを確認する
- scenario group `GG_GPO_WS_Admins` を `OU=Groups` に作成し、`adminDescription` へ scenario marker を設定する
- `john.smith` に `GG_GPO_WS_Admins` の `member` 属性 `WriteProperty` を許可する explicit ACE を追加する
- `GPO-Workstation-Baseline` を作成し、GPO の AD container に scenario marker を設定する
- `GG_GPO_WS_Admins` に GPO AD object の `GenericWrite` を許可する
- `GG_GPO_WS_Admins` に GPO SYSVOL folder の `Modify` を許可する
- GPO に registry policy marker を追加する
- GPO を Workstations OU へ enabled link として追加する

同名の group または GPO が既に存在し、scenario marker が付いていない場合、`setup.ps1` は停止します。既存の運用資産を教材として再利用しないためです。

## Validation

`validate.ps1` は次を確認します。

- `john.smith`、`GG_GPO_WS_Admins`、`CLIENT01`、対象 OU、対象 GPO が存在する
- `GG_GPO_WS_Admins` と GPO container が scenario marker を持つ
- `john.smith` が `GG_GPO_WS_Admins` の `member` 属性に `WriteProperty` ACE を持つ
- `john.smith` が既定状態では `GG_GPO_WS_Admins` の直接 member ではない
- `GG_GPO_WS_Admins` が GPO AD object の `GenericWrite` を持つ
- `GG_GPO_WS_Admins` が GPO SYSVOL folder の `Modify` を持つ
- GPO が Workstations OU に linked かつ enabled である
- `CLIENT01` が linked OU の scope に入っている
- registry policy marker と SYSVOL の `Machine\registry.pol` が存在する
- security filtering が既定の computer scope を許可している
- WMI filter が未設定である

`-IncludeAcl` を付けると、`GG_GPO_WS_Admins` に一致する GPO AD / SYSVOL の explicit ACE 要約も出力します。

## Cleanup

`cleanup.ps1` は scenario marker を確認してから次を削除します。

- `john.smith` から `GG_GPO_WS_Admins` への `WriteMembers` ACE
- `GG_GPO_WS_Admins` から GPO AD object への `GenericWrite` ACE
- `GG_GPO_WS_Admins` から GPO SYSVOL folder への `Modify` ACE
- Workstations OU の GPO link
- scenario GPO `GPO-Workstation-Baseline`
- scenario group `GG_GPO_WS_Admins`

GPO または group が同名で存在しても scenario marker がない場合、cleanup は停止します。

## 観察ポイント

このシナリオの経路は次の形です。

```text
john.smith
  -> WriteMembers
      -> GG_GPO_WS_Admins
          -> GenericWrite on GPO AD object
          -> Modify on GPO SYSVOL folder
              -> GPO-Workstation-Baseline
                  -> linked to Workstations OU
                      -> CLIENT01
```

GPO は AD object だけでは完結しません。実際の編集可否と適用可否を判断するには、少なくとも次を分けて確認します。

- AD 側の `groupPolicyContainer` ACL
- SYSVOL 側の GPO folder ACL
- OU の `gPLink`
- security filtering
- WMI filter
- 対象 computer または user の OU 所属
- 端末側の通常の Group Policy processing

このシナリオでは、`GenericWrite` と表示される権限があっても、SYSVOL、link、filter、対象 OU が揃わなければ端末上の変更には到達しないことを確認できます。

## Baseline との差分

| 種別 | DN / 名前 | Baseline 06 | シナリオ適用後 |
|---|---|---|---|
| Group | `CN=GG_GPO_WS_Admins,OU=Groups,OU=LAB,DC=ad,DC=lab,DC=exceeds,DC=jp` | なし | scenario marker 付き group |
| Group ACL | `GG_GPO_WS_Admins` | なし | `john.smith` に `member` 属性 `WriteProperty` |
| GPO | `GPO-Workstation-Baseline` | なし | scenario marker 付き GPO |
| GPO AD ACL | GPO container | なし | `GG_GPO_WS_Admins` に `GenericWrite` |
| GPO SYSVOL ACL | GPO folder | なし | `GG_GPO_WS_Admins` に `Modify` |
| GPO content | `Machine\registry.pol` | なし | registry policy marker |
| OU link | Workstations OU | Baseline 06 のまま | `GPO-Workstation-Baseline` の enabled link |
| Computer | `CLIENT01` | Baseline 06 のまま | 属性変更なし。scope 確認対象 |

## 参考資料

- Microsoft Learn: New-GPO
  https://learn.microsoft.com/en-us/powershell/module/grouppolicy/new-gpo
- Microsoft Learn: New-GPLink
  https://learn.microsoft.com/en-us/powershell/module/grouppolicy/new-gplink
- Microsoft Learn: Set-GPRegistryValue
  https://learn.microsoft.com/en-us/powershell/module/grouppolicy/set-gpregistryvalue
