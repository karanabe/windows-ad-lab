# AdminSDHolder

[English](README.md)

このシナリオは `06-ADCS-HTTP-CDP` から分岐して、AdminSDHolder と SDProp が protected account の ACL に与える影響を観察する教材です。

`GG_AdminSD_Resetters` を作成し、`john.smith` をその member にします。その group に対して `CN=AdminSDHolder,CN=System,...` 上で `Reset Password` control access right を付与し、既定では SDProp を手動トリガーして `yagami_adm` に ACE が伝播した状態を確認します。

このシナリオは protected account の password reset、権限昇格、外部 offensive tool の実行を自動化しません。`validate.ps1` は ACL、`adminCount`、group membership の静的条件だけを確認します。

実行先の DC01 では `ActiveDirectory` PowerShell module が必要です。

## 使い方

Hyper-V ホスト上のリポジトリ clone をカレントにして実行します。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'AdminSDHolder' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'AdminSDHolder' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'AdminSDHolder' `
    -Action Audit `
    -ScriptParameters @{
        Mode = 'SetupAudit'
        StartTime = (Get-Date).AddHours(-6)
    }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'AdminSDHolder' `
    -Action Cleanup
```

SDProp の手動トリガーを行わず、AdminSDHolder 上の差分だけを確認する場合は `TriggerSdProp = $false` を指定します。その場合、protected user 側の ACE は次回の SDProp 実行まで反映されないため、validation も `ExpectPropagatedAce = $false` にします。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'AdminSDHolder' `
    -AcknowledgeIsolatedLabRisk `
    -ScriptParameters @{ TriggerSdProp = $false }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'AdminSDHolder' `
    -Action Validate `
    -ScriptParameters @{
        ExpectPropagatedAce = $false
        FailOnValidationError = $true
    }
```

既定値は次のとおりです。

| 項目 | 値 |
|---|---|
| Scenario | `AdminSDHolder` |
| Delegate member | `john.smith` |
| Delegate group | `GG_AdminSD_Resetters` |
| Protected user | `yagami_adm` |
| AdminSDHolder target | `CN=AdminSDHolder,CN=System,DC=ad,DC=lab,DC=exceeds,DC=jp` |
| Delegated right | `Reset Password` (`00299570-246d-11d0-a768-00aa006e0529`) |
| Require non-privileged delegate | disabled |
| SDProp trigger | enabled |

## 構成内容

`setup.ps1` は次を行います。

- baseline の `john.smith`、`yagami_adm`、`OU=Groups,OU=LAB,...` が存在することを確認する
- `yagami_adm` が `Domain Admins` member であることを確認する
- `RequireDelegateMemberNonPrivileged = $true` の場合だけ、`john.smith` が privileged admin group の member ではないことを要求する
- scenario group `GG_AdminSD_Resetters` を `OU=Groups` に作成し、`adminDescription` へ scenario marker を設定する
- `john.smith` を `GG_AdminSD_Resetters` の member にする
- AdminSDHolder ACL で `GG_AdminSD_Resetters` に `Reset Password` control access right を付与する
- 既定では `RunProtectAdminGroupsTask` で SDProp を手動トリガーし、`yagami_adm` 側に ACE が現れるまで待つ
- cleanup 用に group SID などを `C:\ProgramData\ADLabBootstrap\Scenarios\AdminSDHolder\state.json` へ保存する

同名の group が既に存在し、scenario marker が付いていない場合、`setup.ps1` は停止します。既存の運用資産を教材として再利用しないためです。

## Validation

`validate.ps1` は次を確認します。

- AdminSDHolder container が存在する
- `john.smith`、`GG_AdminSD_Resetters`、`yagami_adm` が存在する
- `GG_AdminSD_Resetters` が scenario marker を持つ
- `john.smith` が `GG_AdminSD_Resetters` の member である
- `john.smith` の privileged admin group membership を観察する。`RequireDelegateMemberNonPrivileged = $true` の場合だけ失敗条件にする
- `yagami_adm` が `Domain Admins` member である
- `yagami_adm` の `adminCount` が `1` で、ACL inheritance が無効化されている
- AdminSDHolder 上に `GG_AdminSD_Resetters` 向けの explicit `Reset Password` ACE がある
- 既定では `yagami_adm` 上にも SDProp 後の explicit `Reset Password` ACE がある
- protected account の password reset は自動化していない

`-IncludeAcl` を付けると、AdminSDHolder と protected user の explicit ACE 要約も出力します。

## Audit

`Audit.ps1` は読み取り専用で、イベントログと現在の LDAP / ACL posture を収集します。`validate.ps1` がシナリオ成立条件の検証であるのに対し、`Audit.ps1` はログ上の見え方を確認するための script です。

`Invoke-Scenario.ps1` の `Status=Succeeded` は、監査 script が正常終了したという意味です。悪用有無は `Assessment`、`AbuseDetected`、`AbuseDetectionFindingCount` を見ます。

`Mode` で出力分類を絞れます。

| Mode | 用途 |
|---|---|
| `All` | setup 監査、悪用後確認、telemetry gap をまとめて見る |
| `SetupAudit` | setup / cleanup と現在の構成姿勢を `EvidenceClass=SetupAudit` として見る |
| `AbuseDetection` | setup では自動実行しない password reset や Reset Password control access を `EvidenceClass=AbuseDetection` として見る |

setup 後にラボの構成痕跡を見る場合:

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'AdminSDHolder' `
    -Action Audit `
    -ScriptParameters @{
        Mode = 'SetupAudit'
        StartTime = (Get-Date).AddHours(-6)
    }
```

手動で password reset などを試した後に悪用後ログを見る場合:

```powershell
$started = Get-Date
# ここで手動検証を実施する
$ended = Get-Date

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'AdminSDHolder' `
    -Action Audit `
    -ScriptParameters @{
        Mode = 'AbuseDetection'
        StartTime = $started
        EndTime = $ended
    }
```

ゲスト上で直接 JSON を保存する場合:

```powershell
.\scenarios\acl\AdminSDHolder\Audit.ps1 `
    -Mode AbuseDetection `
    -StartTime $started `
    -EndTime $ended |
    ConvertTo-Json -Depth 8
```

`EvidenceClass=TelemetryGap` は、4662 が出ないことを未悪用と断定できない監査前提の不足を示します。特に Reset Password control access の 4662 には `Directory Service Access` 成功監査と対象 object の SACL が必要です。

何も手動実験していない `AbuseDetection` で期待する結果は、通常 `AbuseDetected=False`、`AbuseDetectionFindingCount=0` です。Sysmon が未導入の場合は `CollectionWarning` が出ることがありますが、それは悪用検知ではありません。

## Cleanup

`cleanup.ps1` は scenario marker と state file を使い、次を削除します。

- AdminSDHolder 上の `GG_AdminSD_Resetters` 向け `Reset Password` ACE
- `adminCount=1` の protected objects に伝播した同じ SID の `Reset Password` ACE
- `GG_AdminSD_Resetters` から `john.smith` の membership
- scenario group `GG_AdminSD_Resetters`
- scenario state directory

既定では cleanup 後にも SDProp を手動トリガーします。同名の group が存在しても scenario marker がない場合、cleanup は停止します。

## 観察ポイント

このシナリオの経路は次の形です。

```text
john.smith
  -> GG_AdminSD_Resetters
      -> Reset Password ACE
          -> CN=AdminSDHolder,CN=System,...
              -> SDProp
                  -> yagami_adm and other adminCount=1 protected objects
```

AdminSDHolder の本質は、protected account の ACL を通常の OU inheritance ではなく AdminSDHolder 側の security descriptor で管理する点です。したがって、監視では protected user への直接 ACE だけでなく、AdminSDHolder 自体の ACL 変更と `adminCount=1` オブジェクトの棚卸しも追う必要があります。

## Baseline との差分

| 種別 | DN / 名前 | Baseline 06 | シナリオ適用後 |
|---|---|---|---|
| Group | `CN=GG_AdminSD_Resetters,OU=Groups,OU=LAB,DC=ad,DC=lab,DC=exceeds,DC=jp` | なし | scenario marker 付き group |
| Membership | `john.smith -> GG_AdminSD_Resetters` | なし | 追加 |
| AdminSDHolder ACL | `CN=AdminSDHolder,CN=System,DC=ad,DC=lab,DC=exceeds,DC=jp` | Baseline 06 のまま | `GG_AdminSD_Resetters` に `Reset Password` ACE |
| Protected user ACL | `CN=Yagami Admin,OU=Admin,OU=LAB,DC=ad,DC=lab,DC=exceeds,DC=jp` | Baseline 06 のまま | SDProp 後に同じ `Reset Password` ACE |

## 参考資料

- Microsoft Learn: AdminSDHolder, protected groups and SDProp
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9909ca0d-caf4-44b3-b089-b25aae13e601
- Microsoft Learn: RunProtectAdminGroupsTask rootDSE modify
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f9dbd527-5594-4d27-be4b-ec16d23136e6
- Microsoft Learn: Control access rights
  https://learn.microsoft.com/en-us/windows/win32/ad/control-access-rights
