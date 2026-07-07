# Windows LAPS Delegation

[English](README.md)

このシナリオは `06-ADCS-HTTP-CDP` から分岐して、Windows LAPS の AD 側読み取り委任を観察する教材です。Helpdesk は Workstations OU の `CLIENT01` だけを読める設計にし、Servers OU は読めない状態にします。さらに `FILE01` の computer object へ意図的な `GenericAll` ACE を追加し、OU 設計が正しくてもオブジェクト単位の ACL 誤設定で LAPS 値が漏れる状態を作ります。

端末側の Windows LAPS policy、GPO、`Invoke-LapsPolicyProcessing`、実ローカル管理者パスワードのローテーションはこのシナリオでは自動化しません。DC01 上の既存 computer object に観察用の synthetic `msLAPS-Password` / `msLAPS-PasswordExpirationTime` 値を入れ、委任と ACL の見え方を確認します。

このシナリオの意図、`FILE01` の `GenericAll` が何を意味するか、synthetic value と実パスワードの違いは [concepts.md](./concepts.md) にまとめています。

## 使い方

Hyper-V ホスト上のリポジトリ clone をカレントにして実行します。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'WindowsLAPS-Delegation' `
    -AcknowledgeIsolatedLabRisk

# Windows LAPS schema が未導入の checkpoint でのみ明示的に指定する
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'WindowsLAPS-Delegation' `
    -AcknowledgeIsolatedLabRisk `
    -ScriptParameters @{ UpdateSchemaIfMissing = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'WindowsLAPS-Delegation' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

# FILE01 の誤設定だけを修正し、シナリオ自体は残す
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'WindowsLAPS-Delegation' `
    -AcknowledgeIsolatedLabRisk `
    -ScriptParameters @{ IncludeFile01Misconfiguration = $false }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'WindowsLAPS-Delegation' `
    -Action Validate `
    -ScriptParameters @{
        ExpectFile01Misconfiguration = $false
        FailOnValidationError = $true
    }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'WindowsLAPS-Delegation' `
    -Action Cleanup
```

既定値は次のとおりです。

| 項目 | 値 |
|---|---|
| Scenario | `WindowsLAPS-Delegation` |
| Helpdesk group | `LAB\GG_LAPS_Helpdesk` |
| Helpdesk member | `john.smith` |
| Client scope | `OU=Workstations,OU=Computers,OU=LAB,...` |
| Client computer | `CLIENT01` |
| Server scope | `OU=Servers,OU=Computers,OU=LAB,...` |
| Misconfigured server object | `FILE01` |
| Control server object | `WEB01` |

## 構成内容

`setup.ps1` は次を行います。

- Windows LAPS module と `msLAPS-Password` / `msLAPS-PasswordExpirationTime` schema attributes の存在を確認する
- `-UpdateSchemaIfMissing` が指定された場合だけ、`Update-LapsADSchema` で LAPS schema attributes を追加する
- `OU=Groups,OU=LAB,...` に marker 付きの `GG_LAPS_Helpdesk` を作成し、`john.smith` を追加する
- Microsoft の Windows LAPS cmdlet `Set-LapsADReadPasswordPermission` で Workstations OU へ Helpdesk の password query permission を付与する
- Servers OU には Helpdesk の読み取り委任を付与しない
- 既定では `FILE01` computer object に Helpdesk の explicit `GenericAll` ACE を追加し、オブジェクト単位の誤設定を作る
- `CLIENT01`、`FILE01`、`WEB01` に観察用の synthetic `msLAPS-Password` / `msLAPS-PasswordExpirationTime` 値を設定する

既に対象 computer object に別の Windows LAPS 値が入っている場合、`setup.ps1` は上書きせず停止します。既存または実運用由来の LAPS 値を壊さないためです。`Update-LapsADSchema` による schema extension は cleanup では戻せないため、checkpoint ごと戻せる isolated lab でだけ使います。

Windows LAPS schema extension は forest-wide な追加変更です。既存の証明書テンプレート、RBCD、KeyCredentialLink、ESC8 などのシナリオとは共存できますが、scenario cleanup だけでは schema を削除できません。Baseline 06 と完全に同じ schema へ戻す必要がある場合は、`UpdateSchemaIfMissing` を使った後に checkpoint から復元してください。

## LDAP schema とは何か

LDAP は AD に問い合わせたり変更要求を送ったりするためのプロトコルです。既に `Get-ADUser`、`Get-ADComputer`、`Get-ADObject -LDAPFilter ...` で検索できているのは、DC が LDAP 要求を受け付け、既存の user、group、computer、OU などのオブジェクトと属性を返せるという意味です。

LDAP schema は、その LDAP ディレクトリで「どの種類のオブジェクトが存在できるか」「各オブジェクトにどの属性を保存できるか」「属性の名前、型、単一値/複数値、検索や権限評価上の扱いは何か」を定義するメタデータです。AD では schema naming context 配下に `classSchema` や `attributeSchema` として保存され、forest 全体で共有されます。

このシナリオの schema check は、LDAP が使えるかどうかの確認ではなく、Windows LAPS 用の属性定義が forest に存在するかを確認しています。具体的には `msLAPS-Password` や `msLAPS-PasswordExpirationTime` という属性名を AD がまだ知らない状態では、computer object にその値を保存できず、Windows LAPS の委任 cmdlet も期待した権限設定を組めません。

`Update-LapsADSchema` は LDAP サーバーを有効化する操作ではありません。Windows LAPS が使う属性定義を AD schema に追加し、computer object でそれらの属性を扱えるようにする schema extension です。この追加が終わると、通常の LDAP/AD cmdlet から `msLAPS-*` 属性を検索、保存、ACL 評価できるようになります。

## Validation

`validate.ps1` は次を確認します。

- Windows LAPS schema attributes が存在する
- `GG_LAPS_Helpdesk` が scenario marker を持ち、`john.smith` を含む
- `CLIENT01` が Workstations OU、`FILE01` と `WEB01` が Servers OU にある
- 3台の computer object に synthetic LAPS 値がある
- `Find-LapsADExtendedRights` で Workstations OU の Helpdesk read holder が見える
- Servers OU に Helpdesk の OU-level read holder がない
- `FILE01` だけに explicit Helpdesk `GenericAll` がある、または修正後はない
- `WEB01` に explicit Helpdesk `GenericAll` がない

`-IncludeAcl` を付けると、対象 computer object 上で Helpdesk SID に一致する ACE の要約も表示します。synthetic LAPS password の `p` 値は validate 出力に出しません。

## Cleanup

`cleanup.ps1` は、次だけを削除または消去します。

- Workstations OU、Servers OU、`CLIENT01`、`FILE01`、`WEB01` 上の scenario group に対する explicit ACE
- scenario が作成した synthetic `msLAPS-Password` / `msLAPS-PasswordExpirationTime` 値
- marker 付きの `GG_LAPS_Helpdesk`

対象 computer object の LAPS 値が scenario の synthetic 値から変わっている場合、cleanup は停止します。実端末の Windows LAPS client が値を書いた可能性があるため、手動で確認してください。
Windows LAPS schema が未導入のまま setup が停止した場合でも、cleanup は no-op として実行できます。

## 境界

このシナリオは LAPS の権限設計教材です。実端末上の local Administrator password を変更したり、LAPS GPO を作成したり、暗号化された LAPS password の復号権限設計を自動化したりはしません。

参考資料:

- Microsoft Learn: Get started with Windows LAPS and Windows Server Active Directory
  https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory
- Microsoft Learn: Windows LAPS schema extensions reference
  https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference
- Microsoft Learn: Windows LAPS PowerShell cmdlets
  https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-powershell
- Microsoft Learn: Set-LapsADReadPasswordPermission
  https://learn.microsoft.com/en-us/powershell/module/laps/set-lapsadreadpasswordpermission
- Microsoft Learn: Find-LapsADExtendedRights
  https://learn.microsoft.com/en-us/powershell/module/laps/find-lapsadextendedrights
