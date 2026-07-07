# ESC13 Issuance Policy 設計書

[English](README.md)

このシナリオは、隔離された Windows Server 2025 Active Directory / AD CS ラボで、Issuance Policy の OID group link による ESC13（Authentication Mechanism Assurance の悪用）を理解するための教材である。空のユニバーサルグループ `UG_ESC13_AMA`、`msDS-OIDToGroupLink` を持つ issuance policy OID、Client Authentication とその issuance policy を持つ `ESC13LabAma` を追加する。`Domain Users` が Enroll でき、グループには `CLIENT01` への GenericWrite を付ける。

この文書は設計説明であり、GUI手順や攻撃手順は扱わない。証明書要求、PFX 保存、証明書による認証は自動化しない。

## 使い方

Hyper-V ホスト上のリポジトリ clone をカレントにして実行します。`Invoke-Scenario.ps1` はこの clone から guest の `C:\LabBootstrap\scenarios` へ同期します。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc13' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc13' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc13' `
    -Action Cleanup
```

## ESC13 成立条件

- 低権限主体がテンプレートへ Enroll できる。
- テンプレートに Client Authentication EKU がある。
- テンプレートの `msPKI-Certificate-Policy` が issuance policy OID を持つ。
- その OID の `msDS-OIDToGroupLink` が AD グループを指す。
- グループは空で Universal である。
- manager approval がなく、authorized signatures が 0 である。
- Enterprise CA がそのテンプレートを公開している。

要求者指定 Subject はオフのままである。これは ESC1 ではない。OID リンクが観察対象である。

参考資料:

- SpecterOps: ADCS ESC13 Abuse Technique
  https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/
- Microsoft Learn: msDS-OIDToGroupLink
  https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-oidtogrouplink
