# ESC16 Disable Extension List 設計書

[English](README.md)

このシナリオは、完成済みの `06-ADCS-HTTP-CDP` から分岐し、CA が SID security extension をグローバルに無効化する ESC16 を観察する。既定の setup は `Stage = Hardened` である。証明書要求、テンプレートの `CT_FLAG_NO_SECURITY_EXTENSION`（ESC9）、`EDITF_ATTRIBUTESUBJECTALTNAME2`（ESC6）は扱わない。

## 使い方

Hyper-V ホスト上のリポジトリ clone をカレントにして実行します。`Invoke-Scenario.ps1` はこの clone から guest の `C:\LabBootstrap\scenarios` へ同期します。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc16' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc16' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc16' `
    -Action Cleanup
```

危険な比較状態を観察する場合だけ `Stage = Vulnerable` を指定する。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc16' `
    -AcknowledgeIsolatedLabRisk `
    -ScriptParameters @{ Stage = 'Vulnerable' }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc16' `
    -Action Validate `
    -ScriptParameters @{
        ExpectedState = 'Vulnerable'
        FailOnValidationError = $true
    }
```

## ESC16 成立条件

ESC16 はテンプレートではなく CA の policy module 設定である。

- `policy\DisableExtensionList` に `szOID_NTDS_CA_SECURITY_EXT` `1.3.6.1.4.1.311.25.2` が含まれる。
- その CA が発行するすべての証明書から SID security extension が落ちる。
- ESC9 は同じ拡張をテンプレートの `CT_FLAG_NO_SECURITY_EXTENSION` で落とす。この教材は CA グローバル側だけを扱う。

`ExpectedState = Vulnerable` は構成確認であり、UPN 操作や ESC6 との組み合わせが成功することを証明しない。

参考資料:

- Microsoft Learn: KB5014754 certificate-based authentication changes
  https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
