# ESC11 RPC Enrollment

[English](README.md)

このシナリオは、完成済みの `06-ADCS-HTTP-CDP` から分岐し、AD CS の RPC 証明書登録インターフェースで `IF_ENFORCEENCRYPTICERTREQUEST` が有効な状態と無効な状態を比較する。NTLM relay、強制認証、証明書要求、PFX 保存は実行しない。

目的は、Web Enrollment を無効化しても RPC enrollment 側の `MS-ICPR` 経路が残ること、そして `CA\InterfaceFlags` の packet privacy 要求が ESC11 の中心的な確認点であることを観察できるようにすることである。

## 使い方

Hyper-V ホスト上のリポジトリ clone をカレントにして実行します。`Invoke-Scenario.ps1` はこの clone から guest の `C:\LabBootstrap\scenarios` へ同期します。

```powershell
# 既定では hardened 状態を適用する
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ESC11-RpcEnrollment' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ESC11-RpcEnrollment' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ESC11-RpcEnrollment' `
    -Action Cleanup
```

危険な比較状態を先に観察する場合は、`Stage = Vulnerable` を指定する。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ESC11-RpcEnrollment' `
    -AcknowledgeIsolatedLabRisk `
    -ScriptParameters @{ Stage = 'Vulnerable' }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ESC11-RpcEnrollment' `
    -Action Validate `
    -ScriptParameters @{
        ExpectedState = 'Vulnerable'
        FailOnValidationError = $true
    }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ESC11-RpcEnrollment' `
    -AcknowledgeIsolatedLabRisk `
    -ScriptParameters @{ Stage = 'Hardened' }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ESC11-RpcEnrollment' `
    -Action Validate `
    -ScriptParameters @{
        ExpectedState = 'Hardened'
        FailOnValidationError = $true
    }
```

## 構成内容

`setup.ps1` は初回実行時に `C:\ProgramData\ADLabBootstrap\Scenarios\ESC11-RpcEnrollment\state.json` へ実行前の active CA と `InterfaceFlags` を保存する。その後、`CertSvc` が動作していることを確認し、指定された stage に合わせて `CA\InterfaceFlags` を変更する。値を変更した場合だけ `CertSvc` を再起動する。

`Stage = Vulnerable` では、比較用に次の条件を作る。

- `IF_ENFORCEENCRYPTICERTREQUEST` を無効化する
- `IF_NORPCICERTREQUEST` は変更せず、RPC certificate enrollment の有効/無効は baseline のまま観察する

`Stage = Hardened` では、次の条件を作る。

- `IF_ENFORCEENCRYPTICERTREQUEST` を有効化する
- RPC certificate enrollment 接続に `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` を要求する状態にする

## Validation

`validate.ps1` は `ExpectedState` に応じて、次を確認する。

| ExpectedState | 主な確認 |
|---|---|
| `Vulnerable` | `CertSvc` が動作している、RPC certificate enrollment が無効化されていない、`IF_ENFORCEENCRYPTICERTREQUEST` がない、ESC11 relay 前提条件が同時に成立する |
| `Hardened` | `IF_ENFORCEENCRYPTICERTREQUEST` がある、ESC11 relay 前提条件が同時に成立しない |

どちらも構成検証であり、relay、証明書要求、外部ツールの実行は行わない。

この validation は `InterfaceFlags` を中心にした flag-based posture check である。Windows の更新状態によっては、CA flag とは別に RPC packet privacy が強制される場合があるため、`ExpectedState = Vulnerable` は relay 成功を証明するものではない。

## Cleanup

`cleanup.ps1` は state file を使って、シナリオ前の `InterfaceFlags` に戻す。値を復元した場合だけ `CertSvc` を再起動する。active CA が state file 作成時と異なる場合は、別の CA 設定を壊さないため停止する。

state file がない場合は、`InterfaceFlags` を変更しない。

## 観察ポイント

ESC11 は template 設定不備ではなく、RPC certificate enrollment インターフェースの transport/authentication 設定を見るシナリオである。発行される証明書の影響は既存 template と relayed identity の enrollment 権限に依存するが、このシナリオでは発行処理までは扱わない。

ESC8 を hardening して `/CertSrv` の HTTP/NTLM/EPA 条件を潰しても、RPC enrollment 側で packet privacy が要求されないままだと別経路の確認が必要になる。したがって、ESC8 と ESC11 は同じ AD CS relay 系でも確認対象が異なる。

参考資料:

- Microsoft Learn: Enforce encryption for RPC certificate enrollment interface (ESC11)
  https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-insecure-adcs-certificate-enrollment
- Microsoft Learn: MS-ICPR CertServerRequest
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/0c6f150e-3ead-4006-b37f-ebbf9e2cf2e7
