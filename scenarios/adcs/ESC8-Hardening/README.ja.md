# ESC8 Hardening

[English](README.md)

このシナリオは、完成済みの `06-ADCS-HTTP-CDP` から分岐し、AD CS Web Enrollment の ESC8 前提条件を設定値として比較する。NTLM relay や強制認証は実行しない。

目的は、`/CertSrv` が HTTP、NTLM、EPAなしで動く状態と、HTTPS、EPA必須、Kerberos-only provider に寄せた状態の差分を確認できるようにすることである。baselineの `/CertEnroll` はCRLとCA証明書の公開用であり、検証対象のWeb Enrollment endpointではない。

## 使い方

Hyper-V ホスト上のリポジトリ clone をカレントにして実行します。`Invoke-Scenario.ps1` はこの clone から guest の `C:\LabBootstrap\scenarios` へ同期します。

```powershell
# 既定では hardened 状態を適用する
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ESC8-Hardening' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ESC8-Hardening' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ESC8-Hardening' `
    -Action Cleanup
```

危険な比較状態を先に観察する場合は、`Stage = Vulnerable` を指定する。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ESC8-Hardening' `
    -AcknowledgeIsolatedLabRisk `
    -ScriptParameters @{ Stage = 'Vulnerable' }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ESC8-Hardening' `
    -Action Validate `
    -ScriptParameters @{
        ExpectedState = 'Vulnerable'
        FailOnValidationError = $true
    }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ESC8-Hardening' `
    -AcknowledgeIsolatedLabRisk `
    -ScriptParameters @{ Stage = 'Hardened' }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ESC8-Hardening' `
    -Action Validate `
    -ScriptParameters @{
        ExpectedState = 'Hardened'
        FailOnValidationError = $true
    }
```

## 構成内容

`setup.ps1` は AD CS Web Enrollment role service を追加し、`Default Web Site/CertSrv` を構成する。初回実行時に `C:\ProgramData\ADLabBootstrap\Scenarios\ESC8-Hardening\state.json` へ実行前の IIS/Web Enrollment 状態を保存する。

`Stage = Vulnerable` では、比較用に次の条件を作る。

- `CertSrv` で Windows Authentication を有効化する
- Anonymous Authentication を無効化する
- Require SSL を無効化し、HTTP enrollment を許可する
- Extended Protection の `tokenChecking` を `None` にする
- Windows Authentication provider を `Negotiate, NTLM` にする

`Stage = Hardened` では、次の条件を作る。

- `Default Web Site` に HTTPS `:443` binding を用意する
- 既存の HTTPS 証明書がない場合だけ、ラボ用 self-signed certificate を `Cert:\LocalMachine\My` に作成して binding へ割り当てる
- `CertSrv` で Require SSL を有効化する
- Extended Protection の `tokenChecking` を `Require` にする
- Windows Authentication provider を `Negotiate:Kerberos` のみにする

このシナリオの HTTPS 証明書は、IIS binding を成立させるためのラボ用証明書である。別クライアントから信頼チェーン込みで検証したい場合は、ラボ CA から発行した Server Authentication 証明書へ置き換える。

## Validation

`validate.ps1` は `ExpectedState` に応じて、次を確認する。

| ExpectedState | 主な確認 |
|---|---|
| `Vulnerable` | Web Enrollment が存在する、HTTP enrollment が許可される、EPA が必須ではない、NTLM provider が残っている |
| `Hardened` | HTTPS binding が証明書を持つ、Require SSL が有効、EPA が必須、NTLM provider がない、provider が `Negotiate:Kerberos` のみ |

どちらも構成検証であり、relay、証明書要求、PFX保存、外部ツールの実行は行わない。

## Cleanup

`cleanup.ps1` は state file を使って、シナリオ前の状態へ戻す。

- シナリオ前から Web Enrollment が存在した場合は、`CertSrv` の SSL/EPA/provider/authentication 設定を復元する
- シナリオが作成した HTTPS binding と self-signed certificate を削除する
- シナリオ前に Web Enrollment が存在しなかった場合は、Web Enrollment role service を削除する
- scenario state directory を削除する

state file がない場合は、シナリオ marker が付いた証明書だけを削除し、Web Enrollment や既存 IIS 設定は変更しない。

参考資料:

- Microsoft Learn: Install-AdcsWebEnrollment
  https://learn.microsoft.com/powershell/module/adcsdeployment/install-adcswebenrollment
- Microsoft Learn: Windows Extended Protection
  https://learn.microsoft.com/iis/configuration/system.webserver/security/authentication/windowsauthentication/extendedprotection/
- Microsoft Learn: Windows Authentication Providers
  https://learn.microsoft.com/iis/configuration/system.webserver/security/authentication/windowsauthentication/providers/add
