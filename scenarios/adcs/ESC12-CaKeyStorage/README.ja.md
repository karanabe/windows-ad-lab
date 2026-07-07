# ESC12 CA Key Storage 設計書

[English](README.md)

このシナリオは、隔離された Windows Server 2025 Active Directory / AD CS ラボで、CA 秘密鍵の保管場所を観察する教材である。公開されている ESC12 は YubiHSM2 固有の話で、ホスト上の authkey ファイルがあると低権限シェルから CA 鍵を使える、という指摘である。このラボは YubiHSM を導入しない。代わりにラボ CA の CSP/KSP を記録する。

この文書は設計説明であり、GUI手順や攻撃手順は扱わない。CA 秘密鍵の export、証明書の偽造、HSM ソフトウェアの導入は自動化しない。

## 使い方

Hyper-V ホスト上のリポジトリ clone をカレントにして実行します。`Invoke-Scenario.ps1` はこの clone から guest の `C:\LabBootstrap\scenarios` へ同期します。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc12' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc12' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc12' `
    -Action Cleanup
```

## ESC12 の位置づけ

公開 ESC12 は次を前提にする。

- CA が YubiHSM2 に秘密鍵を置く。
- YubiHSM の authkey が CA ホスト上のファイルまたはレジストリで使える。
- 攻撃者は CA ホストへ低権限シェルを持つ。

このラボの `LAB-ROOT-CA` は Microsoft software Key Storage Provider を使う。DC と CA が同居しているため、DC01 へのシェルはソフトウェア保管の CA 鍵利用も含む。これは YubiHSM の authkey 問題より強いホスト侵害結果だが、公開 ESC12 のハードウェア分類そのものではない。

## 観察対象

- `HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA>\CSP` の `Provider` と `KeyContainer`
- `YubiHSM Key Storage Provider` が使われていないこと
- YubiHSM のホスト側レジストリと `ProgramData\YubiHSM` が無いこと
- シナリオが CA 秘密鍵を読まないこと

`cleanup.ps1` は観察用 state だけを削除し、CA CSP は変更しない。

参考資料:

- Hans-Joachim Knobloch: ESC12 Shell access to ADCS CA with YubiHSM
  https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm
