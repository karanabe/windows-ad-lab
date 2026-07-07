# 設定例

[English](README.md)

`Test-LabConfig.ps1` は隔離ラボ設定のスキーマ（必須セクション、名前、参照整合、Private Switch、default gateway なし）を検証します。`ad.lab.exceeds.test` である必要はありません。

| ファイル | 役割 |
|---|---|
| [../LabConfig.psd1](../LabConfig.psd1) | このリポジトリのシナリオが使う出荷インスタンス |
| [generic-lab.psd1](generic-lab.psd1) | スキーマ検証を通る例（`ad.lab.example.test`） |

`generic-lab.psd1` はスキーマを通る例です。対応するラボではありません。`config/LabConfig.psd1` へコピーすると `Invoke-StaticValidation.ps1` と `Invoke-ValidatedLabSetup.ps1` が失敗し、このリポジトリのシナリオは出荷ドメイン `ad.lab.exceeds.test` を確認します。構築と検証は出荷ファイルのまま行います。
