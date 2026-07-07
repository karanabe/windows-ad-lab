# 貢献

[English](CONTRIBUTING.md)

このリポジトリは隔離された Windows Server 2025 Active Directory ラボです。変更は既存の bootstrap、checkpoint、シナリオ契約を壊さないようにしてください。

## 作業ツリー

ラボのスクリプトとシナリオは、Hyper-Vホスト上の1つのcloneにまとめます。Windowsドライブ上でもWSL上でも、編集した作業ツリーをそのまま検証します。

`config/LabSecrets.psd1`、`logs/`、`artifacts/`、生成された `BUILD_*` はcommitしません。

## 検証

PowerShellまたは設定を変更したら、Windows上のPowerShellでリポジトリのルートから次を実行します。

```powershell
.\scripts\Test-LabConfig.ps1
.\tests\Invoke-StaticValidation.ps1
```

WSLのリポジトリのルートからは、WindowsのPowerShell 7.2以降で同じファイルを実行できます。

```bash
pwsh.exe -ExecutionPolicy Bypass -File "$(wslpath -w "$PWD/scripts/Test-LabConfig.ps1")"
pwsh.exe -ExecutionPolicy Bypass -File "$(wslpath -w "$PWD/tests/Invoke-StaticValidation.ps1")"
```

Windows PowerShell 5.1では、`pwsh.exe -ExecutionPolicy Bypass` を `powershell.exe -ExecutionPolicy Bypass` に置き換えます。WSLから起動したWindowsプログラムは、現在のWindowsユーザーの権限で動きます。Hyper-V操作は管理者権限のWindowsセッションから実行してください。

`Test-LabConfig.ps1` はスキーマ検証だけです。`config/examples/generic-lab.psd1` のような別インスタンスも通せます。出荷の `ad.lab.exceeds.test` は静的検証経由の `tests/Assert-ShippedLabInstance.ps1` が確認します。

VM を変更せず bootstrap 計画だけを見る場合:

```powershell
.\bootstrap\Invoke-LabBootstrap.ps1 -WhatIf
```

## シナリオの追加

1. `scenarios/` 配下のカテゴリ（`adcs`、`credentials`、`delegation`、`acl`）を選ぶ。
2. そのカテゴリに番号なしの `ShortName/` ディレクトリを作る。
3. `README.md`、`setup.ps1`、`validate.ps1`、`cleanup.ps1`、`scenario.psd1` を置く。
4. 検知メモやログ調査が必要なら `Detect.md` と `Audit.ps1` を追加する。
5. 正本は英語。日本語は `README.ja.md` と `Detect.ja.md` に置く。
6. 改名や移動でも `Id` を維持する。任意の `Aliases` を使う場合も番号は付けない。
7. 完成済みの `06-ADCS-HTTP-CDP` checkpoint から分岐する。VM 状態を破棄する前に `Restore-LabBaseline.ps1 -WhatIf` で対象を確認する。

`scenario.psd1` の形:

```powershell
@{
    Id                 = 'esc1'
    Title              = 'ESC1 Certificate Template'
    Category           = 'adcs'
    BaselineCheckpoint = '06-ADCS-HTTP-CDP'
}
```

秘密情報、パスワード、トークン、実行ログ全文はドキュメントに書かないでください。
