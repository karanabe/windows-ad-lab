# ラボの構築と復旧

[English](setup.md)

最短の手順は[README](../README.ja.md)にあります。ホスト用コマンドは、Hyper-Vホストのローカルドライブに置いたcloneからの実行を推奨します。出荷構成は `ad.lab.exceeds.test`、`DC01`、`10.10.6.10/28` に固定されています。シナリオも同じcloneから実行します。

## 自動構築の前に

1. [Microsoft Evaluation Center](https://www.microsoft.com/ja-jp/evalcenter)からWindows Server 2025 Standard Evaluation（Desktop Experience）のISOを取得します。このリポジトリはWindowsをダウンロード・再配布しません。
2. 管理者PowerShell 7.2以降、またはWindows PowerShell 5.1を開きます。Hyper-Vを使用可能にし、Windows Updateへ接続できる既存のスイッチを選びます。
3. cloneからVMを作成します。

```powershell
.\scripts\host\New-LabVm.ps1 `
    -IsoPath '<評価版ISOのパス>' `
    -ExternalSwitchName '<Windows-Updateに使う既存スイッチ>'
```

スクリプトは4 vCPU、固定メモリ8 GiB、可変長80 GiB VHDX、NIC 1枚、Secure Boot有効のGeneration 2 VM `DC01` を作成します。自動checkpointを無効にしてStandard checkpointを使用し、Private Switch `AD-Internal` がなければ作成して、ISOからVMを起動します。既存のVMやVHDは変更しません。

4. VMコンソールでWindows Serverをインストールし、ローカルAdministratorのパスワードを設定・保管します。認証または評価版の状態確認とWindows Updateを済ませ、必要な再起動後にAdministratorで一度サインインします。NIC切替前にオンライン作業を終えます。
5. NICをPrivate Switchへ移し、forest作成前のcheckpointを作ります。

```powershell
.\scripts\host\Set-VMNetwork.ps1
.\scripts\host\New-LabBaseCheckpoint.ps1
```

checkpoint名は `01-Updated` です。スクリプトはNICが1枚の起動中VMを要求し、作成後は10秒待ってHyper-Vに表示されたことを確認します。以後のPowerShell DirectはゲストIP、WinRM、default gatewayを必要としません。

## 構築と確認

同じcloneから一括構築します。

```powershell
.\scripts\host\Invoke-ValidatedLabSetup.ps1
```

引数を追加しない通常の対話実行では、Windowsインストール時のローカルAdministrator、DSRM、新規ADユーザー用のパスワードを別々に入力します。昇格後の `LAB\Administrator` はローカルAdministratorのパスワードを引き継ぎます。この実行で `06-ADCS-HTTP-CDP` まで構築できます。ラッパーは設定・スクリプト、Hyper-V、PowerShell Directを検証し、bootstrapを `-WhatIf` で確認してからforestとAD CSを構築・検証します。成功した段階に `02-Baseline` から `06-ADCS-HTTP-CDP` までのcheckpointを作り、同名の既存checkpointは置き換えません。各checkpointの作成後は10秒待ち、Hyper-Vに表示されるまで最大120秒確認します。出荷構成のタイムゾーンは実行時にHyper-Vホストの `(Get-TimeZone).Id` から取得し、ゲストの設定と最終検証に同じ値を使います。各パスワードは `-LocalCredential`、`-DsrmPassword`、`-DefaultUserPassword` でも個別に渡せます。

無人実行が必要な場合だけ、[LabSecrets.example.psd1](../config/LabSecrets.example.psd1) のコメントに従ってGit対象外の `config/LabSecrets.psd1` を作り、`-SecretsPath .\config\LabSecrets.psd1` を指定します。

checkpointを確認し、完成したbaselineからシナリオを実行します。

```powershell
Get-VMCheckpoint -VMName 'DC01' | Sort-Object CreationTime | Format-Table Name, CreationTime
.\scenarios\Invoke-Scenario.ps1 -ScenarioName 'esc1' -AcknowledgeIsolatedLabRisk
```

ホストログは `logs/`、ゲストのtranscriptとvalidation JSONは `C:\ProgramData\ADLabBootstrap\Logs` に保存されます。

## 失敗、復元、更新

構築に失敗したら、`logs/` のホストログ、`logs/*-host-summary-failed.json` の `FailedPhase`、該当段階のゲストログを確認します。原因を修正し、forest昇格直後ならDC01の起動完了を待ってから `scripts/host/Invoke-ValidatedLabSetup.ps1` を再実行します。既存のforestと同名checkpointは再利用されます。

シナリオが失敗した場合や変更を破棄したい場合は、ホストの管理者PowerShellで `06-ADCS-HTTP-CDP` への復元を確認して実行します。このcheckpointの作成が完了している必要があります。

```powershell
.\scenarios\Restore-LabBaseline.ps1 -WhatIf
.\scenarios\Restore-LabBaseline.ps1 -AcknowledgeDataLoss -StartVM
```

forestとCAを再構築する場合は、同じVMのforest作成前の `01-Updated` を復元します。`Restore-LabBaseline.ps1` はこのcheckpointを対象にしないため、ホストの管理者PowerShellで次を実行します。

```powershell
$base = @(Get-VMCheckpoint -VMName 'DC01' -Name '01-Updated')
if ($base.Count -ne 1) { throw "Expected exactly one 01-Updated checkpoint; found $($base.Count)." }
$base[0] | Format-List Name, Id, CreationTime
$base[0] | Restore-VMCheckpoint -WhatIf
$base[0] | Restore-VMCheckpoint -Confirm:$false
if ((Get-VM -Name 'DC01').State -eq 'Off') { Start-VM -Name 'DC01' }
```

checkpointの復元では、それ以降のゲスト内の変更とログを失います。`01-Updated` に戻すとforestとCAも失います。checkpointはバックアップではありません。

更新時はホストのcloneで `git pull --ff-only` を実行します。シナリオは実行時に毎回ゲストへコピーされ、bootstrapのゲスト用スクリプトは構築を再実行した時にコピーされます。Gitの更新だけで既存forestの名前は変わりません。旧ドメインのVMは `01-Updated` から再構築するか、対応する旧版コードを使います。

構築後の `DC01` は `AD-Internal` に置き、gatewayを設定しません。DCとCAの同居、新規ラボユーザー間で共通の初期パスワード、シナリオの弱い権限は隔離検証用です。
