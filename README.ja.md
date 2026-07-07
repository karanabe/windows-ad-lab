<br />
<h1 align="center">Windows Active Directory Lab</h1>
<h3 align="center"> 約20分で再現可能なActive Directory Labのベースラインを構築し、シナリオの追加・リセット・反復を容易に。</h3>
<br />
<br />

[English](README.md)

Windows Server 2025 のVM `DC01` に、Hyper-VホストからPowerShell Directで構築する隔離型のActive Directoryラボです。学習・検証用の固定構成であり、本番ADやPKIの構成例ではありません。

forestは `ad.lab.exceeds.test`（NetBIOS `LAB`）、UPN suffixは `exceeds.test` です。DCはPrivate Switch `AD-Internal` 上の `10.10.6.10/28` を使用し、default gatewayは設定しません。ユーザー・グループ、監査、Enterprise Root CA、HTTP CDP/AIAを構築します。シナリオはcheckpoint `06-ADCS-HTTP-CDP` を起点とします。

## 必要な環境

- Hyper-Vを使えるWindows 11 Pro・Enterprise・Education、またはWindows Server。管理者PowerShell 7.2以降かWindows PowerShell 5.1を使用します。
- Microsoftから取得したWindows Server 2025 Standard Evaluation（Desktop Experience）のISO。
- 4 vCPU、8 GiBメモリ、80 GiB VHDXのGeneration 2 VMを動かせる容量。
- インストールとWindows Updateに使う既存のスイッチ。Private Switch `AD-Internal` はスクリプトが作成します。

## ラボの構築

Hyper-Vホストのローカルドライブへのcloneを推奨します。WSL上のcloneを `\\wsl.localhost` 経由で使う場合、ゲストへの直接転送が失敗したときだけホストのローカル一時コピーから再試行します。管理者PowerShellで実行します。

```powershell
git clone https://github.com/karanabe/windows-ad-lab.git
Set-Location .\windows-ad-lab
Set-ExecutionPolicy -Scope Process Bypass

.\scripts\host\New-LabVm.ps1 `
    -IsoPath '<Windows-Server-2025評価版ISOのパス>' `
    -ExternalSwitchName '<Windows-Updateに使う既存スイッチ>'
```

VMコンソールでWindows Serverをインストールし、ローカルAdministratorのパスワードを設定・保管します。認証または評価版の状態確認とWindows Updateを済ませ、必要な再起動後にAdministratorで一度サインインします。その後、次を実行します。

```powershell
.\scripts\host\Set-VMNetwork.ps1
.\scripts\host\New-LabBaseCheckpoint.ps1
.\scripts\host\Invoke-ValidatedLabSetup.ps1
```

最後のコマンドでは、**インストール時に設定したローカルAdministratorのパスワード**、DSRMのパスワード、新規ラボユーザー用のパスワードをそれぞれ入力します。forest昇格後の `LAB\Administrator` はローカルAdministratorと同じパスワードです。構築を検証し、`02-Baseline` から `06-ADCS-HTTP-CDP` までのcheckpointを作成します。出荷構成のタイムゾーンにはホストの `(Get-TimeZone).Id` を使います。無人実行が必要な場合だけ、Git対象外の `config/LabSecrets.psd1` を使用します。

## 更新とシナリオ実行

```powershell
git pull --ff-only
.\scenarios\Restore-LabBaseline.ps1 -WhatIf
.\scenarios\Invoke-Scenario.ps1 -ScenarioName 'esc1' -AcknowledgeIsolatedLabRisk
```

`git pull` はホスト上のcloneを更新します。シナリオrunnerは実行時に対象シナリオをゲストへコピーします。bootstrapのゲスト用スクリプトは構築を再実行した時にコピーされます。取得だけで既存forestの設定は変わりません。旧ドメインで構築したラボは、forest作成前の `01-Updated` から再構築します。

詳しくは[構築・復旧手順](docs/setup.ja.md)、[シナリオ一覧](scenarios/README.ja.md)、任意の[Debianクライアント接続](docs/debian-client-network.ja.md)と[LDAP接続](docs/ldap.ja.md)を参照してください。開発者向け手順は[CONTRIBUTING.ja.md](CONTRIBUTING.ja.md)にあります。

インストール後の `DC01` はPrivate Switchから外さないでください。checkpointはバックアップではありません。DCとCAの同居、新規ラボユーザー間で共通の初期パスワード、シナリオの弱い権限は隔離ラボ専用です。

## License

このプロジェクトは [MIT License](LICENSE) で公開されています。
