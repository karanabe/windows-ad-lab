# PKINIT KDC Certificate

[English](README.md)

このシナリオは、完成済みの `06-ADCS-HTTP-CDP` から分岐し、DC01 に PKINIT 用の KDC 証明書を明示発行する。Base checkpoint には昇格しない。LDAPS もこのシナリオでは扱わない。

目的は、KDC が証明書ベース認証に使える証明書を持つ状態を、Windows 標準ツールだけで確認できるところまで整えることである。ユーザー証明書を使った AS-REQ / AS-REP の実PKINIT認証は、今回は自動化しない。

## 使い方

Hyper-V ホスト上のリポジトリ clone をカレントにして実行します。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'PKINIT-KDCCertificate' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'PKINIT-KDCCertificate' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'PKINIT-KDCCertificate' `
    -Action Cleanup
```

既定値は次のとおり。

| 項目 | 値 |
|---|---|
| Scenario | `PKINIT-KDCCertificate` |
| Lab template | `LAB-PKINIT-KDCAuthentication` |
| Source template | `KerberosAuthentication` |
| Enroll principal | `Domain Controllers` |
| Certificate store | `Cert:\LocalMachine\My` |
| CA | local active CA, usually `LAB-ROOT-CA` |

`setup.ps1`、`validate.ps1`、`cleanup.ps1` は `-CACommonName` と `-Server` を受け取れる。通常の単一DCラボでは指定しない。

## 構成内容

`setup.ps1` は、組み込み `KerberosAuthentication` テンプレートを基準に、ラボ専用テンプレート `LAB-PKINIT-KDCAuthentication` を作成する。作成したテンプレートと OID オブジェクトには `windows-ad-lab:PKINIT-KDCCertificate` の marker を付ける。

テンプレートは、KDC Authentication EKU を保持し、Subject/SAN を要求者指定にしない。Enroll 権限は `Domain Controllers` に付与し、ラボCAの発行テンプレート一覧へ追加する。その後、DC01 の machine context で `certreq.exe -enroll -machine` を実行し、証明書を `Cert:\LocalMachine\My` に入れる。

既に同じテンプレートOIDのPKINIT-readyな証明書が1枚だけ存在する場合、再発行しない。複数枚ある場合や、同じテンプレートの証明書があるが秘密鍵、EKU、期限、DC名の条件を満たさない場合は、重複発行せず停止する。

新しい証明書を発行した場合だけ、KDCサービスを再起動して証明書選択を再評価させる。

## Validation

`validate.ps1` は次を確認する。

- source template `KerberosAuthentication` が存在する
- lab template が存在し、scenario marker と有効な template OID を持つ
- template が KDC Authentication EKU を含む
- template が request-supplied subject になっていない
- template が manager approval や authorized signature を要求しない
- `Domain Controllers` に Enroll 権限がある
- lab CA が template を発行対象にしている
- `Cert:\LocalMachine\My` に同じ template OID の有効な証明書が1枚だけある
- 証明書が private key と KDC Authentication EKU を持つ
- 証明書の DNS SAN または Subject に `dc01.ad.lab.exceeds.test` が含まれる
- 証明書チェーンと失効確認が成功する
- `certutil -DCInfo <domain> Verify` が成功する

これはPKINIT-readyなKDC証明書の検証であり、ユーザー証明書を使ったTGT取得そのものの検証ではない。

## Cleanup

`cleanup.ps1` は、scenario marker が付いたテンプレートだけを削除対象にする。marker がない同名テンプレートが存在する場合は停止する。

削除対象は次に限定する。

- lab template OID と一致する `Cert:\LocalMachine\My` の証明書
- lab CA の template 公開設定
- lab template
- scenario marker または lab template OID に一致する OID オブジェクト
- `C:\ProgramData\ADLabBootstrap\Scenarios\PKINIT-KDCCertificate` の state / temporary files

証明書を削除した場合だけ、KDCサービスを再起動する。

## 境界

このシナリオはPKINITのDC側準備であり、攻撃手順、ユーザー証明書の発行、PFX保存、外部PKINITツールの実行は扱わない。将来、実AS-REQ/TGT検証を追加する場合は、専用ユーザーと一時PFXを使う別シナリオとして追加する。

参考資料:

- Microsoft Learn: Certificate requirements and enumeration
  https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration
- Microsoft Learn: certreq
  https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1
- Microsoft Learn: certutil
  https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
