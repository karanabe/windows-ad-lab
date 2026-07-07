# ESC15 Schema V1 Template 設計書

[English](README.md)

このシナリオは、隔離された Windows Server 2025 Active Directory / AD CS ラボで、schema version 2 以降のテンプレートと ESC15 が成立する schema version 1 テンプレートの差分を理解するための教材である。既定テンプレートは変更せず、`User` テンプレートを基準にした学習用テンプレート `ESC15LabWeb` だけを追加する。

この文書は設計説明であり、GUI手順や攻撃手順は扱わない。証明書要求、Application Policy の注入、PFX 保存、証明書による認証は自動化しない。

## 使い方

Hyper-V ホスト上のリポジトリ clone をカレントにして実行します。`Invoke-Scenario.ps1` はこの clone から guest の `C:\LabBootstrap\scenarios` へ同期します。通常は `-SkipSync` を指定しません。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc15' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc15' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc15' `
    -Action Cleanup
```

## Certificate Template の schema version

Certificate Template は、Enterprise CA が証明書要求を処理するときに参照する AD DS 上のポリシーオブジェクトである。`msPKI-Template-Schema-Version` が 1 のテンプレートは古い形式であり、`msPKI-Certificate-Application-Policy` による利用目的の強制を持たない。

Certificate Templates MMC で既存テンプレートを複製すると、通常は schema version が 2 以降になる。このシナリオは LDAP 上に schema version 1 の学習用オブジェクトを明示作成する。既定の `WebServer` を変更しない。Windows Server 2025 の既定 `WebServer` は schema version 2 であることが多いため、古典的な ESC15 条件を観察するには専用テンプレートが必要になる。

参考資料:

- Microsoft Learn: Certificate templates concepts
  https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts
- TrustedSec: EKUwu: Not just another AD CS ESC
  https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc
- Microsoft: CVE-2024-49019
  https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019

## ESC15 成立条件

ESC15 は、1つの schema version 1 テンプレートに次の条件が同時に揃うと成立する。

- テンプレートの schema version が 1 である。
- `msPKI-Certificate-Application-Policy` が空である。schema v1 は Application Policy を強制しない。
- 低権限ユーザーまたは広いグループが、そのテンプレートに対する Enroll 権限を持つ。
- Subject Name が `Supply in the request` であり、要求者が Subject または SAN を指定できる。
- CA manager approval が不要である。
- authorized signatures が 0 である。
- Enterprise CA がそのテンプレートを発行対象として公開している。

テンプレート本体の EKU が Client Authentication である必要はない。未パッチの CA では、要求者が CSR に Application Policy を入れて Client Authentication や Certificate Request Agent を足せる点が ESC1 との違いである。この学習用テンプレートは Server Authentication `1.3.6.1.5.5.7.3.1` だけを持ち、認証 EKU は置かない。

このラボの OS は Windows Server 2025 であり、2024年11月の CA 修正（CVE-2024-49019）を含む。validation はテンプレート条件の静的確認であり、要求指定の Application Policy が発行されることの証明ではない。

## 各 Template 設定の意味

`msPKI-Template-Schema-Version` はテンプレート世代を表す。1 のとき、CA は `pKIExtendedKeyUsage` を主な利用目的として扱い、v2 以降の Application Policy 属性を強制しない。

`pKIExtendedKeyUsage` はこの学習用テンプレートでは Server Authentication のみである。認証用途ではないため、同じ条件でも ESC1 にはならない。

`msPKI-Certificate-Application-Policy` は v2 以降でテンプレート側の利用目的を固定する属性である。schema v1 では空のままにする。未パッチ CA では、要求内の Application Policy が発行証明書へコピーされ得た。パッチ後の CA は、schema v1 要求に含まれる Application Policy を無視する。

`msPKI-Certificate-Name-Flag` の `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` は、要求者が Subject / SAN を供給できることを表す。ESC15 の古典的な確認対象は、このフラグと schema v1 の組み合わせである。

`nTSecurityDescriptor` 上の Certificate-Enrollment extended right は、誰がそのテンプレートで証明書を要求できるかを決める。広いグループに Enroll を与えると、確認対象の利用者範囲も広がる。

`msPKI-Enrollment-Flag` の `CT_FLAG_PEND_ALL_REQUESTS` と `msPKI-RA-Signature` は発行ゲートである。どちらも無い場合、ほかの制約がなければ要求は自動処理される。

CA Publish 状態は、CA の `pKIEnrollmentService` オブジェクトの `certificateTemplates` にテンプレート名が含まれるかで判断できる。

参考資料:

- MS-WCCE: Certificate.Template.msPKI-Certificate-Name-Flag
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/cf805c29-6f58-4087-a395-3d0233a89f3c
- MS-WCCE: msPKI-Enrollment-Flag
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9cc7ba15-fcbc-48b3-8a3b-121faef3d5ef
- Microsoft Defender for Identity: Prevent Certificate Enrollment with arbitrary Application Policies (ESC15)
  https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates

## なぜ既定設定だけでは教材にならないのか

Microsoft 既定の `User` テンプレートは schema version 1 だが、Client Authentication を含む。Subject を要求者指定にすると ESC1 と重なり、ESC15 固有の「テンプレート EKU を超えて利用目的を足せる」点が分かりにくくなる。

既定の `WebServer` は、古い環境では schema v1 かつ `Supply in the request` であり、TrustedSec の説明でも代表例になる。ただし既定の Enroll は管理者グループに閉じていることが多く、このラボの Server 2025 では schema v2 になっていることもある。既定テンプレートは変更せず、同じ条件を学習用オブジェクトへ閉じる。

## Microsoft Best Practice

本番では、用途に合わせて schema v2 以降のカスタムテンプレートを使い、`msPKI-Certificate-Application-Policy` で利用目的を固定する。使っていない schema v1 テンプレートは CA の公開一覧から外す。Certificate Templates MMC で複製すると schema version が上がるため、意図せず v1 を複製し続ける必要はない。

低権限主体へ Enroll を与えるテンプレートで `Supply in the request` を使わない。どうしても要求者指定 Subject が必要な場合は、Enroll を専用グループへ限定し、manager approval や authorized signatures を検討する。

AD CS サーバーへ CVE-2024-49019 を適用する。パッチは発行時の Application Policy 注入を止めるが、広い Enroll と要求者指定 Subject を持つ v1 テンプレート自体は残る。テンプレート条件の棚卸しと CA パッチは両方必要である。

参考資料:

- Microsoft Defender for Identity: Certificates security posture assessment
  https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates

## ESC1 との違い

ESC1 は、テンプレート自体が認証 EKU を持ち、要求者が Subject / SAN を供給できる設定不備である。中心は `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` と Client Authentication などの認証 EKU である。このラボの `esc1` は schema version 2 の学習用テンプレートを追加する。

ESC15 は、テンプレート EKU が認証用途でなくても、schema v1 であるがゆえに要求側 Application Policy が発行へ影響し得た問題である。中心は `msPKI-Template-Schema-Version = 1` と空の Application Policy である。この学習用テンプレートは Server Authentication のみを持ち、認証 EKU は置かない。

パッチ済み CA では ESC15 の発行経路は止まる。同じテンプレート条件でも、ESC1 のようにテンプレート EKU だけで認証証明書になるわけではない。

Kerberos PKINIT は主に Extended Key Usage を見る。Application Policy だけが追加された証明書は、Schannel / LDAPS 側の評価と PKINIT 側の評価が分かれる場合がある。このシナリオはその差を観察するための設定教材であり、認証試験は行わない。

## BloodHound ではどのように見えるか

AD CS 収集では、schema version 1 かつ enrollee supplies subject の公開テンプレートが ESC15 条件として分類されることがある。`ADCSESC1` とは別に、テンプレート EKU ではなく schema v1 と Application Policy の扱いを見る後処理である。

収集ツールが見るのはテンプレート条件である。このラボの CA がパッチ済みでも、条件そのものは残る。

## Microsoft 既定 Template と学習用 Template の差分

| 項目 | Microsoft既定Template `User` | 学習用Template `ESC15LabWeb` | ESC15への意味 |
|---|---|---|---|
| テンプレート種別 | Microsoft既定の組み込みテンプレート | ラボ専用の新規カスタムテンプレート | 既定テンプレートは変更せず、差分を新規オブジェクトに閉じる |
| Template schema | 既定の `User` は schema version 1 | schema version 1 を明示維持する | Application Policy 強制がない世代を観察できる |
| EKU | Client Authentication などを含む | Server Authentication のみ | テンプレート EKU だけでは ESC1 にならない |
| Application Policy | 通常は空 | 空のまま維持する | v1 では要求側 Application Policy をテンプレート属性で固定できない |
| Subject Name | ADからSubjectを構成し、要求者指定Subjectを前提にしない | `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` のみを設定 | 要求者が任意のSubject/SANを要求に入れられる |
| Enroll ACE | 既定テンプレート自体には新しいACEを追加しない | `Domain Users` に Certificate-Enrollment を明示付与 | 低権限ユーザーが学習用テンプレートで enrollment できる |
| CA発行テンプレート一覧 | 既定の `User` テンプレート公開状態はそのまま | CAの `certificateTemplates` に `ESC15LabWeb` を追加 | 学習用テンプレートが実際にCAで発行対象になる |
| Enterprise OID | 既定テンプレート既存のOID | 学習用テンプレート用に新規OIDを登録 | カスタムテンプレートとして識別、cleanupで対応OIDだけ削除できる |
