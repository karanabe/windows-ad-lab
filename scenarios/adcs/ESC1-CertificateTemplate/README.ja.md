# ESC1 Certificate Template 設計書

[English](README.md)

このシナリオは、隔離された Windows Server 2025 Active Directory / AD CS ラボで、Microsoft 既定設定と ESC1 が成立する Certificate Template の差分を理解するための教材である。既定テンプレートは変更せず、`User` テンプレートを基準にした学習用テンプレート `ESC1LabUser` だけを追加する。

この文書は設計説明であり、GUI手順や攻撃手順は扱わない。

## 使い方

Hyper-V ホスト上のリポジトリ clone をカレントにして実行します。`Invoke-Scenario.ps1` はこの clone から guest の `C:\LabBootstrap\scenarios` へ同期します。通常は `-SkipSync` を指定しません。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ESC1-CertificateTemplate' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ESC1-CertificateTemplate' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'ESC1-CertificateTemplate' `
    -Action Cleanup
```

## Certificate Template とは何か

Certificate Template は、Enterprise CA が証明書要求を処理するときに参照する AD DS 上のポリシーオブジェクトである。Configuration パーティション配下の `CN=Certificate Templates,CN=Public Key Services,CN=Services,...` に格納され、証明書の用途、鍵の用途、Subject Name の作り方、発行要件、登録権限を定義する。

テンプレートは、CA側の発行ポリシーであると同時に、クライアントがどのような要求を作るべきかを示す入力仕様でもある。Enterprise CA だけがテンプレートに基づく証明書発行を行う。テンプレートを作成しただけでは発行対象にならず、対象CAの発行テンプレート一覧に追加されて初めて enrollment の対象になる。

参考資料:

- [Microsoft Learn: Certificate templates concepts](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts)
- [Microsoft Learn: Manage certificate templates](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/manage-certificate-templates)
- [Microsoft Learn: Add-CATemplate / Get-CATemplate / Remove-CATemplate](https://learn.microsoft.com/en-us/powershell/module/adcsadministration/add-catemplate)

## ESC1 成立条件

ESC1 は、1つの証明書テンプレートに次の条件が同時に揃うと成立する。

- 低権限ユーザーまたは広いグループが、そのテンプレートに対する Enroll 権限を持つ。
- Subject Name が `Supply in the request` であり、要求者が Subject または SAN を指定できる。
- Client Authentication、Smart Card Logon、PKINIT Client Authentication、Any Purpose のような認証用途の EKU がある。
- CA manager approval が不要である。
- authorized signatures が 0 である。
- Enterprise CA がそのテンプレートを発行対象として公開している。

このシナリオでは、`ESC1LabUser` に `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` を設定し、`Domain Users` に Enroll を許可し、Client Authentication EKU を持つテンプレートとして lab CA に公開する。差分は新規テンプレート、新規OID、学習用テンプレートACL、CA公開一覧への追加に閉じ、既定テンプレートは変更しない。

## 各 Template 設定の意味

`msPKI-Certificate-Name-Flag` は、発行証明書の Subject / SAN を誰が決めるかを表す。`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` が有効な場合、要求者が証明書要求内で Subject 情報を供給する。Microsoft の WCCE 仕様では、このフラグがない場合、CA は要求内の Subject 情報を無視し、AD から要求者の属性を使って Subject を構成する。

`pKIExtendedKeyUsage` と `msPKI-Certificate-Application-Policy` は、証明書の利用目的を表す。Client Authentication EKU は、発行された証明書がクライアント認証に使われることを意味する。ESC1では、この認証用途と要求者指定Subjectが組み合わさる点が重要である。

`nTSecurityDescriptor` 上の Certificate-Enrollment extended right は、誰がそのテンプレートで証明書を要求できるかを決める。広いグループに Enroll を与えると、攻撃可能な利用者の範囲も広がる。

`msPKI-Enrollment-Flag` の `CT_FLAG_PEND_ALL_REQUESTS` は、CA manager approval を要求する。これが無い場合、ほかの制約がなければ要求は自動処理される。`msPKI-RA-Signature` は authorized signatures の必要数であり、0であれば登録エージェント署名を要求しない。

CA Publish 状態は、CA の `pKIEnrollmentService` オブジェクトの `certificateTemplates` にテンプレート名が含まれるかで判断できる。テンプレートがADに存在しても、CAが発行対象にしていなければ enrollment には使えない。

参考資料:

- [MS-WCCE: Certificate.Template.msPKI-Certificate-Name-Flag](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/cf805c29-6f58-4087-a395-3d0233a89f3c)
- [MS-WCCE: msPKI-Enrollment-Flag](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9cc7ba15-fcbc-48b3-8a3b-121faef3d5ef)

## なぜ既定設定では成立しないのか

Microsoft 既定の `User` テンプレートは、ユーザー向けのメール、EFS、Client Authentication 用途を持つ。低権限ユーザーが enrollment できる構成であっても、Subject Name は通常 AD 情報から構成される。つまり、要求者が任意のUPNやSANを入れて別ユーザーの証明書として発行させる設計ではない。

既定テンプレートの中には、`Supply in the request` を使うものもある。しかし、それらは用途、公開状態、対象主体、権限、EKUが異なる。ESC1は単一設定の問題ではなく、Enroll、Subject Name、認証EKU、発行ゲート、CA公開状態が同じテンプレート上で揃うことが条件である。

## Microsoft Best Practice

本番では、テンプレートは「誰が、何のために、どのCAから、どの承認条件で証明書を得るか」を明示して設計する。既定テンプレートをそのまま広く使うのではなく、用途に最も近い既定テンプレートを複製し、用途別にスコープを狭くする。

認証用途のテンプレートでは、Subject は AD から構成する。どうしても要求者が Subject を供給する必要がある場合は、Enroll 権限を専用グループへ限定し、manager approval や authorized signatures などの補完統制を設ける。Domain Users や Authenticated Users への広い Enroll は、認証EKUと組み合わせない。

CAには必要なテンプレートだけを公開する。テンプレートの作成権限、公開権限、Enroll 権限、ManageCA / ManageCertificates 権限は分離する。証明書ベース認証では、KB5014754 以降の強い証明書マッピングとSID security extensionを前提にし、`CT_FLAG_NO_SECURITY_EXTENSION` を不用意に使わない。

Microsoft Defender for Identity の AD CS 関連評価でも、広すぎる enrollment、`Supply in the request`、任意SANや任意Application Policyを許すテンプレートは是正対象になる。

参考資料:

- [Microsoft Defender for Identity: AD CS certificate enrollment assessments](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-insecure-adcs-certificate-enrollment)
- [Microsoft Support: KB5014754 certificate-based authentication changes](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)

## 企業での Template 設計

企業では、テンプレートを用途単位で分離する。ユーザー認証、端末認証、サーバーTLS、コード署名、S/MIME、Enrollment Agent、デバイス証明書を同じテンプレートに混ぜない。

各テンプレートには、所有部門、利用目的、対象CA、対象セキュリティグループ、EKU、Subject Name 方式、有効期限、更新方式、鍵保護、承認要件、監査観点を定義する。利用者はセキュリティグループで管理し、テンプレートACLへ個人や広い既定グループを直接置かない。

ライフサイクルも設計対象である。古いテンプレートは supersede し、CAの公開一覧から外し、発行済み証明書の期限と失効方針を見ながら廃止する。テンプレート変更はドメイン全体へ影響するため、変更管理とレビューの対象にする。

## BloodHound ではどのように見えるか

BloodHound CE / Enterprise の AD CS 収集では、Certificate Template、Enterprise CA、Root CA、NTAuth store などのPKI構成がグラフ化される。ESC1 条件が揃うと、低権限ユーザー、グループ、またはコンピューターから Domain へ `ADCSESC1` の攻撃パスとして見える。

`ADCSESC1` は単純なACLエッジだけではない。テンプレートに enrollment できること、Subject/SANを指定できること、認証EKUがあること、Enterprise CAがそのテンプレートを公開していること、CAが有効なAD CS階層にいることを組み合わせた後処理エッジである。

参考資料:

- [BloodHound: ADCSESC1](https://bloodhound.specterops.io/resources/edges/adcs-esc1)
- [BloodHound: SharpHound AD CS collection permissions](https://bloodhound.specterops.io/collect-data/sharphound-data-permissions)

## ESC9 との違い

ESC1 は、要求者が Subject / SAN を供給できるテンプレートに、認証EKUと広い Enroll が組み合わさる問題である。中心となる属性は `msPKI-Certificate-Name-Flag` の `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` である。

ESC9 は、証明書にSID security extensionを入れないテンプレート設定を悪用する。中心となる属性は `msPKI-Enrollment-Flag` の `CT_FLAG_NO_SECURITY_EXTENSION` である。ESC9では、弱い証明書マッピングや対象アカウントのUPN / dNSHostNameを書き換える権限など、ESC1とは別の前提が絡む。

この学習用テンプレートは ESC1 の教材であり、`CT_FLAG_NO_SECURITY_EXTENSION` は設定しない。

## Shadow Credentials との違い

Shadow Credentials は AD CS テンプレートの誤設定ではない。対象ユーザーまたはコンピューターの `msDS-KeyCredentialLink` に攻撃者が制御する公開鍵資格情報を追加し、Key Trust 型の認証材料として使う手法である。

ESC1 は「CAが証明書を発行する」問題であり、テンプレート、CA公開状態、EKU、Enroll権限が関係する。Shadow Credentials は「対象アカウントの属性に鍵資格情報を書き込む」問題であり、CAテンプレートの公開や発行処理は不要である。必要な権限も、テンプレートEnrollではなく対象オブジェクトへの書き込み権限である。

参考資料:

- [Microsoft Learn: Windows Hello for Business hybrid key trust](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/deploy/hybrid-key-trust)
- [MS-ADTS: msDS-KeyCredentialLink](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f70afbcc-780e-4d91-850c-cfadce5bb15c)

## Microsoft 既定 Template と学習用 Template の差分

| 項目 | Microsoft既定Template `User` | 学習用Template `ESC1LabUser` | ESC1への意味 |
|---|---|---|---|
| テンプレート種別 | Microsoft既定の組み込みテンプレート | ラボ専用の新規カスタムテンプレート | 既定テンプレートは変更せず、差分を新規オブジェクトに閉じる |
| Template schema | 既定の `User` テンプレート定義 | カスタムテンプレートとして schema version 2 を明示 | 新規テンプレートとして管理、削除、差分確認できる |
| Subject Name | ADからSubjectを構成し、要求者指定Subjectを前提にしない | `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` を設定 | 要求者が任意のSubject/SANを要求に入れられる |
| Enroll ACE | 既定テンプレート自体には新しいACEを追加しない | `Domain Users` に Certificate-Enrollment を明示付与 | 低権限ユーザーが学習用テンプレートで enrollment できる |
| CA発行テンプレート一覧 | 既定の `User` テンプレート公開状態はそのまま | CAの `certificateTemplates` に `ESC1LabUser` を追加 | 学習用テンプレートが実際にCAで発行対象になる |
| Enterprise OID | 既定テンプレート既存のOID | 学習用テンプレート用に新規OIDを登録 | カスタムテンプレートとして識別、cleanupで対応OIDだけ削除できる |
