# KeyCredentialLink 属性の観察・比較

[English](README.md)

このシナリオは `06-ADCS-HTTP-CDP` から分岐して、`msDS-KeyCredentialLink`、AD オブジェクト属性、ACL、所有者、PowerShell から見える情報、LDAP から見える情報を比較するための教材です。Baseline の既存ユーザー、既存グループ、証明書 Template、CA 公開設定は変更しません。

## 使い方

Hyper-V ホスト上のリポジトリ clone をカレントにして実行します。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'KeyCredentialLink-Observation' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'KeyCredentialLink-Observation' `
    -Action Validate

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'KeyCredentialLink-Observation' `
    -Action Cleanup
```

`setup.ps1` は専用 OU と無効化された学習専用ユーザーだけを追加します。`kcl.sample` には観察用の `msDS-KeyCredentialLink` 値を 1 つ追加しますが、秘密鍵は保存せず、アカウントも無効のままです。これは認証手順を再現する教材ではなく、属性と ACL の見え方を比較する教材です。

## msDS-KeyCredentialLink とは何か

`msDS-KeyCredentialLink` は、公開鍵に関するキー マテリアルと用途情報を保持する AD 属性です。Microsoft の AD schema 仕様では `ldapDisplayName` が `msDS-KeyCredentialLink`、`attributeID` が `1.2.840.113556.1.4.2328`、`schemaIdGuid` が `5b47d60f-6090-40b2-9f37-2a4de88f3063` の複数値属性として定義されています。値は DN-Binary 形式で、`B:[keylen]:[key]:[objectDN]` という形を取ります。

参考: [MS-ADA2: msDS-KeyCredentialLink](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/45916e5b-d66f-444e-b1e5-5b0666ed4d66)、[MS-KPP: ms-DS-Key-Credential-Link](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kpp/e6a6634c-f395-46a7-8100-1eb12dd2b8e3)

## Windows Hello for Business との関係

Windows Hello for Business は、プロビジョニング時にデバイス上で公開鍵と秘密鍵のペアを生成し、公開鍵を ID プロバイダーへ登録します。ハイブリッド key trust では、Microsoft Entra Connect Sync が Windows Hello for Business 資格情報の公開鍵をユーザー オブジェクトの `msDS-KeyCredentialLink` に同期します。key trust はオンプレミス認証用のクライアント証明書を必要としませんが、ドメイン コントローラー証明書を含む PKI が必要です。

参考: [Windows Hello for Business のしくみ](https://learn.microsoft.com/ja-jp/windows/security/identity-protection/hello-for-business/how-it-works)、[Hybrid key trust deployment guide](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/deploy/hybrid-key-trust)

## KeyCredential とは何か

KeyCredential は、`msDS-KeyCredentialLink` の DN-Binary 値のバイナリ部分に入る `KEYCREDENTIALLINK_BLOB` です。Blob は version と複数の entry から構成され、entry は `KeyID`、`KeyHash`、`KeyMaterial`、`KeyUsage`、`KeySource`、`DeviceId`、`KeyCreationTime` などを持ちます。`KeyUsage` の `KEY_USAGE_NGC` は Windows Hello for Business の Next Generation Credential 用途を示し、`KeySource` の `KEY_SOURCE_AD` は AD 由来のキーであることを示します。

このシナリオの `setup.ps1` は PowerShell と .NET 暗号 API だけで 2048-bit RSA 公開鍵を作成し、公開鍵部分だけを `KEY_USAGE_NGC` / `KEY_SOURCE_AD` の観察用 blob として保存します。

参考: [KEYCREDENTIALLINK_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f3f01e95-6d0c-4fe6-8b43-d585167658fa)、[KEYCREDENTIALLINK_ENTRY Identifiers](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a99409ea-4982-4f72-b7ef-8596013a36c7)、[Key Credential Link Constants](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d4b9b239-dbe8-4475-b6f9-745612c64ed0)

## 属性が追加される仕組み

通常運用では、Windows Hello for Business のプロビジョニングでユーザーの公開鍵が登録されます。ハイブリッド key trust では、Microsoft Entra ID 側に登録された公開鍵が Microsoft Entra Connect Sync の同期サイクルでオンプレミス AD の `msDS-KeyCredentialLink` に書き込まれます。Microsoft のプロビジョニング資料では、この同期が完了するまでユーザーは Windows Hello for Business でオンプレミス AD にサインインできないと説明されています。

この教材では、Entra ID や Entra Connect を使わず、属性観察だけを目的に `Set-ADObject -Add @{ msDS-KeyCredentialLink = ... }` で学習専用ユーザーへ値を追加します。

参考: [How Windows Hello for Business provisioning works](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/how-it-works-provisioning)

## どのような運用で利用されるか

主な用途は、Windows Hello for Business の key trust や関連するデバイス登録/公開鍵マッピングです。ユーザーまたはコンピューターに紐づいた公開鍵を AD に保持し、KDC や ID 基盤が対応する秘密鍵の所有を検証できるようにします。

この属性は認証境界に近い属性なので、通常の人事属性や説明属性と同じ感覚で委任してはいけません。特に特権アカウントや Tier 0 コンピューターでは、誰がこの属性を書けるかを明示的に把握する必要があります。

## リスクになる権限委任

次のような委任は、`msDS-KeyCredentialLink` に対する不正な書き込みや永続化につながる可能性があります。

- ユーザーまたはコンピューター オブジェクトへの `GenericAll`
- ユーザーまたはコンピューター オブジェクトへの `GenericWrite`
- 全属性への `WriteProperty`
- `msDS-KeyCredentialLink` の schema GUID `5b47d60f-6090-40b2-9f37-2a4de88f3063` への明示的な `WriteProperty`
- `WriteDacl` または `WriteOwner` の委任
- 特権アカウントを含む OU に対する広すぎる継承 ACE

`validate.ps1` は、対象オブジェクトの ACL からこれらの観点で危険になり得る ACE を `ACL risk view` として抽出します。

## Microsoft が推奨する運用

Microsoft は Windows Hello for Business の計画資料で、key trust と比較して cloud Kerberos trust を推奨モデルとしています。cloud Kerberos trust はユーザー公開鍵を AD に同期する必要がなく、PKI 変更も不要なため、要件に合う場合は優先候補です。

Windows Hello for Business を GPO で展開する場合、Microsoft はセキュリティ グループ フィルターによる段階展開を推奨しています。また cloud Kerberos trust の展開ガイドでは、`Use a hardware security device` を任意だが推奨の設定として扱っています。高権限アカウントについては、AzureADKerberos コンピューター オブジェクトの Password Replication Policy を緩めないよう注意が示されています。

参考: [Plan a Windows Hello for Business deployment](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/deploy/)、[Cloud Kerberos trust deployment guide](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/deploy/hybrid-cloud-kerberos-trust)

## 監査イベント

Baseline 06 では `Directory Service Changes` の成功監査が有効です。ただし、属性単位の 5136 を確実に残すには対象オブジェクトの SACL 設計も必要です。

観察対象の主なイベントは次のとおりです。

| Event ID | 意味 | このシナリオで見る観点 |
| --- | --- | --- |
| 5136 | AD オブジェクトが変更された | `AttributeLDAPDisplayName=msDS-KeyCredentialLink`、`OperationType=Value Added`、`ObjectDN`、`SubjectUserName` |
| 5137 | AD オブジェクトが作成された | 専用 OU と学習ユーザーの作成 |
| 5141 | AD オブジェクトが削除された | cleanup による専用 OU と学習ユーザーの削除 |

参考: [Audit Directory Service Changes](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-directory-service-changes)、[5136(S): A directory service object was modified](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136)

## Defender for Identity で観察できる内容

Microsoft Defender for Identity はオンプレミス AD と Microsoft Entra ID などの identity signal を監視し、ID ベース攻撃の検出、調査、対応コンテキストを Microsoft Defender ポータルへ提供します。Security posture assessment では AD CS、Group Policy、Accounts、Hybrid security などのカテゴリで構成不備と修復パスを提示します。

Microsoft の Defender for Identity AD CS sensor 紹介記事では、`msDS-KeyCredentialLink` を編集できる権限があると任意の公開鍵を追加してアカウント乗っ取りに悪用され得ること、および Shadow Credentials 技術の悪用検出に Defender for Identity が対応していることが説明されています。ラボでは、`msDS-KeyCredentialLink` の変更主体、変更対象、時刻、対象アカウントの感度、ACL 上の委任関係をあわせて観察します。

参考: [Microsoft Defender for Identity overview](https://learn.microsoft.com/en-us/defender-for-identity/what-is)、[Microsoft Defender for Identity security posture assessments](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment)、[Securing AD CS: Microsoft Defender for Identity's Sensor Unveiled](https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/securing-ad-cs-microsoft-defender-for-identitys-sensor-unveiled/3980265)

## Baseline との差分

| 種別 | DN / 名前 | Baseline 06 | シナリオ適用後 |
| --- | --- | --- | --- |
| OU | `OU=KeyCredentialLink-Lab,OU=LAB,DC=ad,DC=lab,DC=exceeds,DC=jp` | 存在しない | 追加。`adminDescription=windows-ad-lab:KeyCredentialLink-Observation` |
| User | `CN=KCL Sample User,OU=KeyCredentialLink-Lab,OU=LAB,DC=ad,DC=lab,DC=exceeds,DC=jp` / `kcl.sample` | 存在しない | 追加。無効アカウント。観察用 `msDS-KeyCredentialLink` 1 値 |
| User | `CN=KCL Control User,OU=KeyCredentialLink-Lab,OU=LAB,DC=ad,DC=lab,DC=exceeds,DC=jp` / `kcl.control` | 存在しない | 追加。無効アカウント。`msDS-KeyCredentialLink` なし |
| Certificate Template | 既存 Template 全体 | Baseline 06 のまま | 変更なし |
| 既存 User / Group | Baseline 06 の既存オブジェクト | Baseline 06 のまま | 変更なし |
| CA / AD CS 公開設定 | `LAB-ROOT-CA` と公開 Template | Baseline 06 のまま | 変更なし |
