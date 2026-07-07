# Windows LAPS Delegation の考え方

[English](concepts.md)


この文書は、`WindowsLAPS-Delegation` が何を検証していて、何を検証していないかを整理する補足です。操作手順は [README.md](./README.md) を参照してください。

## 結論

このシナリオでは、`john.smith` が `FILE01` という実サーバーを直接管理できるようになったわけではありません。

正確には、`john.smith` は `GG_LAPS_Helpdesk` のメンバーであり、そのグループに `FILE01` の AD computer object への広い操作権限が付いている状態です。

```text
john.smith
  └─ member of GG_LAPS_Helpdesk
       ├─ Workstations OU
       │    └─ LAPS password read permission
       │         └─ CLIENT01 の LAPS 情報を読める
       │
       └─ FILE01 computer object
            └─ GenericAll
                 └─ FILE01 の LAPS 情報を読める可能性がある
                    + LAPS 以外の属性も変更できる
```

その結果、`FILE01` の AD object に保存された `msLAPS-Password` を読み取れる可能性があります。ただし、このラボで入れている値は synthetic value です。その値は `FILE01` 上の実際のローカル Administrator password とは連動していないため、そのパスワードで `FILE01` にログインできるわけではありません。

## Windows LAPS とは何か

Windows LAPS は、Windows 端末やサーバーのローカル管理者アカウントのパスワードを端末ごとに自動生成、保存、定期変更するための機能です。LAPS は Local Administrator Password Solution の略です。

LAPS を使わず、複数端末で同じローカル Administrator password を共有すると、1台から漏れたパスワードで他の端末にも横展開される危険があります。

```text
LAPS なし

CLIENT01 Administrator = CommonPassword!
CLIENT02 Administrator = CommonPassword!
FILE01   Administrator = CommonPassword!
```

Windows LAPS では、端末ごとに異なる値を持たせます。

```text
LAPS あり

CLIENT01 Administrator = random value A
CLIENT02 Administrator = random value B
FILE01   Administrator = random value C
```

実運用では、各端末上の Windows LAPS client が概ね次を行います。

```text
1. ローカル管理者パスワードを生成する
2. 端末自身のローカルアカウントへ設定する
3. 自分自身の AD computer object へバックアップする
4. 有効期限が来たらローテーションする
```

Windows Server Active Directory へ保存する場合、LAPS 情報は通常、その端末を表す computer object の `msLAPS-*` 属性に保存されます。

```text
実サーバー FILE01
    │
    │ 自分のパスワードをバックアップ
    ▼
Active Directory
    └─ CN=FILE01,OU=Servers,...
         ├─ msLAPS-Password
         ├─ msLAPS-EncryptedPassword
         └─ msLAPS-PasswordExpirationTime
```

古い Microsoft LAPS では主に `ms-Mcs-AdmPwd` と `ms-Mcs-AdmPwdExpirationTime` を使いました。OS 組み込みの Windows LAPS では、`msLAPS-Password`、`msLAPS-EncryptedPassword`、`msLAPS-PasswordExpirationTime` などの属性を使います。Windows LAPS は、暗号化されたパスワード保存や Windows Server の DSRM password 管理も扱えます。

## OU を Workstations と Servers に分ける理由

OU を分ける主目的は、管理範囲と権限委任の境界を分けることです。

このシナリオでは、Helpdesk の役割を「一般クライアント PC のトラブル対応はするが、サーバーは管理しない」と置いています。そのため、設計上の意図は次のようになります。

| OU | LAPS password を読める主体 |
|---|---|
| Workstations | Helpdesk、Domain Admins など |
| Servers | Server Admins、Domain Admins など |
| Domain Controllers | より限定した管理者のみ |

このラボの OU 構造は概念的には次の形です。

```text
OU=Computers
├─ OU=Workstations
│   └─ CLIENT01
└─ OU=Servers
    ├─ FILE01
    └─ WEB01
```

Workstations OU だけに Helpdesk の LAPS 読み取り権限を付与すると、その ACE が配下の computer object へ継承されます。

```powershell
Set-LapsADReadPasswordPermission `
    -Identity "OU=Workstations,OU=Computers,OU=LAB,DC=..." `
    -AllowedPrincipals "LAB\GG_LAPS_Helpdesk"
```

このため、Helpdesk は `CLIENT01` の LAPS 情報を取得できますが、Servers OU 配下の `FILE01` や `WEB01` には OU-level delegation が及びません。

端末ごとに個別 ACL を付けると、設定忘れや過剰許可が起きやすくなります。OU 単位で設計すれば、端末を Workstations OU へ配置するだけで適切な権限を継承できます。

ただし、OU はそれだけで完全なセキュリティ境界になるわけではありません。OU を移動できる主体、OU の ACL を変更できる主体、GPO をリンクできる主体、個別 object に explicit ACE を追加できる主体も合わせて管理する必要があります。

## 正常な委任

このシナリオで意図した正常な委任は、Workstations OU への LAPS password read permission です。

```text
Workstations OU
  └─ GG_LAPS_Helpdesk
       └─ LAPS password read permission
```

実際の Windows LAPS 環境なら、管理端末から次のように取得します。

```powershell
Get-LapsADPassword -Identity CLIENT01 -AsPlainText
```

意図した権限関係は次のとおりです。

| 対象 | john.smith |
|---|---:|
| `CLIENT01` の LAPS 情報 | 読める |
| `FILE01` の LAPS 情報 | 読めない |
| `WEB01` の LAPS 情報 | 読めない |
| `CLIENT01` の任意属性変更 | 原則できない |
| `CLIENT01` 自体の OS 管理 | 実 LAPS password を使った場合のみ可能 |

## 何が誤設定なのか

誤設定は、`FILE01` computer object に Helpdesk group の explicit `GenericAll` ACE を追加している点です。

```text
CN=FILE01,OU=Servers,...

GG_LAPS_Helpdesk:
    GenericAll
```

`GenericAll` は、AD object に対する非常に広い権限です。一般には、その AD object への Full Control に近い権限と考えてよいです。

本来 Helpdesk は Servers OU の LAPS 情報を読めないはずです。しかし `FILE01` にだけ直接 ACE が設定されているため、OU の正常な設計を迂回します。

```text
Servers OU:
  Helpdesk delegation なし
      │
      ├─ WEB01
      │    └─ Helpdesk explicit ACE なし
      │
      └─ FILE01
           └─ Helpdesk GenericAll あり
```

つまり、OU level では安全に見えても、個別 computer object に危険な ACE がある、という教材です。

実務でも、OU 設計だけを見て「Server OU には Helpdesk 権限がないから安全」と判断すると、個別 object に直接設定された ACE を見落とす可能性があります。

## john.smith は FILE01$ を扱えるのか

「FILE01$ を扱う」という表現は、意味を分けて考える必要があります。

### AD 上の FILE01 computer object

`john.smith` は `GG_LAPS_Helpdesk` 経由で、AD 上の `FILE01` computer object を広い範囲で操作できます。

対象は次の AD object です。

```text
CN=FILE01,OU=Servers,OU=Computers,...
```

`GenericAll` によって、少なくとも次の観点が問題になります。

- 属性の読み取り
- 属性の書き換え
- ACL の変更
- SPN 関連属性の変更
- 委任関連属性の変更
- LAPS 属性の読み取り
- 他の攻撃経路につながる属性の操作

正確に何が可能かは、ACE の継承対象、ObjectType、Deny ACE、所有者、保護された object かどうかによって変わります。

### FILE01$ としての認証

`GenericAll` を持っているだけで、直ちに `LAB\FILE01$` として認証できるわけではありません。

```text
GenericAll on FILE01 object
    != 自動的に FILE01$ の認証情報を取得
```

AD object を操作できることと、computer account の秘密情報を知ってその account として認証できることは別です。

ただし、computer object の属性変更を悪用して、RBCD、SPN 操作、Shadow Credentials など別の経路へ発展させられる場合があります。そのため、`GenericAll` は LAPS の情報漏えいだけに限定されない危険な権限です。

### FILE01 のローカル管理者

現在のシナリオでは、`john.smith` は `FILE01` サーバーのローカル管理者にはなりません。

理由は、このラボで AD に入れている `msLAPS-Password` が synthetic value だからです。

```text
AD 上の synthetic msLAPS-Password
    != FILE01 上の実際の local Administrator password
```

実際の Windows LAPS client を動かしていないため、AD へ入れた値と `FILE01` のローカルアカウントは同期していません。このシナリオで実証しているのは、`john.smith` が `FILE01` の secret-like AD attribute を読めてしまう、というところまでです。実サーバーへのログインは実証していません。

## このシナリオは LAPS Delegation なのか

教材としては LAPS Delegation の範囲に入りますが、論点は2つあります。

純粋な LAPS delegation mistake は、Helpdesk に LAPS password 属性だけを読む権限を誤って付与するケースです。

```text
FILE01:
  Helpdesk に LAPS password attributes だけを読む権限
```

この場合に学ぶことは、LAPS 権限の過剰委任、機密属性の読み取り、スコープ設定ミス、OU 継承ミスです。

現在のシナリオは、`FILE01` computer object 全体に `GenericAll` を誤って付与した結果、LAPS 情報まで漏れるケースです。

```text
FILE01:
  Helpdesk に GenericAll
```

この場合に学ぶことは、computer object ACL の過剰権限、LAPS 情報漏えい、RBCD などへの発展可能性、object-level ACE の見落としです。

つまり現状は「LAPS 読み取り権限を狭く誤委任した」教材ではなく、「computer object への広い誤権限が LAPS 漏えいにもつながる」教材です。

## Synthetic 属性を使う現在のラボの位置づけ

このラボは、厳密には Windows LAPS の完全な動作検証ではありません。

目的は、Windows LAPS 属性を使った AD ACL の権限評価です。

検証できるものは次です。

- LAPS schema が存在するか
- `msLAPS-*` 属性へ値を格納できるか
- OU からの権限継承
- explicit ACE
- LAPS 情報を誰が読めるか
- 誤設定修正後に読めなくなるか

検証していないものは次です。

- ローカル管理者パスワードの実変更
- GPO による Windows LAPS 有効化
- client-side policy processing
- AD への実パスワードバックアップ
- password rotation
- encrypted LAPS password
- authorized decryptor
- 認証失敗後の自動ローテーション
- 実際の `FILE01` へのログイン

このため、このシナリオは Windows LAPS の完全な運用構成ではなく、Windows LAPS 属性を使った AD 権限委任と誤設定の検証を目的とします。Synthetic value は `FILE01` 上の local Administrator password とは連動しません。

## このシナリオで見せたい差分

最終的に比較したいのは、次の3パターンです。

```text
CLIENT01
  Workstations OU に所属
  OU-level LAPS delegation あり
  Helpdesk が読める
  => 正常な業務委任

FILE01
  Servers OU に所属
  本来は Helpdesk が読めない
  object-level GenericAll ACE あり
  => 誤設定

WEB01
  Servers OU に所属
  object-level Helpdesk ACE なし
  Helpdesk が読めない
  => 正常なサーバー保護
```

この比較で学ぶことは次の3点です。

1. OU が管理スコープを作る
2. 継承された権限と個別 ACE は別に調査する必要がある
3. LAPS は安全な機能でも、読み取り権限を誤るとローカル管理者資格情報の漏えい経路になる

特に重要なのは、`Find-LapsADExtendedRights -Identity <OU>` だけでは安心しきれないことです。OU-level delegation が安全でも、個別 computer object の explicit ACE や、広い `GenericAll` / `AllExtendedRights` が存在する可能性があります。

そのため、このラボでは OU-level LAPS 権限調査と computer object ごとの ACL 調査を組み合わせて観察します。

## 参考資料

- Microsoft Learn: Windows LAPS schema extensions reference
  https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference
- Microsoft Learn: Get started with Windows LAPS and Windows Server Active Directory
  https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory
- Microsoft Learn: LAPS PowerShell module
  https://learn.microsoft.com/en-us/powershell/module/laps/?view=windowsserver2025-ps
