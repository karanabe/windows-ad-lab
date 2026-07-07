# Windows以外のクライアントからのLDAP接続

[English](ldap.md)

このラボではTCP 389のKerberos SASLでLDAPに接続します。[Debianクライアント接続](debian-client-network.ja.md)を済ませ、`krb5-user`、`ldap-utils`、`libsasl2-modules-gssapi-mit` を導入してください。`dig _kerberos._udp.ad.lab.exceeds.test SRV` でDCが返ることを確認します。

一時的なKerberos設定で、AD DNS名とrealmを対応付けます。

```text
[libdefaults]
    default_realm = AD.LAB.EXCEEDS.TEST
    dns_lookup_kdc = true
    dns_canonicalize_hostname = false
    rdns = false

[domain_realm]
    .ad.lab.exceeds.test = AD.LAB.EXCEEDS.TEST
    ad.lab.exceeds.test = AD.LAB.EXCEEDS.TEST
```

リポジトリの外に保存して `KRB5_CONFIG` に指定し、ラボアカウントで確認します。

```bash
export KRB5_CONFIG=/tmp/krb5-adlab.conf
kinit yagami@AD.LAB.EXCEEDS.TEST
klist
ldapsearch -N -H ldap://dc01.ad.lab.exceeds.test:389 -Y GSSAPI -O minssf=1 -b 'DC=ad,DC=lab,DC=exceeds,DC=test' '(objectClass=domain)' dn
```

`Server not found in Kerberos database` が出る場合は、`KRB5_TRACE=/dev/stderr ldapsearch ...` で要求されたサービス名を確認します。`ldap/dc01.ad.lab.exceeds.test` になっていたら、[Debianクライアント接続](debian-client-network.ja.md)の `/etc/hosts` を `.test` に修正してください。

GSSAPIのbindとSASL security strengthが0より大きいことを確認します。LDAPS用のDC証明書はこのラボでは自動構築されません。
