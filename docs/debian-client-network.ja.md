# Debianクライアントの接続

[English](debian-client-network.md)

同じHyper-VホストのDebian VMに `AD-Internal` 用NICを追加します。外部ネットワークは既存のNICで使い、ラボ用NICにはdefault gatewayを設定しません。以下はDCが `10.10.6.10`、クライアントが `10.10.6.11/28` の例です。`10.10.6.2` は将来のedge VM用です。

```powershell
Add-VMNetworkAdapter -VMName 'DEBIAN01' -Name 'AD-Internal' -SwitchName 'AD-Internal'
```

Debian側で `ip -br link` を実行し、NIC名を確認します。ifupdownを使う場合は `/etc/network/interfaces` に追加します。ここでは `eth2` の例です。

```text
allow-hotplug eth2
iface eth2 inet static
  address 10.10.6.11
  netmask 255.255.255.240
  dns-nameservers 10.10.6.10
  dns-search ad.lab.exceeds.test
```

`dns-nameservers` と `dns-search` は動作した設定に合わせて記載しています。DNSの振り分けは後述の `dnsmasq` が行うため、`/etc/resolv.conf` が `127.0.0.1` のままになることを確認してください。NICの設定変更後は `sudo ifdown eth2`、続いて `sudo ifup eth2` で反映します。初回は `sudo ifup eth2` のみ実行します。

外部DNSとAD DNSを同時に使うため、`sudo apt install dnsmasq` を実行し、`/etc/dnsmasq.d/adlab.conf` に次を設定します。`no-resolv` はローカルDNS自身を上流として読み込むことを防ぎます。

```text
no-resolv
listen-address=127.0.0.1
bind-interfaces
server=/ad.lab.exceeds.test/10.10.6.10
server=1.1.1.1
server=1.0.0.1
```

`sudo systemctl enable dnsmasq` と `sudo systemctl restart dnsmasq` で反映します。`/etc/resolv.conf` は次の内容にします。

```text
nameserver 127.0.0.1
search ad.lab.exceeds.test
```

`/etc/resolv.conf` がDHCPなどで自動更新される場合は、その管理元で `127.0.0.1` を設定します。公開DNSとDCを `nameserver` に並べても、ADドメインの問い合わせ先は振り分けられません。

以前の `.jp` 名がKerberosの接続先として使われないよう、`/etc/hosts` の古い行を次に置き換えます。

```text
10.10.6.10     DC01.ad.lab.exceeds.test ad.lab.exceeds.test DC01
```

最後にADと外部の名前解決を確認します。

```bash
ip route get 10.10.6.10
dig _kerberos._udp.ad.lab.exceeds.test SRV
getent hosts dc01.ad.lab.exceeds.test
getent hosts debian.org
```

KerberosとLDAPの確認は[LDAP接続](ldap.ja.md)を参照してください。
