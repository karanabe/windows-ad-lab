# Connect a Debian client

[日本語](debian-client-network.ja.md)

Add an `AD-Internal` NIC to a Debian VM on the same Hyper-V host. Keep the existing NIC for external access and do not set a default gateway on the lab NIC. This example uses `10.10.6.10` for the DC and `10.10.6.11/28` for the client. `10.10.6.2` is reserved for a future edge VM.

```powershell
Add-VMNetworkAdapter -VMName 'DEBIAN01' -Name 'AD-Internal' -SwitchName 'AD-Internal'
```

Run `ip -br link` on Debian to check the NIC name. With ifupdown, add this configuration to `/etc/network/interfaces`, replacing `eth2` if necessary:

```text
allow-hotplug eth2
iface eth2 inet static
  address 10.10.6.11
  netmask 255.255.255.240
  dns-nameservers 10.10.6.10
  dns-search ad.lab.exceeds.test
```

The `dns-nameservers` and `dns-search` lines reflect the working configuration. `dnsmasq` handles domain routing below, so confirm that `/etc/resolv.conf` remains set to `127.0.0.1`. After changing the NIC configuration, run `sudo ifdown eth2` and then `sudo ifup eth2`. For the initial setup, only `sudo ifup eth2` is needed.

To use external and AD DNS at the same time, run `sudo apt install dnsmasq` and create `/etc/dnsmasq.d/adlab.conf` with these settings. `no-resolv` prevents the local DNS server from reading itself as an upstream server.

```text
no-resolv
listen-address=127.0.0.1
bind-interfaces
server=/ad.lab.exceeds.test/10.10.6.10
server=1.1.1.1
server=1.0.0.1
```

Apply this with `sudo systemctl enable dnsmasq` and `sudo systemctl restart dnsmasq`. Set `/etc/resolv.conf` to:

```text
nameserver 127.0.0.1
search ad.lab.exceeds.test
```

If DHCP or another service updates `/etc/resolv.conf`, configure that service to use `127.0.0.1`. Listing public DNS servers alongside the DC as `nameserver` entries does not route AD queries by domain.

Replace any old `.jp` line in `/etc/hosts` with this `.test` entry so Kerberos uses the intended service name:

```text
10.10.6.10     DC01.ad.lab.exceeds.test ad.lab.exceeds.test DC01
```

Check AD and external name resolution:

```bash
ip route get 10.10.6.10
dig _kerberos._udp.ad.lab.exceeds.test SRV
getent hosts dc01.ad.lab.exceeds.test
getent hosts debian.org
```

For Kerberos and LDAP checks, see [LDAP connection](ldap.md).
