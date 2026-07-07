# LDAP from a non-Windows client

[日本語](ldap.ja.md)

This lab connects to LDAP on TCP 389 with Kerberos SASL. Complete [Debian client connection](debian-client-network.md) and install `krb5-user`, `ldap-utils`, and `libsasl2-modules-gssapi-mit`. Confirm that `dig _kerberos._udp.ad.lab.exceeds.test SRV` returns the DC.

A temporary Kerberos configuration can map the AD DNS name to its realm:

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

Save it outside the repository, set `KRB5_CONFIG` to that file, and test with a lab account:

```bash
export KRB5_CONFIG=/tmp/krb5-adlab.conf
kinit yagami@AD.LAB.EXCEEDS.TEST
klist
ldapsearch -N -H ldap://dc01.ad.lab.exceeds.test:389 -Y GSSAPI -O minssf=1 -b 'DC=ad,DC=lab,DC=exceeds,DC=test' '(objectClass=domain)' dn
```

If `Server not found in Kerberos database` occurs, use `KRB5_TRACE=/dev/stderr ldapsearch ...` to inspect the requested service name. If it becomes `ldap/dc01.ad.lab.exceeds.test`, correct `/etc/hosts` to `.test` as shown in [Debian client connection](debian-client-network.md).

Check that the bind uses GSSAPI and reports a SASL security strength greater than zero. The lab does not automatically configure a DC certificate for LDAPS.
