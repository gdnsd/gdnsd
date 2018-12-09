@   SOA  ns1 hostmaster 1 7200 30M 3D 900
@   NS   ns1
@   NS   ns2
ns1 A    192.0.2.1
ns2 A    192.0.2.2
any A    192.0.2.192
    AAAA 2001:DB8::1
    MX   0 ns1
    TXT  "example text"
