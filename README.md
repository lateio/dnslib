dnslib
=====

dnslib provides tools for working with Domain Name System (DNS; RFCs 1034 and 1035) in Erlang. dnslib mainly facilitates working with DNS messages, master files and other related data types.

Note that since dnslib restricts itself to dealing with DNS wire format and master files, compliance with one RFC or another simply means that dnslib can take data described in a DNS master file, translate it to an internal representation, then translate it into the DNS wire format. Or in reverse, dnslib can translate DNS wire format to an internal representation and potentially even produce a master file representation based on the data.

Thus dnslib claiming compliance a spec does not necessarily mean that merely using dnslib is enough for compliance. Obvious example is the CNAME resource type defined by RFCs 1034 and 1035. Although dnslib understands CNAME in various formats, it does not include any clues about how encountering a CNAME record is to affect a query for a resource. Thus full compliance with different specs might require implementing functionality not included in dnslib.

Documentation for dnslib is currently (version 0.0.0) non-existent. Rectifying the lack of documentation is one of the main goals of 0.0.1.


Compliance
----------
dnslib claims to be compliant with the following specifications:
* Original DNS spec: [RFC1034](https://tools.ietf.org/html/rfc1034) and [RFC1035](https://tools.ietf.org/html/rfc1035)
* Host names may begin with a digit: [RFC1123](https://tools.ietf.org/html/rfc1123)
* Original spec clarification: [RFC2181](https://tools.ietf.org/html/rfc2181)
* DNS Cookies: [RFC7873](https://tools.ietf.org/html/rfc7873)
* NAPTR: [RFC2915](https://tools.ietf.org/html/rfc2915)
* DNS SRV Records: [RFC2782](https://tools.ietf.org/html/rfc2782)
* IPv6 (AAAA) Records: [RFC3596](https://tools.ietf.org/html/rfc3596)
* DNS case insensitivity: [RFC4343](https://tools.ietf.org/html/rfc4343)
* URI DNS Records: [RFC7553](https://tools.ietf.org/html/rfc7553)
* Extension Mechanism for DNS: [RFC6891](https://tools.ietf.org/rfc/rfc6891.txt)
* The Role of Wilcards in the DNS: [RFC4592](https://tools.ietf.org/rfc/rfc4592.txt)


Roadmap
---
For version 0.0.1
* Documentation
* Better eunit test coverage
* Possibly `dnsfile:write_resources()`
