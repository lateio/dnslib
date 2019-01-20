dnslib
=====

dnslib will be a standards compliant, reliable and extensible library for working with Domain Name System (DNS) data. At the time of writing, however, it lacks the testing to verify it as any of the aforementioned.

dnslib can be included in an application when it is necessary to work with DNS master files or DNS wire format.
A variety of functionality for working with DNS messages and assorted data types is included.

The reader should note that dnslib **does not** implement any of the networking functionality of DNS. While it will get an application up to the binary representation of a DNS message, dnslib will not send that binary anywhere.

[Documentation](doc/src/manual/index.asciidoc) for dnslib can be found in the doc/ directory.

Quick start
-----------

```Erlang
% Request
Question = dnslib:question("arv.io", a, in),
Request0 = dnsmsg:new(#{}, Question),
{ok, ReqBinLen, ReqBin} = dnswire:to_binary(Request0),
ReqBinLen = byte_size(ReqBin),
{ok, Request0, <<>>} = dnswire:from_binary(ReqBin),

% Response
Answer = dnslib:resource("arv.io IN 60 A 127.0.0.1"),
Request1 = dnsmsg:add_response_answer(Request0, Answer),
Response = dnsmsg:response(Request1),
{ok, ResBinLen, ResIolist} = dnswire:to_iolist(Response),
ResBin = iolist_to_binary(ResIolist),
ResBinLen = byte_size(ResBin),
{ok, Response, <<"Trailing">>} = dnswire:from_binary(<<ResBin/binary, "Trailing">>),

% Make sense of the response
{ok, [{Question, ok, [Answer]}]} = dnsmsg:interpret_response(Response),

% Keep the answer safe...
ok = dnsfile:write_resources("/BleepBloop/treasures", [Answer]),

% ...But but take a good look at it every now and then
{ok, [Answer]} = dnsfile:consult("/BleepBloop/treasures").
```


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
* Handling of Unknown DNS Resource Record (RR) Types: [RFC3597](https://tools.ietf.org/rfc/rfc3597.txt)


Roadmap
---
For version 0.0.2
* Better eunit coverage
* Custom classes similar to custom resource types
* New opcodes/return codes as required by [Kurremkarmerruk](https://github.com/lateio/kurremkarmerruk)
* Progress towards DNSSEC (?)
