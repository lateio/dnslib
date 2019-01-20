% This module implements support for DNS MAILB QTYPE (RFC1034, RFC1035)
-module(dnsrr_mailb).

-behavior(dnsrr).
-export([
    atom/0,
    value/0,

    message_section/0,

    aka/0
]).


atom() -> mailb.
value() -> 253.


message_section() -> [question].


aka() -> [mb, mg, mr].
