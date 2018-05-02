% This module implements support for DNS MAILA QTYPE (RFC1034, RFC1035)
-module(dnsrr_maila).

-behavior(dnsrr).
-export([
    atom/0,
    value/0,

    can_appear_in/0,

    aka/0
]).


atom() -> maila.
value() -> 254.


can_appear_in() -> question.


aka() -> [md, mf].
