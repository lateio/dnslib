% This module implements support for DNS AXFR QTYPE (RFC1034, RFC1035)
-module(dnsrr_axfr).

-behavior(dnsrr).
-export([
    atom/0,
    value/0,
    cacheable/0,

    can_appear_in/0
]).


atom() -> axfr.
value() -> 252.
cacheable() -> false.


can_appear_in() -> question.
