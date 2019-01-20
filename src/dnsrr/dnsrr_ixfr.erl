% This module implements support for DNS IXFR QTYPE (RFC1995)
-module(dnsrr_ixfr).

-behavior(dnsrr).
-export([
    atom/0,
    value/0,
    cacheable/0,

    message_section/0
]).


atom() -> ixfr.
value() -> 251.
cacheable() -> false.


message_section() -> [question].
