% This module implements support for DNS ALL QTYPE (RFC1034, RFC1035)
-module(dnsrr_all).

-behavior(dnsrr).
-export([
    atom/0,
    value/0,

    message_section/0,

    aka/0
]).


atom() -> all.
value() -> 255.


message_section() -> [question].


aka() -> ['_'].
