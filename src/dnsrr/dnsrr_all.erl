% This module implements support for DNS ALL QTYPE (RFC1034, RFC1035)
-module(dnsrr_all).

-behavior(dnsrr).
-export([
    atom/0,
    value/0,

    can_appear_in/0,

    aka/0
]).


atom() -> all.
value() -> 255.


can_appear_in() -> question.


aka() -> ['_'].
