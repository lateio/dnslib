% This module implements support for DNS NULL records (RFC1034, RFC1035)
-module(dnsrr_null).

-behavior(dnsrr).
-export([
    atom/0,
    value/0,

    to_binary/1,
    from_binary/1
]).


atom() -> null.
value() -> 10.


to_binary(Bin) when byte_size(Bin) =< 16#FFFF ->
    {ok, Bin}.


from_binary(Bin) ->
    {ok, Bin}.
