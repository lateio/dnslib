% This module implements support for DNS OPT records (RFC6891)
-module(dnsrr_opt).

-behavior(dnsrr).
-export([
    atom/0,
    value/0,

    cacheable/0,

    to_binary/1,
    from_binary/1
]).

atom() -> opt.
value() -> 41.

cacheable() -> false.


to_binary(Attributes) ->
    to_binary([], Attributes).


% Need something like the resource_record modular solution for opt values?
to_binary(Acc, []) ->
    {ok, lists:reverse(Acc)};
to_binary(Acc, [{Key,Value}|Attributes]) when is_integer(Key), is_binary(Value) ->
    to_binary([<<Key:16, (byte_size(Value)):16, Value/binary>>|Acc], Attributes).


from_binary(Bin) ->
    from_binary([], Bin).


from_binary(Acc, <<>>) ->
    {ok, lists:reverse(Acc)};
from_binary(Acc, <<Code:16, Len:16, Data:Len/binary, Rest/binary>>) ->
    from_binary([{Code, Data}|Acc], Rest).
