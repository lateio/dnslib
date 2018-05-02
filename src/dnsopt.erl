% This file contains code be used to with EDNS
% functionality
-module(dnsopt).

-export([
    from_binary/1,
    to_binary/1,
    new/1
]).


from_binary(Entries) ->
    from_binary(Entries, []).


from_binary([], Acc) ->
    {ok, maps:from_list(Acc)};
from_binary([{10, <<Cookie1:8/binary, Cookie2/binary>>}|Rest], Acc)
when byte_size(Cookie2) >= 8, byte_size(Cookie2) =< 32 ->
    from_binary(Rest, [{cookie, {Cookie1, Cookie2}}|Acc]);
from_binary([_|Rest], Acc) ->
    from_binary(Rest, Acc).


to_binary(Map) ->
    to_binary(maps:to_list(Map), []).

to_binary([], Acc) ->
    {ok, lists:reverse(Acc)};
to_binary([{cookie, Value0}|Rest], Acc) ->
    Value1 = case Value0 of
        {Cookie, nil} when byte_size(Cookie) =:= 8 -> Cookie;
        {Cookie1, Cookie2} when Cookie2 =/= nil, byte_size(Cookie1) =:= 8,
        byte_size(Cookie2) >= 8, byte_size(Cookie2) =< 32 -> <<Cookie1/binary, Cookie2/binary>>
    end,
    to_binary(Rest, [{10, Value1}|Acc]);
to_binary([_|Rest], Acc) ->
    to_binary(Rest, Acc).


new(cookie) ->
    {crypto:strong_rand_bytes(8), nil}.
