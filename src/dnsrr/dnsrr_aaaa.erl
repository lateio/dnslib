% This module implements support for DNS AAAA records (RFC3596)
-module(dnsrr_aaaa).

-behavior(dnsrr).
-export([
    masterfile_token/0,
    atom/0,
    value/0,
    class/0,

    masterfile_format/0,
    from_masterfile/1,
    to_masterfile/1,

    to_binary/1,
    from_binary/1,

    valid_data/1
]).

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

masterfile_token() -> "aaaa".
atom() -> aaaa.
value() -> 28.

class() -> [in].

masterfile_format() -> [token].

from_masterfile([Address]) ->
    case inet:parse_ipv6strict_address(Address) of
        {ok, Address1} -> {ok, Address1};
        _ -> {error, {invalid_address, Address}}
    end.

-ifdef(EUNIT).
from_masterfile_test() ->
    {ok, {0,0,0,0,0,0,0,0}} = from_masterfile(["::"]),
    {ok, {0,0,0,0,0,0,0,0}} = from_masterfile(["0:0:0:0:0:0:0:0"]),
    {ok, {1,2,3,4,5,6,7,8}} = from_masterfile(["1:2:3:4:5:6:7:8"]),
    {error, _} = from_masterfile(["0.0.0.0"]),
    {error, _} = from_masterfile(["Hello"]).
-endif.


to_masterfile(Address={_, _, _, _, _, _, _, _}) ->
    [inet:ntoa(Address)].

-ifdef(EUNIT).
to_masterfile_test() ->
    ["::"] = to_masterfile({0,0,0,0,0,0,0,0}),
    ["::1"] = to_masterfile({0,0,0,0,0,0,0,1}),
    ["1::1"] = to_masterfile({1,0,0,0,0,0,0,1}).
-endif.


to_binary({S1, S2, S3, S4, S5, S6, S7, S8}) ->
    {ok, <<S1:16, S2:16, S3:16, S4:16, S5:16, S6:16, S7:16, S8:16>>}.

-ifdef(EUNIT).
to_binary_test() ->
    {ok, <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>} = to_binary({0,0,0,0,0,0,0,0}).
-endif.


from_binary(<<B1:16, B2:16, B3:16, B4:16, B5:16, B6:16, B7:16, B8:16>>) ->
    {ok, {B1, B2, B3, B4, B5, B6, B7, B8}}.

-ifdef(EUNIT).
from_binary_test() ->
    {'EXIT', {function_clause, _}} = (catch from_binary(<<>>)),
    {'EXIT', {function_clause, _}} = (catch from_binary(<< <<0:16>> || _ <- lists:seq(1,16)>>)),
    {'EXIT', {function_clause, _}} = (catch from_binary(<< <<0:16>> || _ <- lists:seq(1,7)>>)),
    {ok, {0,0,0,0,0,0,0,0}} = from_binary(<< <<0:16>> || _ <- lists:seq(1,8)>>),
    {'EXIT', {function_clause, _}} = (catch from_binary(<< <<0:16>> || _ <- lists:seq(1,9)>>)).
-endif.


valid_data(Address) when tuple_size(Address) =:= 8 ->
    Fn = fun (FunMember) ->
        is_integer(FunMember) andalso FunMember >= 0 andalso FunMember =< 16#FFFF
    end,
    lists:all(Fn, tuple_to_list(Address)).
