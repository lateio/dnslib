% This module implements support for DNS A records (RFC1034, RFC1035)
-module(dnsrr_a).

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
    from_binary/1
]).

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

masterfile_token() -> "a".
atom() -> a.
value() -> 1.

class() -> in.

masterfile_format() ->
    [token].


from_masterfile([Address0]) ->
    case inet:parse_ipv4strict_address(Address0) of
        {ok, Address} -> {ok, Address};
        _ -> {error, {invalid_address, Address0}}
    end.

-ifdef(EUNIT).
from_masterfile_test() ->
    {ok, {0,0,0,0}} = from_masterfile(["0.0.0.0"]),
    {error, _} = from_masterfile(["0.0.0."]),
    {error, _} = from_masterfile(["0.0."]),
    {error, _} = from_masterfile(["0."]),
    {error, _} = from_masterfile(["::1"]),
    {error, _} = from_masterfile(["Hello"]).
-endif.


to_masterfile(Address={_, _, _, _}) ->
    [inet:ntoa(Address)].

-ifdef(EUNIT).
to_masterfile_test() ->
    ["0.0.0.0"] = to_masterfile({0,0,0,0}),
    ["1.2.3.4"] = to_masterfile({1,2,3,4}).
-endif.


to_binary({B1, B2, B3, B4}) ->
    {ok, <<B1, B2, B3, B4>>}.

-ifdef(EUNIT).
to_binary_test() ->
    {ok, <<0,0,0,0>>} = to_binary({0,0,0,0}),
    {ok, <<1,2,3,4>>} = to_binary({1,2,3,4}).
-endif.


from_binary(<<B1, B2, B3, B4>>) ->
    {ok, {B1, B2, B3, B4}};
from_binary(_) ->
    {error, invalid_address}.

-ifdef(EUNIT).
from_binary_test() ->
    {ok, {0,0,0,0}} = from_binary(<<0,0,0,0>>),
    {error, invalid_address} = from_binary(<<0,0,0>>),
    {error, invalid_address} = from_binary(<<0,0,0,0,0>>).
-endif.
