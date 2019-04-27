% This module implements support for DNS SOA records (RFC1034, RFC1035)
-module(dnsrr_soa).

-behavior(dnsrr).
-export([
    masterfile_token/0,
    atom/0,
    value/0,
    masterfile_format/0,
    from_masterfile/1,
    to_masterfile/1,
    to_binary/1,
    from_binary/1,
    from_binary_finalize/1,
    valid_data/1,
    normalize_data/1,

    nameserver/1,
    contact/1,
    serial/1,
    refresh/1,
    retry/1,
    expire/1,
    minimum/1,

    serial_compare/2
]).

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

-include_lib("dnslib/include/dnslib.hrl").

-define(FIX_TTL(Ttl), (Ttl band ?MAX_TTL)).

masterfile_token() -> "soa".
atom() -> soa.
value() -> 6.


masterfile_format() ->
    [domain, domain, uint32, ttl, ttl, ttl, ttl].

from_masterfile([Nameserv, Admin, Serial, Refresh, Retry, Expire, Minimum]) ->
    Data = {
        Nameserv,
        Admin,
        Serial,
        Refresh,
        Retry,
        Expire,
        Minimum
    },
    {ok, Data}.


to_masterfile({Nameserv, Admin, Serial, Refresh, Retry, Expire, Minimum}) ->
    [
        dnsfile:indicate_domain(Nameserv),
        dnsfile:indicate_domain(Admin),
        integer_to_list(Serial),
        integer_to_list(Refresh),
        integer_to_list(Retry),
        integer_to_list(Expire),
        integer_to_list(Minimum)
    ].


to_binary({Ns, Contact, Id, Refresh, Retry, Expire, Minimum}) ->
    {domains, [
        dnswire:to_binary_domain(Ns, true),
        dnswire:to_binary_domain(Contact, true),
        <<Id:32, Refresh:32, Retry:32, Expire:32, Minimum:32>>
    ]}.


from_binary(Bin) ->
    from_binary([], 0, Bin).


from_binary([Contact, Ns], _, <<Id:32,Refresh:32,Retry:32,Expire:32,Minimum:32>>) ->
    {domains, [Ns, Contact, Id, Refresh, Retry, Expire, Minimum]};
from_binary(Acc, Offset0, Bin) when length(Acc) < 2 ->
    case dnswire:binary_to_domain(Bin) of
        {error, Reason} -> {error, Reason};
        {_, Domain, Tail} ->
            Offset = Offset0 + dnswire:domain_binary_length(Domain),
            from_binary([dnswire:from_binary_domain(Domain, Offset0)|Acc], Offset, Tail)
    end.


from_binary_finalize([Ns, Contact, Id, Refresh, Retry, Expire, Minimum]) ->
    {ok, {Ns, Contact, Id, ?FIX_TTL(Refresh), ?FIX_TTL(Retry), ?FIX_TTL(Expire), ?FIX_TTL(Minimum)}}.


valid_data(Data) when tuple_size(Data) =:= 7 ->
    [Nameserv, Admin, Serial|Ttls] = tuple_to_list(Data),
    case
        true =:= dnslib:is_valid_domain(Nameserv) andalso
        true =:= dnslib:is_valid_domain(Admin)
    of
        true when is_integer(Serial), Serial >= 0, Serial =< 16#FFFFFFFF ->
            Fn = fun
                (FunTtl) ->
                    is_integer(FunTtl) andalso
                    FunTtl >= 0 andalso
                    FunTtl =< ?MAX_TTL
            end,
            lists:all(Fn, Ttls);
        false -> false
    end.


normalize_data({Nameserv, Admin, Id, Refresh, Retry, Expire, Minimum}) ->
    {
        dnslib:normalize_domain(Nameserv),
        dnslib:normalize_domain(Admin),
        Id,
        Refresh,
        Retry,
        Expire,
        Minimum
    }.


nameserver(Data = {_, _, _, _, _, _, _}) ->
    element(1, Data);
nameserver(Resource) when ?IS_RESOURCE(Resource) ->
    nameserver(?RESOURCE_DATA(Resource)).


contact(Data = {_, _, _, _, _, _, _}) ->
    element(2, Data);
contact(Resource) when ?IS_RESOURCE(Resource) ->
    contact(?RESOURCE_DATA(Resource)).


serial(Data = {_, _, _, _, _, _, _}) ->
    element(3, Data);
serial(Resource) when ?IS_RESOURCE(Resource) ->
    serial(?RESOURCE_DATA(Resource)).


refresh(Data = {_, _, _, _, _, _, _}) ->
    element(4, Data);
refresh(Resource) when ?IS_RESOURCE(Resource) ->
    refresh(?RESOURCE_DATA(Resource)).


retry(Data = {_, _, _, _, _, _, _}) ->
    element(5, Data);
retry(Resource) when ?IS_RESOURCE(Resource) ->
    retry(?RESOURCE_DATA(Resource)).


expire(Data = {_, _, _, _, _, _, _}) ->
    element(6, Data);
expire(Resource) when ?IS_RESOURCE(Resource) ->
    expire(?RESOURCE_DATA(Resource)).


minimum(Data = {_, _, _, _, _, _, _}) ->
    element(7, Data);
minimum(Resource) when ?IS_RESOURCE(Resource) ->
    minimum(?RESOURCE_DATA(Resource)).


-ifdef(EUNIT).
convenience_fn_test() ->
    Ns = dnslib:domain("test"),
    Contact = dnslib:domain("contact"),
    Soa = {Ns, Contact, 0, 1, 2, 3, 4},
    Rr = {nil, nil, nil, nil, Soa},
    Tests = [
        {Ns,      fun nameserver/1},
        {Contact, fun contact/1},
        {0,       fun serial/1},
        {1,       fun refresh/1},
        {2,       fun retry/1},
        {3,       fun expire/1},
        {4,       fun minimum/1}
    ],
    true = lists:all(fun ({Expect, Fn}) -> Expect = Fn(Rr), Expect =:= Fn(Soa) end, Tests).
-endif.


% Compare SOA serials as per RFC1982
serial_compare(Soa1, Soa2) when ?IS_RESOURCE(Soa1) ->
    serial_compare(serial(Soa1), Soa2);
serial_compare(Serial1, Soa2) when ?IS_RESOURCE(Soa2) ->
    serial_compare(Serial1, serial(Soa2));
serial_compare(Serial, Serial) ->
    false;
serial_compare(Serial1, Serial2) ->
    (Serial1 < Serial2 andalso Serial2 - Serial1 < 16#80000000) orelse
    (Serial1 > Serial2 andalso Serial1 - Serial2 > 16#80000000).
