% This module implements support for DNS MINFO records (RFC1034, RFC1035)
-module(dnsrr_minfo).

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
    valid_data/1
]).

masterfile_token() -> "minfo".
atom() -> minfo.
value() -> 14.


masterfile_format() -> [domain, domain].

from_masterfile([Domain1, Domain2]) ->
    {ok, {Domain1, Domain2}}.


to_masterfile({Domain1, Domain2}) ->
    [
        dnsfile:indicate_domain(Domain1),
        dnsfile:indicate_domain(Domain2)
    ].


to_binary({Domain1, Domain2}) ->
    {domains, [
        dnswire:to_binary_domain(Domain1, true),
        dnswire:to_binary_domain(Domain2, true)
    ]}.

from_binary(Bin) ->
    from_binary([], Bin).

from_binary([D2, D1], <<>>) ->
    {domains, [
        dnswire:from_binary_domain(D1, 0),
        dnswire:from_binary_domain(D2, dnswire:domain_binary_length(D1))
    ]};
from_binary(Acc, Bin) when length(Acc) < 2 ->
    case dnswire:binary_to_domain(Bin) of
        {error, _} -> {error, invalid_data};
        {_, Domain, Tail} -> from_binary([Domain|Acc], Tail)
    end.


valid_data({Domain1, Domain2}) ->
    true =:= dnslib:is_valid_domain(Domain1) andalso true =:= dnslib:is_valid_domain(Domain2).
