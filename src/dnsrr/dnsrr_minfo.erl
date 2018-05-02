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
    from_binary_finalize/1
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
        dnswire:indicate_domain_compress(Domain1),
        dnswire:indicate_domain_compress(Domain2)
    ]}.

from_binary(Bin) ->
    from_binary([], 0, Bin).


from_binary([D2, D1], _, <<>>) when is_tuple(D1), is_tuple(D2) ->
    {domains, [D1, D2]};
from_binary([{compressed, _, _, _}=D2, D1], _, <<>>) ->
    {domains, [dnswire:indicate_domain(D1, 0), D2]};
from_binary([D2, {compressed, _, Acc, _}=D1], _, <<>>) ->
    Offset = dnslib:domain_binary_length(Acc) + 1,
    {domains, [D1, dnswire:indicate_domain(D2, Offset)]};
from_binary([D2, D1], _, <<>>) ->
    Offset = dnslib:domain_binary_length(D1),
    {domains, [
        dnswire:indicate_domain(D1,0),
        dnswire:indicate_domain(D2,Offset)
    ]};
from_binary([_, _], _, _) ->
    error;
from_binary(Acc, Offset, Bin) ->
    case dnslib:binary_to_domain(Bin) of
        {ok, Domain, Tail} -> from_binary([Domain|Acc], dnslib:domain_binary_length(Domain) + Offset, Tail);
        {{compressed, _, DomainAcc} = Tuple, Tail} ->
            Domain = dnswire:indicate_domain_decompress(Tuple, Offset),
            from_binary([Domain|Acc], dnslib:domain_binary_length(DomainAcc) + 1, Tail);
        _ -> error
    end.


from_binary_finalize([Domain1, Domain2]) ->
    {ok, {Domain1, Domain2}}.
