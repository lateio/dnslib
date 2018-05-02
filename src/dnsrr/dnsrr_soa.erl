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
    from_binary_finalize/1
]).

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
        dnswire:indicate_domain_compress(Ns),
        dnswire:indicate_domain_compress(Contact),
        <<Id:32, Refresh:32, Retry:32, Expire:32, Minimum:32>>
    ]}.


from_binary(Bin) ->
    from_binary([], 0, Bin).


from_binary([Contact, Ns], _, <<Id:32,Refresh:32,Retry:32,Expire:32,Minimum:32>>)
when is_tuple(Contact), is_tuple(Ns) ->
    {domains, [Ns, Contact, Id, Refresh, Retry, Expire, Minimum]};
from_binary([Contact, {compressed, _, Acc, _}=Ns], _, <<Id:32,Refresh:32,Retry:32,Expire:32,Minimum:32>>) ->
    Offset = dnslib:domain_binary_length(Acc) + 1,
    {domains, [Ns, dnswire:indicate_domain(Contact, Offset), Id, Refresh, Retry, Expire, Minimum]};
from_binary([Contact, Ns], _, <<Id:32,Refresh:32,Retry:32,Expire:32,Minimum:32>>) when is_tuple(Contact) ->
    {domains, [dnswire:indicate_domain(Ns, 0), Contact, Id, Refresh, Retry, Expire, Minimum]};
from_binary([Contact, Ns], _, <<Id:32,Refresh:32,Retry:32,Expire:32,Minimum:32>>) ->
    Offset = dnslib:domain_binary_length(Ns),
    {domains, [dnswire:indicate_domain(Ns, 0), dnswire:indicate_domain(Contact, Offset), Id, Refresh, Retry, Expire, Minimum]};
from_binary([_, _], _, _) ->
    error;
from_binary(Acc, Offset, Bin) ->
    case dnslib:binary_to_domain(Bin) of
        {ok, Domain, Tail} -> from_binary([Domain|Acc], dnslib:domain_binary_length(Domain)+Offset, Tail);
        {{compressed, _, NsAcc} = Tuple, Tail} ->
            Domain = dnswire:indicate_domain_decompress(Tuple, Offset),
            from_binary([Domain|Acc], dnslib:domain_binary_length(NsAcc) + 1 + Offset, Tail);
        _ -> error
    end.


from_binary_finalize([Ns, Contact, Id, Refresh, Retry, Expire, Minimum]) ->
    {ok, {Ns, Contact, Id, ?FIX_TTL(Refresh), ?FIX_TTL(Retry), ?FIX_TTL(Expire), ?FIX_TTL(Minimum)}}.
