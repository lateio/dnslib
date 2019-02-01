% This module implements support for DNS SRV records (RFC2782)
-module(dnsrr_srv).

-behavior(dnsrr).
-export([
    masterfile_token/0,
    atom/0,
    value/0,
    class/0,
    additionally/1,
    masterfile_format/0,
    from_masterfile/1,
    to_masterfile/1,
    to_binary/1,
    from_binary/1,
    valid_data/1,
    normalize_data/1
]).

masterfile_token() -> "srv".
atom() -> srv.
value() -> 33.

class() -> [in].


additionally({_, _, in, _, {_, _, _, Domain}}) ->
    [
        {Domain, a, in},
        {Domain, aaaa, in}
    ];
additionally(_) ->
    [].

masterfile_format() -> [uint16, uint16, uint16, domain].


from_masterfile([Priority, Weight, Port, Domain]) ->
    {ok, {Priority, Weight, Port, Domain}}.


to_masterfile({Priority, Weight, Port, Domain}) ->
    [
        integer_to_list(Priority),
        integer_to_list(Weight),
        integer_to_list(Port),
        dnsfile:indicate_domain(Domain)
    ].


to_binary({Priority, Weight, Port, Domain}) ->
    {domains, [
        <<Priority:16, Weight:16, Port:16>>,
        dnswire:to_binary_domain(Domain, true)
    ]}.


from_binary(<<Priority:16, Weight:16, Port:16, Tail/binary>>) ->
    case dnswire:binary_to_domain(Tail) of
        {error, _} -> {error, invalid_domain};
        {_, Domain, <<>>} ->
            {domains, [Priority, Weight, Port, dnswire:from_binary_domain(Domain, 6)]}
    end.


valid_data(Data0) when tuple_size(Data0) =:= 4 ->
    Data = tuple_to_list(Data0),
    case dnslib:is_valid_domain(lists:last(Data)) of
        true ->
            Fn = fun
                (FunUint) ->
                    is_integer(FunUint) andalso
                    FunUint >= 0 andalso
                    FunUint =< 16#FFFF
            end,
            lists:all(Fn, lists:droplast(Data));
        _ -> false
    end.


normalize_data({_, _, _, Domain}=Data) ->
    setelement(4, Data, dnslib:normalize_domain(Domain)).
