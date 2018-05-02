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
    from_binary_finalize/1
]).

masterfile_token() -> "srv".
atom() -> srv.
value() -> 33.

class() -> in.


additionally({_, _, Class, _, {_, _, _, Domain}}) ->
    [
        {Domain, dnsrr_a:atom(), Class},
        {Domain, dnsrr_aaaa:atom(), Class}
    ].

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
        dnswire:indicate_domain_compress(Domain)
    ]}.


from_binary(<<Priority:16, Weight:16, Port:16, Tail/binary>>) ->
    case dnslib:binary_to_domain(Tail) of
        {ok, Domain, <<>>} ->
            {domains, [Priority, Weight, Port, dnswire:indicate_domain(Domain, 3)]};
        {{compressed, _, _} = Tuple, <<>>} ->
            Domain = dnswire:indicate_domain_decompress(Tuple, 6),
            {domains, [Priority, Weight, Port, Domain]};
        _ -> {error, invalid_domain}
    end.


from_binary_finalize([Priority, Weight, Port, Domain]) ->
    {ok, {Priority, Weight, Port, Domain}}.
