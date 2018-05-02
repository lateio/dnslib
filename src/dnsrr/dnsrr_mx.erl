% This module implements support for DNS MX records (RFC1034, RFC1035)
-module(dnsrr_mx).

-behavior(dnsrr).
-export([
    masterfile_token/0,
    atom/0,
    value/0,
    additionally/1,
    masterfile_format/0,
    from_masterfile/1,
    to_masterfile/1,
    to_binary/1,
    from_binary/1,
    from_binary_finalize/1
]).

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

masterfile_token() -> "mx".
atom() -> mx.
value() -> 15.


additionally({_, _, Class, _, {_, Domain}}) ->
    [
        {Domain, a, Class},
        {Domain, aaaa, Class}
    ].


masterfile_format() -> [uint16, domain].

from_masterfile([Priority, Domain]) ->
    {ok, {Priority, Domain}}.


to_masterfile({Priority, Domain}) ->
    [
        integer_to_list(Priority),
        dnsfile:indicate_domain(Domain)
    ].


to_binary({Priority, Domain}) ->
    {domains, [<<Priority:16>>, dnswire:indicate_domain_compress(Domain)]}.


from_binary(<<Priority:16, Bin/binary>>) ->
    case dnslib:binary_to_domain(Bin) of
        {ok, Domain, <<>>} -> {domains, [Priority, dnswire:indicate_domain(Domain, 2)]};
        {{compressed, _, _} = Tuple, <<>>} ->
            {domains, [Priority, dnswire:indicate_domain_decompress(Tuple, 2)]};
        _ -> error
    end;
from_binary(_) ->
    {error, invalid_data}.

-ifdef(EUNIT).
from_binary_test() ->
    {error, _} = from_binary(<<>>).
-endif.


from_binary_finalize([Priority, Domain]) ->
    {ok, {Priority, Domain}}.
