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
    valid_data/1,
    normalize_data/1
]).

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

masterfile_token() -> "mx".
atom() -> mx.
value() -> 15.


additionally({_, _, in, _, {_, Domain}}) ->
    [
        {Domain, a, in},
        {Domain, aaaa, in}
    ];
additionally(_) ->
    [].


masterfile_format() -> [uint16, domain].

from_masterfile([Priority, Domain]) ->
    {ok, {Priority, Domain}}.


to_masterfile({Priority, Domain}) ->
    [
        integer_to_list(Priority),
        dnsfile:indicate_domain(Domain)
    ].


to_binary({Priority, Domain}) ->
    {domains, [<<Priority:16>>, dnswire:to_binary_domain(Domain, true)]}.


from_binary(<<Priority:16, Bin/binary>>) ->
    case dnswire:binary_to_domain(Bin) of
        {error, Reason} -> {error, Reason};
        {_, Domain, <<>>} -> {domains, [Priority, dnswire:from_binary_domain(Domain, 2)]}
    end.

-ifdef(EUNIT).
from_binary_test() ->
    {'EXIT', {function_clause, _}} = (catch from_binary(<<>>)).
-endif.


valid_data({Priority, Domain})
when is_integer(Priority), Priority >= 0, Priority =< 16#FFFF ->
    true =:= dnslib:is_valid_domain(Domain).


normalize_data({Priority, Domain}) ->
    {Priority, dnslib:normalize_domain(Domain)}.
