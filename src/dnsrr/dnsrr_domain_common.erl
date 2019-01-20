% A number of DNS resource types have a single domain as their data.
% Instead of repeating the same functionality in each module,
% we'll do it once here.
-module(dnsrr_domain_common).

-export([
    masterfile_format/0,
    from_masterfile/1,
    to_masterfile/1,
    to_binary/1,
    to_binary/2,
    from_binary/1,
    from_binary/2,
    from_binary_finalize/1,
    valid_data/1,
    normalize_data/1
]).

masterfile_format() -> [domain].

from_masterfile([Domain]) ->
    {ok, Domain}.

to_masterfile(Domain) ->
    [dnsfile:indicate_domain(Domain)].


to_binary(Domain) ->
    to_binary(Domain, true).

to_binary(Domain, Boolean) ->
    {domains, [dnswire:to_binary_domain(Domain, Boolean)]}.


from_binary(Bin) ->
    from_binary(Bin, true).

from_binary(Bin, true) ->
    case dnslib:binary_to_domain(Bin) of
        {error, _} -> {error, invalid_data};
        {_, Domain, <<>>} -> {domains, [dnswire:from_binary_domain(Domain, 0)]}
    end;
from_binary(Bin, false) ->
    case dnslib:binary_to_domain(Bin) of
        {error, _} -> {error, invalid_data};
        {compressed, _, _} -> {errors, compressed_domain};
        {ok, Domain, <<>>} -> {domains, [dnswire:from_binary_domain(Domain, 0)]}
    end.


from_binary_finalize([Domain]) ->
    {ok, Domain}.


valid_data(Domain) ->
    true =:= dnslib:is_valid_domain(Domain).


normalize_data(Domain) ->
    dnslib:normalize_domain(Domain).
