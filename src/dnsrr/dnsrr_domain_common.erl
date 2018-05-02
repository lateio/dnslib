% A number of DNS resource types have a single domain as their data.
% Instead of repeating the same functionality in each module,
% we'll do it once here.
-module(dnsrr_domain_common).

-export([
    masterfile_format/0,
    from_masterfile/1,
    to_masterfile/1,
    to_binary/1,
    from_binary/1,
    from_binary_finalize/1
]).

masterfile_format() -> [domain].

from_masterfile([Domain]) ->
    {ok, Domain}.

to_masterfile(Domain) ->
    [dnsfile:indicate_domain(Domain)].


to_binary(Domain) ->
    {domains, [dnswire:indicate_domain_compress(Domain)]}.


from_binary(Bin) ->
    case dnslib:binary_to_domain(Bin) of
        {ok, Domain, <<>>} -> {domains, [dnswire:indicate_domain(Domain, 0)]};
        {{compressed, _, _} = Tuple, <<>>} -> {domains, [dnswire:indicate_domain_decompress(Tuple, 0)]};
        _ -> {error, invalid_data}
    end.


from_binary_finalize([Domain]) ->
    {ok, Domain}.
