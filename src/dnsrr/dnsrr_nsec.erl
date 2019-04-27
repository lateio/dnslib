-module(dnsrr_nsec).

-behavior(dnsrr).
-export([
    masterfile_token/0,
    atom/0,
    value/0,
    masterfile_format/0,
    from_masterfile/1,
    %to_masterfile/1,
    to_binary/1,
    from_binary/1
]).

masterfile_token() -> "nsec".
atom() -> nsec.
value() -> 47.

masterfile_format() -> [domain, token, '...'].

from_masterfile(_) ->
    error(type_bitmap_not_implemented).
    % Fold types into a bitmap
    %{ok, {Domain, <<>>}}.

to_binary({Domain, Bitmap}) ->
    {domains, [
        dnswire:to_binary_domain(Domain, false),
        Bitmap
    ]}.

from_binary(Bin) ->
    case dnswire:binary_to_domain(Bin) of
        {ok, Domain, Bitmap} -> {ok, {Domain, Bitmap}};
        _ -> {error, invalid_data}
    end.
