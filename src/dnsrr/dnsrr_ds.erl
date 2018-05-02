-module(dnsrr_ds).

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

masterfile_token() -> "ds".
atom() -> ds.
value() -> 43.


masterfile_format() -> [uint16, token, '...'].

from_masterfile([Tag, Algorithm0, Type0|Digest0]) ->
    case dnssec_algorithm:from_to(Algorithm0, masterfile_token, value) of
        Algorithm0 -> {error, invalid_algorithm};
        Algorithm ->
            case dnssec_digest:from_to(Type0, masterfile_token, value) of
                Type0 -> {error, invalid_digest_type};
                Type ->
                    Digest = base64:decode(lists:flatten(Digest0)),
                    {ok, {Tag, Algorithm, Type, Digest}}
            end
    end.


to_binary({Tag, Algorithm, Type, Digest}) ->
    {ok, [
        <<Tag:16, Algorithm, Type>>,
        Digest
    ]}.


from_binary(<<Tag:16, Algorithm, Type, Digest>>) ->
    {ok, {Tag, Algorithm, Type, Digest}};
from_binary(_) ->
    {error, invalid_data}.
