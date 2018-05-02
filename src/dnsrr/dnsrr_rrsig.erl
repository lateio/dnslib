-module(dnsrr_rrsig).

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

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

masterfile_token() -> "rrsig".
atom() -> rrsig.
value() -> 46.


masterfile_format() ->
    [
        token, % Type covered
        token, % Algorithm
        uint16, % Labels
        uint32, % Original TTL
        uint32, % Signature expiration
        uint32, % Signature inception
        uint16, % Key tag
        domain, % Signer's name
        token, '...' % Signature
    ].

from_masterfile([Type0, Algorithm0, Labels, Ttl, Expiration, Inception, Tag, Signer|Signature0]) when Labels < 16#FF ->
    case dnsrr:from_to(Type0, masterfile_token, value) of
        Type0 -> {error, unknown_type};
        Type ->
            case dnssec_algorithm:from_to(Algorithm0, masterfile_token, value) of
                Algorithm0 -> {error, invalid_algorithm};
                Algorithm ->
                    Signature = base64:decode(lists:flatten(Signature0)),
                    {ok, {Type, Algorithm, Labels, Ttl, Expiration, Inception, Tag, Signer, Signature}}
            end
    end;
from_masterfile(_) ->
    {error, too_many_labels}.


to_binary({Type, Algorithm, Labels, Ttl, Expiration, Inception, Tag, Signer, Signature}) ->
    {domains, [
        <<Type:16, Algorithm, Labels, Ttl:32, Expiration:32, Inception:32, Tag:16>>,
        dnswire:indicate_domain(Signer),
        Signature
    ]}.


from_binary(<<Type:16, Algorithm, Labels, Ttl:32, Expiration:32, Inception:32, Tag:16, Tail/binary>>) ->
    case dnslib:binary_to_domain(Tail) of
        {ok, Signer, Signature} -> {ok, {Type, Algorithm, Labels, Ttl, Expiration, Inception, Tag, Signer, Signature}};
        _ -> {error, invalid_data}
    end;
from_binary(_) ->
    {error, invalid_data}.
