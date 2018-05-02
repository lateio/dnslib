-module(dnsrr_dnskey).

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

masterfile_token() -> "dnskey".
atom() -> dnskey.
value() -> 48.


masterfile_format() -> [uint16, uint16, token, token, '...'].

valid_flags(0) -> true;
valid_flags(256) -> true;
valid_flags(257) -> true;
valid_flags(_) -> false.


from_masterfile([Flags, 3=Protocol, Algorithm0|Base64Key]) ->
    case valid_flags(Flags) of
        false -> {error, invalid_flags};
        true ->
            case dnssec_algorithm:from_to(Algorithm0, masterfile_token, value) of
                Algorithm0 -> {error, invalid_algorithm};
                Algorithm ->
                    Key = base64:decode(lists:flatten(Base64Key)),
                    {ok, {Flags, Protocol, Algorithm, Key}}
            end
    end;
from_masterfile(_) ->
    {error, invalid_protocol}.


to_binary({Flags, Protocol, Algorithm, Key}) ->
    {ok, [
        <<Flags:16, Protocol, Algorithm>>,
        Key
    ]}.


from_binary(<<Flag:16, Protocol, Algorithm, Key/binary>>) ->
    {ok, {Flag, Protocol, Algorithm, Key}};
from_binary(_) ->
    {error, invalid_data}.
