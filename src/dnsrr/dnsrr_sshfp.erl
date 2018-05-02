% This module implements support for DNS SSHFP records (RFC4255)
-module(dnsrr_sshfp).

-behavior(dnsrr).
-export([
    masterfile_token/0,
    atom/0,
    value/0,
    masterfile_format/0,
    from_masterfile/1,
    to_masterfile/1,
    to_binary/1,
    from_binary/1
]).

masterfile_token() -> "sshfp".
atom() -> sshfp.
value() -> 44.

masterfile_format() -> [uint16, uint16, text_unlimited].


algorithm(1) -> rsa;
algorithm(2) -> dss;
algorithm(rsa) -> 1;
algorithm(dss) -> 2;
algorithm(Int) when is_integer(Int) -> Int.


fptype(1) -> sha1;
fptype(sha1) -> 1;
fptype(Int) when is_integer(Int) -> Int.


from_masterfile([Algorithm, FingerprintType, _]) when Algorithm > 16#FF - 1; FingerprintType > 16#FF - 1 ->
    {error, invalid_value};
from_masterfile([_, _, Fingerprint]) when length(Fingerprint) > 16#FFFF - 2 ->
    {error, invalid_value};
from_masterfile([Algorithm, FingerprintType, Fingerprint]) ->
    {ok, {algorithm(Algorithm), fptype(FingerprintType), list_to_binary(Fingerprint)}}.


to_masterfile({Algorithm, FingerprintType, Fingerprint}) ->
    [
        integer_to_list(algorithm(Algorithm)),
        integer_to_list(fptype(FingerprintType)),
        dnsfile:escape_text(Fingerprint)
    ].



to_binary({Algorithm, FingerprintType, Fingerprint}) ->
    {ok, <<(algorithm(Algorithm)), (fptype(FingerprintType)), Fingerprint/binary>>}.


from_binary(<<Algorithm, FingerprintType, Fingerprint/binary>>) ->
    {ok, {algorithm(Algorithm), fptype(FingerprintType), Fingerprint}}.
