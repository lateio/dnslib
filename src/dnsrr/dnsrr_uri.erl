% This module implements support for DNS URI records (RFC7553)
-module(dnsrr_uri).

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

masterfile_token() -> "uri".
atom() -> uri.
value() -> 256.

masterfile_format() -> [uint16, uint16, qtext_unlimited].

from_masterfile([_, _, Uri]) when length(Uri) > 65531 ->
    {error, data_too_large};
from_masterfile([Priority, Weight, Uri]) ->
    {ok, {Priority, Weight, list_to_binary(Uri)}}.


to_masterfile({Priority, Weight, Uri}) ->
    [
        list_to_integer(Priority),
        list_to_integer(Weight),
        dnsfile:escape_text(Uri)
    ].


to_binary({Priority, Weight, Uri}) ->
    {ok, <<Priority:16, Weight:16, Uri/binary>>}.


from_binary(<<Priority:16, Weight:16, Uri/binary>>) ->
    {ok, {Priority, Weight, Uri}}.
