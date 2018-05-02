% This module implements support for DNS NAPTR records (RFC2915)
-module(dnsrr_naptr).

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

masterfile_token() -> "naptr".
atom() -> naptr.
value() -> 35.

masterfile_format() ->
    [uint16, uint16, text, text, text, domain].

from_masterfile([Order, Preference, Flags, Services, Regexp, Replacement]) ->
    {ok, {
        Order,
        Preference,
        list_to_binary(Flags),
        list_to_binary(Services),
        list_to_binary(Regexp),
        Replacement
    }}.


to_masterfile({Order, Preference, Flags, Services, Regexp, Replacement}) ->
    [
        list_to_integer(Order),
        list_to_integer(Preference),
        dnsfile:escape_text(Flags),
        dnsfile:escape_text(Services),
        dnsfile:escape_text(Regexp),
        dnsfile:indicate_domain(Replacement)
    ].


to_binary({Order, Preference, Flags, Services, Regexp, Replacement}) ->
    {domains, [
        <<
            Order:16, Preference: 16,
            (byte_size(Flags)), Flags/binary,
            (byte_size(Services)), Services/binary,
            (byte_size(Regexp)), Regexp/binary
        >>,
        dnswire:indicate_domain(Replacement)
    ]}.


from_binary(<<Order:16, Preference:16, Tail/binary>>) ->
    from_binary([Preference, Order], Tail);
from_binary(_) ->
    {error, invalid_data}.

from_binary([Regexp, Services, Flags, Preference, Order], Bin) ->
    case dnslib:binary_to_domain(Bin) of
        {ok, Replacement, <<>>} ->
            Offset = 4 + 3 + byte_size(Flags) + byte_size(Services) + byte_size(Regexp),
            {domains, [Order, Preference, Flags, Services, Regexp, dnswire:indicate_domain(Replacement, Offset)]};
        _ -> {error, invalid_data}
    end;
from_binary(Acc, <<Len, Str:Len/binary, Tail/binary>>) ->
    from_binary([Str|Acc], Tail).

%from_binary_finalize([Order, Preference, Flags, Services, Regexp, Replacement]) ->
%    {ok {Order, Preference, Flags, Services, Regexp, Replacement}}.
