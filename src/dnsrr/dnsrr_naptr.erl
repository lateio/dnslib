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
    from_binary/1,
    valid_data/1,
    normalize_data/1
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
        integer_to_list(Order),
        integer_to_list(Preference),
        dnsfile:to_masterfile_escape_text(Flags),
        dnsfile:to_masterfile_escape_text(Services),
        dnsfile:to_masterfile_escape_text(Regexp),
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
        dnswire:to_binary_domain(Replacement, false)
    ]}.


from_binary(<<Order:16, Preference:16, Tail/binary>>) ->
    from_binary([Preference, Order], Tail).

from_binary([Regexp, Services, Flags, Preference, Order], Bin) ->
    case dnswire:binary_to_domain(Bin) of
        {ok, Replacement, <<>>} ->
            Offset = 4 + 3 + byte_size(Flags) + byte_size(Services) + byte_size(Regexp),
            {domains, [Order, Preference, Flags, Services, Regexp, dnswire:from_binary_domain(Replacement, Offset)]};
        _ -> {error, invalid_data}
    end;
from_binary(Acc, <<Len, Str:Len/binary, Tail/binary>>) ->
    from_binary([Str|Acc], Tail).


valid_data(Data0) when tuple_size(Data0) =:= 6 ->
    [Order, Preference|Tail] = tuple_to_list(Data0),
    Domain = lists:last(Tail),
    FnUint = fun
        (FunData) ->
            is_integer(FunData) andalso
            FunData >= 0 andalso
            FunData =< 16#FFFF
    end,
    FnTxt = fun
        (FunData) ->
            is_binary(FunData) andalso
            byte_size(FunData) =< 16#FF
    end,
    case
        FnUint(Order) andalso
        FnUint(Preference) andalso
        true =:= dnslib:is_valid_domain(Domain)
    of
        true -> lists:all(FnTxt, lists:droplast(Tail));
        false -> false
    end.


normalize_data({_, _, _, _, _, Replacement}=Data) ->
    % Character case in text?
    setelement(6, Data, dnslib:normalize_domain(Replacement)).
