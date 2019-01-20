% This module implements support for DNS HINFO records (RFC1034, RFC1035)
-module(dnsrr_hinfo).

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
    valid_data/1
]).

masterfile_token() -> "hinfo".
atom() -> hinfo.
value() -> 13.


masterfile_format() -> [text, text].

from_masterfile([Cpu, Os]) ->
    {ok, {list_to_binary(Cpu), list_to_binary(Os)}}.


to_masterfile({Cpu, Os}) ->
    [
        dnsfile:to_masterfile_escape_text(Cpu),
        dnsfile:to_masterfile_escape_text(Os)
    ].


to_binary({Cpu, Os}) ->
    {ok, [[<<(byte_size(Bin))>>, Bin] || Bin <- [Cpu, Os]]}.


from_binary(<<Len1, Cpu:Len1/binary, Len2, Os:Len2/binary>>) ->
    {ok, {Cpu, Os}}.


valid_data({Cpu, Os}) ->
    Fn = fun
        (FunTxt) -> is_binary(FunTxt) andalso byte_size(FunTxt) =< 16#FF
    end,
    Fn(Cpu) andalso Fn(Os).
