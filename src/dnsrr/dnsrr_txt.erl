% This module implements support for DNS TXT records (RFC1034, RFC1035)
-module(dnsrr_txt).

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

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

masterfile_token() -> "txt".
atom() -> txt.
value() -> 16.


masterfile_format() -> [text, '...'].


from_masterfile(Content) ->
    case lists:foldl(fun (Txt, Acc) -> length(Txt) + 1 + Acc end, 0, Content) of
        TotalLength when TotalLength > 16#FFFF -> {error, data_too_large};
        _ -> {ok, [list_to_binary(Entry) || Entry <- Content]}
    end.

-ifdef(EUNIT).
from_masterfile_test() ->
    MaxStr = lists:seq(0,255),
    MaxStrList = lists:map(fun (_) -> MaxStr end, lists:seq(1,255)),
    {ok, _} = from_masterfile(MaxStrList),
    {error, data_too_large} = from_masterfile([[]|MaxStrList]).
-endif.


to_masterfile(Txt) ->
    lists:map(fun dnsfile:to_masterfile_escape_text/1, Txt).


to_binary(Content) ->
    {ok, [[byte_size(Bin), Bin] || Bin <- Content]}.

-ifdef(EUNIT).
to_binary_test() ->
    {ok, Iolist1} = to_binary([<<>>]),
    <<0>> = iolist_to_binary(Iolist1),
    {ok, Iolist2} = to_binary([<<>>, <<"abc">>]),
    <<0,3,"abc">> = iolist_to_binary(Iolist2).
-endif.


from_binary(Data) when byte_size(Data) > 0 ->
    case collect_text(Data, []) of
        {ok, Txt} -> {ok, Txt};
        {error, _} = Tuple -> Tuple
    end.

-ifdef(EUNIT).
from_binary_test() ->
    {ok, [<<>>]} = from_binary(<<0>>),
    {'EXIT', {function_clause, _}} = (catch from_binary(<<>>)),
    {error, truncated_data} = from_binary(<<1>>),
    {error, truncated_data} = from_binary(<<1,2,1>>).
-endif.


collect_text(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
collect_text(<<Len, Txt:Len/binary, Tail/binary>>, Acc) ->
    collect_text(Tail, [Txt|Acc]);
collect_text(_, _) ->
    {error, truncated_data}.


valid_data(List) when is_list(List) ->
    Fn = fun (FunText) -> is_binary(FunText) andalso byte_size(FunText) =< 16#FF end,
    lists:all(Fn, List).
