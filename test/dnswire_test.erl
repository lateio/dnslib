-module(dnswire_test).
-include_lib("eunit/include/eunit.hrl").

dnswire_from_binary_error_test() ->
    application:ensure_all_started(dnslib),
    {ok, _, <<>>} = dnswire:from_binary(<<0:(12*8)>>),
    {ok, _, <<0>>} = dnswire:from_binary(<<0:(13*8)>>),
    {error, {format_error, truncated_message, _}} = dnswire:from_binary(<<0:32, 1:16, 0:48>>),
    {error, {format_error, truncated_message, _}} = dnswire:from_binary(<<0:32, 0:16, 1:16, 0:32>>).

dnswire_encode_decode_test() ->
    application:ensure_all_started(dnslib),
    %Msg1 = dnsmsg:add_question(dnsmsg:new(), {[], ns, in}),
    Msg1 = dnsmsg:new(),
    {ok, _, Bin1} = dnswire:to_binary(Msg1),
    {ok, Msg2, <<>>} = dnswire:from_binary(Bin1),
    {ok, _, Bin1} = dnswire:to_binary(Msg2).
