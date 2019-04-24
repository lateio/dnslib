-module(rfc1123_SUITE).
-include_lib("common_test/include/ct.hrl").

%% RFC1123
%%
%% What is tested:
%%
%%
%% What is likely to go wrong:
%%

-export([
    all/0,
    basic/1
]).


all() -> [
    basic
].


basic(_) ->
    {ok, _, _Domain} = dnslib:list_to_domain("3234423and.com").
