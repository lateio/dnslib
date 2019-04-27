-module(dnsclass_classes).

-export([
    value/0,
    atom/0,
    masterfile_token/0
]).

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.


value() ->
    #{
        1   => dnsclass_in,   %% RFC1035
        2   => dnsclass_cs,   %% RFC1035
        3   => dnsclass_ch,   %% RFC1035
        4   => dnsclass_hs,   %% RFC1035
        254 => dnsclass_none,
        255 => dnsclass_any
    }.


atom() ->
    #{
        in   => dnsclass_in,   %% RFC1035
        cs   => dnsclass_cs,   %% RFC1035
        ch   => dnsclass_ch,   %% RFC1035
        hs   => dnsclass_hs,   %% RFC1035
        none => dnsclass_none,
        any  => dnsclass_any
    }.


masterfile_token() ->
    #{
        "in"  => dnsclass_in,   %% RFC1035
        "cs"  => dnsclass_cs,   %% RFC1035
        "ch"  => dnsclass_ch,   %% RFC1035
        "hs"  => dnsclass_hs    %% RFC1035
    }.


-ifdef(EUNIT).
builtin_modules_sanity_test() ->
    Builtin = dnsclass:builtin(),
    CheckFn = fun ({_, FunMod}) -> not lists:member(FunMod, Builtin) end,
    [] = lists:filter(CheckFn, maps:to_list(atom())),
    [] = lists:filter(CheckFn, maps:to_list(value())),
    [] = lists:filter(CheckFn, maps:to_list(masterfile_token())),
    TakeFn = fun ({_, FunMod}, FunAcc) -> lists:delete(FunMod, FunAcc) end,
    [] = lists:foldl(TakeFn, Builtin, maps:to_list(atom())),
    [] = lists:foldl(TakeFn, Builtin, maps:to_list(value())).
-endif.
