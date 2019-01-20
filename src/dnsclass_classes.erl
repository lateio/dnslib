-module(dnsclass_classes).

-export([
    value/0,
    atom/0,
    masterfile_token/0
]).

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
