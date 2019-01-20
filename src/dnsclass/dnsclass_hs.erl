-module(dnsclass_hs).

-behavior(dnsclass).
-export([atom/0,value/0,masterfile_token/0]).

atom() -> hs.
value() -> 4.
masterfile_token() -> "hs".
