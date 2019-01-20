-module(dnsclass_cs).

-behavior(dnsclass).
-export([atom/0,value/0,masterfile_token/0]).

atom() -> cs.
value() -> 2.
masterfile_token() -> "cs".
