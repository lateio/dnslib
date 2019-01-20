-module(dnsclass_ch).

-behavior(dnsclass).
-export([atom/0,value/0,masterfile_token/0]).

atom() -> ch.
value() -> 3.
masterfile_token() -> "ch".
