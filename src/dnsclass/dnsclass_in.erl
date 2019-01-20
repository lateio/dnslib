-module(dnsclass_in).

-behavior(dnsclass).
-export([atom/0,value/0,masterfile_token/0]).

atom() -> in.
value() -> 1.
masterfile_token() -> "in".
