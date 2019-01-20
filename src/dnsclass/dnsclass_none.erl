-module(dnsclass_none).

-behavior(dnsclass).
-export([atom/0,value/0]).

atom() -> none.
value() -> 254.
