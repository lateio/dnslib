-module(dnsclass_any).

-behavior(dnsclass).
-export([atom/0,value/0]).

atom() -> any.
value() -> 255.
