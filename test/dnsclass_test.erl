-module(dnsclass_test).
-include_lib("eunit/include/eunit.hrl").

basic_test() ->
    1 = dnsclass:from_to(in, atom, value),
    "in" = dnsclass:from_to(in, atom, masterfile_token),
    "class1" = dnsclass:from_to(in, atom, masterfile_token_generic),
    dnsclass_in = dnsclass:from_to(in, atom, module),

    in = dnsclass:from_to(1, value, atom),
    dnsclass_in = dnsclass:from_to(1, value, module),
    "in" = dnsclass:from_to(1, value, masterfile_token),
    "class1" = dnsclass:from_to(1, value, masterfile_token_generic),

    % An unknown value
    100 = dnsclass:from_to(100, value, atom),
    100 = dnsclass:from_to("CLASS100", masterfile_token, value),
    100 = dnsclass:from_to("class100", masterfile_token, value),
    "class100" = dnsclass:from_to(100, value, masterfile_token),
    "class100" = dnsclass:from_to("class100", masterfile_token, module).
