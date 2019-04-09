-module(dnsrr_test).
-include_lib("eunit/include/eunit.hrl").

basic_test() ->
    1 = dnsrr:from_to(a, atom, value),
    "a" = dnsrr:from_to(a, atom, masterfile_token),
    "type1" = dnsrr:from_to(a, atom, masterfile_token_generic),
    dnsrr_a = dnsrr:from_to(a, atom, module),

    a = dnsrr:from_to(1, value, atom),
    dnsrr_a = dnsrr:from_to(1, value, module),
    "a" = dnsrr:from_to(1, value, masterfile_token),
    "type1" = dnsrr:from_to(1, value, masterfile_token_generic),

    100 = dnsrr:from_to(100, value, atom),
    100 = dnsrr:from_to(100, value, atom),
    "type100" = dnsrr:from_to(100, value, masterfile_token),
    100 = dnsrr:from_to("type100", masterfile_token, value),
    "type100" = dnsrr:from_to("type100", masterfile_token, module).
