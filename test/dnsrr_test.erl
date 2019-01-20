-module(dnsrr_test).
-include_lib("eunit/include/eunit.hrl").

basic_test() ->
    1 = dnsrr:from_to(a, atom, value),
    "a" = dnsrr:from_to(a, atom, masterfile_token),
    dnsrr_a = dnsrr:from_to(a, atom, module),

    a = dnsrr:from_to(1, value, atom),
    dnsrr_a = dnsrr:from_to(1, value, module),
    "a" = dnsrr:from_to(1, value, masterfile_token),

    100 = dnsrr:from_to(100, value, atom).
