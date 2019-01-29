-module(dnsfile_test).
-include_lib("eunit/include/eunit.hrl").

-define(ALL_RESOURCES, [
    {[], soa, in, 60, {[<<"ns1">>], [<<"hostmaster">>], 0, 60, 60, 60, 60}},
    {[], a, in, 60, {0,0,0,0}},
    {[], aaaa, in, 60, {0,0,0,0,0,0,0,0}},
    {[<<"alias">>], cname, in, 60, []},
    {[], hinfo, in, 60, {<<"amd64">>,<<"GNU/Linux">>}},
    {[], mb, in, 60, []},
    {[], md, in, 60, []},
    {[], mf, in, 60, []},
    {[], mg, in, 60, []},
    {[], minfo, in, 60, {[],[]}},
    {[], mr, in, 60, []},
    {[], mx, in, 60, {0, [<<"smtp">>]}},
    {[], naptr, in, 60, {0,0,<<>>,<<>>,<<>>,[<<"naptr">>]}},
    {[], ns, in, 60, [<<"ns1">>]},
    {[], null, in, 60, <<0>>},
    {[], ptr, in, 60, [<<"ptr">>]},
    {[], srv, in, 60, {0,0,0,[]}},
    {[], txt, in, 60, [<<"Hello, world!">>,<<"Token">>,<<255,255>>,<<"あ"/utf8>>]},
    {[], uri, in, 60, {0,0,<<"https://arv.io">>}},
    {[], wks, in, 60, {{0,0,0,0}, 6, <<0,0,66,0,0,0,0,0,0,0,128>>}}
]).

all_types_test() ->
    Records = ?ALL_RESOURCES,
    {ok, Records} = dnsfile:consult("test/sample_files/all_rrs.zone").


parse_resource_test() ->
    Resource = {[<<"arv">>,<<"io">>],a,in,60,{0,0,0,0}},
    {ok, Resource} = dnsfile:parse_resource("arv.io IN 60 A 0.0.0.0"),
    {ok, Resource} = dnsfile:parse_resource("arv.io\t60\tA\t0.0.0.0"),
    {ok, Resource} = dnsfile:parse_resource("arv.io. 60 A 0.0.0.0"),
    {ok, Resource} = dnsfile:parse_resource("arv.io. 1min A 0.0.0.0"),
    {ok, Resource} = dnsfile:parse_resource("arv.io CLASS1 60 TYPE1 \\# 4 00 00 00 00"),
    {error, empty} = dnsfile:parse_resource(""),
    {error, empty} = dnsfile:parse_resource("    \t\t\t\t      "),
    {error, partial} = dnsfile:parse_resource("arv.io IN 60 SOA ("),
    {error, partial} = dnsfile:parse_resource("arv.io IN 60 SOA \""),
    {error, _} = dnsfile:parse_resource("@  60  A  0.0.0.0"),
    {error, _} = dnsfile:parse_resource("$INCLUDE \"other.zone\"").


write_consult_test() ->
    ok = dnsfile:write_resources("test/sample_files/write_consult_test", ?ALL_RESOURCES),
    {ok, ?ALL_RESOURCES} = dnsfile:consult("test/sample_files/write_consult_test"),
    ok = dnsfile:write_resources("test/sample_files/write_consult_test", ?ALL_RESOURCES, [{generic, true}]),
    {ok, ?ALL_RESOURCES} = dnsfile:consult("test/sample_files/write_consult_test").


root_servers_test() ->
    {ok, Records} = dnsfile:consult("test/sample_files/root_servers"),
    {ok, Records} = dnsfile:consult("test/sample_files/root_servers", [{class, in}]).


write_append_test() ->
    Records = [First|Rest] = ?ALL_RESOURCES,
    ok = dnsfile:write_resources("test/sample_files/append", [First]),
    [ dnsfile:write_resources("test/sample_files/append", [GenResource], [append]) || GenResource <- Rest],
    {ok, Records} = dnsfile:consult("test/sample_files/append").
