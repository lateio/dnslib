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

file(Filename) ->
    filename:join(["test", "sample_files", Filename]).


all_types_test() ->
    Records = ?ALL_RESOURCES,
    {ok, Records} = dnsfile:consult(file("all_rrs.zone")).


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
    Path = file("write_consult_test"),
    ok = dnsfile:write_resources(Path, ?ALL_RESOURCES),
    {ok, ?ALL_RESOURCES} = dnsfile:consult(Path),
    ok = dnsfile:write_resources(Path, ?ALL_RESOURCES, [{generic, true}]),
    {ok, ?ALL_RESOURCES} = dnsfile:consult(Path).


root_servers_test() ->
    Path = file("root_servers"),
    {ok, Records} = dnsfile:consult(Path),
    {ok, Records} = dnsfile:consult(Path, [{class, in}]).


write_append_test() ->
    Records = [First|Rest] = ?ALL_RESOURCES,
    Path = file("append"),
    ok = dnsfile:write_resources(Path, [First]),
    [ dnsfile:write_resources(Path, [GenResource], [append]) || GenResource <- Rest],
    {ok, Records} = dnsfile:consult(Path).


foldl_test() ->
    Path = file("all_rrs.zone"),
    Fun = fun (Tuple, Acc) -> [element(2, Tuple)|Acc] end,
    ResList = lists:foldl(Fun, [], ?ALL_RESOURCES),
    {ok, ResList} = dnsfile:foldl(Fun, [], Path),
    Fun2 = fun (Tuple) -> nil end,
    {error, {foldl_error, _, _, _}} = dnsfile:foldl(Fun2, [], Path).


is_valid_test() ->
    true = dnsfile:is_valid(file("all_rrs.zone")),
    false = dnsfile:is_valid(file("invalid")).


iterate_test() ->
    {ok, State} = dnsfile:iterate_begin(file("all_rrs.zone")),
    ?ALL_RESOURCES = iterate_helper(State, []).

iterate_helper(State0, Acc) ->
    case dnsfile:iterate_next(State0) of
        {ok, Resource, State1} ->
            iterate_helper(State1, [Resource|Acc]);
        eof -> lists:reverse(Acc)
    end.
