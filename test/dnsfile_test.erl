-module(dnsfile_test).
-include_lib("dnslib/include/dnsfile.hrl").
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
    filename:absname(filename:join(["test", "sample_files", Filename])).


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


generic_data_list_to_binary_test() ->
    {ok, <<0,0,0,0>>} = dnsfile:generic_data_list_to_binary("\\# 4 00 0000 00"),
    {ok, <<0,0,0,0>>} = dnsfile:generic_data_list_to_binary("\\# 4 ( 00 0000 00 )"),
    {ok, <<>>} = dnsfile:generic_data_list_to_binary("\\# 0"),
    {ok, <<>>} = dnsfile:generic_data_list_to_binary("\\# 0          "),
    {error, empty_string} = dnsfile:generic_data_list_to_binary(""),
    {error, invalid_syntax} = dnsfile:generic_data_list_to_binary("\\# 4 0 0 0 0"),
    {error, {bad_data_length, "-4"}} = dnsfile:generic_data_list_to_binary("\\# -4 00 00 00 00"),
    {error, {bad_data_length, "foo"}} = dnsfile:generic_data_list_to_binary("\\# foo 00 00 00 00"),
    {error, invalid_syntax} = dnsfile:generic_data_list_to_binary("\\# 4 gh ijklm op").


read_file_test() ->
    DnsFile = #dnsfile{
        path=file("all_rrs.zone"),
        resources=?ALL_RESOURCES,
        included_from=undefined
    },
    {ok, [DnsFile]} = dnsfile:read_file(file("all_rrs.zone")),
    RootHead = #dnsfile{
        path=file("root.zone"),
        resources=[
            dnslib:resource("root IN 30d SOA ns1.root hostmaster.root 100 1h 1h 1h 1h"),
            {[<<"ns1">>,<<"root">>], a, in, 36000, {10,140,96,1}},
            dnslib:resource([<<"www">>,<<"root">>], a, in, "10h", "10.140.85.1")
        ],
        included_from=undefined
    },
    Include1 = #dnsfile{
        path=file("include.zone"),
        resources=[
            dnslib:resource("alias1.included.root", cname, in, "10min", "included.root"),
            dnslib:resource("included.root", txt, in, "10min", "included.root.")
        ],
        included_from=file("root.zone")
    },
    Include2 = #dnsfile{
        path=file("include.zone"),
        resources=[
            dnslib:resource("alias1.root", cname, in, "10min", "root"),
            dnslib:resource("root", txt, in, "10min","root.")
        ],
        included_from=file("root.zone")
    },
    RootTail = #dnsfile{
        path=file("root.zone"),
        resources=[
            dnslib:resource([<<"www">>,<<"root">>], aaaa, in, "1h", "::1"),
            dnslib:resource("Tail.root", txt, in, "2h", [<<>>,<<>>])
        ],
        included_from=undefined
    },
    {ok, [RootHead, Include1, Include2, RootTail]} = dnsfile:read_file(file("root.zone")).


include_loop_test() ->
    {error, _} = dnsfile:consult(file("include_loop")),
    {error, _} = dnsfile:consult(file("include_loop_step1")).
