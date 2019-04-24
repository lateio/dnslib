-module(dnslib_test).
-include_lib("eunit/include/eunit.hrl").

% Domains
list_to_domain_test() ->
    {ok, absolute, []} = dnslib:list_to_domain("."),
    {ok, relative, [<<"foo">>]} = dnslib:list_to_domain("foo"),
    {ok, absolute, [<<"foo">>]} = dnslib:list_to_domain("foo."),
    {ok, relative, ['_',<<"foo*">>,<<"*">>,<<"*bar">>]} = dnslib:list_to_domain("*.foo*.*.*bar"),
    {ok, absolute, ['_',<<"foo*">>,<<"*">>,<<"*bar">>]} = dnslib:list_to_domain("*.foo*.*.*bar."),
    {ok, relative, [<<"*">>,<<"foo*">>,<<"*">>,<<"*bar">>]} = dnslib:list_to_domain("\\*.foo*.*.*bar"),
    {ok, absolute, [<<"*">>,<<"foo*">>,<<"*">>,<<"*bar">>]} = dnslib:list_to_domain("\\*.foo*.*.*bar."),
    {ok, relative, [<<" ">>,<<" ">>]} = dnslib:list_to_domain("\\ .\\032"),
    {ok, absolute, [<<" ">>,<<" ">>]} = dnslib:list_to_domain("\\ .\\032."),
    {ok, relative, [<<"arv.io">>]} = dnslib:list_to_domain("arv\\.io"),
    {ok, absolute, [<<"arv.io">>]} = dnslib:list_to_domain("arv\\.io."),
    {error, empty_string} = dnslib:list_to_domain(""),
    {error, empty_label} = dnslib:list_to_domain(".."),
    {error, {invalid_escape_integer, "0a0"}} = dnslib:list_to_domain("\\0a0"),
    {error, {escape_out_of_range, 256}} = dnslib:list_to_domain("\\256"),
    {'error', {'non_ascii_codepoint', [255]}} = dnslib:list_to_domain("\\255"),
    {'error', {'non_ascii_codepoint', "ä"}} = dnslib:list_to_domain("ä").


list_to_codepoint_domain_test() ->
    {ok, absolute, true, []} = dnslib:list_to_codepoint_domain("."),
    {ok, relative, true, ["foo"]} = dnslib:list_to_codepoint_domain("foo"),
    {ok, absolute, true, ["foo"]} = dnslib:list_to_codepoint_domain("foo."),
    {ok, relative, true, ['_',"foo*","*","*bar"]} = dnslib:list_to_codepoint_domain("*.foo*.*.*bar"),
    {ok, absolute, true, ['_',"foo*","*","*bar"]} = dnslib:list_to_codepoint_domain("*.foo*.*.*bar."),
    {ok, relative, true, ["*","foo*","*","*bar"]} = dnslib:list_to_codepoint_domain("\\*.foo*.*.*bar"),
    {ok, absolute, true, ["*","foo*","*","*bar"]} = dnslib:list_to_codepoint_domain("\\*.foo*.*.*bar."),
    {ok, relative, true, [" ", " "]} = dnslib:list_to_codepoint_domain("\\ .\\032"),
    {ok, absolute, true, [" ", " "]} = dnslib:list_to_codepoint_domain("\\ .\\032."),
    Domain1 = lists:reverse([$.|[$ä || _ <- lists:seq(1,63)]]),
    {ok, absolute, false, _} = dnslib:list_to_codepoint_domain(Domain1),
    Domain2 = lists:reverse([$.|[$あ || _ <- lists:seq(1,63)]]),
    {ok, absolute, false, _} = dnslib:list_to_codepoint_domain(Domain2),
    {error, empty_string} = dnslib:list_to_codepoint_domain(""),
    {error, empty_label} = dnslib:list_to_codepoint_domain(".."),
    {error, {invalid_escape_integer, "0a0"}} = dnslib:list_to_codepoint_domain("\\0a0"),
    {error, {escape_out_of_range, 256}} = dnslib:list_to_codepoint_domain("\\256").


codepoint_domain_to_domain_test() ->
    {ok, [<<"ARV">>,<<"io">>]} = dnslib:codepoint_domain_to_domain(["ARV","io"]),
    {ok, ['_', <<"ARV">>,<<"io">>]} = dnslib:codepoint_domain_to_domain(['_', "ARV","io"]),
    {error, {codepoint_too_large, "あ"}} = dnslib:codepoint_domain_to_domain(["あ"]).


domain_to_codepoint_domain_test() ->
    ["ARV","io"] = dnslib:domain_to_codepoint_domain([<<"ARV">>,<<"io">>]).


domain_to_list_test() ->
    "*.arv.io." = dnslib:domain_to_list(['_',<<"arv">>,<<"io">>]),
    "\\\"arv.io." = dnslib:domain_to_list([<<"\"arv">>,<<"io">>]),
    "\\*.arv.io." = dnslib:domain_to_list([<<"*">>,<<"arv">>,<<"io">>]),
    "\\*.arv\\.io." = dnslib:domain_to_list([<<"*">>,<<"arv.io">>]),
    "\\*.arv\\032io." = dnslib:domain_to_list([<<"*">>,<<"arv io">>]),
    "\\*.arv.*.io." = dnslib:domain_to_list([<<"*">>,<<"arv">>,<<"*">>,<<"io">>]),
    "\\(arv.*.io." = dnslib:domain_to_list([<<"(arv">>,<<"*">>,<<"io">>]),
    "\\\"arv.*.io." = dnslib:domain_to_list([<<"\"arv">>,<<"*">>,<<"io">>]),
    "*.arv.io." = dnslib:domain_to_list(['_',"arv","io"]),
    "\\*.arv.io." = dnslib:domain_to_list(["*","arv","io"]),
    "\\*.arv\\.io." = dnslib:domain_to_list(["*","arv.io"]),
    "\\*.arv\\032io." = dnslib:domain_to_list(["*","arv io"]),
    "\\*.arv.*.io." = dnslib:domain_to_list(["*","arv","*","io"]),
    "\\(arv.*.io." = dnslib:domain_to_list(["(arv","*","io"]),
    "\\\"arv.*.io." = dnslib:domain_to_list(["\"arv","*","io"]).


reset_id_test() ->
    Msg1 = dnsmsg:new(),
    Msg2 = dnsmsg:reset_id(Msg1),
    true = Msg1 =/= Msg2.


subdomain_test() ->
    true = dnslib:is_subdomain([<<"arv">>,<<"io">>], [<<"io">>]),
    true = dnslib:is_subdomain([<<"arv">>,<<"io">>], ['_']),
    false = dnslib:is_subdomain([<<"arv">>,<<"io">>], ['_',<<"io">>]),
    false = dnslib:is_subdomain([<<"arv">>,<<"io">>], [<<"IO">>]),
    false = dnslib:is_subdomain([<<"def">>, <<"abc">>], [<<"ABC">>]),
    true  = dnslib:is_subdomain([<<"def">>, <<"abc">>], [<<"abc">>]),
    true  = dnslib:is_subdomain([<<"def">>, <<"abc">>], ['_']),
    false = dnslib:is_subdomain([<<"def">>, <<"abc">>], ['_', <<"abc">>]).


domain_in_zone_test() ->
    false = dnslib:domain_in_zone([<<"def">>, <<"abc">>], [<<"ABC">>]),
    true  = dnslib:domain_in_zone([<<"def">>, <<"abc">>], [<<"abc">>]),
    false = dnslib:domain_in_zone([<<"def">>, <<"abc">>], [<<"def">>]),
    true  = dnslib:domain_in_zone([<<"def">>, <<"abc">>], [<<"def">>, <<"abc">>]),
    true  = dnslib:domain_in_zone(['_', <<"def">>, <<"abc">>], [<<"def">>, <<"abc">>]),
    true  = dnslib:domain_in_zone([<<"def">>, <<"abc">>], ['_']),
    true  = dnslib:domain_in_zone([<<"def">>, <<"abc">>], ['_', <<"abc">>]),
    true  = dnslib:domain_in_zone(['_', <<"abc">>], ['_', <<"abc">>]).


append_domain_test() ->
    {ok, [<<"arv">>,<<"io">>,<<"*">>]} = dnslib:append_domain([<<"arv">>,<<"io">>], ['_']),
    {ok, ['_', <<"arv">>,<<"io">>,<<"*">>]} = dnslib:append_domain(['_', <<"arv">>,<<"io">>], ['_']),
    {ok, [<<"arv">>,<<"io">>,<<"*">>]} = dnslib:append_domain([[<<"arv">>,<<"io">>], ['_']]),
    {ok, ['_',<<"arv">>,<<"io">>,<<"*">>]} = dnslib:append_domain([['_'], [<<"arv">>,<<"io">>], ['_']]),
    {error, label_too_long} = dnslib:append_domain([<< <<$a>> || _ <- lists:seq(1,64)>>], []),
    Label = << <<$a>> || _ <- lists:seq(1,63)>>,
    {error, domain_too_long} = dnslib:append_domain([Label, Label], [Label, Label]),
    {error, empty_label} = dnslib:append_domain([<<>>], []).


is_valid_domain_test() ->
    true = dnslib:is_valid_domain([<<"arv">>,<<"io">>]),
    LongLabel = << <<$a>> || _ <- lists:seq(1,64)>>,
    {false, label_too_long} = dnslib:is_valid_domain([LongLabel]),
    Label = << <<$a>> || _ <- lists:seq(1,63)>>,
    {false, domain_too_long} = dnslib:is_valid_domain([Label, Label, Label, Label]),
    {false, empty_label} = dnslib:is_valid_domain([<<>>]),
    {false, non_binary_label} = dnslib:is_valid_domain([1]),
    {false, not_a_list} = dnslib:is_valid_domain(atom).


normalize_domain_test() ->
    ['_'] = dnslib:normalize_domain(['_']),
    [<<"arv">>, <<"io">>] = dnslib:normalize_domain([<<"ARV">>, <<"io">>]),
    [<<"Ä">>, <<"arv">>, <<"io">>] = dnslib:normalize_domain([<<"Ä">>,<<"ARV">>, <<"io">>]).


reverse_dns_domain_test() ->
    [<<"4">>,<<"3">>,<<"2">>,<<"1">>,<<"in-addr">>,<<"arpa">>] = dnslib:reverse_dns_domain({1,2,3,4}),

    IPv6 = {16#0123, 16#4567, 16#89abc, 16#def0, 16#1234, 16#5678, 16#9abc, 16#def0},
    [<<"0">>,<<"f">>,<<"e">>,<<"d">>,<<"c">>,<<"b">>,<<"a">>,<<"9">>,<<"8">>,
     <<"7">>,<<"6">>,<<"5">>,<<"4">>,<<"3">>,<<"2">>,<<"1">>,<<"0">>,<<"f">>,
     <<"e">>,<<"d">>,<<"c">>,<<"b">>,<<"a">>,<<"9">>,<<"7">>,<<"6">>,<<"5">>,
     <<"4">>,<<"3">>,<<"2">>,<<"1">>,<<"0">>,<<"ip6">>,<<"arpa">>] = dnslib:reverse_dns_domain(IPv6).


reverse_dns_question_test() ->
    {[<<"4">>,<<"3">>,<<"2">>,<<"1">>,<<"in-addr">>,<<"arpa">>], ptr, in} = dnslib:reverse_dns_question({1,2,3,4}),

    IPv6 = {16#0123, 16#4567, 16#89abc, 16#def0, 16#1234, 16#5678, 16#9abc, 16#def0},
    IPv6Domain = dnslib:reverse_dns_domain(IPv6),
    {IPv6Domain, ptr, in} = dnslib:reverse_dns_question(IPv6).


question_test() ->
    Question1 = {[<<"arv">>,<<"io">>], a, in} = dnslib:question("arv.io", a, in),
    Question1 = dnslib:question("arv.io."),
    Question1 = dnslib:question("arv.io.", a),
    Question1 = dnslib:question("arv.io.", a, in),
    Question1 = dnslib:question("arv.io", 1, 1),
    Question1 = dnslib:question("arv.io", "A", in),
    Question1 = dnslib:question("arv.io", "A", "IN"),
    Question1 = dnslib:question("arv.io", "TYPE1", "CLASS1"),
    Question1 = dnslib:question("arv.io A IN"),
    Question1 = dnslib:question("arv.io. A IN"),

    {'EXIT', {badarg, _}} = (catch dnslib:question([], -1, 1)), % out of range type
    {'EXIT', {badarg, _}} = (catch dnslib:question([], 16#FFFF+1, 1)), % out of range type
    {'EXIT', {badarg, _}} = (catch dnslib:question([], 1, -1)), % out of range class
    {'EXIT', {badarg, _}} = (catch dnslib:question([], 1, 16#FFFF+1)), % out of range class
    {'EXIT', {badarg, _}} = (catch dnslib:question("väinämöinen", 1, 1)), % non-ASCII error
    {'EXIT', {badarg, _}} = (catch dnslib:question([], not_a_type, 1)), % unknown type atom
    {'EXIT', {badarg, _}} = (catch dnslib:question([], 1, not_a_class)), % unknown class atom
    {'EXIT', {badarg, _}} = (catch dnslib:question([], "TYPE", 1)), % invalid type error
    {'EXIT', {badarg, _}} = (catch dnslib:question([], 1, "CLASS")). % invalid class error


resource_test() ->
    Resource1 = {[<<"arv">>,<<"io">>], a, in, 1800, {0,0,0,0}} = dnslib:resource("arv.io", a, in, 1800, {0,0,0,0}),
    Resource1 = dnslib:resource("arv.io", 1, 1, 1800, {0,0,0,0}),
    Resource1 = dnslib:resource("arv.io", 1, 1, 1800, <<0:32>>),
    Resource1 = dnslib:resource("arv.io", a, 1, 1800, <<0:32>>),
    Resource1 = dnslib:resource("arv.io", "A", 1, 1800, <<0:32>>),
    Resource1 = dnslib:resource("arv.io", "TYPE1", 1, 1800, <<0:32>>),
    Resource1 = dnslib:resource("arv.io", 1, 1, 1800, "\\# 4 00 00 00 00"),
    Resource1 = dnslib:resource("arv.io", a, 1, 1800, "\\# 4 00 00 00 00"),
    Resource1 = dnslib:resource("arv.io", "A", 1, 1800, "\\# 4 00 00 00 00"),
    Resource1 = dnslib:resource("arv.io", 1, 1, 1800, "0.0.0.0"),
    Resource1 = dnslib:resource("arv.io", "A", 1, 1800, "0.0.0.0"),
    Resource1 = dnslib:resource("arv.io", "A", "IN", 1800, "0.0.0.0"),
    Resource1 = dnslib:resource("arv.io", 1, "IN", 1800, "0.0.0.0"),
    Resource1 = dnslib:resource("arv.io", 1, "CLASS1", 1800, "0.0.0.0"),
    Resource1 = dnslib:resource("arv.io", "A", "IN", "30min", "0.0.0.0"),
    Resource1 = dnslib:resource("arv.io   IN  30min  A 0.0.0.0"),
    Resource1 = dnslib:resource("arv.io   IN  30min  A 0.0.0.0"),

    Resource2 = {[], a, in, 0, {0,0,0,0}} = dnslib:resource(". IN 0 A 0.0.0.0"),
    Resource2 = dnslib:resource(". IN 0 A \\# 4 00 00 00 00"),
    Resource2 = dnslib:resource(". CLASS1 0 TYPE1 \\# 4 00 00 00 00"),
    Resource2 = dnslib:resource(". CLASS1 0 A \\# 4 00 00 00 00"),
    Resource2 = dnslib:resource(".", a, in, 0, {0,0,0,0}),
    Resource2 = dnslib:resource([], 1, 1, 0, <<0:32>>),
    Resource2 = dnslib:resource(".", a, in, 0, "0.0.0.0"),
    Resource2 = dnslib:resource(".", a, in, 0, "\\# 4 00 00 00 00"),

    {[<<"arv">>,<<"io">>], a, in, 0, {0,0,0,0}} = dnslib:resource("arv.io IN 0 A 0.0.0.0"),

    Resource3 = {[<<"_spf">>,<<"arv">>,<<"io">>], txt, in, 0, [<<"v=spf1 mx -all">>]},
    Resource3 = dnslib:resource("_spf.arv.io", txt, in, 0, "\"v=spf1 mx -all\""),

    {[], a, in, 3600, {0,0,0,0}} = dnslib:resource([], a, in, "60min", "0.0.0.0"),

    {'EXIT', {badarg, _}} = (catch dnslib:resource([], -1, 1, 0, nil)),
    {'EXIT', {badarg, _}} = (catch dnslib:resource([], 16#FFFF+1, 1, 0, nil)),
    {'EXIT', {badarg, _}} = (catch dnslib:resource([], not_a_type, 1, 0, nil)),
    {'EXIT', {badarg, _}} = (catch dnslib:resource([], 1, -1, 0, nil)),
    {'EXIT', {badarg, _}} = (catch dnslib:resource([], 1, 16#FFFF+1, 0, nil)),
    {'EXIT', {badarg, _}} = (catch dnslib:resource([], 1, not_a_class, 0, nil)),
    {'EXIT', {badarg, _}} = (catch dnslib:resource([], 1, 1, -1, nil)),
    {'EXIT', {badarg, _}} = (catch dnslib:resource([], 1, 1, 16#7FFFFFFF+1, nil)),
    {'EXIT', {badarg, _}} = (catch dnslib:resource([], 1, 1, not_a_ttl, nil)),
    {'EXIT', {badarg, _}} = (catch dnslib:resource([], 1, 1, "foobar", nil)),
    {'EXIT', {badarg, _}} = (catch dnslib:resource([], cname, in, 60, {0,0,0,0})),
    {'EXIT', {badarg, _}} = (catch dnslib:resource([], "TYPE", in, 60, {0,0,0,0})),
    {'EXIT', {badarg, _}} = (catch dnslib:resource([], cname, "CLASS", 60, {0,0,0,0})),
    {'EXIT', {badarg, _}} = (catch dnslib:resource([], cname, "CLASS1", 60, "\\# -4 00")),
    {'EXIT', {badarg, _}} = (catch dnslib:resource([], cname, "CLASS1", 60, "\\# 4 0")).


resource_doc_test() ->
    RRLine = ".    IN    30min    A  0.0.0.0",
    {[], a, in, 1800, {0,0,0,0}} = Resource1 = dnslib:resource(RRLine),
    Resource1 = dnslib:resource(". IN 30min A \\# 4 00 00 00 00"),
    Resource1 = dnslib:resource(". CLASS1 30min TYPE1 \\# 4 00 00 00 00"),
    Resource1 = dnslib:resource(". CLASS1 30min A \\# 4 00 00 00 00"),
    Resource1 = dnslib:resource(".", a, in, "30min", {0,0,0,0}),
    Resource1 = dnslib:resource(".", "A", "IN", "30min", {0,0,0,0}),
    Resource1 = dnslib:resource(".", "TYPE1", "CLASS1", "30min", {0,0,0,0}),
    Resource1 = dnslib:resource(".", "TYPE1", "CLASS1", "30min", <<0:32>>),
    Resource1 = dnslib:resource(".", "TYPE1", "CLASS1", "30min", "\\# 4 00000000"),
    Resource1 = dnslib:resource([], 1, 1, 1800, <<0:32>>),
    Resource1 = dnslib:resource(".", a, in, 1800, "0.0.0.0"),
    Resource1 = dnslib:resource(".", a, in, 1800, "\\# 4 00 00 00 00"),

    {[<<"arv">>,<<"io">>], a, in, 0, {0,0,0,0}} = dnslib:resource("arv.io IN 0 A 0.0.0.0"),

    Resource2 = {[<<"_spf">>,<<"arv">>,<<"io">>], txt, in, 0, [<<"v=spf1 mx -all">>]},
    Resource2 = dnslib:resource("_spf.arv.io", txt, in, 0, "\"v=spf1 mx -all\""),

    Resource3 = {[], a, in, 3600, {0,0,0,0}} = dnslib:resource([], a, in, "60min", "0.0.0.0"),
    {[], a, in, 1892160000, {0,0,0,0}} = dnslib:resource([], a, in, "60 years", "0.0.0.0").


normalize_resource_test() ->
    {[], a, in, 0, {0,0,0,0}} = dnslib:normalize_resource({[], 1, 1, 0, <<0:32>>}),
    {[<<"arv">>,<<"io">>], a, in, 0, {0,0,0,0}} = dnslib:normalize_resource({[<<"ARV">>,<<"IO">>], 1, 1, 0, <<0:32>>}),
    {[<<"arv">>,<<"io">>], ns, in, 0, [<<"arv">>,<<"io">>]} = dnslib:normalize_resource({[<<"ARV">>,<<"IO">>], ns, 1, 0, <<3, "ARV", 2, "IO", 0>>}).


list_to_ttl_test() ->
    {ok, 2049840000} = dnslib:list_to_ttl("65 YEARS"),
    {ok, 168480000} = dnslib:list_to_ttl("65 month"),
    {ok, 39312000} = dnslib:list_to_ttl("65w"),
    {ok, 5616000} = dnslib:list_to_ttl("65 DAYS"),
    {ok, 234000} = dnslib:list_to_ttl("65hour"),
    {ok, 3900} = dnslib:list_to_ttl("65 mins"),
    {ok, 65} = dnslib:list_to_ttl("65"),
    {ok, 16#7FFFFFFF} = dnslib:list_to_ttl("max"),
    {error, empty_string} = dnslib:list_to_ttl(""),
    {error, {out_of_range, -60}} = dnslib:list_to_ttl("-60"),
    {error, {out_of_range, _}} = dnslib:list_to_ttl(integer_to_list(16#80000000)),
    {error, invalid_ttl} = dnslib:list_to_ttl("foobar"),
    {error, invalid_ttl} = dnslib:list_to_ttl("28 viikkoa").


deduplicate_test() ->
    Question1 = dnslib:question("arv.io", a, in),
    [Question1] = dnslib:deduplicate([Question1 || _ <- lists:seq(1,3)]),
    Resource1 = dnslib:resource("arv.io", cname, in, 60, "ARV.IO"),
    Resource2 = dnslib:resource("ARV.IO", cname, in, 60, "ARV.IO"),
    Resource3 = dnslib:resource("ARV.IO", a, in, 60, "0.0.0.0"),
    [Resource1, Resource3] = dnslib:deduplicate([Resource1, Resource3, Resource2]).


domain_test() ->
    [<<"arv">>,<<"io">>] = dnslib:domain("arv.io"),
    [<<"arv">>,<<"io">>] = dnslib:domain([<<"arv">>,<<"io">>]),
    [<<"arv">>,<<"io">>] = dnslib:domain(<<3, "arv", 2, "io", 0>>),
    {'EXIT', {badarg, _}} = (catch dnslib:domain("väinämöinen.com")), % Non-ASCII
    Long = [$a || _ <- lists:seq(1,64)],
    {'EXIT', {badarg, _}} = (catch dnslib:domain(Long)), % Too long label
    {'EXIT', {badarg, _}} = (catch dnslib:domain("abc..com")), % Empty label
    {'EXIT', {badarg, _}} = (catch dnslib:domain(<<3, "arv", 2, "io", 0, 0>>)). % Trailing byte(s)


type_test() ->
    a = dnslib:type("A"),
    a = dnslib:type("TYPE1"),
    a = dnslib:type(1),
    a = dnslib:type(a),
    a = dnslib:type(dnsrr_a), % Module responsible for the type

    % An unknown type
    2000 = dnslib:type("TYPE2000"),
    2000 = dnslib:type(2000),

    {'EXIT', {badarg, _}} = (catch dnslib:type(-1)), % Invalid value
    {'EXIT', {badarg, _}} = (catch dnslib:type("TYPEKIT")), % Invalid string
    {'EXIT', {badarg, _}} = (catch dnslib:type(unknown_atom)). % Unknown atom


class_test() ->
    in = dnslib:class("IN"),
    in = dnslib:class("CLASS1"),
    in = dnslib:class(1),
    in = dnslib:class(in),
    in = dnslib:class(dnsclass_in), % Module responsible for the class

    % An unknown type
    2000 = dnslib:class("CLASS2000"),
    2000 = dnslib:class(2000),

    {'EXIT', {badarg, _}} = (catch dnslib:class(-1)), % Invalid value
    {'EXIT', {badarg, _}} = (catch dnslib:class("CLASSROOM")), % Invalid string
    {'EXIT', {badarg, _}} = (catch dnslib:class(unknown_atom)). % Unknown atom


binary_label_test() ->
    {ok, _, [{binary, <<10,0,0,0>>}]} = dnslib:list_to_domain("\\[10.0.0.0]"),
    {ok, _, [{binary, <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1>>}]} = dnslib:list_to_domain("\\[::1]"),
    {ok, _, [{binary, <<1:1, 1:1>>}]} = dnslib:list_to_domain("\\[o6/2]"),
    {ok, _, [{binary, <<1:1, 1:1, 0:1>>}]} = dnslib:list_to_domain("\\[b110]"),
    {ok, _, [{binary, <<1:1, 1:1, 1:1, 1:1>>}]} = dnslib:list_to_domain("\\[xf]"),
    {ok, _, [{binary, <<1:1, 1:1, 1:1, 1:1>>}]} = dnslib:list_to_domain("\\[xf/4]"),

    {ok, _, SampleDomain} = dnslib:list_to_domain("\\[b11010000011101]"),
    {ok, _, SampleDomain} = dnslib:list_to_domain("\\[o64072/14]"),
    {ok, _, SampleDomain} = dnslib:list_to_domain("\\[xd074/14]"),
    {ok, _, SampleDomain} = dnslib:list_to_domain("\\[208.116.0.0/14]"),

    {error, _} = dnslib:list_to_domain("\\[f]"),
    {error, _} = dnslib:list_to_domain("\\[xf/3]"),
    {error, _} = dnslib:list_to_domain("\\[f"),
    {error, _} = dnslib:list_to_domain("\\[b111/2]"),
    {error, _} = dnslib:list_to_domain("\\[b110/2]"),

    "\\[xf]" = dnslib:domain_to_list([{binary, <<16#F:4>>}]),
    "\\[xff]" = dnslib:domain_to_list([{binary, <<16#FF>>}]),
    _ = (catch dnslib:domain_to_list([{binary, <<>>}])),

    [{binary, <<208, 29:6>>}] = dnslib:normalize_domain([{binary, <<1:1, 1:1, 1:1, 0:1, 1:1>>}, {binary, <<8#640:9>>}]),
    [{binary, <<16#F0>>}] = dnslib:normalize_domain([{binary, <<0:4>>}, {binary, <<16#F:4>>}]),
    [{binary, <<0:255>>}, {binary, <<1:256>>}] = dnslib:normalize_domain([{binary, <<1:1, 0:255>>}, {binary, <<0:255>>}]).
