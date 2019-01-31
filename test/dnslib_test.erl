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


binary_to_domain_test() ->
    {ok, [<<"arv">>,<<"io">>], <<>>} = dnslib:binary_to_domain(<<3, "arv", 2, "io", 0>>),
    {compressed, {compressed, 2, [<<"io">>,<<"arv">>]}, <<>>} = dnslib:binary_to_domain(<<3, "arv", 2, "io", 1:1, 1:1, 2:14>>),
    {error, truncated_domain} = dnslib:binary_to_domain(<<0:2>>),
    {error, truncated_domain} = dnslib:binary_to_domain(<<3, "arv", 2, "io">>),
    {error, empty_binary} = dnslib:binary_to_domain(<<>>),
    BinLabel = << <<$a>> || _ <- lists:seq(1,63)>>,
    LongBinary = <<63, BinLabel/binary, 63, BinLabel/binary, 63, BinLabel/binary, 63, BinLabel/binary, 0>>,
    {error, domain_too_long} = dnslib:binary_to_domain(LongBinary),
    LastLabel = << <<$a>> || _ <- lists:seq(1,61)>>,
    MaxBinary = <<63, BinLabel/binary, 63, BinLabel/binary, 63, BinLabel/binary, 61, LastLabel/binary, 0>>,
    {ok, _, <<>>} = dnslib:binary_to_domain(MaxBinary),
    {error, {invalid_length, 0, 1}} = dnslib:binary_to_domain(<<0:1, 1:1, 0:6>>).


domain_to_binary_test() ->
    {ok, <<3, "ARV", 2, "io", 0>>} = dnslib:domain_to_binary([<<"ARV">>,<<"io">>]),
    {ok, <<3, "ARV", 2, "io", 3:2, 12:14>>} = dnslib:domain_to_binary({compressed, 12, [<<"io">>, <<"ARV">>]}),
    BinLabel = << <<$a>> || _ <- lists:seq(1,63)>>,
    {error, domain_too_long} = dnslib:domain_to_binary([BinLabel || _ <- lists:seq(1,4)]),
    {error, label_too_long} = dnslib:domain_to_binary([<< <<$a>> || _ <- lists:seq(1,64)>>]),
    {error, empty_label} = dnslib:domain_to_binary([<<>>]),
    {error, ref_out_of_range} = dnslib:domain_to_binary({compressed, -1, [<<"io">>, <<"ARV">>]}),
    {error, ref_out_of_range} = dnslib:domain_to_binary({compressed, 16#4000, [<<"io">>, <<"ARV">>]}).


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


domain_binary_length_test() ->
    1 = dnslib:domain_binary_length([]),
    8 = dnslib:domain_binary_length([<<"arv">>,<<"io">>]),
    9 = dnslib:domain_binary_length({compressed, 12, [<<"io">>,<<"arv">>]}).


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
    Question1 = dnslib:question("arv.io", 1, 1),

    {'EXIT', {badarg, _}} = (catch dnslib:question([], -1, 1)), % out of range type
    {'EXIT', {badarg, _}} = (catch dnslib:question([], 16#FFFF+1, 1)), % out of range type
    {'EXIT', {badarg, _}} = (catch dnslib:question([], 1, -1)), % out of range class
    {'EXIT', {badarg, _}} = (catch dnslib:question([], 1, 16#FFFF+1)), % out of range class
    {'EXIT', {badarg, _}} = (catch dnslib:question("väinämöinen", 1, 1)), % non-ASCII error
    {'EXIT', {badarg, _}} = (catch dnslib:question([], not_a_type, 1)), % unknown type atom
    {'EXIT', {badarg, _}} = (catch dnslib:question([], 1, not_a_class)). % unknown class atom


resource_test() ->
    Resource1 = {[<<"arv">>,<<"io">>], a, in, 0, {0,0,0,0}} = dnslib:resource("arv.io", a, in, 0, {0,0,0,0}),
    Resource1 = dnslib:resource("arv.io", 1, 1, 0, {0,0,0,0}),
    Resource1 = dnslib:resource("arv.io", 1, 1, 0, <<0:32>>),
    Resource1 = dnslib:resource("arv.io", 1, 1, 0, "0.0.0.0"),
    Resource1 = dnslib:resource("arv.io   IN  0  A 0.0.0.0"),

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
    {'EXIT', {badarg, _}} = (catch dnslib:resource([], cname, in, 60, {0,0,0,0})).


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
    {'EXIT', {badarg, _}} = (catch dnslib:domain("väinämöinen.com")), % Non-ASCII
    Long = [$a || _ <- lists:seq(1,64)],
    {'EXIT', {badarg, _}} = (catch dnslib:domain(Long)), % Too long label
    {'EXIT', {badarg, _}} = (catch dnslib:domain("abc..com")). % Empty label
