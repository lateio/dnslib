-module(dnsmsg_test).
-include_lib("eunit/include/eunit.hrl").

o() -> #{is_response => true}.

interpret_response_cname_test() ->
    Question = {[<<"abc">>], a , in},
    Cname = {[<<"abc">>], cname, in, 0, [<<"def">>]},
    A = {[<<"def">>], a, in, 0, {0,0,0,0}},
    {ok, [{Question, ok, [A,Cname]}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question, [Cname, A])),
    {ok, [{Question, cname, {Cname, [Cname]}}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question, Cname)),
    Cname2 = {[<<"def">>], cname, in, 0, [<<"ghi">>]},
    {ok, [{Question, cname, {Cname2, [Cname2, Cname]}}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question, [Cname, Cname2])),
    Question2 = {[<<"def">>], a , in},
    Cname3 = {[<<"ghi">>], cname, in, 0, [<<"jkl">>]},
    Cname4 = {[<<"jkl">>], cname, in, 0, [<<"mno">>]},
    Cname5 = {[<<"mno">>], cname, in, 0, [<<"def">>]},
    {ok, [{Question2, cname_loop, [Cname5, Cname4, Cname3, Cname2]}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question2, [Cname2, Cname3, Cname4, Cname5])).


interpret_response_referral_test() ->
    Question = {[<<"b">>,<<"a">>], a, in},
    Ns = {[<<"a">>], ns, in, 0, [<<"dns1">>,<<"b">>,<<"a">>]},
    A = {[<<"dns1">>,<<"b">>,<<"a">>], a, in, 0, {1,2,3,4}},
    {ok, [{Question, referral, [{Ns, [A]}]}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question, [], Ns, A)),
    Ns2 = {[], ns, in, 0, [<<"dns1">>,<<"b">>,<<"a">>]},
    {ok, [{Question, missing_glue_referral, [Ns]}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question, [], [Ns, Ns2])),
    Ns3 = {[<<"a">>], ns, in, 0, []},
    A2 = {[], a, in, 0, {1,2,3,4}},
    {ok, [{Question, referral, [{Ns3, [A2]}]}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question, [], Ns3, A2)),
    {ok, [{Question, missing_glue_referral, [Ns]}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question, [], Ns)),
    {ok, [{Question, addressless_referral, [Ns3]}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question, [], Ns3)).


interpret_response_addressless_referral_test() ->
    Question = {[<<"b">>,<<"a">>], a, in},
    Ns = {[<<"c">>,<<"b">>,<<"a">>], ns, in, 0, [<<"dns1">>,<<"b">>,<<"a">>]},
    {ok, [{Question, undefined}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question, [], Ns)).


sanitize_glue_test() ->
    New = {{}, referral, [{{[<<"com">>], ns, in, 0, [<<"dns">>,<<"com">>]}, [{[<<"dns">>,<<"com">>], a, in, 0, {1,2,3,4}}]}]},
    Old = {{}, referral, [{{[<<"arv">>,<<"io">>], ns, in, 0, [<<"dns">>,<<"arv">>,<<"io">>]}, [{[<<"dns">>,<<"arv">>,<<"io">>], a, in, 0, {1,2,3,4}}]}]},
    {{}, addressless_referral, [{[<<"com">>], ns, in, 0, [<<"dns">>,<<"com">>]}]} = dnsmsg:sanitize_glue(New, Old),
    New2 = {{}, referral, [{{[<<"tree">>,<<"arv">>,<<"io">>], ns, in, 0, [<<"dns">>,<<"com">>]}, [{[<<"dns">>,<<"com">>], a, in, 0, {1,2,3,4}}]}]},
    {{}, addressless_referral, [{[<<"tree">>,<<"arv">>,<<"io">>], ns, in, 0, [<<"dns">>,<<"com">>]}]} = dnsmsg:sanitize_glue(New2, Old).
