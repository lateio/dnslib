-module(dnsmsg_test).
-include_lib("eunit/include/eunit.hrl").

o() -> #{is_response => true}.

order_test() ->
    Question1 = {[], ns, in},
    Question2 = dnslib:question("ns1", a, in),
    QList = [Question2, Question1],
    Resource1 = dnslib:resource("", ns, in, 60, "ns1"),
    Resource2 = dnslib:resource("ns1", a, in, 60, {0,0,0,0}),
    RList = [Resource2, Resource1],
    Msg0 = dnsmsg:new(),
    Msg1 = dnsmsg:add_question(Msg0, Question1),
    Msg2 = dnsmsg:add_question(Msg1, Question2),
    Msg3 = dnsmsg:add_answer(Msg2, Resource1),
    Msg4 = dnsmsg:add_answer(Msg3, Resource2),
    Msg5 = dnsmsg:add_authority(Msg4, Resource1),
    Msg6 = dnsmsg:add_authority(Msg5, Resource2),
    Msg7 = dnsmsg:add_additional(Msg6, Resource1),
    Msg8 = dnsmsg:add_additional(Msg7, Resource2),
    Msg8 = Msg0#{'Questions' => QList, 'Answers' => RList, 'Nameservers' => RList, 'Additional' => RList},
    Msg0_1 = dnsmsg:add_question(Msg0, QList),
    Msg0_2 = dnsmsg:add_answer(Msg0_1, RList),
    Msg0_3 = dnsmsg:add_authority(Msg0_2, RList),
    Msg0_4 = dnsmsg:add_additional(Msg0_3, RList),
    Msg0_4 = Msg0#{'Questions' => QList, 'Answers' => RList, 'Nameservers' => RList, 'Additional' => RList},
    Msg8 =
        dnsmsg:set_section(
            dnsmsg:set_section(
                dnsmsg:set_section(
                    dnsmsg:set_section(Msg0, question, [Question1, Question2]
                ), answer, [Resource1, Resource2]
            ), authority, [Resource1, Resource2]
        ), additional, [Resource1, Resource2]).


response_test() ->
    Resource = dnslib:resource("arv.io", a, in, 60, {0,0,0,0}),
    Req = dnsmsg:new(),
    Req1 = dnsmsg:add_response_answer(Req, Resource),
    #{'Answers' := [Resource]} = dnsmsg:response(Req1).


interpret_documentation_test() ->
    Question = dnslib:question("arv.io", a, in),
    Resource = dnslib:resource("arv.io", a, in, 60, {0,0,0,0}),
    Res = dnsmsg:new(#{is_response => true}, Question, Resource),
    {ok, [{Question, ok, [Resource]}]} = dnsmsg:interpret_response(Res).

interpret_documentation2_test() ->
    Question = dnslib:question("arv.io", axfr, in),
    Soa = dnslib:resource("arv.io IN 60 SOA ns1.arv.io hostmaster.arv.io 0 1min 1min 1min 1min"),
    Resource = dnslib:resource("arv.io", a, in, 60, {0,0,0,0}),
    Res = dnsmsg:new(#{is_response => true}, Question, [Soa, Resource, Soa]),
    {ok, [{Question, zone_transfer, {Soa, complete, [Resource]}}]} = dnsmsg:interpret_response(Res).

interpret_documentation3_test() ->
    Question = dnslib:question("alias.arv.io", a, in),
    Cname = dnslib:resource("alias.arv.io", cname, in, 60, "arv.io"),
    Resource = dnslib:resource("arv.io", a, in, 60, {0,0,0,0}),
    Res = dnsmsg:new(#{is_response => true}, Question, [Cname, Resource]),
    {ok, [{Question, ok, [Resource, Cname]}]} = dnsmsg:interpret_response(Res).

interpret_documentation4_test() ->
    Question = dnslib:question("alias.arv.io", a, in),
    Res = dnsmsg:new(#{is_response => true}, Question),
    {ok, [{Question, undefined}]} = dnsmsg:interpret_response(Res).


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


interpret_response_all_test() ->
    Question = {[<<"b">>,<<"a">>], all, in},
    Answer1 = {[<<"b">>,<<"a">>], a, in, 0, {}},
    Answer2 = {[<<"b">>,<<"a">>], txt, in, 0, {}},
    Answers = [Answer1, Answer2],
    {ok, [{Question, ok, [Answer1, Answer2]}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question, Answers)).


interpret_response_all_any_test() ->
    Question = {[<<"b">>,<<"a">>], all, any},
    Answer1 = {[<<"b">>,<<"a">>], a, in, 0, {}},
    Answer2 = {[<<"b">>,<<"a">>], txt, hs, 0, {}},
    Answers = [Answer1, Answer2],
    {ok, [{Question, ok, [Answer1, Answer2]}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question, Answers)).


interpret_response_transfer_test() ->
    Question = {[<<"b">>,<<"a">>], axfr, in},
    Soa = {[<<"b">>,<<"a">>], soa, in , 0, {}},
    Answer1 = {[<<"b">>,<<"a">>], a, in, 0, {}},
    Answer2 = {[<<"b">>,<<"a">>], txt, in, 0, {}},
    First = [
        Soa,
        Answer1,
        Answer2
    ],
    Middle = [
        Answer1,
        Answer2
    ],
    Last = [
        Answer1,
        Answer2,
        Soa
    ],
    Complete = [
        Soa,
        Answer1,
        Answer2,
        Soa
    ],
    {ok, [{Question, zone_transfer, {Soa, first, [Answer1, Answer2]}}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question, First)),
    {ok, [{Question, zone_transfer, {nil, middle, [Answer1, Answer2]}}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question, Middle)),
    {ok, [{Question, zone_transfer, {Soa, last, [Answer1, Answer2]}}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question, Last)),
    {ok, [{Question, zone_transfer, {Soa, complete, [Answer1, Answer2]}}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question, Complete)),
    Question2 = {[<<"b">>,<<"a">>], ixfr, in},
    {ok, [{Question2, zone_transfer, {Soa, first, [Answer1, Answer2]}}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question2, First)),
    {ok, [{Question2, zone_transfer, {nil, middle, [Answer1, Answer2]}}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question2, Middle)),
    {ok, [{Question2, zone_transfer, {Soa, last, [Answer1, Answer2]}}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question2, Last)),
    {ok, [{Question2, zone_transfer, {Soa, complete, [Answer1, Answer2]}}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question2, Complete)),
    Error = [
        {[<<"a">>], a, in, 0, {}}
    ],
    {ok, [{Question, {error, _}}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question, Error)),
    {ok, [{Question2, {error, _}}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question2, Error)).


interpret_response_incremental_transfer_test() ->
    Question = {[<<"b">>,<<"a">>], ixfr, in},
    NewSoa = {[<<"b">>,<<"a">>], soa, in , 0, {[],[],1,1,2,3,4}},
    OldSoa = {[<<"b">>,<<"a">>], soa, in , 0, {[],[],0,1,2,3,4}},
    Answer1 = {[<<"b">>,<<"a">>], a, in, 0, {}},
    Answer2 = {[<<"b">>,<<"a">>], txt, in, 0, {}},
    First = [
        NewSoa,
        OldSoa,
        Answer1,
        NewSoa,
        Answer2
    ],
    Middle = [
        OldSoa,
        Answer1,
        NewSoa,
        Answer2
    ],
    Last = [
        OldSoa,
        Answer1,
        NewSoa,
        Answer2,
        NewSoa
    ],
    Complete = [
        NewSoa,
        OldSoa,
        Answer1,
        NewSoa,
        Answer2,
        NewSoa
    ],
    {ok, [{Question, incremental_zone_transfer, {NewSoa, first, [{{OldSoa, [Answer1]}, {NewSoa, [Answer2]}}]}}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question, First)),
    {ok, [{Question, incremental_zone_transfer, {nil, middle, [{{OldSoa, [Answer1]}, {NewSoa, [Answer2]}}]}}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question, Middle)),
    {ok, [{Question, incremental_zone_transfer, {NewSoa, last, [{{OldSoa, [Answer1]}, {NewSoa, [Answer2]}}]}}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question, Last)),
    {ok, [{Question, incremental_zone_transfer, {NewSoa, complete, [{{OldSoa, [Answer1]}, {NewSoa, [Answer2]}}]}}]} = dnsmsg:interpret_response(dnsmsg:new(o(), Question, Complete)).


term_limit_test() ->
    % The dnsmsg currently matches duplicates in dnsmsg:add_* makes it slow enough that
    % a default unit test timeouts...
    Resources = [{[], a, in, 60, {0,0,0,0}}|[{[], Type, in, 60, nil} || Type <- lists:seq(1,16#FFFF)]],
    {'EXIT', {function_clause, _}} = (catch dnsmsg:new(#{}, [], Resources)).


wrong_section_test() ->
    Resource = {[], opt, 512, 0, nil}, % Invalid term, doesn't matter
    Msg = dnsmsg:new(),
    {'EXIT', {{badmatch, _}, _}} = (catch dnsmsg:add_answer(Msg, Resource)).
