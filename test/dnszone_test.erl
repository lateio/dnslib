-module(dnszone_test).
-include_lib("eunit/include/eunit.hrl").

file(Filename) ->
    filename:absname(filename:join(["test", "sample_files", Filename])).

is_valid_test() ->
    Resources1 = [
        dnslib:resource(". in 60 SOA ns1 hostmaster 0 60 60 60 0"),
        dnslib:resource("alias2 in 60 cname alias1"),
        dnslib:resource("ALIAS1 in 60 cname ALIAS2")
    ],
    {false, {cname_loop, [<<"alias2">>]}} = dnszone:is_valid(Resources1),
    Resources2 = [
        dnslib:resource(". in 60 SOA ns1 hostmaster 0 60 60 60 0"),
        dnslib:resource("alias1 in 60 cname alias2"),
        dnslib:resource("alias2 in 60 cname alias1")
    ],
    {false, {cname_loop, [<<"alias1">>]}} = dnszone:is_valid(Resources2),
    Resources3 = [
        dnslib:resource(". in 60 SOA ns1 hostmaster 0 60 60 60 0"),
        dnslib:resource("alias1 in 60 cname alias2"),
        dnslib:resource("alias1 in 60 cname alias3")
    ],
    {false, {non_exclusive_cname, _}} = dnszone:is_valid(Resources3).

o() -> #{is_response => true}.

transfer_zone_test() ->
    % Copied from dnsmsg_test:interpret_response_transfer_test()
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
    FirstMsg = dnsmsg:new(o(), Question, First),
    MiddleMsg = dnsmsg:new(o(), [], Middle),
    LastMsg = dnsmsg:new(o(), [], Last),
    CompleteMsg = dnsmsg:new(o(), Question, Complete),
    Transfer0 = dnszone:new_transfer(Question),
    {more, Transfer1} = dnszone:continue_transfer(FirstMsg, Transfer0),
    {more, Transfer2} = dnszone:continue_transfer(MiddleMsg, Transfer1),
    {ok, {zone, Soa, [Answer1, Answer2, Answer1, Answer2, Answer1, Answer2]}} = dnszone:continue_transfer(LastMsg, Transfer2),
    {error, unexpected_answer_type} = dnszone:continue_transfer(MiddleMsg, Transfer0),
    {error, unexpected_answer_type} = dnszone:continue_transfer(LastMsg, Transfer0),
    {ok, {zone, Soa, [Answer1, Answer2]}} = dnszone:continue_transfer(CompleteMsg, Transfer0).

transfer_incremental_test() ->
    % Copied from dnsmsg_test:interpret_response_incremental_transfer_test()
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
    FirstMsg = dnsmsg:new(o(), Question, First),
    MiddleMsg = dnsmsg:new(o(), [], Middle),
    LastMsg = dnsmsg:new(o(), [], Last),
    EmptyLastMsg = dnsmsg:new(o(), [], [NewSoa]),
    CompleteMsg = dnsmsg:new(o(), Question, Complete),
    Transfer0 = dnszone:new_transfer(Question),
    {more, Transfer1} = dnszone:continue_transfer(FirstMsg, Transfer0),
    {more, Transfer2} = dnszone:continue_transfer(MiddleMsg, Transfer1),
    {ok, {change_sets, NewSoa, [
        {{OldSoa, [Answer1]}, {NewSoa, [Answer2]}},
        {{OldSoa, [Answer1]}, {NewSoa, [Answer2]}},
        {{OldSoa, [Answer1]}, {NewSoa, [Answer2]}}
    ]}} = dnszone:continue_transfer(LastMsg, Transfer2),
    {error, unexpected_answer_type} = dnszone:continue_transfer(MiddleMsg, Transfer0),
    {error, unexpected_answer_type} = dnszone:continue_transfer(LastMsg, Transfer0),
    {ok, {change_sets, NewSoa, [
        {{OldSoa, [Answer1]}, {NewSoa, [Answer2]}}
    ]}} = dnszone:continue_transfer(CompleteMsg, Transfer0),
    {ok, {change_sets, NewSoa, [
        {{OldSoa, [Answer1]}, {NewSoa, [Answer2]}},
        {{OldSoa, [Answer1]}, {NewSoa, [Answer2]}}
    ]}} = dnszone:continue_transfer(EmptyLastMsg, Transfer2).


is_valid_file_test() ->
    true = dnszone:is_valid_file(file("all_rrs.zone")),
    AllSoa = dnslib:resource(".   IN   60   SOA     ns1 hostmaster 0 60 60 60 60"),
    {true, AllSoa} = dnszone:is_valid_file(file("all_rrs.zone"), [return_soa]).


stream_validate_test() ->
    State0 = dnszone:new_validate(),
    {false, _} = dnszone:end_validate(State0),
    Zone1 = [
        dnslib:resource(". in 60 SOA ns1 hostmaster 0 60 60 60 0"),
        dnslib:resource("alias2 in 60 cname alias1"),
        dnslib:resource("ALIAS1 in 60 cname ALIAS2")
    ],
    State1_1 = dnszone:continue_validate(Zone1, State0),
    {false, {cname_loop, [<<"alias2">>]}} = dnszone:end_validate(State1_1),
    Zone2 = [
        dnslib:resource(". in 60 SOA ns1 hostmaster 0 60 60 60 0"),
        dnslib:resource("alias1 in 60 cname alias2"),
        dnslib:resource("alias2 in 60 cname alias1")
    ],
    State2_1 = dnszone:continue_validate(Zone2, State0),
    {false, {cname_loop, [<<"alias1">>]}} = dnszone:end_validate(State2_1),
    Zone3 = [
        dnslib:resource(". in 60 SOA ns1 hostmaster 0 60 60 60 0"),
        dnslib:resource("alias1 in 60 cname alias2"),
        dnslib:resource("alias1 in 60 cname alias3")
    ],
    {false, {non_exclusive_cname, _}} = dnszone:continue_validate(Zone3, State0),
    Zone4_1 = [
        dnslib:resource(". in 60 SOA ns1 hostmaster 0 60 60 60 0")
    ],
    State4_1 = dnszone:continue_validate(Zone4_1, State0),
    true = dnszone:end_validate(State4_1),
    Zone4_2 = [
        dnslib:resource(". 60 TXT Hello")
    ],
    State4_2 = dnszone:continue_validate(Zone4_2, State4_1),
    true = dnszone:end_validate(State4_2).
