% ------------------------------------------------------------------------------
%
% Copyright (c) 2018, Lauri Moisio <l@arv.io>
%
% The MIT License
%
% Permission is hereby granted, free of charge, to any person obtaining a copy
% of this software and associated documentation files (the "Software"), to deal
% in the Software without restriction, including without limitation the rights
% to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
% copies of the Software, and to permit persons to whom the Software is
% furnished to do so, subject to the following conditions:
%
% The above copyright notice and this permission notice shall be included in
% all copies or substantial portions of the Software.
%
% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
% OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
% THE SOFTWARE.
%
% ------------------------------------------------------------------------------
%
% This file provides functions to create and modify DNS messages.
-module(dnsmsg).

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([
    new/0,
    new/1,
    new/2,
    new/3,
    new/4,
    new/5,
    response/1,
    response/2,

    id/1,
    opcode/1,
    return_code/1,
    is_request/1,
    is_response/1,
    udp_payload_max_size/1,

    reset_id/1,

    % Request functions
    set_header/2,
    set_header/3,
    add_to_section/3,
    add_question/2,
    add_answer/2,
    add_authority/2,
    add_additional/2,

    % Response functions
    set_response_header/2,
    set_response_header/3,
    add_to_response_section/3,
    add_response_answer/2,
    add_response_authority/2,
    add_response_additional/2,

    set_edns/3,

    interpret_response/1,
    interpret_results_to_response/1,
    apply_interpret_results/2,

    sanitize_glue/2,
    split_cname_referral/1
]).

-type message() ::
    #{
        'ID'                  => 0..16#FFFF - 1,
        'Is_response'         => boolean(),
        'Opcode'              => dnslib:opcode(),
        'Authoritative'       => boolean(),
        'Truncated'           => boolean(),
        'Recursion_desired'   => boolean(),
        'Recursion_available' => boolean(),
        'Reserved'            => 0,
        'Authenticated_data'  => boolean(), % DNSSEC
        'Checking_disabled'   => boolean(), % DNSSEC
        'Return_code'         => dnslib:return_code(),

        'EDNS_version'              => 0,
        'EDNS_udp_payload_size'     => 512..16#FFFF - 1,
        'EDNS_dnssec_ok'            => boolean(), % DNSSEC
        'EDNS' => map(),

        'Questions'     => [dnslib:question()],
        'Answers'       => [dnslib:resource()],
        'Nameservers'   => [dnslib:resource()],
        'Additional'    => [dnslib:resource()],

        'Response_Authoritative'       => boolean(),
        'Response_Truncated'           => boolean(),
        'Response_Recursion_desired'   => boolean(),
        'Response_Recursion_available' => boolean(),
        'Response_Reserved'            => 0,
        'Response_Authenticated_data'  => boolean(), % DNSSEC
        'Response_Checking_disabled'   => boolean(), % DNSSEC
        'Response_Return_code'         => dnslib:return_code(),

        'Response_Answers'     => [dnslib:resource()],
        'Response_Nameservers' => [dnslib:resource()],
        'Response_Additional'  => [dnslib:resource()]
    }.

-type message_section() ::
    'question'    |
    'answer'      |
    'nameserver'  |
    'additional'.

-type non_cname_interpret_result() ::
    {dnslib:question(), 'ok',         [dnslib:resource()]}                                            |
    {dnslib:question(), 'nodata',     {Soa :: dnslib:resource(), CnameTrail :: [dnslib:resource()]}}  |
    {dnslib:question(), 'name_error', {Soa :: dnslib:resource(), CnameTrail :: [dnslib:resource()]}}.

-type referral_interpret_result() ::
    {dnslib:question(), 'addressless_referral', [dnslib:resource()]}            |
    {dnslib:question(), 'missing_glue_referral', [dnslib:resource()]}           |
    {dnslib:question(), 'referral', {dnslib:resource(), [dnslib:resource()]}}.


-type interpret_result() ::
    non_cname_interpret_result() |
    referral_interpret_result()  |
    {dnslib:question(), 'cname_loop', Cnames :: [dnslib:resource()]} |
    {dnslib:question(), 'cname', {Cname :: dnslib:resource(cname), PreceedingCnames :: [dnslib:resource()]}} |
    {dnslib:question(), 'cname_referral', {Cname :: dnslib:resource(), PreceedingCnames :: [dnslib:resource()]}}.


-export_type([
    message/0,
    message_section/0,
    non_cname_interpret_result/0,
    referral_interpret_result/0,
    interpret_result/0
]).


-spec new() -> dnsmsg:message().
new() ->
    new(#{}).


-spec new(map()) -> dnsmsg:message().
new(Opts) ->
    MaxSize = application:get_env(dnslib, udp_payload_max_size, 512),
    Req = #{
        % Basic header
        'ID'                  => maps:get(id, Opts, rand:uniform(16#FFFF) - 1),
        'Is_response'         => maps:get(is_response, Opts, false),
        'Opcode'              => maps:get(opcode, Opts, query),
        'Authoritative'       => maps:get(authoritative, Opts, false),
        'Truncated'           => maps:get(truncated, Opts, false),
        'Recursion_desired'   => maps:get(recursion_desired, Opts, false),
        'Recursion_available' => maps:get(recursion_available, Opts, false),
        'Reserved'            => 0, % Better not to return a bitstring (<<0:3>>), More complicated, no upside
        'Authenticated_data'  => maps:get(authenticated_data, Opts, false),
        'Checking_disabled'   => maps:get(checking_disabled, Opts, false),
        'Return_code'         => maps:get(return_code, Opts, ok),

        'Questions'   => [],
        'Answers'     => [],
        'Nameservers' => [],
        'Additional'  => []
    },
    case Opts of
        #{edns := false} -> Req;
        #{} ->
            % edns
            % Should this be here by default or should this be a module
            % executed due to a config like post_new_message()
            % and the pre_message_serialization, post_message_deserialization
            % or just have a config for message extensions and then
            % they can export callbacks for response, new, pre serialization, etc.
            Req#{
                'EDNS_version'              => maps:get(edns_version, Opts, 0),
                'EDNS_udp_payload_size'     => maps:get(edns_udp_payload_size, Opts, MaxSize),
                'EDNS_dnssec_ok'            => maps:get(edns_dnssec_ok, Opts, false),
                'EDNS'                      => #{} % edns key-value options
            }
    end.

new(Opts, Questions) ->
    dnsmsg:new(Opts, Questions, [], [], []).

new(Opts, Questions, Answers) ->
    dnsmsg:new(Opts, Questions, Answers, [], []).

new(Opts, Questions, Answers, Nameservers) ->
    dnsmsg:new(Opts, Questions, Answers, Nameservers, []).

new(Opts, Questions, Answers, Nameservers, Additional) ->
    lists:foldl(fun ({Section, Entries}, FunMsg) -> add_to_section(FunMsg, Section, Entries) end, dnsmsg:new(Opts), [
        {question, Questions},
        {answer, Answers},
        {authority, Nameservers},
        {additional, Additional}
    ]).


-spec response(Req :: dnsmsg:message()) -> dnsmsg:message().
response(Req = #{'Is_response' := false}) ->
    response(Req, #{}).


-spec response(Req :: dnsmsg:message(), map()) -> dnsmsg:message().
response(Request = #{'Is_response' := false}, Opts) ->
    MaxSize = application:get_env(dnslib, udp_payload_max_size, 512),
    Response = Request#{
        % Changes to basic header
        'Is_response'         => true,
        'Authoritative'       => maps:get(authoritative, Opts, maps:get('Response_Authoritative', Request, false)),
        'Truncated'           => maps:get(truncated, Opts, maps:get('Response_Truncated', Request, false)),
        'Recursion_available' => maps:get(recursion_available, Opts, maps:get('Response_Recursion_available', Request, false)),
        'Reserved'            => 0,
        'Authenticated_data'  => maps:get(authenticated_data, Opts, maps:get('Response_Authenticated_data', Request, false)),
        'Checking_disabled'   => maps:get(checking_disabled, Opts, maps:get('Response_Checking_disabled', Request, false)),
        'Return_code'         => maps:get(return_code, Opts, maps:get('Response_Return_code', Request, ok)),

        'Answers'     => maps:get('Response_Answers', Request, []),
        'Nameservers' => maps:get('Response_Nameservers', Request, []),
        'Additional'  => maps:get('Response_Additional', Request, [])
    },
    case Request of
        #{'EDNS' := _} ->
            Response#{
                'EDNS_version'              => maps:get(edns_version, Opts, 0),
                'EDNS_udp_payload_size'     => maps:get(edns_udp_payload_size, Opts, MaxSize),
                'EDNS_dnssec_ok'            => maps:get(edns_dnssec_ok, Opts, false),
                'EDNS'                      => #{} % edns key-value options
            };
        #{} -> Response
    end.


-spec id(Msg :: dnsmsg:message()) -> 0..16#FFFF - 1.
id(#{'ID' := Id}) -> Id.


-spec udp_payload_max_size(message()) -> 512..16#FFFF - 1.
udp_payload_max_size(Msg) ->
    maps:get('EDNS_udp_payload_size', Msg, 512).


-spec reset_id(Msg :: message()) -> message().
reset_id(Msg = #{'ID' := Old}) ->
    case rand:uniform(16#FFFF) - 1 of
        Old -> reset_id(Msg);
        New -> Msg#{'ID' := New}
    end.


-spec opcode(Msg :: dnsmsg:message()) -> dnslib:opcode().
opcode(#{'Opcode' := Opcode}) -> Opcode.


-spec return_code(Msg :: dnsmsg:message()) -> dnslib:return_code().
return_code(#{'Return_code' := ReturnCode}) -> ReturnCode.


-spec is_request(message()) -> boolean().
is_request(Msg) ->
    not maps:get('Is_response', Msg).


-spec is_response(message()) -> boolean().
is_response(Msg) ->
    maps:get('Is_response', Msg).


-spec set_header
    (Msg :: dnsmsg:message(), 'authoritative', boolean()) -> dnsmsg:message();
    (Msg :: dnsmsg:message(), 'recursion_desired', boolean()) -> dnsmsg:message();
    (Msg :: dnsmsg:message(), 'truncated', boolean()) -> dnsmsg:message();
    (Msg :: dnsmsg:message(), 'return_code', dnslib:return_code()) -> dnsmsg:message().
set_header(Msg, authoritative, Boolean) when Boolean =:= true; Boolean =:= false ->
    Msg#{'Authoritative' => Boolean};
set_header(Msg, recursion_desired, Boolean) when Boolean =:= true; Boolean =:= false ->
    Msg#{'Recursion_desired' => Boolean};
set_header(Msg, truncated, Boolean) when Boolean =:= true; Boolean =:= false ->
    Msg#{'Truncated' => Boolean};
set_header(Msg, return_code, Code) ->
    true = dnslib:is_valid_return_code(Code),
    Msg#{'Return_code' => Code}.


-spec set_header(Msg :: message(), map() | list()) -> message().
set_header(Msg, Map) when is_map(Map) ->
    set_header(Msg, maps:to_list(Map));
set_header(Msg, List) when is_list(List) ->
    lists:foldl(fun ({Key, Value}, FunMsg) -> set_header(FunMsg, Key, Value) end, Msg, List).


-spec add_to_section(message(), message_section(), dnslib:question() | dnslib:resource()) -> dnsmsg:message().
add_to_section(Req, question, Tuple) ->
    add_question(Req, Tuple);
add_to_section(Req, answer, Tuple) ->
    add_answer(Req, Tuple);
add_to_section(Req, authority, Tuple) ->
    add_authority(Req, Tuple);
add_to_section(Req, additional, Tuple) ->
    add_additional(Req, Tuple).


-spec add_entry(term(), [term()]) -> [term()].
add_entry(Entry, List) ->
    % Don't allow adding duplicates
    case lists:member(Entry, List) of
        true  -> List;
        false -> [Entry|List]
    end.


-spec add_question(message(), dnslib:question()) -> message().
add_question(Msg = #{'Questions' := List}, Entry = {_, _, _}) ->
    Msg#{'Questions' => add_entry(Entry, List)};
add_question(Msg = #{'Questions' := List0}, Entries = [{_, _, _}|_]) ->
    List1 = lists:foldl(fun (Entry = {_, _, _}, FunList) -> add_entry(Entry, FunList) end, List0, Entries),
    Msg#{'Questions' => List1}.


-spec add_answer(message(), dnslib:resource()) -> message().
add_answer(Msg = #{'Answers' := List}, Entry = {_, _, _, _, _}) ->
    Msg#{'Answers' => add_entry(Entry, List)};
add_answer(Msg, []) ->
    Msg;
add_answer(Msg = #{'Answers' := List0}, Entries = [{_, _, _, _, _}|_]) ->
    List1 = lists:foldl(fun (Entry = {_, _, _, _, _}, FunList) -> add_entry(Entry, FunList) end, List0, Entries),
    Msg#{'Answers' => List1}.


-spec add_authority(message(), dnslib:resource()) -> message().
add_authority(Msg = #{'Nameservers' := List}, Entry = {_, _, _, _, _}) ->
    Msg#{'Nameservers' => add_entry(Entry, List)};
add_authority(Msg, []) ->
    Msg;
add_authority(Msg = #{'Nameservers' := List0}, Entries = [{_, _, _, _, _}|_]) ->
    List1 = lists:foldl(fun (Entry = {_, _, _, _, _}, FunList) -> add_entry(Entry, FunList) end, List0, Entries),
    Msg#{'Nameservers' => List1}.


-spec add_additional(message(), dnslib:resource()) -> message().
add_additional(Msg = #{'Additional' := List}, Entry = {_, _, _, _, _}) ->
    Msg#{'Additional' => add_entry(Entry, List)};
add_additional(Msg, []) ->
    Msg;
add_additional(Msg = #{'Additional' := List0}, Entries = [{_, _, _, _, _}|_]) ->
    List1 = lists:foldl(fun (Entry = {_, _, _, _, _}, FunList) -> add_entry(Entry, FunList) end, List0, Entries),
    Msg#{'Additional' => List1}.


-spec set_edns(message(), Key :: atom(), Value :: term()) -> message().
set_edns(Msg = #{'EDNS' := Edns}, Key, Value) ->
    Msg#{'EDNS'=>Edns#{Key => Value}}.


-spec set_response_header
    (Msg :: dnsmsg:message(), 'authoritative', boolean()) -> dnsmsg:message();
    (Msg :: dnsmsg:message(), 'recursion_desired', boolean()) -> dnsmsg:message();
    (Msg :: dnsmsg:message(), 'truncated', boolean()) -> dnsmsg:message();
    (Msg :: dnsmsg:message(), 'return_code', dnslib:return_code()) -> dnsmsg:message().
set_response_header(Msg = #{'Is_response' := false}, authoritative, Boolean) when Boolean =:= true; Boolean =:= false ->
    Msg#{'Response_Authoritative' => Boolean};
set_response_header(Msg = #{'Is_response' := false}, recursion_desired, Boolean) when Boolean =:= true; Boolean =:= false ->
    Msg#{'Response_Recursion_desired' => Boolean};
set_response_header(Msg = #{'Is_response' := false}, truncated, Boolean) when Boolean =:= true; Boolean =:= false ->
    Msg#{'Response_Truncated' => Boolean};
set_response_header(Msg = #{'Is_response' := false}, return_code, Code) ->
    true = dnslib:is_valid_return_code(Code),
    Msg#{'Response_Return_code' => Code}.


set_response_header(Msg = #{'Is_response' := false}, Map) when is_map(Map) ->
    set_response_header(Msg, maps:to_list(Map));
set_response_header(Msg = #{'Is_response' := false}, List) when is_list(List) ->
    lists:foldl(fun ({Key, Value}, FunMsg) -> set_response_header(FunMsg, Key, Value) end, Msg, List).


-spec add_to_response_section(message(), message_section(), dnslib:question() | dnslib:resource()) -> dnsmsg:message().
add_to_response_section(Req, answer, Tuple) ->
    add_response_answer(Req, Tuple);
add_to_response_section(Req, authority, Tuple) ->
    add_response_authority(Req, Tuple);
add_to_response_section(Req, additional, Tuple) ->
    add_response_additional(Req, Tuple).


-spec add_response_answer
    (message(), dnslib:resource()) -> message();
    (message(), interpret_result()) -> {ok, message()}.
add_response_answer(Msg = #{'Is_response' := false}, Entry = {_, _, _, _, _}) ->
    List = maps:get('Response_Answers', Msg, []),
    Msg#{'Response_Answers' => add_entry(Entry, List)};
add_response_answer(Msg = #{'Is_response' := false}, Entry = {_, _, _}) ->
    add_response_interpret_result(Msg, Entry);
add_response_answer(Msg = #{'Is_response' := false}, []) ->
    Msg;
add_response_answer(Msg = #{'Is_response' := false}, Entries = [{_, _, _, _, _}|_]) ->
    List0 = maps:get('Response_Answers', Msg, []),
    List1 = lists:foldl(fun (Entry = {_, _, _, _, _}, FunList) -> add_entry(Entry, FunList) end, List0, Entries),
    Msg#{'Response_Answers' => List1}.


add_response_interpret_result(Msg, _) ->
    maps:get('Response_Interpret_result', Msg, []),
    {ok, Msg}.


%add_response_nodata_answer(Msg, Query, SoaRR).
%add_response_name_error_answer(Msg, Query, SoaRR)


-spec add_response_authority(message(), dnslib:resource()) -> message().
add_response_authority(Msg = #{'Is_response' := false}, Entry = {_, _, _, _, _}) ->
    List = maps:get('Response_Nameservers', Msg, []),
    Msg#{'Response_Nameservers' => add_entry(Entry, List)};
add_response_authority(Msg = #{'Is_response' := false}, []) ->
    Msg;
add_response_authority(Msg = #{'Is_response' := false}, Entries = [{_, _, _, _, _}|_]) ->
    List0 = maps:get('Response_Nameservers', Msg, []),
    List1 = lists:foldl(fun (Entry = {_, _, _, _, _}, FunList) -> add_entry(Entry, FunList) end, List0, Entries),
    Msg#{'Response_Nameservers' => List1}.


-spec add_response_additional(message(), dnslib:resource()) -> message().
add_response_additional(Msg = #{'Is_response' := false}, Entry = {_, _, _, _, _}) ->
    List = maps:get('Response_Additional', Msg, []),
    Msg#{'Response_Additional' => add_entry(Entry, List)};
add_response_additional(Msg = #{'Is_response' := false}, []) ->
    Msg;
add_response_additional(Msg = #{'Is_response' := false}, Entries = [{_, _, _, _, _}|_]) ->
    List0 = maps:get('Response_Additional', Msg, []),
    List1 = lists:foldl(fun (Entry = {_, _, _, _, _}, FunList) -> add_entry(Entry, FunList) end, List0, Entries),
    Msg#{'Response_Additional' => List1}.


-spec interpret_response(dnsmsg:message()) -> {ok, list()} | {leftovers, list(), list()}.
interpret_response(Msg = #{'Is_response' := true}) ->
    #{
        'Return_code'   := ReturnCode,
        'Authoritative' := Authoritative,
        'Questions'     := Questions,
        'Answers'       := Answers,
        'Nameservers'   := Nameservers,
        'Additional'    := Additional
    } = Msg,
    % What should we accept from whom. How to make glue not stick around...
    fix_return_code_n_authoritative(ReturnCode, Authoritative, interpret_response(Questions, Answers, Nameservers, Additional, []), []).


fix_return_code_n_authoritative(_, _, [], Acc) ->
    {ok, lists:reverse(Acc)};
fix_return_code_n_authoritative(name_error, Authoritative, [{Question, nodata, SoaTuple}|Rest], Acc) ->
    fix_return_code_n_authoritative(name_error, Authoritative, Rest, [{Question, name_error, SoaTuple}|Acc]);
fix_return_code_n_authoritative(ReturnCode, Authoritative, [{Question, undefined}|Rest], Acc)
when ReturnCode =:= refused; ReturnCode =:= format_error; ReturnCode =:= server_error ->
    fix_return_code_n_authoritative(ReturnCode, Authoritative, Rest, [{Question, ReturnCode}|Acc]);
fix_return_code_n_authoritative(ReturnCode, Authoritative, [Tuple|Rest], Acc) ->
    fix_return_code_n_authoritative(ReturnCode, Authoritative, Rest, [Tuple|Acc]).


% Should we preserve sections?
% What if the response is malicious and mangled,
% we should somehow filter/check to preserve sanity...
interpret_response([], _, _, _, Acc) ->
    Acc;
%interpret_response([], Leftovers, Acc) ->
%    {leftover_resources, Acc, Leftovers};
interpret_response([{Domain0, Type, Class}=Question|Rest], Answers0, Nameservers, Additional, Acc) ->
    Domain = dnslib:normalize(Domain0),
    Fn = interpret_response_split_fun(Domain, Type, Class),
    case Fn(Answers0) of
        {[], _} -> interpret_response(Rest, Answers0, Nameservers, Additional, [infer_question_response(Domain, Question, Nameservers, Additional)|Acc]);
        {RelatedAnswers, Answers1} -> interpret_response_check_cname(Rest, Answers1, Nameservers, Additional, Acc, Question, RelatedAnswers, [])
    end.


interpret_response_check_cname(Rest, Answers, Nameservers, Additional, Acc, {_, cname, _}=Question, QuestionAnswers, _) ->
    interpret_response(Rest, Answers, Nameservers, Additional, [{Question, ok, QuestionAnswers}|Acc]);
interpret_response_check_cname(Rest, Answers0, Nameservers, Additional, Acc, {_, Type, _}=Question, QuestionAnswers, PrevAnswers) ->
    case lists:filter(fun (Tuple) -> element(2, Tuple) =:= cname end, QuestionAnswers) of
        [] ->
            % Should we consider additionally here?
            interpret_response(Rest, Answers0, Nameservers, Additional, [{Question, ok, lists:append(QuestionAnswers, PrevAnswers)}|Acc]);
        [{_, cname, Class, _, CanonDomain0}=CnameRR] ->
                CanonDomain = dnslib:normalize(CanonDomain0),
                Fn = interpret_response_split_fun(CanonDomain, Type, Class),
                case Fn(Answers0) of
                    {[], _} ->
                        AccTuple = case infer_question_response(CanonDomain, {CanonDomain0, Type, Class}, Nameservers, Additional) of
                            % cname result always encloses another interpret result?
                            % Except that undefined will be considered a 'clueless' referral.
                            {_, undefined} ->
                                case interpret_response_check_cname_loop(CnameRR, PrevAnswers) of
                                    true -> {Question, cname_loop, lists:append(QuestionAnswers, PrevAnswers)};
                                    false -> {Question, cname, {CnameRR, lists:append(QuestionAnswers, PrevAnswers)}}
                                end;
                            {_, nodata, {SoaRR, _}} -> {Question, nodata, {SoaRR, lists:append(QuestionAnswers, PrevAnswers)}};
                            Tuple -> {Question, cname_referral, {CnameRR, Tuple, lists:append(QuestionAnswers, PrevAnswers)}}
                        end,
                        interpret_response(Rest, Answers0, Nameservers, Additional, [AccTuple|Acc]);
                    {RelatedAnswers, Answers1} -> interpret_response_check_cname(Rest, Answers1, Nameservers, Additional, Acc, Question, RelatedAnswers, lists:append(QuestionAnswers, PrevAnswers))
                end;
        _ -> % Multiple cnames, error
            error(multiple_cnames)
    end.


interpret_response_check_cname_loop({_, _, _, _, CanonDomain0}, PrevAnswers) ->
    CanonDomain = dnslib:normalize(CanonDomain0),
    case lists:filter(fun ({FunDomain0, cname, _, _, _}) -> dnslib:normalize(FunDomain0) =:= CanonDomain; (_) -> false end, PrevAnswers) of
        [] -> false;
        _ -> true
    end.


infer_question_response(Domain, Question, Nameservers, Additional) ->
    infer_question_response_nodata(Domain, Question, Nameservers, Additional).


infer_question_response_nodata(Domain, {_, _, Class}=Question, Nameservers, Additional) ->
    case lists:filter(fun ({_, Type, FunClass, _, _}) -> Type =:= soa andalso FunClass =:= Class end, Nameservers) of
        [] -> infer_question_response_referral(Domain, Question, Nameservers, Additional);
        SoaDomains0 ->
            SoaDomains = lists:sort(fun ({D1, _, _, _, _}, {D2, _, _, _, _}) -> length(D1) > length(D2) end, SoaDomains0),
            case
                lists:splitwith(
                    fun ({FunDomain, _, _, _, _}) -> not dnslib:in_zone(Domain, dnslib:normalize(FunDomain)) end,
                    SoaDomains
                )
            of
                {_, []} -> infer_question_response_referral(Domain, Question, Nameservers, Additional);
                {_, [SoaRR|_]} -> {Question, nodata, {SoaRR, []}}
            end
    end.


infer_question_response_referral(Domain, {_, _, Class}=Question, Nameservers, Additional) ->
    case lists:filter(fun ({_, Type, FunClass, _, _}) -> Type =:= ns andalso FunClass =:= Class end, Nameservers) of
        [] -> {Question, undefined};
        NsDomains0 ->
            NsDomains1 = lists:sort(fun ({D1, _, _, _, _}, {D2, _, _, _, _}) -> length(D1) > length(D2) end, NsDomains0),
            case
                lists:filter(
                    fun ({FunDomain, _, _, _, _}) -> dnslib:in_zone(Domain, dnslib:normalize(FunDomain)) end,
                    NsDomains1
                )
            of
                [] -> {Question, undefined};
                [{NsDomain0, _, _, _, _}|_] = CaseList0 ->
                    NsDomain = dnslib:normalize(NsDomain0),
                    {CaseList1, _} = lists:splitwith(fun ({FunDomain, _, _, _, _}) -> NsDomain =:= dnslib:normalize(FunDomain) end, CaseList0),
                    case referral_ns_address_match(CaseList1, Additional, []) of
                        {missing_glue, NsList} -> {Question, missing_glue_referral, NsList};
                        {addressless, NsList} -> {Question, addressless_referral, NsList};
                        {ok, NsAddrList} -> {Question, referral, NsAddrList}
                    end
            end
    end.


interpret_response_split_fun(Domain, Type, Class) ->
    fun (List) ->
        lists:partition(
            fun (Tuple) ->
                case Tuple of
                    {ResourceDomain, Type, Class, _, _} ->
                        case dnslib:normalize(ResourceDomain) of
                            Domain -> true;
                            _ -> false
                        end;
                    {ResourceDomain, cname, Class, _, _} ->
                        case dnslib:normalize(ResourceDomain) of
                            Domain -> true;
                            _ -> false
                        end;
                    _ -> false
                end
            end,
        List)
    end.


referral_ns_address_match([], _, Acc) ->
    % Should we make sure that addresses are sane?
    {Normal, Addressless} = lists:partition(fun ({_, AddrList}) -> AddrList =/= [] end, Acc),
    case lists:filter(fun ({{NsDomain, _, _, _, ServerDomain}, _}) -> not dnslib:in_zone(dnslib:normalize(ServerDomain), dnslib:normalize(NsDomain)) end, Addressless) of
        [] when Normal =:= [] -> {missing_glue, [NsTuple || {NsTuple, _} <- Acc]};
        [] -> {ok, Normal};
        NotInZone when Normal =:= [] -> {addressless, [NsTuple || {NsTuple, _} <- NotInZone]};
        NotInZone -> {ok, lists:append(Normal, NotInZone)}
    end;
referral_ns_address_match([{_, _, Class, _, Domain0}=Ns|Rest], Additional, Acc) ->
    Domain = dnslib:normalize(Domain0),
    Addresses = lists:filter(fun ({FunDomain, _, FunClass, _, _}) -> dnslib:normalize(FunDomain) =:= Domain andalso FunClass =:= Class end, Additional),
    referral_ns_address_match(Rest, Additional, [{Ns, lists:filter(fun referral_ns_address_filter/1, Addresses)}|Acc]).


referral_ns_address_filter({_, a, _, _, {_, _, _, _}=Address}) ->
    case Address of
        {0, _, _, _} -> false;         % 0.0.0.0/8
        {192, 0, 2, _} -> false;       % Documentation
        {224, _, _, _} -> false;       % Multicast
        {255, 255, 255, 255} -> false; % Broadcast
        _ -> true
    end;
referral_ns_address_filter({_, aaaa, _, _, {_B1, _B2, _B3, _B4, _B5, _B6, _B7, _B8}=Address}) ->
    case Address of
        {0, 0, 0, 0, 0, 0, 0, 0} -> false;       % Routing
        {16#FFFF, 16#FFFF, 16#FFFF, 16#FFFF, 16#FFFF, 16#FFFF, 16#FFFF, 16#FFFF} -> false;
        {16#2001, 16#0DB8, _, _, _, _, _, _} -> false; % Documentation
        _ when (_B1 band 16#FF00) =:= 16#FF00 -> false; % Multicast
        _ -> true
    end.


interpret_results_to_response(Res) ->
    case apply_interpret_results(Res, dnsmsg:new(#{is_response => true})) of
        {ok, _}=Tuple -> Tuple
    end.


apply_interpret_results(Res, Msg) ->
    % We should somehow figure out what results the message is already representing,
    % then use those to set a proper value for PrevResTypes list
    apply_interpret_results(Res, Msg, []).


apply_interpret_results([], Msg, _) ->
    {ok, Msg};
apply_interpret_results([Tuple|Rest], Msg, PrevResTypes) ->
    ResType = element(2, Tuple),
    {Add, Set} = case maps:get('Is_response', Msg) of
        false -> {fun add_to_response_section/3, fun set_response_header/3};
        true -> {fun add_to_section/3, fun set_header/3}
    end,
    case results_can_coexist(ResType, PrevResTypes) of
        false -> {error, {cannot_coexist, ResType}};
        true  ->
            case Tuple of
                {Question, ok, Answers} ->
                    Msg1 = Add(add_question(Msg, Question), answer, Answers),
                    apply_interpret_results(Rest, Set(Msg1, return_code, ok), [ResType|PrevResTypes]);
                {Question, name_error, {Soa, Answers}} ->
                    Msg1 = Add(add_question(Msg, Question), answer, Answers),
                    Msg2 = Add(Msg1, authority, Soa),
                    apply_interpret_results(Rest, Set(Msg2, return_code, name_error), [ResType|PrevResTypes]);
                {Question, nodata, {Soa, Answers}} ->
                    Msg1 = Add(add_question(Msg, Question), answer, Answers),
                    Msg2 = Add(Msg1, authority, Soa),
                    apply_interpret_results(Rest, Set(Msg2, return_code, ok), [ResType|PrevResTypes]);
                {Question, referral, NsAddressRrs} ->
                    Msg1 = add_question(Msg, Question),
                    Msg2 = lists:foldl(fun ({NsRr, AddressRr}, FunMsg) -> Add(Add(FunMsg, authority, NsRr), additional, AddressRr) end, Msg1, NsAddressRrs),
                    apply_interpret_results(Rest, Set(Msg2, authoritative, false), [ResType|PrevResTypes]);
                {Question, addressless_referral, NsRrs} ->
                    Msg1 = Add(add_question(Msg, Question), authority, NsRrs),
                    apply_interpret_results(Rest, Set(Msg1, authoritative, false), [ResType|PrevResTypes]);
                {Question, cname, {_, Prev}} ->
                    Msg1 = Add(add_question(Msg, Question), answer, Prev),
                    apply_interpret_results(Rest, Msg1, [ResType|PrevResTypes]);
                {Question, cname_loop, Answers} ->
                    Msg1 = Add(add_question(Msg, Question), answer, Answers),
                    apply_interpret_results(Rest, Msg1, [ResType|PrevResTypes]);
                {Question, cname_referral, {CnameRr, Referral, Resources}} ->
                    CnameTuple = {Question, cname, {CnameRr, Resources}},
                    apply_interpret_results([CnameTuple, setelement(1, Referral, Question)|Rest], Msg, PrevResTypes);
                {Question, refused} ->
                    Msg1 = add_question(Set(Msg, return_code, refused), Question),
                    apply_interpret_results(Rest, Msg1, [ResType|PrevResTypes]);
                {Question, _} ->
                    Msg1 = add_question(Set(Msg, return_code, server_error), Question),
                    apply_interpret_results(Rest, Msg1, [server_error|PrevResTypes])
            end
    end.


results_can_coexist(name_error, Previous) ->
    not lists:member(nodata, Previous);
results_can_coexist(nodata, Previous) ->
    not lists:member(name_error, Previous);
results_can_coexist(refused, Previous) ->
    not lists:member(name_error, Previous);
results_can_coexist(_, _) ->
    true.


sanitize_glue({Question, referral, [{{NewNsDomain, _, _, _, _}, _}|_]=NsAddressRrs0}, {_, referral, [{{OldNsDomain0, _, _, _, _}, _}|_]}) ->
    OldNsDomain = dnslib:normalize(OldNsDomain0),
    case dnslib:subdomain(dnslib:normalize(NewNsDomain), OldNsDomain) of
        false -> {Question, addressless_referral, [NsRr || {NsRr, _} <- NsAddressRrs0]};
        true ->
            % Make sure that all presented addresses are also subdomains of previous
            Fn = fun ({FunDomain0, _, _, _, _}) -> dnslib:in_zone(dnslib:normalize(FunDomain0), OldNsDomain) end,
            NsAddressRrs1 = lists:map(fun ({FunNsRr, FunAddresses}) -> {FunNsRr, lists:filter(Fn, FunAddresses)} end, NsAddressRrs0),
            case lists:all(fun ({_, FunAddresses}) -> FunAddresses =:= [] end, NsAddressRrs1) of
                true -> {Question, addressless_referral, [NsRr || {NsRr, _} <- NsAddressRrs0]};
                false -> {Question, referral, NsAddressRrs1}
            end
    end.


split_cname_referral({Question, cname_referral, {CnameRr, ReferralTuple, Resources}}) ->
    Base = case interpret_response_check_cname_loop(CnameRr, Resources) of
        true -> [{Question, cname_loop, Resources}];
        false -> [{Question, cname, {CnameRr, Resources}}]
    end,
    [ReferralTuple|Base].
