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
    is_response/1,
    is_request/1,
    questions/1,
    answers/1,
    authority/1,
    additional/1,
    udp_payload_max_size/1,

    reset_id/1,

    % Request functions
    set_header/2,
    set_header/3,
    add_to_section/3,
    set_section/3,
    add_question/2,
    add_answer/2,
    add_authority/2,
    add_additional/2,

    % Response functions
    set_response_header/2,
    set_response_header/3,
    add_to_response_section/3,
    set_response_section/3,
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

-type message() :: map().
%%
%%    #{
%%        'ID'                  => 0..16#FFFF,
%%        'Is_response'         => boolean(),
%%        'Opcode'              => dnslib:opcode() | 0..16#F,
%%        'Authoritative'       => boolean(),
%%        'Truncated'           => boolean(),
%%        'Recursion_desired'   => boolean(),
%%        'Recursion_available' => boolean(),
%%        'Reserved'            => 0,
%%        'Authenticated_data'  => boolean(), % DNSSEC
%%        'Checking_disabled'   => boolean(), % DNSSEC
%%        'Return_code'         => dnslib:return_code() | 0..16#FFF,
%%
%%        'EDNS_version'              => 0,
%%        'EDNS_udp_payload_size'     => 512..16#FFFF,
%%        'EDNS_dnssec_ok'            => boolean(), % DNSSEC
%%        'EDNS' => map(),
%%
%%        'Questions'     => [dnslib:question()],
%%        'Answers'       => [dnslib:resource()],
%%        'Nameservers'   => [dnslib:resource()],
%%        'Additional'    => [dnslib:resource()],
%%
%%        'Response'      => map()
%%    }.

-type message_section() ::
    'question'    |
    'answer'      |
    'nameserver'  |
    'additional'.

-type terminal_interpret_result() ::
    {dnslib:question(), 'ok',         [dnslib:resource()]}                                            |
    {dnslib:question(), 'nodata',     {Soa :: dnslib:resource(), CnameTrail :: [dnslib:resource()]}}  |
    {dnslib:question(), 'name_error', {Soa :: dnslib:resource(), CnameTrail :: [dnslib:resource()]}}.

-type referral_interpret_result() ::
    {dnslib:question(), 'addressless_referral', [dnslib:resource()]}            |
    {dnslib:question(), 'missing_glue_referral', [dnslib:resource()]}           |
    {dnslib:question(), 'referral', [{dnslib:resource(), [dnslib:resource()]}]}.

-type cname_interpret_result() ::
    {dnslib:question(), 'cname_loop', Cnames :: [dnslib:resource()]} |
    {dnslib:question(), 'cname', {Cname :: dnslib:resource(cname), PreceedingCnames :: [dnslib:resource()]}} |
    {dnslib:question(), 'cname_referral', {Cname :: dnslib:resource(), Referral :: referral_interpret_result(), PreceedingCnames :: [dnslib:resource()]}}.

-type transfer_result_type() ::
      'complete'
    | 'first'
    | 'middle'
    | 'last'.

-type incremental_transfer_change_set() ::
    {Deletions :: {OldSoa :: dnslib:resource(), [dnslib:resources()]}, Adds :: {NewSoa :: dnslib:resource(), [dnslib:resources()]}}.

-type transfer_interpret_result() ::
    {dnslib:question(), 'zone_transfer' | 'incremental_zone_transfer', {Soa :: dnslib:resource() | 'nil', Type :: transfer_result_type(), Resources :: [dnslib:resource()] | [incremental_transfer_change_set()]}}.

-type error_interpret_result() ::
    {dnslib:question(), term()}.

-type interpret_result() ::
    terminal_interpret_result()  |
    referral_interpret_result()  |
    cname_interpret_result()     |
    transfer_interpret_result()  |
    error_interpret_result().


-export_type([
    message/0,
    message_section/0,
    terminal_interpret_result/0,
    cname_interpret_result/0,
    referral_interpret_result/0,
    error_interpret_result/0,
    interpret_result/0
]).


-spec new() -> dnsmsg:message().
new() ->
    new(#{}).


-spec new(map()) -> dnsmsg:message().
new(Opts) ->
    MaxSize = application:get_env(dnslib, udp_payload_max_size, 512),
    Opcode = case maps:get(opcode, Opts, query) of
        CaseOp when is_atom(CaseOp) -> CaseOp;
        CaseOp when is_integer(CaseOp) -> dnswire:opcode(CaseOp)
    end,
    ReturnCode = case maps:get(return_code, Opts, ok) of
        CaseReturn when is_atom(CaseReturn) -> CaseReturn;
        CaseReturn when is_integer(CaseReturn) -> dnswire:return_code(CaseReturn)
    end,
    Req = #{
        % Basic header
        'ID'                  => maps:get(id, Opts, rand:uniform(16#FFFF + 1) - 1),
        'Is_response'         => maps:get(is_response, Opts, false),
        'Opcode'              => Opcode,
        'Authoritative'       => maps:get(authoritative, Opts, false),
        'Truncated'           => maps:get(truncated, Opts, false),
        'Recursion_desired'   => maps:get(recursion_desired, Opts, false),
        'Recursion_available' => maps:get(recursion_available, Opts, false),
        'Reserved'            => 0, % Better not to return a bitstring (<<0:3>>), More complicated, no upside
        'Authenticated_data'  => maps:get(authenticated_data, Opts, false),
        'Checking_disabled'   => maps:get(checking_disabled, Opts, false),
        'Return_code'         => ReturnCode,

        'Questions'   => [],
        'Answers'     => [],
        'Nameservers' => [],
        'Additional'  => [],

        'Response' => #{
            'Answers'     => [],
            'Nameservers' => [],
            'Additional'  => []
        }
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

new(Opts, Questions, Answers, Nameservers, Additional) when is_tuple(Questions) ->
    new(Opts, [Questions], Answers, Nameservers, Additional);
new(Opts, Questions, Answers, Nameservers, Additional) when is_tuple(Answers) ->
    new(Opts, Questions, [Answers], Nameservers, Additional);
new(Opts, Questions, Answers, Nameservers, Additional) when is_tuple(Nameservers) ->
    new(Opts, Questions, Answers, [Nameservers], Additional);
new(Opts, Questions, Answers, Nameservers, Additional) when is_tuple(Additional) ->
    new(Opts, Questions, Answers, Nameservers, [Additional]);
new(Opts, Questions, Answers, Nameservers, Additional) ->
    lists:foldl(fun ({Section, Entries}, FunMsg) -> set_section(FunMsg, Section, Entries) end, dnsmsg:new(Opts), [
        {question, Questions},
        {answer, Answers},
        {authority, Nameservers},
        {additional, Additional}
    ]).


-spec response(Req :: dnsmsg:message()) -> dnsmsg:message().
response(Req = #{'Is_response' := false}) ->
    response(Req, #{}).


-spec response(Req :: dnsmsg:message(), map()) -> dnsmsg:message().
response(Request = #{'Is_response' := false, 'Response' := ProtoResponse}, Opts) ->
    MaxSize = application:get_env(dnslib, udp_payload_max_size, 512),
    ReturnCode = case maps:get(return_code, Opts, maps:get('Return_code', ProtoResponse, ok)) of
        CaseCode when is_atom(CaseCode) -> CaseCode;
        Value when is_integer(Value) ->
            case dnswire:return_code(Value) of
                Value -> Value;
                CaseCode -> CaseCode
            end
    end,
    Response = Request#{
        % Changes to basic header
        'Is_response'         => true,
        'Authoritative'       => maps:get(authoritative, Opts, maps:get('Authoritative', ProtoResponse, false)),
        'Truncated'           => maps:get(truncated, Opts, maps:get('Truncated', ProtoResponse, false)),
        'Recursion_available' => maps:get(recursion_available, Opts, maps:get('Recursion_available', ProtoResponse, false)),
        'Reserved'            => 0,
        'Authenticated_data'  => maps:get(authenticated_data, Opts, maps:get('Authenticated_data', ProtoResponse, false)),
        'Checking_disabled'   => maps:get(checking_disabled, Opts, maps:get('Checking_disabled', ProtoResponse, false)),
        'Return_code'         => ReturnCode,

        'Answers'     => maps:get('Answers', ProtoResponse, []),
        'Nameservers' => maps:get('Nameservers', ProtoResponse, []),
        'Additional'  => maps:get('Additional', ProtoResponse, [])
    },
    maps:remove('Response',
        case Request of
            #{'EDNS' := _} ->
                Response#{
                    'EDNS_version'              => maps:get(edns_version, Opts, 0),
                    'EDNS_udp_payload_size'     => maps:get(edns_udp_payload_size, Opts, MaxSize),
                    'EDNS_dnssec_ok'            => maps:get(edns_dnssec_ok, Opts, false),
                    'EDNS'                      => #{} % edns key-value options
                };
            #{} -> Response
        end
    ).


-spec id(Msg :: dnsmsg:message()) -> 0..16#FFFF.
id(#{'ID' := Id}) -> Id.


-spec udp_payload_max_size(message()) -> 512..16#FFFF.
udp_payload_max_size(Msg) ->
    maps:get('EDNS_udp_payload_size', Msg, 512).


-spec reset_id(Msg :: message()) -> message().
reset_id(Msg = #{'ID' := Old, 'Is_response' := false}) ->
    case rand:uniform(16#FFFF + 1) - 1 of
        Old -> reset_id(Msg);
        New -> Msg#{'ID' := New}
    end.


-spec opcode(Msg :: dnsmsg:message()) -> dnslib:opcode() | 0..16#F.
opcode(#{'Opcode' := Opcode}) -> Opcode.


-spec return_code(Msg :: dnsmsg:message()) -> dnslib:return_code() | 0..16#FFF.
return_code(#{'Return_code' := ReturnCode}) -> ReturnCode.


-spec is_request(message()) -> boolean().
is_request(Msg) ->
    not is_response(Msg).


-spec is_response(message()) -> boolean().
is_response(Msg) ->
    maps:get('Is_response', Msg).


questions(#{'Questions' := List}) ->
    lists:reverse(List).

answers(#{'Answers' := List}) ->
    lists:reverse(List).

authority(#{'Nameservers' := List}) ->
    lists:reverse(List).

additional(#{'Additional' := List}) ->
    lists:reverse(List).


-spec set_header
    (Msg :: dnsmsg:message(), 'id', 0..16#FFFF) -> dnsmsg:message();
    (Msg :: dnsmsg:message(), 'opcode', dnslib:opcode() | 0..16#F) -> dnsmsg:message();
    (Msg :: dnsmsg:message(), 'return_code', dnslib:return_code() | 0..16#FFF) -> dnsmsg:message();
    (Msg :: dnsmsg:message(),
          'authoritative'
        | 'truncated'
        | 'recursion_desired'
        | 'recursion_available'
        | 'authenticated_data'
        | 'checking_disabled',
     boolean()) -> dnsmsg:message().
set_header(Msg, authoritative, Boolean) when Boolean =:= true; Boolean =:= false ->
    Msg#{'Authoritative' => Boolean};
set_header(Msg, truncated, Boolean) when Boolean =:= true; Boolean =:= false ->
    Msg#{'Truncated' => Boolean};
set_header(Msg, recursion_desired, Boolean) when Boolean =:= true; Boolean =:= false ->
    Msg#{'Recursion_desired' => Boolean};
set_header(Msg, recursion_available, Boolean) when Boolean =:= true; Boolean =:= false ->
    Msg#{'Recursion_available' => Boolean};
set_header(Msg, authenticated_data, Boolean) when Boolean =:= true; Boolean =:= false ->
    Msg#{'Authenticated_data' => Boolean};
set_header(Msg, checking_disabled, Boolean) when Boolean =:= true; Boolean =:= false ->
    Msg#{'Checking_disabled' => Boolean};
set_header(Msg, id, Id) when Id >= 0, Id =< 16#FFFF ->
    Msg#{'ID' => Id};
set_header(Msg, opcode, Code)
when is_integer(Code), Code >= 0, Code =< 16#F ->
    case dnswire:return_code(Code) of
        Code -> Msg#{'Opcode' => Code};
        Atom ->
            true = dnslib:is_valid_return_code(Atom),
            Msg#{'Opcode' => Atom}
    end;
set_header(Msg, opcode, Code) when is_atom(Code) ->
    true = dnslib:is_valid_opcode(Code),
    Msg#{'Opcode' => Code};
set_header(Msg, return_code, Code)
when is_integer(Code), Code >= 0, Code =< 16#FFF ->
    case dnswire:opcode(Code) of
        Code -> Msg#{'Opcode' => Code};
        Atom ->
            true = dnslib:is_valid_return_code(Atom),
            Msg#{'Opcode' => Atom}
    end;
set_header(Msg, return_code, Code) when is_atom(Code) ->
    true = dnslib:is_valid_return_code(Code),
    Msg#{'Return_code' => Code}.


-spec set_header(Msg :: message(), map() | list()) -> message().
set_header(Msg, Map) when is_map(Map) ->
    set_header(Msg, maps:to_list(Map));
set_header(Msg, List) when is_list(List) ->
    lists:foldl(fun ({Key, Value}, FunMsg) -> set_header(FunMsg, Key, Value) end, Msg, List).


-spec add_to_section(message(), message_section(), dnslib:question() | [dnslib:question()] | dnslib:resource() | [dnslib:resource()]) -> dnsmsg:message().
add_to_section(Req, question, Tuple) ->
    add_question(Req, Tuple);
add_to_section(Req, answer, Tuple) ->
    add_answer(Req, Tuple);
add_to_section(Req, authority, Tuple) ->
    add_authority(Req, Tuple);
add_to_section(Req, additional, Tuple) ->
    add_additional(Req, Tuple).


-spec set_section(message(), message_section(), [dnslib:question()] | [dnslib:resource()]) -> dnsmsg:message().
set_section(Req, question, List) when length(List) =< 16#FFFF ->
    true = lists:all(fun (FunTuple) -> tuple_size(FunTuple) =:= 3 end, List),
    Req#{'Questions' => lists:reverse(List)};
set_section(Req, answer, List) when length(List) =< 16#FFFF ->
    true = lists:all(fun (FunTuple) -> tuple_size(FunTuple) =:= 5 end, List),
    Req#{'Answers' => lists:reverse(List)};
set_section(Req, authority, List) when length(List) =< 16#FFFF ->
    true = lists:all(fun (FunTuple) -> tuple_size(FunTuple) =:= 5 end, List),
    Req#{'Nameservers' => lists:reverse(List)};
set_section(Req, additional, List) when length(List) =< 16#FFFF ->
    true = lists:all(fun (FunTuple) -> tuple_size(FunTuple) =:= 5 end, List),
    Req#{'Additional' => lists:reverse(List)}.


-spec add_entry(term(), [term()]) -> [term()].
add_entry(Entry, List) when length(List) < 16#FFFF ->
    % Don't allow adding duplicates ?
    %case lists:member(Entry, List) of
    %    true  -> List;
    %    false -> [Entry|List]
    %end.
    [Entry|List].


-spec add_question(message(), dnslib:question() | [dnslib:question()]) -> message().
add_question(Msg, Entry = {_, _, _}) ->
    add_question(Msg, [Entry]);
add_question(Msg, []) ->
    Msg;
add_question(Msg = #{'Questions' := List0}, Entries = [{_, _, _}|_]) ->
    List1 = lists:foldr(
        fun (Entry = {_, Type, _}, FunList) ->
            true = dnsrr:section_valid_for_type(question, Type),
            add_entry(Entry, FunList)
        end, List0, Entries),
    true = length(List1) =< 16#FFFF,
    Msg#{'Questions' => List1}.


-spec add_answer(message(), dnslib:resource() | [dnslib:resource()]) -> message().
add_answer(Msg, Entry = {_, _, _, _, _}) ->
    add_answer(Msg, [Entry]);
add_answer(Msg, []) ->
    Msg;
add_answer(Msg = #{'Answers' := List0}, Entries = [{_, _, _, _, _}|_]) ->
    List1 = lists:foldr(
        fun (Entry = {_, Type, _, _, _}, FunList) ->
            true = dnsrr:section_valid_for_type(answer, Type),
            add_entry(Entry, FunList)
        end, List0, Entries),
    true = length(List1) =< 16#FFFF,
    Msg#{'Answers' => List1}.


-spec add_authority(message(), dnslib:resource() | [dnslib:resource()]) -> message().
add_authority(Msg, Entry = {_, _, _, _, _}) ->
    add_authority(Msg, [Entry]);
add_authority(Msg, []) ->
    Msg;
add_authority(Msg = #{'Nameservers' := List0}, Entries = [{_, _, _, _, _}|_]) ->
    List1 = lists:foldr(
        fun (Entry = {_, Type, _, _, _}, FunList) ->
            true = dnsrr:section_valid_for_type(authority, Type),
            add_entry(Entry, FunList)
        end, List0, Entries),
    true = length(List1) =< 16#FFFF,
    Msg#{'Nameservers' => List1}.


-spec add_additional(message(), dnslib:resource() | [dnslib:resource()]) -> message().
add_additional(Msg, Entry = {_, _, _, _, _}) ->
    add_additional(Msg, [Entry]);
add_additional(Msg, []) ->
    Msg;
add_additional(Msg = #{'Additional' := List0}, Entries = [{_, _, _, _, _}|_]) ->
    List1 = lists:foldr(
        fun (Entry = {_, Type, _, _, _}, FunList) ->
            true = dnsrr:section_valid_for_type(additional, Type),
            add_entry(Entry, FunList)
        end, List0, Entries),
    true = length(List1) =< 16#FFFF,
    Msg#{'Additional' => List1}.


-spec set_edns(message(), Key :: atom(), Value :: term()) -> message().
set_edns(Msg = #{'EDNS' := Edns}, Key, Value) ->
    Msg#{'EDNS'=>Edns#{Key => Value}}.


-spec set_response_header
    (Msg :: dnsmsg:message(), 'authoritative', boolean()) -> dnsmsg:message();
    (Msg :: dnsmsg:message(), 'truncated', boolean()) -> dnsmsg:message();
    (Msg :: dnsmsg:message(), 'recursion_available', boolean()) -> dnsmsg:message();
    (Msg :: dnsmsg:message(), 'authenticated_data', boolean()) -> dnsmsg:message();
    (Msg :: dnsmsg:message(), 'checking_disabled', boolean()) -> dnsmsg:message();
    (Msg :: dnsmsg:message(), 'return_code', dnslib:return_code() | 0..16#FFF) -> dnsmsg:message().
set_response_header(Msg = #{'Is_response' := false, 'Response' := Response}, authoritative, Value) ->
    Msg#{'Response' => set_header(Response, authoritative, Value)};
set_response_header(Msg = #{'Is_response' := false, 'Response' := Response}, truncated, Value) ->
    Msg#{'Response' => set_header(Response, truncated, Value)};
set_response_header(Msg = #{'Is_response' := false, 'Response' := Response}, recursion_available, Value) ->
    Msg#{'Response' => set_header(Response, recursion_available, Value)};
set_response_header(Msg = #{'Is_response' := false, 'Response' := Response}, authenticated_data, Value) ->
    Msg#{'Response' => set_header(Response, authenticated_data, Value)};
set_response_header(Msg = #{'Is_response' := false, 'Response' := Response}, checking_disabled, Value) ->
    Msg#{'Response' => set_header(Response, checking_disabled, Value)};
set_response_header(Msg = #{'Is_response' := false, 'Response' := Response}, return_code, Value) ->
    Msg#{'Response' => set_header(Response, return_code, Value)}.


set_response_header(Msg = #{'Is_response' := false}, Map) when is_map(Map) ->
    set_response_header(Msg, maps:to_list(Map));
set_response_header(Msg = #{'Is_response' := false, 'Response' := Response}, List) when is_list(List) ->
    Msg#{'Response' => set_header(Response, List)}.
    %lists:foldl(fun ({Key, Value}, FunMsg) -> set_response_header(FunMsg, Key, Value) end, Msg, List).


-spec add_to_response_section(message(), message_section(), dnslib:question() | dnslib:resource()) -> dnsmsg:message().
add_to_response_section(Req = #{'Response' := Response}, Section, Tuple)
when Section =:= answer; Section =:= authority; Section =:= additional ->
    Req#{'Response' => add_to_section(Response, Section, Tuple)}.


-spec set_response_section(message(), message_section(), [dnslib:question()] | [dnslib:resource()]) -> dnsmsg:message().
set_response_section(Req = #{'Response' := Response}, Section, List) ->
    Req#{'Response' => set_section(Response, Section, List)}.


-spec add_response_answer
    (message(), dnslib:resource()) -> message();
    (message(), interpret_result()) -> {ok, message()}.
add_response_answer(Msg = #{'Is_response' := false, 'Response' := Response}, Answer) ->
    Msg#{'Response' => add_answer(Response, Answer)}.
%add_response_answer(Msg = #{'Is_response' := false}, Entry = {_, _, _}) ->
%    add_response_interpret_result(Msg, Entry);


%add_response_interpret_result(Msg, _) ->
%    maps:get('Response_Interpret_result', Msg, []),
%    {ok, Msg}.


%add_response_nodata_answer(Msg, Query, SoaRR).
%add_response_name_error_answer(Msg, Query, SoaRR)


-spec add_response_authority(message(), dnslib:resource()) -> message().
add_response_authority(Msg = #{'Is_response' := false, 'Response' := Response}, Authority) ->
    Msg#{'Response' => add_authority(Response, Authority)}.


-spec add_response_additional(message(), dnslib:resource()) -> message().
add_response_additional(Msg = #{'Is_response' := false, 'Response' := Response}, Additional) ->
    Msg#{'Response' => add_additional(Response, Additional)}.


-spec interpret_response(dnsmsg:message()) -> {ok, list()}.
interpret_response(Msg = #{'Is_response' := true}) ->
    #{
        'Return_code'   := ReturnCode,
        'Authoritative' := Authoritative,
        'Questions'     := Questions0,
        'Answers'       := Answers0,
        'Nameservers'   := Nameservers0,
        'Additional'    := Additional0
    } = Msg,
    Questions = lists:reverse(Questions0),
    Answers = lists:reverse(Answers0),
    Nameservers = lists:reverse(Nameservers0),
    Additional = lists:reverse(Additional0),
    %Check that axfr/ixfr is the only question
    case [GenTuple || GenTuple <- Questions, element(2, GenTuple) =:= axfr orelse element(2, GenTuple) =:= ixfr] of
        [Transfer] -> fix_return_code_n_authoritative(ReturnCode, Authoritative, interpret_response(Transfer, Answers, Nameservers, Additional, []), []);
        [] -> fix_return_code_n_authoritative(ReturnCode, Authoritative, interpret_response(Questions, Answers, Nameservers, Additional, []), [])
    end.


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
interpret_response({Domain0, axfr, Class}=Question, Answers0, Nameservers, Additional, Acc) ->
    Domain = dnslib:normalize_domain(Domain0),
    case Answers0 of
        [CaseResource] when element(2, CaseResource) =:= soa ->
            case is_valid_transfer_soa(Question, CaseResource) of
                true -> interpret_response([], Answers0, Nameservers, Additional, [{Question, zone_transfer, {CaseResource, last, []}}|Acc]);
                {false, Reason} -> interpret_response([], Answers0, Nameservers, Additional, [{Question, {error, Reason}}|Acc])
            end;
        [CaseResource|TransferResources] when element(2, CaseResource) =:= soa ->
            case is_valid_transfer_soa(Question, CaseResource) of
                true ->
                    case lists:splitwith(fun (FunTuple) -> dnslib:domain_in_zone(dnslib:normalize_domain(element(1, FunTuple)), Domain) andalso element(3, FunTuple) =:= Class andalso element(2, FunTuple) =/= soa end, TransferResources) of
                        {Resources, []} -> interpret_response([], [], Nameservers, Additional, [{Question, zone_transfer, {CaseResource, first, Resources}}|Acc]);
                        {Resources, [CaseResource]} -> interpret_response([], [], Nameservers, Additional, [{Question, zone_transfer, {CaseResource, complete, Resources}}|Acc]);
                        _ -> interpret_response([], [], Nameservers, Additional, [{Question, {error, invalid_resources}}|Acc])
                    end;
                {false, Reason} -> interpret_response([], Answers0, Nameservers, Additional, [{Question, {error, Reason}}|Acc])
            end;
        _ ->
            case lists:splitwith(fun (FunTuple) -> dnslib:domain_in_zone(dnslib:normalize_domain(element(1, FunTuple)), Domain) andalso element(3, FunTuple) =:= Class andalso element(2, FunTuple) =/= soa end, Answers0) of
                {Resources, []} -> interpret_response([], [], Nameservers, Additional, [{Question, zone_transfer, {nil, middle, Resources}}|Acc]);
                {Resources, [Soa]} when element(2, Soa) =:= soa ->
                    case is_valid_transfer_soa(Question, Soa) of
                        true -> interpret_response([], [], Nameservers, Additional, [{Question, zone_transfer, {Soa, last, Resources}}|Acc]);
                        {false, Reason} -> interpret_response([], Answers0, Nameservers, Additional, [{Question, {error, Reason}}|Acc])
                    end;
                _ -> interpret_response([], [], Nameservers, Additional, [{Question, {error, invalid_resources}}|Acc])
            end
    end;
interpret_response({Domain0, ixfr, Class}=Question, Answers0, Nameservers, Additional, Acc) ->
    Domain = dnslib:normalize_domain(Domain0),
    case Answers0 of
        [R1] when element(2, R1) =:= soa ->
            % End (either normal or incremental)
            case is_valid_transfer_soa(Question, R1) of
                true -> interpret_response([], [], Nameservers, Additional, [{Question, zone_transfer, {R1, last, []}}|Acc]);
                {false, Reason} -> interpret_response([], Answers0, Nameservers, Additional, [{Question, {error, Reason}}|Acc])
            end;
        [R1, R2|_] when element(2, R1) =:= soa, element(2, R2) =:= soa ->
            % Incremental start
            case is_valid_transfer_soa(Question, R1) of
                true ->
                    [_|Resources] = Answers0,
                    case collect_incremental_changes(Question, Resources, []) of
                        {middle, Changes} -> interpret_response([], [], Nameservers, Additional, [{Question, incremental_zone_transfer, {R1, first, Changes}}|Acc]);
                        {last, R1, Changes} -> interpret_response([], [], Nameservers, Additional, [{Question, incremental_zone_transfer, {R1, complete, Changes}}|Acc]);
                        {error, Reason} -> interpret_response([], [], Nameservers, Additional, [{Question, {error, Reason}}|Acc])
                        % _ handle errors
                    end;
                {false, Reason} -> interpret_response([], Answers0, Nameservers, Additional, [{Question, {error, Reason}}|Acc])
            end;
        [R1, R2|_] when element(2, R1) =:= soa, element(2, R2) =/= soa ->
            % Incremental middle
            % Or regular transfer start.
            case [GenTuple || GenTuple <- Answers0, element(2, GenTuple) =:= soa] of
                [R1] -> % regular start
                    [_|TransferResources] = Answers0,
                    case lists:splitwith(fun (FunTuple) -> dnslib:domain_in_zone(dnslib:normalize_domain(element(1, FunTuple)), Domain) andalso element(3, FunTuple) =:= Class andalso element(2, FunTuple) =/= soa end, TransferResources) of
                        {Resources, []} -> interpret_response([], [], Nameservers, Additional, [{Question, zone_transfer, {R1, first, Resources}}|Acc]);
                        _ -> interpret_response([], [], Nameservers, Additional, [{Question, {error, invalid_resources}}|Acc])
                    end;
                [R1, R1] -> % Complete regular
                    [_|TransferResources] = Answers0,
                    case lists:splitwith(fun (FunTuple) -> dnslib:domain_in_zone(dnslib:normalize_domain(element(1, FunTuple)), Domain) andalso element(3, FunTuple) =:= Class andalso element(2, FunTuple) =/= soa end, TransferResources) of
                        {Resources, [Soa]} when element(2, Soa) =:= soa ->
                            case is_valid_transfer_soa(Question, Soa) of
                                true -> interpret_response([], [], Nameservers, Additional, [{Question, zone_transfer, {Soa, complete, Resources}}|Acc]);
                                {false, Reason} -> interpret_response([], Answers0, Nameservers, Additional, [{Question, {error, Reason}}|Acc])
                            end;
                        _ -> interpret_response([], [], Nameservers, Additional, [{Question, {error, invalid_resources}}|Acc])
                    end;
                _ -> % Incremental middle
                    case collect_incremental_changes(Question, Answers0, []) of
                        {middle, Changes} -> interpret_response([], [], Nameservers, Additional, [{Question, incremental_zone_transfer, {nil, middle, Changes}}|Acc]);
                        {last, Soa, Changes} -> interpret_response([], [], Nameservers, Additional, [{Question, incremental_zone_transfer, {Soa, last, Changes}}|Acc]);
                        {error, Reason} -> interpret_response([], [], Nameservers, Additional, [{Question, {error, Reason}}|Acc])
                        % _ handle errors
                    end
            end;
        _ ->
            case lists:splitwith(fun (FunTuple) -> dnslib:domain_in_zone(dnslib:normalize_domain(element(1, FunTuple)), Domain) andalso element(3, FunTuple) =:= Class andalso element(2, FunTuple) =/= soa end, Answers0) of
                {Resources, []} -> interpret_response([], [], Nameservers, Additional, [{Question, zone_transfer, {nil, middle, Resources}}|Acc]);
                {Resources, [Soa]} when element(2, Soa) =:= soa ->
                    case is_valid_transfer_soa(Question, Soa) of
                        true -> interpret_response([], [], Nameservers, Additional, [{Question, zone_transfer, {Soa, last, Resources}}|Acc]);
                        {false, Reason} -> interpret_response([], Answers0, Nameservers, Additional, [{Question, {error, Reason}}|Acc])
                    end;
                _ -> interpret_response([], [], Nameservers, Additional, [{Question, {error, invalid_resources}}|Acc])
            end
    end;
interpret_response([{Domain0, Type, Class}=Question|Rest], Answers0, Nameservers, Additional, Acc) ->
    Domain = dnslib:normalize_domain(Domain0),
    Fn = case is_atom(Type)of
        false -> interpret_response_split_fun(Domain, Type, Class);
        true ->
            Module = dnsrr:from_to(Type, atom, module),
            case erlang:function_exported(Module, aka, 0) of
                false -> interpret_response_split_fun(Domain, Type, Class);
                true -> interpret_response_split_fun(Domain, Module:aka(), Class)
            end
    end,
    case Fn(Answers0) of
        {[], _} -> interpret_response(Rest, Answers0, Nameservers, Additional, [infer_question_response(Domain, Question, Nameservers, Additional)|Acc]);
        {RelatedAnswers, Answers1} -> interpret_response_check_cname(Rest, Answers1, Nameservers, Additional, Acc, Question, RelatedAnswers, [])
    end.


is_valid_transfer_soa({Domain, _, Class}, {SoaDomain, soa, Class, _, _}=Soa) ->
    case dnslib:normalize_domain(SoaDomain) =:= dnslib:normalize_domain(Domain) of
        true -> true;
        false -> {false, {invalid_soa, domain, Soa}}
    end;
is_valid_transfer_soa({_, _, Class1}, {_, soa, Class2, _, _}=Soa) when Class1 =/= Class2 ->
    {false, {invalid_soa, class, Soa}}.


collect_incremental_changes(_, [], Acc) ->
    {middle, Acc};
collect_incremental_changes(Question, [Soa], Acc) when element(2, Soa) =:= soa ->
    case is_valid_transfer_soa(Question, Soa) of
        true -> {last, Soa, Acc};
        {false, Reason} -> {error, Reason}
    end;
collect_incremental_changes(Question, [OldSoa|DeleteResources], Acc) when element(2, OldSoa) =:= soa ->
    Fn = fun (FunTuple) -> element(2, FunTuple) =/= soa end,
    case lists:splitwith(Fn, DeleteResources) of
        {_, []} -> {error, missing_add_section};
        {Deletions, [NewSoa|AddResources]} ->
            {Adds, Resources} = lists:splitwith(Fn, AddResources),
            ChangeSet = {{OldSoa, Deletions}, {NewSoa, Adds}},
            case is_valid_incremental_change(Question, ChangeSet) of
                true -> collect_incremental_changes(Question, Resources, [ChangeSet|Acc]);
                {false, Reason} -> {error, Reason}
            end
    end.


is_valid_incremental_change({Domain0, _, Class}=Question, {{OldSoa, Deletions}, {NewSoa, Adds}}) ->
    case is_valid_transfer_soa(Question, OldSoa) of
        {false, _}=Tuple -> Tuple;
        true ->
            OldSerial = dnsrr_soa:serial(element(5, OldSoa)),
            NewSerial = dnsrr_soa:serial(element(5, NewSoa)),
            case is_valid_transfer_soa(Question, NewSoa) of
                {false, _}=Tuple -> Tuple;
                % Since serials can wrap, we should compare them properly...
                true when NewSerial =< OldSerial -> {false, {invalid_serial_change, OldSerial, NewSerial}};
                true ->
                    Domain = dnslib:normalize_domain(Domain0),
                    Fn = fun (FunTuple) -> dnslib:domain_in_zone(dnslib:normalize_domain(element(1, FunTuple)), Domain) andalso element(3, FunTuple) =:= Class end,
                    DeletionsValid = lists:all(Fn, Deletions),
                    AddsValid = lists:all(Fn, Adds),
                    case DeletionsValid andalso AddsValid of
                        true -> true;
                        false when AddsValid -> {false, {invalid_deletions, [OldSoa|Deletions]}};
                        false when DeletionsValid -> {false, {invalid_adds, [NewSoa|Adds]}}
                    end
            end
    end.


interpret_response_check_cname(Rest, Answers, Nameservers, Additional, Acc, {_, cname, _}=Question, QuestionAnswers, _) ->
    interpret_response(Rest, Answers, Nameservers, Additional, [{Question, ok, QuestionAnswers}|Acc]);
interpret_response_check_cname(Rest, Answers0, Nameservers, Additional, Acc, {_, Type, _}=Question, QuestionAnswers, PrevAnswers) ->
    case lists:filter(fun (Tuple) -> element(2, Tuple) =:= cname end, QuestionAnswers) of
        [] ->
            % Should we consider additionally here?
            interpret_response(Rest, Answers0, Nameservers, Additional, [{Question, ok, lists:append(QuestionAnswers, PrevAnswers)}|Acc]);
        [{_, cname, Class, _, CanonDomain0}=CnameRR] ->
                CanonDomain = dnslib:normalize_domain(CanonDomain0),
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
    CanonDomain = dnslib:normalize_domain(CanonDomain0),
    case lists:filter(fun ({FunDomain0, cname, _, _, _}) -> dnslib:normalize_domain(FunDomain0) =:= CanonDomain; (_) -> false end, PrevAnswers) of
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
                    fun ({FunDomain, _, _, _, _}) -> not dnslib:domain_in_zone(Domain, dnslib:normalize_domain(FunDomain)) end,
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
                    fun ({FunDomain, _, _, _, _}) -> dnslib:domain_in_zone(Domain, dnslib:normalize_domain(FunDomain)) end,
                    NsDomains1
                )
            of
                [] -> {Question, undefined};
                [{NsDomain0, _, _, _, _}|_] = CaseList0 ->
                    NsDomain = dnslib:normalize_domain(NsDomain0),
                    {CaseList1, _} = lists:splitwith(fun ({FunDomain, _, _, _, _}) -> NsDomain =:= dnslib:normalize_domain(FunDomain) end, CaseList0),
                    case referral_ns_address_match(CaseList1, Additional, []) of
                        {missing_glue, NsList} -> {Question, missing_glue_referral, NsList};
                        {addressless, NsList} -> {Question, addressless_referral, NsList};
                        {ok, NsAddrList} -> {Question, referral, NsAddrList}
                    end
            end
    end.


interpret_response_split_fun(Domain, Type, Class) ->
    MatchDomain = fun (FunTuple) -> dnslib:normalize_domain(element(1, FunTuple)) =:= Domain end,
    MatchClass = case Class of
        any -> fun (_) -> true end;
        _ -> fun (FunTuple) -> element(3, FunTuple) =:= Class end
    end,
    MatchType = case Type of
        TypeList when is_list(TypeList) ->
            case lists:member('_', TypeList) of
                true -> fun (_) -> true end;
                false -> fun (FunTuple) -> lists:member(element(2, FunTuple), TypeList) orelse element(2, FunTuple) =:= cname end
            end;
        _ -> fun (FunTuple) -> element(2, FunTuple) =:= Type orelse element(2, FunTuple) =:= cname end
    end,
    MatchReqs = [MatchDomain, MatchType, MatchClass],
    Fn = fun (FunTuple) -> MatchReqs =:= [GenFn || GenFn <- MatchReqs, GenFn(FunTuple)] end,
    fun (List) -> lists:partition(Fn, List) end.


referral_ns_address_match([], _, Acc) ->
    % Should we make sure that addresses are sane?
    {Normal, Addressless} = lists:partition(fun ({_, AddrList}) -> AddrList =/= [] end, Acc),
    case lists:filter(fun ({{NsDomain, _, _, _, ServerDomain}, _}) -> not dnslib:domain_in_zone(dnslib:normalize_domain(ServerDomain), dnslib:normalize_domain(NsDomain)) end, Addressless) of
        [] when Normal =:= [] -> {missing_glue, [NsTuple || {NsTuple, _} <- Acc]};
        [] -> {ok, Normal};
        NotInZone when Normal =:= [] -> {addressless, [NsTuple || {NsTuple, _} <- NotInZone]};
        NotInZone -> {ok, lists:append(Normal, NotInZone)}
    end;
referral_ns_address_match([{_, _, Class, _, Domain0}=Ns|Rest], Additional, Acc) ->
    Domain = dnslib:normalize_domain(Domain0),
    Addresses = lists:filter(fun ({FunDomain, _, FunClass, _, _}) -> dnslib:normalize_domain(FunDomain) =:= Domain andalso FunClass =:= Class end, Additional),
    referral_ns_address_match(Rest, Additional, [{Ns, lists:filter(fun referral_ns_address_filter/1, Addresses)}|Acc]).


referral_ns_address_filter({_, a, _, _, Address}) ->
    case Address of
        {0, _, _, _} -> false;         % 0.0.0.0/8
        {192, 0, 2, _} -> false;       % Documentation
        {224, _, _, _} -> false;       % Multicast
        {255, 255, 255, 255} -> false; % Broadcast
        _ -> true
    end;
referral_ns_address_filter({_, aaaa, _, _, Address}) ->
    case Address of
        {0, 0, 0, 0, 0, 0, 0, 0} -> false;       % Routing
        {16#FFFF, 16#FFFF, 16#FFFF, 16#FFFF, 16#FFFF, 16#FFFF, 16#FFFF, 16#FFFF} -> false;
        {16#2001, 16#0DB8, _, _, _, _, _, _} -> false; % Documentation
        {B1, _, _, _, _, _, _, _} when (B1 band 16#FF00) =:= 16#FF00 -> false; % Multicast
        _ -> true
    end.


interpret_results_to_response(Res) ->
    case apply_interpret_results(Res, dnsmsg:new(#{is_response => true})) of
        {ok, _}=Tuple -> Tuple
    end.


apply_interpret_results(Res, Msg) ->
    % We should somehow figure out what results the message is already representing,
    % then use those to set a proper value for PrevResTypes list
    FnTuple = case maps:get('Is_response', Msg) of
        false -> {fun add_to_response_section/3, fun set_response_header/3};
        true -> {fun add_to_section/3, fun set_header/3}
    end,
    apply_interpret_results(Res, Msg, FnTuple, []).


apply_interpret_results([], Msg, _, _) ->
    {ok, Msg};
apply_interpret_results([Tuple|Rest], Msg, {Add, Set}=FnTuple, PrevResTypes) ->
    ResType = element(2, Tuple),
    case results_can_coexist(ResType, PrevResTypes) of
        false -> {error, {cannot_coexist, ResType}};
        true  ->
            case Tuple of
                {Question, ok, Answers} ->
                    Msg1 = Add(add_question(Msg, Question), answer, Answers),
                    apply_interpret_results(Rest, Set(Msg1, return_code, ok), FnTuple, [ResType|PrevResTypes]);
                {Question, name_error, {Soa, Answers}} ->
                    Msg1 = Add(add_question(Msg, Question), answer, Answers),
                    Msg2 = Add(Msg1, authority, Soa),
                    apply_interpret_results(Rest, Set(Msg2, return_code, name_error), FnTuple, [ResType|PrevResTypes]);
                {Question, nodata, {Soa, Answers}} ->
                    Msg1 = Add(add_question(Msg, Question), answer, Answers),
                    Msg2 = Add(Msg1, authority, Soa),
                    apply_interpret_results(Rest, Set(Msg2, return_code, ok), FnTuple, [ResType|PrevResTypes]);
                {Question, referral, NsAddressRrs} ->
                    Msg1 = add_question(Msg, Question),
                    Msg2 = lists:foldl(fun ({NsRr, AddressRr}, FunMsg) -> Add(Add(FunMsg, authority, NsRr), additional, AddressRr) end, Msg1, NsAddressRrs),
                    apply_interpret_results(Rest, Set(Msg2, authoritative, false), FnTuple, [ResType|PrevResTypes]);
                {Question, addressless_referral, NsRrs} ->
                    Msg1 = Add(add_question(Msg, Question), authority, NsRrs),
                    apply_interpret_results(Rest, Set(Msg1, authoritative, false), FnTuple, [ResType|PrevResTypes]);
                {Question, cname, {_, Prev}} ->
                    Msg1 = Add(add_question(Msg, Question), answer, Prev),
                    apply_interpret_results(Rest, Msg1, FnTuple, [ResType|PrevResTypes]);
                {Question, cname_loop, Answers} ->
                    Msg1 = Add(add_question(Msg, Question), answer, Answers),
                    apply_interpret_results(Rest, Msg1, FnTuple, [ResType|PrevResTypes]);
                {Question, cname_referral, {CnameRr, Referral, Resources}} ->
                    CnameTuple = {Question, cname, {CnameRr, Resources}},
                    apply_interpret_results([CnameTuple, setelement(1, Referral, Question)|Rest], Msg, FnTuple, PrevResTypes);
                {Question, refused} ->
                    Msg1 = add_question(Set(Msg, return_code, refused), Question),
                    apply_interpret_results(Rest, Msg1, FnTuple, [ResType|PrevResTypes]);
                {Question, _} ->
                    Msg1 = add_question(Set(Msg, return_code, server_error), Question),
                    apply_interpret_results(Rest, Msg1, FnTuple, [server_error|PrevResTypes])
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
    OldNsDomain = dnslib:normalize_domain(OldNsDomain0),
    case dnslib:is_subdomain(dnslib:normalize_domain(NewNsDomain), OldNsDomain) of
        false -> {Question, addressless_referral, [NsRr || {NsRr, _} <- NsAddressRrs0]};
        true ->
            % Make sure that all presented addresses are also subdomains of previous
            Fn = fun ({FunDomain0, _, _, _, _}) -> dnslib:domain_in_zone(dnslib:normalize_domain(FunDomain0), OldNsDomain) end,
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
