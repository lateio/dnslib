% ------------------------------------------------------------------------------
%
% Copyright © 2018-2019, Lauri Moisio <l@arv.io>
%
% The ISC License
%
% Permission to use, copy, modify, and/or distribute this software for any
% purpose with or without fee is hereby granted, provided that the above
% copyright notice and this permission notice appear in all copies.
%
% THE SOFTWARE IS PROVIDED “AS IS” AND THE AUTHOR DISCLAIMS ALL WARRANTIES
% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
%
% ------------------------------------------------------------------------------
%
% This file provides function to verify the validity of a DNS zone.
% Intended to be used with resources acquired with dnsfile:consult().
-module(dnszone).

-export([
    is_valid/1,
    is_valid_file/1,
    is_valid_file/2,
    query/2,
    to_zone/1,
    new_transfer/1,
    continue_transfer/2
%    diff/2
]).

-include_lib("dnslib/include/dnslib.hrl").

-type zone() ::
    #{
        apex      => ApexDomain :: dnslib:domain(),
        id        => ID         :: 0..16#FFFFFFFF,
        class     => Class      :: dnsclass:class(),
        resources => Resources  :: [dnslib:resource(), ...],
        minimum   => 0..16#7FFFFFFF
    }.

-type zone_transfer() ::
    {
        Question :: dnslib:question(),
        TransferType :: 'zone' | 'change_sets' | 'nil',
        NewSoa :: dnslib:resource() | 'nil',
        Resources :: [dnslib:resource()] | [dnsmsg:incremental_transfer_change_set()]
    }.

-export_type([zone/0,zone_transfer/0]).

% Provide some functions to query a zone in Rrs form?
% Instead of just adding Rrs, use interpretation form?

-type or_wildcard(Type) :: '_' | Type.

-spec query({or_wildcard(dnslib:domain()), or_wildcard(dnsrr:type()), or_wildcard(dnsclass:class())}, [dnslib:resource()]) ->
    [dnslib:resource()].
query(Query, #{resources := Rrs}) ->
    query(Query, Rrs);
query({Domain0, Type, Class}, Rrs) ->
    Domain1 = case Domain0 of
        '_' -> Domain0;
        _ -> dnslib:normalize_domain(Domain0)
    end,
    lists:filter(fun ({ResourceDomain, RType, RClass, _, _}) ->
        query_match(Domain1, dnslib:normalize_domain(ResourceDomain)) andalso
        query_match(Type, RType) andalso
        query_match(Class, RClass)
    end,
    Rrs).


-spec query_match(term() | '_', term()) -> boolean().
query_match('_', _) -> true;
query_match(T1, T2) -> T1 =:= T2.


-spec to_zone([dnslib:resource()]) ->
    {'error', 'invalid_zone'} |
    {'ok', zone()}.
to_zone(Rrs) ->
    case is_valid(Rrs) of
        {false, _} -> {error, invalid_zone};
        true ->
            [{ApexDomain, _, Class, _, {_, _, ID, _, _, _, Minimum}}] = query({'_', soa, '_'}, Rrs),
            {ok, #{
                apex => dnslib:normalize_domain(ApexDomain),
                id => ID,
                class => Class,
                resources => Rrs,
                minimum => Minimum
            }}
    end.


%diff(Changes = #{apex := Apex, class := Class}, FromThis = #{apex := Apex, class := Class}) ->
%    [Soa1] = query({Apex, soa, Class}, FromThis),
%    [Soa2] = query({Apex, soa, Class}, Changes),
    % Figure out serial change
    % Removed/added entries


-spec new_transfer(dnsmsg:question()) -> zone_transfer().
% Add Mode argument, to allow transfer to be either 'accumulating' or validating...
new_transfer(Question) ->
    {Question, nil, nil, []}.


-spec continue_transfer(dnsmsg:message(), zone_transfer())
    -> {'ok', {'zone' | 'change_sets', NewSoa :: dnslib:resource(), Resources :: [dnslib:resource()] | [dnsmsg:transfer_interpret_result()]}}
     | {'more', zone_transfer()}
     | {'error',
           'unexpected_transfer_type'
         | 'unexpected_answer_type'
       }.

continue_transfer(Msg, Transfer) ->
    {ok, [Answer]} = dnsmsg:interpret_response(
        case dnsmsg:questions(Msg) of
            [] -> dnsmsg:add_question(Msg, element(1, Transfer));
            _ -> Msg
        end
    ),
    continue_transfer_answer(Answer, Transfer).


-spec continue_transfer_answer(dnsmsg:transfer_interpret_result(), zone_transfer())
    -> {'ok', {'zone' | 'change_sets', NewSoa :: dnslib:resource(), Resources :: [dnslib:resource()] | [dnsmsg:transfer_interpret_result()]}}
     | {'more', zone_transfer()}
     | {'error',
           'unexpected_transfer_type'
         | 'unexpected_answer_type'
       }.
continue_transfer_answer({_, TransferType0, {NewSoa, AnswerType, Resources}}, {Question, nil, nil, []}) ->
    TransferType = case TransferType0 of
        zone_transfer -> zone;
        incremental_zone_transfer -> change_sets
    end,
    case AnswerType of
        complete -> {ok, {TransferType, NewSoa, Resources}};
        first ->
            Transfer = {
                Question,
                TransferType,
                NewSoa,
                Resources
            },
            {more, Transfer};
        _ -> {error, unexpected_answer_type}
    end;
continue_transfer_answer({_, zone_transfer, {_, AnswerType, NewResources}}, {_, zone, NewSoa, PrevResources}=Tuple) ->
    case AnswerType of
        last -> {ok, {zone, NewSoa, lists:append(PrevResources, NewResources)}};
        middle -> {more, setelement(4, Tuple, lists:append(PrevResources, NewResources))};
        _ -> {error, unexpected_answer_type}
    end;
continue_transfer_answer({_, zone_transfer, {_, last, []}}, {_, change_sets, NewSoa, Resources}=Tuple) ->
    {ok, {change_sets, NewSoa, Resources}};
continue_transfer_answer({_, incremental_zone_transfer, {_, AnswerType, NewResources}}, {_, change_sets, NewSoa, PrevResources}=Tuple) ->
    case AnswerType of
        last -> {ok, {change_sets, NewSoa, lists:append(PrevResources, NewResources)}};
        middle -> {more, setelement(4, Tuple, lists:append(PrevResources, NewResources))};
        _ -> {error, unexpected_answer_type}
    end;
continue_transfer_answer(_, _) ->
    {error, unexpected_transfer_type}.


is_valid_file(Path) ->
    is_valid_file(Path, []).

is_valid_file(Path, Opts) ->
    is_valid_fold(dnsfile:foldl(fun valid_file_fold/2, {dnstrie:new(), [], [], nil}, Path, Opts)).

valid_file_fold(Resource, {Trie0, Ns, Cname, Soa}) ->
    Domain = lists:reverse(dnslib:normalize_domain(?RESOURCE_DOMAIN(Resource))),
    Trie1 = case dnstrie:get(Domain, Trie0) of
        {ok, [_|_]} when ?RESOURCE_TYPE(Resource) =:= cname -> throw({non_exclusive_cname, ?RESOURCE_DOMAIN(Resource)});
        {ok, [cname]} -> throw({non_exclusive_cname, ?RESOURCE_DOMAIN(Resource)});
        {ok, List = [_|_]} ->
            case lists:member(?RESOURCE_TYPE(Resource), List) of
                true  -> Trie0;
                false -> dnstrie:set(Domain, [?RESOURCE_TYPE(Resource)|List], Trie0)
            end;
        _ -> dnstrie:set(Domain, [?RESOURCE_TYPE(Resource)], Trie0)
    end,
    case ?RESOURCE_TYPE(Resource) of
        soa when Soa =/= nil -> throw({multiple_soas, [?RESOURCE_DOMAIN(Soa), ?RESOURCE_DOMAIN(Resource)]});
        soa ->
            case ?RESOURCE_DOMAIN(Resource) of
                ['_'|_] -> throw(wildcard_soa);
                _ -> {Trie1, Ns, Cname, Resource}
            end;
        ns -> {Trie1, [Resource|Ns], Cname, Soa};
        cname -> {Trie1, Ns, [Resource|Cname], Soa};
        _ -> {Trie1, Ns, Cname, Soa}
    end.

valid_file_walk(Path, Data, {PrevPath0, Stack0}) ->
    NewLen = length(Path),
    OldLen = length(PrevPath0),
    Diff = OldLen - NewLen,
    {PrevPath1, Stack1} = if
        Diff =:= 0 -> {valid_file_walk_hd(Path, PrevPath0, sibling), valid_file_walk_stack(Data, Stack0, sibling)};
        Diff < 0 -> {valid_file_walk_hd(Path, PrevPath0, child), valid_file_walk_stack(Data, Stack0, child)};
        Diff > 0 ->
            Diff = OldLen - NewLen,
            {
                valid_file_walk_hd(Path, element(2, lists:split(Diff, PrevPath0)), sibling),
                valid_file_walk_stack(Data, element(2, lists:split(Diff, Stack0)), sibling)
            }
    end,
    case valid_file_walk_cur(Stack1) of
        soa -> {keep_going, {PrevPath1, Stack1}};
        none ->
            if
                Data =:= nodata -> {keep_going, {PrevPath1, Stack1}};
                true -> {stop, {false, {not_under_soa, Path}}}
            end;
        Cur ->
            if
                Data =:= nodata -> {keep_going, {PrevPath1, Stack1}};
                true ->
                    Filter = case Cur of
                        past_edge -> fun (FunType) -> FunType =/= a andalso FunType =/= aaaa end;
                        edge ->
                            fun (FunType) ->
                                FunType =/= a    andalso
                                FunType =/= aaaa andalso
                                FunType =/= ds   andalso
                                FunType =/= ns   andalso
                                FunType =/= nsec andalso
                                FunType =/= rrsig
                            end
                    end,
                    case [GenType || GenType <- Data, Filter(GenType)] of
                        [] -> {keep_going, {PrevPath1, Stack1}};
                        _ -> {stop, {false, {other_than_glue_past_edges, Path}}}
                    end
            end
    end.

valid_file_walk_cur([soa|_]) ->
    soa;
valid_file_walk_cur([ns|Rest]) ->
    case valid_file_walk_cur_cont(Rest) of
        past_edge -> past_edge;
        _ -> edge
    end;
valid_file_walk_cur([_|Rest]) ->
    valid_file_walk_cur_cont(Rest).

valid_file_walk_cur_cont([]) -> none;
valid_file_walk_cur_cont([ns|_]) -> past_edge;
valid_file_walk_cur_cont([soa|_]) -> soa;
valid_file_walk_cur_cont([_|Rest]) -> valid_file_walk_cur_cont(Rest).

valid_file_walk_hd([], _, _) ->
    [];
valid_file_walk_hd([Head|_], PrevPath, child) ->
    [Head|PrevPath];
valid_file_walk_hd([Head|_], PrevPath, sibling) ->
    [Head|tl(PrevPath)].


valid_file_walk_stack(Data, Stack0, Direction) ->
    Stack1 = case Direction of
        child -> Stack0;
        sibling when Stack0 =:= [] -> [];
        sibling -> tl(Stack0)
    end,
    case Data of
        nodata -> [nodata|Stack1];
        List ->
            Soa = lists:member(soa, List),
            Ns = not Soa andalso lists:member(ns, List),
            if
                Soa  -> [soa|Stack1];
                Ns   -> [ns|Stack1];
                true -> [none|Stack1]
            end
    end.


-spec is_valid(Resources :: [dnslib:resource()]) ->
      'true'
    | {'false',
          'missing_soa'
        | {'multiple_soas', Soas :: [dnslib:domain()]}
        | 'wildcard_soa'
        | {'missing_glue', dnslib:domain()}
        | {'other_than_glue_past_edges', dnslib:domain()}
        | {'not_under_soa', dnslib:domain()}
        | {'non_exclusive_cname', dnslib:domain()}
        | {'cname_to_cname_loop', dnslib:domain()}
        | {'cname_loop', dnslib:domain()}
      }.
is_valid([]) ->
    {false, missing_soa};
is_valid(Rrs) ->
    try is_valid_fold(lists:foldl(fun valid_file_fold/2, {dnstrie:new(), [], [], nil}, Rrs))
    catch
        throw:Reason -> {false, Reason}
    end.
    % Make sure that for every edge (NS) (That's not the root node), there's an ip (would CNAME suffice?)
    % If we're going to accept CNAMEs, make sure that we have glue for them if they're subdomains of the edge
    %
    % Per 2181, Section 10.3, NS and MX records should not have CNAMEs as their values...
    %
    % Also, we should prune any duplicate records...
    %
    % Should we warn about cases where a wildcard domain is used as NS?


is_valid_fold({ok, {Trie, Ns, Cnames, Soa}}) ->
    % Check for Cname loops
    case check_cname_loop(Cnames) of
        false ->
            %Check that all glue is present
            case glue_present(Ns, Trie) of
                true ->
                    case dnstrie:walk(fun valid_file_walk/3, {[], []}, Trie) of
                        {false, _}=Tuple -> Tuple;
                        _ -> true
                    end;
                {false, Label} -> {false, {missing_glue, Label}}
            end;
        {true, Reason} -> {false, Reason}
    end;
is_valid_fold({error, {foldl_error, throw, Reason, _}}) ->
    {false, Reason};
is_valid_fold({_, _, _, _}=Tuple) ->
    is_valid_fold({ok, Tuple}).


glue_present([], _) ->
    true;
glue_present([Ns|Rest], Trie) ->
    Domain = lists:reverse(dnslib:normalize_domain(?RESOURCE_DATA(Ns))),
    case dnstrie:get_path(Domain, Trie) of
        {full, [List|_]} ->
            case lists:member(a, List) orelse lists:member(aaaa, List) of
                true -> glue_present(Rest, Trie);
                false -> {false, ?RESOURCE_DATA(Ns)}
            end;
        {_, Path} ->
            % Only consider domains under soa
            case [GenList || GenList <- Path, lists:member(soa, GenList)] of
                [] -> {false, ?RESOURCE_DATA(Ns)};
                _ -> glue_present(Rest, Trie)
            end
    end.


check_cname_loop([]) ->
    false;
check_cname_loop([Cname|Cnames]) ->
    check_cname_loop(?RESOURCE_DATA(dnslib:normalize_resource(Cname)), [dnslib:normalize_resource(GenCname) || GenCname <- Cnames]).

check_cname_loop(Domain, Cnames) ->
    check_cname_loop(Domain, Cnames, Cnames).

check_cname_loop(_, [], []) ->
    false;
check_cname_loop(Domain, [], [Next|Cnames]) ->
    check_cname_loop(?RESOURCE_DATA(Next), Cnames, Cnames);
check_cname_loop(Domain, [{Domain, _, _, _, _}|Rest], Cnames) ->
    {true, {cname_loop, Domain}};
check_cname_loop(_, [{Domain, _, _, _, Domain}|Rest], Cnames) ->
    {true, {cname_to_cname_loop, Domain}};
check_cname_loop(Domain, [_|Rest], Cnames) ->
    check_cname_loop(Domain, Rest, Cnames).
