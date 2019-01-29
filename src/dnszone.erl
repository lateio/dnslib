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
    valid/1,
    query/2,
    to_zone/1,
    new_transfer/1,
    continue_transfer/2
%    diff/2
]).

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
    case valid(Rrs) of
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


-spec valid(Resources :: [dnslib:resource()]) ->
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
valid([]) ->
    {false, missing_soa};
valid(Rrs0) ->
    % Find zone root (SOA)
    Rrs = [dnslib:normalize_resource(GenRr) || GenRr <- Rrs0],
    {Cnames, Rrs1} = lists:partition(partition_fun(cname), Rrs),
    % Make sure that CNAMEs are the only records for their domains...
    case unique_and_sane_cnames(Cnames, Rrs) of
        true ->
            case lists:partition(partition_fun(soa), Rrs1) of
                {[], _} -> {false, missing_soa};
                {Soas, _} when length(Soas) > 1 -> {false, {multiple_soas, [ Soa || {Soa, _, _, _, _} <- Soas ]}};
                {[Soa], Rrs2} ->
                    SoaDomain = element(1, Soa),
                    case {dnslib:is_valid_domain(SoaDomain), SoaDomain} of
                        {_, ['_'|_]}  -> {false, wildcard_soa};
                        {true, _} ->
                            case all_under_soa(SoaDomain, lists:append(Cnames, Rrs2)) of
                                true ->
                                    % Find zone edges
                                    {Nss, _Rrs3} = lists:partition(partition_fun(ns), Rrs2),
                                    % Find zone edges (NS) which are distinct from the root
                                    Edges = zone_edges(Nss, Soa),
                                    % Make sure that all other records fall within roots and edges
                                    % Should check that the zone contains NS records?
                                    OtherRrs = lists:flatten([Rrs2, Cnames]),
                                    case only_glue_past_edges(Edges, OtherRrs) of
                                        true ->
                                            case all_glue_present(Edges, OtherRrs, Soa) of
                                                true -> true;
                                                {false, Label} -> {false, {missing_glue, Label}}
                                            end;
                                        {false, Label} -> {false, {other_than_glue_past_edges, Label}}
                                    end;
                                {false, Label} -> {false, {not_under_soa, Label}}
                            end
                    end
            end;
        {false, {duplicate, Label}} ->
            {false, {non_exclusive_cname, Label}};
        {false, {ufo_cname, Label}} ->
            {false, {cname_to_cname_loop, Label}};
        {false, {loop, Label}} ->
            {false, {cname_loop, Label}}
    end.
    % Make sure that for every edge (NS) (That's not the root node), there's an ip (would CNAME suffice?)
    % If we're going to accept CNAMEs, make sure that we have glue for them if they're subdomains of the edge
    %
    % Per 2181, Section 10.3, NS and MX records should not have CNAMEs as their values...
    %
    % Also, we should prune any duplicate records...
    %
    % Should we warn about cases where a wildcard domain is used as NS?


unique_and_sane_cnames([], _) ->
    true;
unique_and_sane_cnames([{Label, cname, _, _, Label}|_], _) ->
    {false, {ufo_cname, Label}};
unique_and_sane_cnames([Cname|Rest], Rrs) ->
    case unique_label(Cname, Rrs) of
        {false, Label} -> {false, {duplicate, Label}};
        true ->
            case check_cname_loop(Cname, Rrs, []) of
                true -> {false, {loop, element(1, Cname)}};
                false -> unique_and_sane_cnames(Rest, Rrs)
            end
    end.


unique_label(_, []) ->
    true;
unique_label(Resource, [Resource|Rrs]) ->
    unique_label(Resource, Rrs);
unique_label({Label, _, _, _, _}, [{Label, _, _, _, _}|_]) ->
    {false, Label};
unique_label(Cname, [_|Rrs]) ->
    unique_label(Cname, Rrs).


check_cname_loop(_, []) ->
    false;
check_cname_loop(Domain, [{Domain, _, _, _, _}|_]) ->
    true;
check_cname_loop(Domain, [_|Rest]) ->
    check_cname_loop(Domain, Rest).

check_cname_loop(_, [], []) ->
    false;
check_cname_loop(Head, [], Tail) ->
    case element(2, Head) of
        cname -> check_cname_loop(element(5, Head), Tail);
        _ -> false
    end;
check_cname_loop(Cname, [Cname|Rest], Acc) ->
    check_cname_loop(Cname, Rest, Acc);
check_cname_loop({_, cname, _, _, Domain}=Cname, [{Domain, _, _, _, _}=Resource|Rest], Acc) ->
    case element(2, Resource) of
        cname -> check_cname_loop(Resource, Rest, [Cname|Acc]);
        _ -> false
    end;
check_cname_loop(Cname, [_|Rest], Acc) ->
    check_cname_loop(Cname, Rest, Acc).


partition_fun(Type) ->
    fun ({_, RType, _, _, _}) -> Type =:= RType end.


zone_edges(Rrs, Soa) ->
    zone_edges(Rrs, Soa, []).

zone_edges([], _, Acc) ->
    lists:reverse(Acc);
zone_edges([{Label, _, _, _, _}|Rrs], Soa = {Label, _, _, _, _}, Acc) ->
    zone_edges(Rrs, Soa, Acc);
zone_edges([Edge|Rrs], Soa, Acc) ->
    zone_edges(Rrs, Soa, [Edge|Acc]).


only_glue_past_edges([], _) ->
    true;
only_glue_past_edges([Edge|Rest], Rrs) ->
    case only_glue_past_edge(Edge, Rrs) of
        true -> only_glue_past_edges(Rest, Rrs);
        {false, Label} -> {false, Label}
    end.

only_glue_past_edge(_, []) ->
    true;
only_glue_past_edge(Edge = {Label, ns, _, _, _}, [{EntryLabel, Type, _, _, _}|Rrs]) ->
    % Make sure that if EntryLabel is subdomain of label
    case dnslib:is_subdomain(EntryLabel, Label) of
        true ->
            case Type of
                a -> only_glue_past_edge(Edge, Rrs);
                aaaa -> only_glue_past_edge(Edge, Rrs);
                % If we were to allow CNAMEs past edges, we'd need to
                % make sure that those would point to domains either in our
                % authoritative zones, or at least not to entries
                % past the borders of the current zone...
                _ -> {false, EntryLabel}
            end;
        false -> only_glue_past_edge(Edge, Rrs)
    end.


all_glue_present([], _, _) ->
    true;
all_glue_present([{_, _, _, _, Label}|Rest], Rrs, Soa = {SoaLabel, _, _, _, _}) ->
    case dnslib:is_subdomain(Label, SoaLabel) of
        true ->
            case glue_present(Label, Rrs) of
                true -> all_glue_present(Rest, Rrs, Soa);
                false -> {false, Label}
            end;
        false -> all_glue_present(Rest, Rrs, Soa)
    end.


glue_present(_, []) ->
    false;
glue_present(Label, [{Label, Type, _, _, _}|_]) when Type =:= a; Type =:= aaaa ->
    true;
glue_present(Label, [_|Rrs]) ->
    glue_present(Label, Rrs).


all_under_soa(_, []) ->
    true;
all_under_soa(Soa, [{Soa, _, _, _, _}|Rrs]) ->
    all_under_soa(Soa, Rrs);
all_under_soa(Soa, [{EntryLabel, _, _, _, _}|Rrs]) ->
    case dnslib:is_subdomain(EntryLabel, Soa) of
        true -> all_under_soa(Soa, Rrs);
        false -> {false, EntryLabel}
    end.
