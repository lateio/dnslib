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
% This file provides function to verify the validity of a DNS zone.
% Intended to be used with resources acquired with dnsfile:consult().
-module(dnszone).

-export([
    valid/1,
    query/2,
    to_zone/1
]).

-type zone() ::
    #{
        apex      => ApexDomain :: dnslib:domain(),
        id        => ID         :: 0..16#FFFFFFFF,
        class     => Class      :: dnsclass:class(),
        resources => Resources  :: [dnslib:resource(), ...],
        minimum   => 0..16#7FFFFFFF
    }.

-export_type([zone/0]).

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
        _ -> dnslib:normalize(Domain0)
    end,
    lists:filter(fun ({ResourceDomain, RType, RClass, _, _}) ->
        query_match(Domain1, dnslib:normalize(ResourceDomain)) andalso
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
                apex => dnslib:normalize(ApexDomain),
                id => ID,
                class => Class,
                resources => Rrs,
                minimum => Minimum
            }}
    end.


%% @doc Check whether provided resource records constitute a valid DNS zone.
-spec valid(Resources :: [dnslib:resource()]) -> 'true' | {'false', Reason :: term()}.
valid([]) ->
    {false, empty_zone};
valid(Rrs) ->
    % Find zone root (SOA)
    {Cnames, Rrs1} = lists:partition(partition_fun(cname), Rrs),
    % Make sure that CNAMEs are the only records for their domains...
    case unique_and_sane_cnames(Cnames, Rrs1) of
        true ->
            case lists:partition(partition_fun(soa), Rrs1) of
                {[], _} -> {false, missing_soa};
                {Soas, _} when length(Soas) > 1 -> {false, {multiple_soas, [ Soa || {Soa, _, _, _, _} <- Soas ]}};
                {[Soa], Rrs2} ->
                    SoaDomain = element(1, Soa),
                    case dnslib:is_valid_domain(SoaDomain) of
                        {true, true} -> {false, wildcard_soa};
                        {true, false} ->
                            case all_under_soa(dnslib:normalize(SoaDomain), lists:flatten([Cnames, Rrs2])) of
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
        {false, {loop, Label}} ->
            {false, {cname_to_cname_loop, Label}}
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
    {false, {loop, Label}};
unique_and_sane_cnames([Cname|Rest], Rrs) ->
    case unique_label(Cname, Rrs) of
        true -> unique_and_sane_cnames(Rest, Rrs);
        {false, Label} -> {false, {duplicate, Label}}
    end.


unique_label(_, []) ->
    true;
unique_label({Label, _, _, _, _}, [{Label, _, _, _, _}|_]) ->
    {false, Label};
unique_label(Cname, [_|Rrs]) ->
    unique_label(Cname, Rrs).


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
    case dnslib:subdomain(EntryLabel, Label) of
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
    case dnslib:subdomain(Label, SoaLabel) of
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
    case dnslib:subdomain(dnslib:normalize(EntryLabel), Soa) of
        true -> all_under_soa(Soa, Rrs);
        false -> {false, EntryLabel}
    end.
