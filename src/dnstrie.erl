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
% This file implements a trie data structure handy for
% various DNS lookup operations.
-module(dnstrie).

-export([
    new/0,
    is_empty/1,
    set/3,
    get/2,
    get/3,
    get_path/2,
    get_subkeys/2,
    remove/2,
    remove/3,
    walk/3
]).


-type trie() :: map().

-type set_key() :: [term() | '_'].
-type get_key() :: [binary()].


-spec new() -> trie().
new() -> #{}.


-spec is_empty(Trie :: trie()) -> boolean().
is_empty(Map) -> map_size(Map) =:= 0.


-spec set(Key :: set_key(), Value :: term(), Map :: trie()) -> trie().
set([], Value, Map) ->
    Map#{'' => Value};
set(['_'], Value, Map) ->
    Map#{'_' => Value};
set([Key|Rest], Value, Map) when Key =/= '_', Key =/= '' ->
    Map#{Key => set(Rest, Value, maps:get(Key, Map, #{}))}.


-spec get(Key :: get_key(), Trie :: trie()) -> {'ok', term()} | 'undefined' | 'nodata'.
get(Key, Trie) ->
    get(Key, Trie, true).


-spec get(Key :: get_key(), Trie :: trie(), FollowWildcards :: boolean())
    -> {'ok', term()} | 'undefined' | 'nodata'.
get([], #{'' := Value}, _) ->
    {ok, Value};
get([], _, _) ->
    nodata;
get([Key|Rest], Map, FollowWildcards) ->
    case Map of
        #{Key := NextMap}                    -> get(Rest, NextMap, FollowWildcards);
        #{'_' := Value} when FollowWildcards -> {ok, Value};
        #{}                                  -> undefined
    end.


-spec get_path(Key :: get_key(), Trie :: trie()) ->
    {'full',    [term(), ...]} |
    {'nodata',  [term()]} |
    {'partial', [term(), ...]} |
    {'none',    []}.
get_path(Key, Trie) ->
    get_path(Key, Trie, []).


get_path([], #{'' := Value}, Acc) ->
    {full, [Value|Acc]};
get_path([], _, Acc) ->
    {nodata, Acc};
get_path([Key|Rest], Map, Acc) ->
    case Map of
        #{Key := NextMap, '' := Value}       -> get_path(Rest, NextMap, [Value|Acc]);
        #{Key := NextMap}                    -> get_path(Rest, NextMap, Acc);
        #{'_' := WildcardValue, '' := Value} -> {full, [WildcardValue,Value|Acc]};
        #{'_' := WildcardValue}              -> {full, [WildcardValue|Acc]};
        #{''  := Value}                      -> {partial, [Value|Acc]};
        #{} ->
            case Acc of
                [] -> {none, []};
                _  -> {partial, Acc}
            end
    end.


-spec get_subkeys(Key :: get_key(), Trie :: trie()) -> Keys :: [term()] | 'undefined'.
get_subkeys([], Map) ->
    [Key || {Key, _} <- maps:to_list(Map), Key =/= ''];
get_subkeys([Key|Rest], Map) ->
    case Map of
        #{Key := NextMap} -> get_subkeys(Rest, NextMap);
        #{}               -> undefined
    end.


remove(Key, Map) ->
    remove(Key, Map, value).


remove([], Map, value) ->
    maps:remove('', Map);
remove(['_'], Map, _) ->
    maps:remove('_', Map);
remove([Key], Map, all) ->
    maps:remove(Key, Map);
remove([Key], Map, subtree) ->
    case maps:get(Key, Map, undefined) of
        undefined -> Map;
        Subtree ->
            case Subtree of
                #{'' := Value} -> Map#{Key => #{'' => Value}};
                #{} -> maps:remove(Key, Map)
            end
    end;
remove([Key|Rest], Map, Mode) ->
    case Map of
        #{Key := Subtree} -> Map#{Key => remove(Rest, Subtree, Mode)};
        #{} -> Map
    end.


walk(Fn, State, Trie) ->
    element(2, walk(Fn, State, [], Trie)).

walk(Fn, State0, Path, [{Key, Child}|Rest]) when Key =/= '' ->
    case walk(Fn, State0, [Key|Path], Child) of
        {keep_going, State1} -> walk(Fn, State1, Path, Rest);
        {stop, _}=Tuple -> Tuple
    end;
walk(Fn, State0, Path, [{'', Data}|Rest]) ->
    case Fn(Path, Data, State0) of
        {keep_going, State1} -> walk(Fn, State1, Path, Rest);
        keep_going -> walk(Fn, State0, Path, Rest);
        {stop, _}=Tuple -> Tuple;
        stop -> {stop, State0}
    end;
walk(_, State, _, []) ->
    {keep_going, State};
walk(Fn, State, Path, Trie) when is_map(Trie) ->
    case lists:partition(fun walk_partition/1, maps:to_list(Trie)) of
        {[], Children} -> walk(Fn, State, Path, [{'', nodata}|lists:sort(fun walk_sort/2, Children)]);
        {Value, Children} -> walk(Fn, State, Path, Value ++ lists:sort(fun walk_sort/2, Children))
    end.

walk_partition({Val, _}) -> Val =:= '';
walk_partition(_) -> false.

walk_sort({Key1, _}, {Key2, _}) -> Key1 < Key2.
