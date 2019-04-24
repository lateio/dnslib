-module(dnstrie_test).
-include_lib("eunit/include/eunit.hrl").

walk_test() ->
    Entries = [
        {[],                 1},
        {"com",              2},
        {"example.com",      3},
        {"ftp.example.com",  4},
        {"www1.example.com", 5},
        {"www2.example.com", 6},
        {"io",               7},
        {"arv.io",           8},
        {"ftp.arv.io",       9},
        {"www.arv.io",       10}
    ],
    Trie = lists:foldl(fun ({Domain, Value}, FunTrie) -> dnstrie:set(lists:reverse(dnslib:domain(Domain)), Value, FunTrie) end, dnstrie:new(), Entries),
    Expect = [Value || {_, Value} <- Entries],
    Expect = lists:reverse(dnstrie:walk(fun (_, Value, Acc) -> {keep_going, [Value|Acc]} end, [], Trie)).
