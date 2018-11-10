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
-module(dnslib).

% Behaviors
-behavior(application).
-export([start/2, stop/1]).
-behavior(supervisor).
-export([init/1]).

%% API exports
-export([
    subdomain/2,
    in_zone/2,
    concat/2,
    normalize/1,
    normalize_question/1,
    normalize_resource/1,
    domain_to_binary/1,
    binary_to_domain/1,
    list_to_domain/1,
    domain_to_list/1,
    is_valid_domain/1,
    reverse_dns_domain/1,
    domain_binary_length/1,
    is_valid_hostname/1,
    reverse_ip_query/1,
    list_to_ttl/1,
    is_valid_opcode/1, % This should be in dnsmsg?
    is_valid_resource_type/1,
    is_valid_resource_class/1,
    is_valid_return_code/1,
    punyencode/1
]).

-include_lib("dnslib/include/dnslib.hrl").

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

-type domain_label() :: binary().
-type domain() :: [domain_label()].
-type wildcard_domain() :: ['_'|domain()].

-type return_code() ::
    'ok'              |
    'format_error'    |
    'server_error'    |
    'name_error'      |
    'not_implemented' |
    'refused'.

-type ttl() :: 0..16#7FFFFFFF.

-type opcode() ::
    'query'   |
    'i_query' |
    'status'.

-type resource() ::
    {
        Domain :: dnslib:domain(),
        Type   :: dnsrr:type(),
        Class  :: dnsclass:class(),
        Ttl    :: ttl(),
        Data   :: term()
    }.

-type resource(Type) ::
    {
        Domain :: dnslib:domain(),
        Type,
        Class  :: dnsclass:class(),
        Ttl    :: ttl(),
        Data   :: term()
    }.

-type question() ::
    {
        Domain :: dnslib:domain(),
        Type   :: dnsrr:type(),
        Class  :: dnsclass:class()
    }.


-export_type([
    domain_label/0,
    domain/0,
    wildcard_domain/0,
    resource/0,
    resource/1,
    question/0,
    %question/1,
    opcode/0,
    return_code/0,
    ttl/0,
    list_to_domain_error/0,
    compressed_binary_to_domain_result/0
]).

%%====================================================================
%% API functions
%%====================================================================


start(_, _) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

stop(_) ->
    ok.

init([]) ->
    dnsrr:compile_dnsrr_types(),
    {ok, {{one_for_one,3,10},[]}}.


%% @doc Test if domain This is a subdomain of OfThis.
%%
%% Neither domain is normalized in any way, thus labels which
%% differ merely in character case will not be considered identical
%% (<<"abc">> =/= <<"ABC">>). Thus:
%% subdomain([<<"def">>, <<"abc">>], [<<"ABC">>]) -> false.
%%
%% Identical domains (This =:= OfThis) are not considered to
%% be subdomains of each other. Thus:
%% subdomain([<<"abc">>], [<<"abc">>]) -> false.
%%
%% @end
-spec subdomain(This :: domain(), OfThis :: domain()) -> boolean().
subdomain([], _) ->
    false;
subdomain(_, []) ->
    true;
subdomain(This, OfThis) ->
    subdomain_of(lists:reverse(This), lists:reverse(OfThis)).

-ifdef(EUNIT).
subdomain_test() ->
    false = subdomain([], []),
    false = subdomain([], [<<"abc">>]),
    true  = subdomain([<<"abc">>], []),
    true  = subdomain([<<"abc">>, <<"com">>], [<<"com">>]),
    false  = subdomain([<<"abc">>, <<"com">>], [<<"COM">>]).
-endif.


in_zone(D1, D2) ->
    D1 =:= D2 orelse subdomain(D1, D2).


%% @doc Normalize ascii character case in domain labels.
-spec normalize(Domain :: domain()) -> domain().
normalize([]) ->
    [];
normalize(Domain) ->
    normalize_label(Domain, []).


normalize_question({Domain, Type, Class}) ->
    {normalize(Domain), Type, Class}.


normalize_resource({Domain, Type, Class, Ttl, Data}) ->
    {normalize(Domain), Type, Class, Ttl, Data}.


-spec concat(domain(), domain()) ->
    {'ok', boolean(), domain()} |
    {'error',
        'domain_too_long' |
        'label_too_long'  |
        'empty_label'
    }.
concat(Domain1, Domain2) ->
    Domain3 = lists:flatten([Domain1, Domain2]),
    case is_valid_domain(Domain3) of
        {true, IsWildcard} -> {ok, IsWildcard, Domain3};
        {false, Reason} -> {error, Reason}
    end.


%% @doc Normalize character case in domain labels.
-spec domain_to_binary(Domain :: domain()) -> binary().
domain_to_binary(Domain) ->
    domain_to_binary(Domain, <<>>).


-type compressed_binary_to_domain_result() :: {'compressed', Ref :: pos_integer(), dnslib:domain()}.
-spec binary_to_domain(Bin :: binary()) ->
    {'ok', dnslib:domain(), Tail :: binary()} |
    {compressed_binary_to_domain_result(), Tail :: binary()} |
    %{'extended', Type :: 0..63, binary()},
    {'error',
        {'invalid_length', Bit1 :: 0..1, Bit2 :: 0..1} |
        'truncated_domain' |
        'empty_binary'
    }.
%binary_to_domain(<<0:1, 1:1, Type:6, Rest/binary>>) ->
%    {extended, Type, Rest};
binary_to_domain(<<>>) ->
    {error, empty_binary};
binary_to_domain(Bin) ->
    binary_to_domain(Bin, []).


%% @doc Transforms a string to a domain.
%%
%% If the first label of the domain consist only of an
%% unescaped asterisk (*), it is transformed to '_' atom. Thus:
%% "*.abc.*.tld"   -> ['_', <<"abc">>, <<"*">>, <<"tld">>]
%% "\\*.abc.tld" -> [<<"*">>, <<"abc">>, <<"tld">>]
%% "abc.\\*.tld" -> [<<"abc">>, <<"*">>, <<"tld">>]
%% "*abc.tld*"   -> [<<"*abc">>, <<"tld*">>]
%%
%% '_' represents a wildcard label.
%%
%%
%% Label and Domain lengths are enforced:
%% - Labels have to be at least 1 byte long
%% - Labels can be at most 63 bytes long
%% - Domain can be at most 255 bytes long
%%   - Domain length =
%%     Sum of labels lengths +
%%     Byte per label +
%%     Terminating zero byte
%%   - Thus the length of arv.io would be 8 bytes
%%     <<3, "arv">>
%%     <<2, "io">>
%%     <<0>>
%%
%% Function allows single character and numerical escape sequences:
%% "acb\\.def" -> [<<"abc\\.def">>]
%% "hello\\.world.tld" -> [<<"hello.world">>, <<"tld">>]
%% "hello\\032world.tld" -> [<<"hello world">>, <<"tld">>]
%%
%% This function does not impose any restrictions on the characters present
%% in labels. Thus:
%% "abc def.tld" -> [<<"abc def">>, <<"tld">>]
%% is handled without errors, even though space is not a valid character
%% in hostnames (and generally not present in domain names). Likewise:
%% "-invalid_hostname-.-tld-" -> [<<"-invalid_hostname-">>, <<"-tld-">>]
%% is handled without errors.
%%
%%
%% Characters are not normalized in any way, thus:
%% "ADCdef.TLD" -> [<<"ADCdef">>, <<"TLD">>]
%%
%% @end
-type list_to_domain_error() ::
    'domain_too_long' |
    'label_too_long'  |
    'empty_label'     |
    {'escape_out_of_range', integer()} |
    {'invalid_escape_integer', string()}.
-type domain_type() :: 'absolute' | 'relative'.
-spec list_to_domain(Str :: string()) ->
    {domain_type(), 'false', domain()} |
    {domain_type(), 'true',  wildcard_domain()} |
    {'error', list_to_domain_error()}.
list_to_domain(".") ->
    {absolute, false, []};
list_to_domain(Str) ->
    list_to_domain(Str, <<>>, [], 1).


%% @doc Transforms a domain to a string.
-spec domain_to_list(Domain :: domain()) -> string().
domain_to_list([]) ->
    ".";
domain_to_list(['_'|Domain]) ->
    domain_to_list(Domain, [$., $*]);
domain_to_list(Domain) ->
    domain_to_list(Domain, []).


%% @doc Verifies that the provided domain is valid.
%%
%% To this function valid means simply that
%% the domain adheres to domain and label length
%% limits:
%% - Total domain length at most 255 bytes
%% - Label length between 1 and 63 bytes
%%
%% @end
-spec is_valid_domain(Domain :: domain()) -> {'true', IsWildcard :: boolean()} | {'false', Reason :: atom()}.
is_valid_domain([]) ->
    {true, false};
is_valid_domain(['_'|Domain]) ->
    is_valid_domain(Domain, 1, true);
is_valid_domain(Domain) ->
    is_valid_domain(Domain, 1, false).


-spec reverse_dns_domain(inet:ip_address()) -> domain().
reverse_dns_domain({_, _, _, _}) ->
    [<<"in-addr">>, <<"arpa">>];
reverse_dns_domain({_, _, _, _, _, _, _, _}) ->
    [<<"ip6">>, <<"arpa">>].


-spec domain_binary_length(domain()) -> 1..255.
domain_binary_length([]) ->
    1;
domain_binary_length(Domain) ->
    domain_binary_length(Domain, 0).


-spec is_valid_hostname(domain()) -> boolean().
is_valid_hostname([]) ->
    false;
is_valid_hostname(Domain) ->
    [Head|Tail] = normalize(Domain),
    is_valid_hostname(Head, Tail).


-spec reverse_ip_query(inet:ip_address()) -> question().
reverse_ip_query(Address) ->
    ElementBits = tuple_size(Address) * 2, % As it happens, 4 * 2 = 8, 2 * 8 = 16
    LabelBits = case Address of
        {_, _, _, _} -> 8;
        {_, _, _, _, _, _, _, _} -> 4
    end,
    % Make elements into appropriate binary terms, chop up the terms (only required for ipv6)
    Nibbles = [ Nibble || <<Nibble:LabelBits>> <= << <<Element:ElementBits>> || Element <- tuple_to_list(Address)>>],
    % Make Nibbles into binary labels
    Fn = label_to_binary_fun(Address),
    Labels = [ Fn(Label) || Label <- Nibbles],
    Domain = lists:foldl(fun (Label, Acc) -> [Label|Acc] end, dnslib:reverse_dns_domain(Address), Labels),
    {Domain, ptr, in}.


-spec list_to_ttl(string()) ->
    {'ok', 0..16#7FFFFFFF} |
    {'error', {'out_of_range', integer()} | 'invalid_ttl' }.
list_to_ttl([]) ->
	{error, empty_string};
list_to_ttl(Str) when is_list(Str) ->
	list_to_ttl(Str, []).


-spec is_valid_opcode(term()) -> boolean().
is_valid_opcode(query)   -> true;
is_valid_opcode(i_query) -> true;
is_valid_opcode(status)  -> true;
is_valid_opcode(_)       -> false.


-spec is_valid_return_code(term()) -> boolean().
is_valid_return_code(ok)               -> true;
is_valid_return_code(format_error)     -> true;
is_valid_return_code(server_error)     -> true;
is_valid_return_code(name_error)       -> true;
is_valid_return_code(not_implemented)  -> true;
is_valid_return_code(refused)          -> true;
is_valid_return_code(_)                -> false.


-spec is_valid_resource_type(dnsrr:type()) -> boolean().
is_valid_resource_type(Type) -> dnsrr:from_to(Type, atom, value) =/= Type.


-spec is_valid_resource_class(term()) -> boolean().
is_valid_resource_class(Class) -> dnsclass:from_to(Class, atom, value) =/= Class.


% punyencode implements the
punyencode(Domain) ->
    punyencode(Domain, []).


%%====================================================================
%% Internal functions
%%====================================================================

-spec subdomain_of(This :: domain(), OfThis :: domain()) -> boolean().
subdomain_of([], _) ->
    false;
subdomain_of(_, []) ->
    true;
subdomain_of([Label|This], OfThis = ['_', Label|OfThis]) ->
    subdomain_of(This, OfThis);
subdomain_of([_|This], OfThis = ['_'|_]) ->
    subdomain_of(This, OfThis);
subdomain_of([Label|This], [Label|OfThis]) ->
    subdomain_of(This, OfThis);
subdomain_of(_, _) ->
    false.


normalize_label([], Acc) when is_list(Acc)->
    lists:reverse(Acc);
normalize_label(['_'|Rest], Acc) when is_list(Acc) ->
    normalize_label(Rest, ['_'|Acc]);
normalize_label([Label|Rest], Acc) when is_binary(Label), is_list(Acc) ->
    normalize_label(Rest, [normalize_label(Label, <<>>)|Acc]);
normalize_label(<<>>, Acc) when is_binary(Acc) ->
    Acc;
normalize_label(<<Char0, Tail/binary>>, Acc) when is_binary(Acc), Char0 >= $A, Char0 =< $Z ->
    Char = Char0 + ($a - $A),
    normalize_label(Tail, <<Acc/bits, Char>>);
normalize_label(<<Char, Tail/binary>>, Acc) when is_binary(Acc) ->
    normalize_label(Tail, <<Acc/bits, Char>>).


-spec domain_to_binary(dnslib:domain(), binary()) -> binary().
domain_to_binary([], Acc) ->
    <<Acc/binary, 0>>;
domain_to_binary([Label|Rest], Acc) when is_binary(Label) ->
    domain_to_binary(Rest, <<Acc/binary, (byte_size(Label)), Label/binary>>).


binary_to_domain(<<0, Tail/binary>>, Acc) ->
    % What if there are trailing bytes?
    {ok, lists:reverse(Acc), Tail};
binary_to_domain(<<1:1, 1:1, Ref:14, Tail/bits>>, Acc) ->
    % What if there are trailing bytes?
    {{compressed, Ref, Acc}, Tail};
binary_to_domain(<<0:1, 0:1, Len:6, Label:Len/binary, Tail/binary>>, Acc) ->
    binary_to_domain(Tail, [Label|Acc]);
binary_to_domain(<<0:1, 0:1, _:6, _/binary>>, _) ->
    {error, truncated_domain};
binary_to_domain(<<B1:1, B2:1, _:6, _/binary>>, _) ->
    {error, {invalid_length, B1, B2}}.


list_to_domain(_, _, _, TotalLength) when TotalLength > 255 ->
    {error, domain_too_long};
list_to_domain(_, Acc, _, _) when byte_size(Acc) > 63 ->
    {error, label_too_long};
list_to_domain([], <<>>, Acc, _) ->
    case lists:reverse(Acc) of
        ['_'|_] = Domain -> {absolute, true, Domain};
        Domain -> {absolute, false, Domain}
    end;
list_to_domain([], <<$*>>, [], _) ->
    {relative, true, ['_']};
list_to_domain([], Cur, Acc, _) ->
    case lists:reverse([Cur|Acc]) of
        ['_'|_] = Domain -> {relative, true, Domain};
        Domain -> {relative, false, Domain}
    end;
list_to_domain([$.|_], <<>>, _, _) ->
    {error, empty_label};
list_to_domain([$.|Rest], <<$*>>, [], _) ->
    list_to_domain(Rest, <<>>, ['_'], 0);
list_to_domain([$.|Rest], Cur, Acc, TotalLength) ->
    list_to_domain(Rest, <<>>, [Cur|Acc], TotalLength+1);
list_to_domain([$\\, C1, C2, C3|Rest], Cur, Acc, TotalLength)
when C1 >= $0, C1 =< $9, C2 >= $0, C2 =< $9, C3 >= $0, C3 =< $9 ->
    case list_to_integer([C1, C2, C3]) of
        Value when Value > 255 -> {error, {escape_out_of_range, Value}};
        Value -> list_to_domain(Rest, <<Cur/binary, Value>>, Acc, TotalLength+1)
    end;
list_to_domain([$\\, C1, C2, C3|_], _, _, _) when C1 >= $0, C1 =< $9 ->
    {error, {invalid_escape_integer, [C1, C2, C3]}};
list_to_domain([$\\, $*, $.|Rest], <<>>, Acc, TotalLength) ->
    list_to_domain(Rest, <<>>, [<<$*>>|Acc], TotalLength+2);
list_to_domain([$\\, Char|Rest], Cur, Acc, TotalLength) when Char >= 0, Char =< 255 ->
    list_to_domain(Rest, <<Cur/binary, Char>>, Acc, TotalLength+1);
list_to_domain([Char|Rest], Cur, Acc, TotalLength) ->
    list_to_domain(Rest, <<Cur/binary, Char>>, Acc, TotalLength+1).


domain_to_list([], Acc) ->
    lists:reverse(Acc);
domain_to_list([Label|Rest], Acc) ->
    domain_to_list(Rest, label_to_list(Label, Acc)).

label_to_list(<<>>, Acc) ->
    [$.|Acc];
label_to_list(<<$., Tail/binary>>, Acc) ->
    label_to_list(Tail, [$., $\\|Acc]);
label_to_list(<<Char, Tail/binary>>, Acc) ->
    label_to_list(Tail, [Char|Acc]).


is_valid_domain(_, TotalLength, _) when TotalLength > 255 ->
    {false, domain_too_long};
is_valid_domain([], _, IsWildcard) ->
    {true, IsWildcard};
is_valid_domain(['_'|_], _, _) ->
    {false, wildcard_label_not_first};
is_valid_domain([Label|_], _, _) when byte_size(Label) > 63 ->
    {false, label_too_long};
is_valid_domain([Label|_], _, _) when byte_size(Label) =:= 0 ->
    {false, empty_label};
is_valid_domain([Label|Rest], TotalLength, IsWildcard) when is_binary(Label) ->
    is_valid_domain(Rest, TotalLength + byte_size(Label) + 1, IsWildcard).


domain_binary_length([], Len) ->
    Len + 1;
domain_binary_length([Label|Domain], Len) ->
    domain_binary_length(Domain, Len + 1 + byte_size(Label)).


is_valid_hostname(<<>>, []) ->
    true;
is_valid_hostname(<<>>, [<<$-,_/bits>>|_]) ->
    false;
is_valid_hostname(<<$->>, _) ->
    false;
is_valid_hostname(<<>>, [Head|Tail]) ->
    is_valid_hostname(Head, Tail);
is_valid_hostname(<<C,Rest/binary>>, Labels)
when C >= $a, C =< $z ->
    is_valid_hostname(Rest, Labels);
is_valid_hostname(<<C,Rest/binary>>, Labels)
when C >= $0, C =< $9 ->
    is_valid_hostname(Rest, Labels);
is_valid_hostname(<<$-,Rest/binary>>, Labels) ->
    is_valid_hostname(Rest, Labels);
is_valid_hostname(_, _) ->
    false.


label_to_binary_fun({_, _, _, _}) ->
    fun erlang:integer_to_binary/1;
label_to_binary_fun({_, _, _, _, _, _, _, _}) ->
    fun
        (Label) when Label < 10 -> <<(Label+$0)>>;
        (Label) when Label >= 10 -> <<(Label+87)>> % $a - 10 = 87
    end.

list_to_ttl(Value, []) when is_integer(Value), Value >= 0, Value =< ?MAX_TTL ->
    {ok, Value}; % TTL range as per RFC2181, Section 8
list_to_ttl(Value, []) when is_integer(Value) ->
    {error, {out_of_range, Value}};
%% list_to_ttl/2
list_to_ttl([], Acc0) ->
    Acc = lists:reverse(Acc0),
    Value =
        try list_to_integer(Acc)
        catch error:badarg -> {error, invalid_ttl}
    end,
    case Value of
        {error, Reason} -> {error, Reason};
        _ -> list_to_ttl(Value, [])
    end;
list_to_ttl([C|Tail], Acc) when C >= $0, C =< $9 ->
	list_to_ttl(Tail, [C|Acc]);
list_to_ttl(Tail, Acc0) ->
    Acc = lists:reverse(Acc0),
    Result =
        try list_to_integer(Acc)
        catch error:badarg -> {error, invalid_ttl}
    end,
    case Result of
        {error, _} = Tuple -> Tuple;
        Value ->
            case string:to_lower(string:trim(Tail)) of
                "m"       -> list_to_ttl(Value * 60, []);        %% Minutes
                "min"     -> list_to_ttl(Value * 60, []);        %% Minutes
                "mins"    -> list_to_ttl(Value * 60, []);        %% Minutes
                "minute"  -> list_to_ttl(Value * 60, []);        %% Minutes
                "minutes" -> list_to_ttl(Value * 60, []);        %% Minutes
                "h"       -> list_to_ttl(Value * 3600, []);      %% Hours
                "hour"    -> list_to_ttl(Value * 3600, []);      %% Hours
                "hours"   -> list_to_ttl(Value * 3600, []);      %% Hours
                "d"       -> list_to_ttl(Value * 86400, []);     %% Days
                "day"     -> list_to_ttl(Value * 86400, []);     %% Days
                "days"    -> list_to_ttl(Value * 86400, []);     %% Days
                "w"       -> list_to_ttl(Value * 604800, []);    %% Weeks
                "week"    -> list_to_ttl(Value * 604800, []);    %% Weeks
                "weeks"   -> list_to_ttl(Value * 604800, []);    %% Weeks
                "mon"     -> list_to_ttl(Value * 2592000, []);   %% Months (30 days)
                "month"   -> list_to_ttl(Value * 2592000, []);   %% Months (30 days)
                "months"  -> list_to_ttl(Value * 2592000, []);   %% Months (30 days)
                "y"       -> list_to_ttl(Value * 31536000, []);  %% Years
                "year"    -> list_to_ttl(Value * 31536000, []);  %% Years
                "years"   -> list_to_ttl(Value * 31536000, []);  %% Years
                "max" when Acc =:= [] -> list_to_ttl(?MAX_TTL, []);
                _ -> {error, invalid_ttl}
            end
    end.

-ifdef(EUNIT).
list_to_ttl_test() ->
    {ok, 1} = list_to_ttl("1"),
    {ok, 1 * 60} = list_to_ttl("1m"),
    {ok, 1 * 60 * 60} = list_to_ttl("1h"),
    {ok, 1 * 60 * 60 * 24} = list_to_ttl("1d"),
    {ok, 1 * 60 * 60 * 24 * 7} = list_to_ttl("1w"),
    {error, invalid_ttl} = list_to_ttl("1wa"),
    {ok, 64 * 31536000} = list_to_ttl("64years"),
    {error, {out_of_range, 69 * 31536000}} = list_to_ttl("69years").
-endif.


-define(PUNYCODE_BASE, 36).
-define(PUNYCODE_TMIN, 1).
-define(PUNYCODE_TMAX, 26).
-define(PUNYCODE_SKEW, 38).
-define(PUNYCODE_DAMP, 700).
-define(PUNYCODE_BIAS_INIT, 72).
-define(PUNYCODE_N_INIT, 128).

punyencode([], Acc) ->
    {ok, lists:reverse(Acc)};
punyencode([Label0|Rest], Acc) when is_binary(Label0) ->
    {ok, Label} = punyencode_label(Label0),
    if
        byte_size(Label) > 63 -> {error, label_too_long};
        true -> punyencode(Rest, [Label|Acc])
    end.

punyencode_label(Label0) ->
    % Should normalize the unicode form as necessary
    case unicode:characters_to_list(Label0, unicode) of
        {error, _, _} ->
            case unicode:characters_to_list(Label0, latin1) of
                Label1 when is_list(Label1) ->
                    punyencode_label(Label1, Label1, [])
            end;
        Label1 when is_list(Label1) ->
            punyencode_label(Label1, Label1, [])
    end.

punyencode_label([], Label, Ascii) when length(Label) =:= length(Ascii) ->
    {ok, list_to_binary(Label)};
punyencode_label([], Label0, Ascii) ->
    Label1 = string:to_lower(unicode:characters_to_nfkc_list(Label0)),
    punyencode_extended(Label1, Ascii);
punyencode_label([C|Rest], Label, Ascii) ->
    if
        C =< 16#7F -> punyencode_label(Rest, Label, [C|Ascii]);
        C > 16#7F -> punyencode_label(Rest, Label, Ascii)
    end.

punyencode_extended(Label, []) ->
    punyencode_extended_choose_m_delta(16#FFFFFFFF, ?PUNYCODE_N_INIT, 0, punyencode_bias(), 0, Label, length(Label), lists:reverse("xn--"));
punyencode_extended(Label, Acc) ->
    punyencode_extended_choose_m_delta(16#FFFFFFFF, ?PUNYCODE_N_INIT, 0, punyencode_bias(), length(Acc), Label, length(Label), lists:append([$-|Acc], lists:reverse("xn--"))).

punyencode_bias() ->
    Fun2 = fun (RetFn) ->
        fun (Delta0, Index) ->
            Delta1 = Delta0 div 2,
            Delta2 = Delta1 + (Delta1 div Index),
            {Delta3, K} = punyencode_bias_loop(Delta2, 0),
            {K + (((?PUNYCODE_BASE - ?PUNYCODE_TMIN + 1) * Delta3) div (Delta3 + ?PUNYCODE_SKEW)), RetFn(RetFn)}
        end
    end,
    Fun1 = fun (RetFn) ->
        fun (Delta0, Index) ->
            Delta1 = Delta0 div ?PUNYCODE_DAMP,
            Delta2 = Delta1 + (Delta1 div Index),
            {Delta3, K} = punyencode_bias_loop(Delta2, 0),
            {K + (((?PUNYCODE_BASE - ?PUNYCODE_TMIN + 1) * Delta3) div (Delta3 + ?PUNYCODE_SKEW)), RetFn(RetFn)}
        end
    end,
    {?PUNYCODE_BIAS_INIT, Fun1(Fun2)}.

%dnslib:punyencode([<<"väinämöinen">>]).


punyencode_bias_loop(Delta, K) when Delta > (((?PUNYCODE_BASE - ?PUNYCODE_TMIN) * ?PUNYCODE_TMAX) div 2) ->
    punyencode_bias_loop(Delta div (?PUNYCODE_BASE - ?PUNYCODE_TMIN), K + ?PUNYCODE_BASE);
punyencode_bias_loop(Delta, K) -> {Delta, K}.


punyencode_extended_choose_m_delta(_, _, _, _, Index, _, LabelLength, Acc) when Index =:= LabelLength ->
    {ok, list_to_binary(lists:reverse(Acc))};
punyencode_extended_choose_m_delta(M0, N, Delta, Bias, Index, Label, LabelLength, Acc) ->
    M1 = lists:foldl(fun (C, FunM) when C >= N, C < FunM -> C; (_, FunM) -> FunM end, M0, Label),
    Delta1 = Delta + (M1 - N) * (Index + 1),
    punyencode_extended_find_n(M1, M1, Delta1, Bias, Index, Label, LabelLength, Label, Acc).


punyencode_extended_find_n(_, N, _, _, _, _, _, _, _) when N > 16#FFFFFFFF ->
    {error, punyencode_overflow};
punyencode_extended_find_n(_, _, Delta, _, _, _, _, _, _) when Delta > 16#FFFFFFFF ->
    {error, punyencode_overflow};
punyencode_extended_find_n(_, _, _, _, Index, _, LabelLength, _, Acc) when Index =:= LabelLength ->
    {ok, list_to_binary(lists:reverse(Acc))};
punyencode_extended_find_n(M, N, Delta0, Bias0, Index, Label, LabelLength, LabelSubStr0, Acc0) ->
    case adjust_delta(N, Delta0, LabelSubStr0) of
        {pass, Delta1} -> punyencode_extended_choose_m_delta(16#FFFFFFFF, N + 1, Delta1 + 1, Bias0, Index, Label, LabelLength, Acc0);
        {ok, Delta1, LabelSubStr1} ->
            {Bias1, Acc1} = punyencode_encode_delta(Delta1, Delta1, Bias0, ?PUNYCODE_BASE, Index, Acc0),
            punyencode_extended_find_n(M, N, 0, Bias1, Index + 1, Label, LabelLength, LabelSubStr1, Acc1)
    end.

adjust_delta(_, Delta, []) ->
    {pass, Delta};
adjust_delta(N, Delta, [C|Rest]) when N > C ->
    adjust_delta(N, Delta + 1, Rest);
adjust_delta(N, Delta, [C|Rest]) when N < C ->
    adjust_delta(N, Delta, Rest);
adjust_delta(N, Delta, [N|Rest]) ->
    {ok, Delta, Rest}.

punyencode_encode_delta(Delta, Q, {Bias,AdjustBias}=BiasTuple, K, Index, Acc) ->
    T = if
        K =< Bias -> ?PUNYCODE_TMIN;
        K >= (Bias + ?PUNYCODE_TMAX) -> ?PUNYCODE_TMAX;
        true -> K - Bias
    end,
    if
        Q < T ->
            NewBias = AdjustBias(Delta, (Index + 1)),
            {NewBias, [punyencode_value(Q)|Acc]};
        true ->
            Digit = T + ((Q - T) rem (?PUNYCODE_BASE - T)),
            punyencode_encode_delta(Delta, (Q - T) div (?PUNYCODE_BASE - T), BiasTuple, K + ?PUNYCODE_BASE, Index, [punyencode_value(Digit)|Acc])
    end.

punyencode_value(Value) when Value =< 25 ->
    Value + $a;
punyencode_value(Value) ->
    Value + ($0 - 26).
