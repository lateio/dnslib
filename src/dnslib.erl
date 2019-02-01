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
-module(dnslib).

% Behaviors
-behavior(application).
-export([start/2, stop/1]).
-behavior(supervisor).
-export([init/1]).

%% API exports
-export([
    list_to_domain/1,
    list_to_codepoint_domain/1,
    codepoint_domain_to_domain/1,
    domain_to_list/1,
    domain_to_codepoint_domain/1,
    is_subdomain/2,
    domain_in_zone/2,
    append_domain/1,
    append_domain/2,
    domain/1,
    question/2,
    question/3,
    resource/1,
    resource/5,
    normalize_domain/1,
    normalize_question/1,
    normalize_resource/1,
    is_valid_domain/1,
    is_valid_hostname/1,
    reverse_dns_domain/1,
    reverse_dns_question/1,
    list_to_ttl/1,
    is_valid_opcode/1, % This should be in dnsmsg?
    is_valid_resource_type/1,
    is_valid_resource_class/1,
    is_valid_return_code/1,
    punyencode/1,
    punyencode_label/1,
    deduplicate/1
]).

-include_lib("dnslib/include/dnslib.hrl").

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

-include("include/pre_otp20_string_macro.hrl").

-type domain_label() :: <<_:8, _:_*8>>.
-type non_wildcard_domain() :: [domain_label()].
-type wildcard_domain() :: ['_'|domain_label()].
%-type normalized_domain() :: {normalized, OrigDomain :: domain(), NormDomain :: domain()}.
-type domain() :: wildcard_domain() | non_wildcard_domain().
%-type domain() :: wildcard_domain() | non_wildcard_domain() | normalized_domain().
-type compressed_domain() :: {'compressed', Ref :: non_neg_integer(), dnslib:domain()}.

-type codepoint_label() :: string().
-type non_wildcard_codepoint_domain() :: [codepoint_label()].
-type wildcard_codepoint_domain() :: ['_'|codepoint_label()].
-type codepoint_domain() :: wildcard_codepoint_domain() | non_wildcard_codepoint_domain().

% Do return_code and opcode belong here?
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

-type resource(Type, Class) ::
    {
        Domain :: dnslib:domain(),
        Type,
        Class,
        Ttl    :: ttl(),
        Data   :: term()
    }.

-type question() ::
    {
        Domain :: dnslib:non_wildcard_domain(),
        Type   :: dnsrr:type(),
        Class  :: dnsclass:class()
    }.

-type question(Type) ::
    {
        Domain :: dnslib:non_wildcard_domain(),
        Type,
        Class  :: dnsclass:class()
    }.

-type question(Type, Class) ::
    {
        Domain :: dnslib:non_wildcard_domain(),
        Type,
        Class
    }.


-export_type([
    domain_label/0,
    non_wildcard_domain/0,
    wildcard_domain/0,
    domain/0,
    codepoint_label/0,
    non_wildcard_codepoint_domain/0,
    wildcard_codepoint_domain/0,
    codepoint_domain/0,
    resource/0,
    resource/1,
    resource/2,
    question/0,
    question/1,
    question/2,
    opcode/0,
    return_code/0,
    ttl/0,
    list_to_domain_error/0,
    compressed_domain/0
]).

%%====================================================================
%% API functions
%%====================================================================


start(_, _) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

stop(_) ->
    ok.

init([]) ->
    %dnclass:compile_dnsclass_types(),
    dnsrr:compile_dnsrr_types(),
    {ok, {{one_for_one,3,10},[]}}.


-spec is_subdomain(This :: domain(), OfThis :: domain()) -> boolean().
is_subdomain([], _) ->
    false;
is_subdomain(_, []) ->
    true;
is_subdomain(This, OfThis) ->
    subdomain_of(lists:reverse(This), lists:reverse(OfThis)).

-ifdef(EUNIT).
subdomain_test() ->
    false = is_subdomain([], []),
    false = is_subdomain([], [<<"abc">>]),
    true  = is_subdomain([<<"abc">>], []),
    true  = is_subdomain([<<"abc">>, <<"com">>], [<<"com">>]),
    false = is_subdomain([<<"abc">>, <<"com">>], [<<"COM">>]).
-endif.


domain_in_zone(['_'|D1], ['_'|D2]) ->
    domain_in_zone(D1, D2);
domain_in_zone(['_'|D1], [_|_] = D2) ->
    domain_in_zone(D1, D2);
domain_in_zone([_|_] = D1, ['_'|D2]) ->
    is_subdomain(D1, D2);
domain_in_zone(D1, D2) ->
    is_subdomain(D1, D2) orelse D1 =:= D2.


domain(String) when is_integer(hd(String)) ->
    case list_to_domain(String) of
        {ok, _, Domain} -> Domain;
        _ -> error(badarg)
    end;
domain(Domain) ->
    case is_valid_domain(Domain) of
        true -> Domain;
        _ -> error(badarg)
    end.


question(Domain, Type) ->
    question(Domain, Type, in).

question(_, Type, _)
when is_integer(Type) andalso Type < 0 orelse is_integer(Type) andalso Type > 16#FFFF ->
    error(badarg);
question(_, _, Class)
when is_integer(Class) andalso Class < 0 orelse is_integer(Class) andalso Class > 16#FFFF ->
    error(badarg);
question([Head|_] = DomainStr, Type, Class) when is_integer(Head) ->
    case list_to_domain(DomainStr) of
        {ok, _, ['_'|Domain]} -> question([<<"*">>|Domain], Type, Class);
        {ok, _, Domain} -> question(Domain, Type, Class);
        _ -> error(badarg)
    end;
question(Domain, Type0, Class0) ->
    case is_valid_domain(Domain) of
        true -> ok;
        _ -> error(badarg)
    end,
    Type = case is_integer(Type0) of
        true -> dnsrr:from_to(Type0, value, atom);
        false ->
            case dnsrr:from_to(Type0, atom, value) of
                Type0 -> error(badarg); % Should we throw?
                _ -> Type0
            end
    end,
    Class = case is_integer(Class0) of
        true -> dnsclass:from_to(Class0, value, atom);
        false ->
            case dnsclass:from_to(Class0, atom, value) of
                Class0 -> error(badarg);  % Should we throw?
                _ -> Class0
            end
    end,
    % Make sure that the type+class combination is allowed
    {Domain, Type, Class}.


resource(Line) when is_list(Line) ->
    case dnsfile:parse_resource(Line) of
        {ok, Resource} -> Resource;
        _ -> error(badarg)
    end.

resource(_, Type, _, _, _)
when is_integer(Type) andalso Type < 0 orelse is_integer(Type) andalso Type > 16#FFFF ->
    error(badarg);
resource(_, _, Class, _, _)
when is_integer(Class) andalso Class < 0 orelse is_integer(Class) andalso Class > 16#FFFF ->
    error(badarg);
resource(_, _, _, Ttl, _)
when is_integer(Ttl) andalso Ttl < 0 orelse is_integer(Ttl) andalso Ttl > ?MAX_TTL ->
    error(badarg);
resource(Domain, Type, Class, TtlStr, Data) when is_list(TtlStr) ->
    case list_to_ttl(TtlStr) of
        {ok, Ttl} -> resource(Domain, Type, Class, Ttl, Data);
        _ -> error(badarg)
    end;
resource(_, _, _, Ttl, _) when not is_integer(Ttl) ->
    error(badarg);
resource([Head|_] = DomainStr, Type, Class, Ttl, Data) when is_integer(Head) ->
    case list_to_domain(DomainStr) of
        {ok, _, ['_'|Domain]} -> resource([<<"*">>|Domain], Type, Class, Ttl, Data);
        {ok, _, Domain} -> resource(Domain, Type, Class, Ttl, Data);
        _ -> error(badarg)
    end;
resource(Domain, Type0, Class0, Ttl, Data0) ->
    case is_valid_domain(Domain) of
        true -> ok;
        _ -> error(badarg)
    end,
    Class = case is_integer(Class0) of
        true -> dnsclass:from_to(Class0, value, atom);
        false ->
            case dnsclass:from_to(Class0, atom, value) of
                Class0 -> error(badarg);  % Should we throw?
                _ -> Class0
            end
    end,
    {Type, Data} = case {is_integer(Type0), dnsrr:from_to(Type0, value, module), dnsrr:from_to(Type0, atom, module)} of
        {true, Type0, _} when is_binary(Data0) -> {Type0, Data0};
        %{true, Type0, _} when is_list(Data0) ->
        % If data is string, it might be in generic format...
        {true, Module, _} when Module =/= Type0 ->
            {_, RecurseType, _, _, RecurseData} = resource(Domain, Module:atom(), Class, Ttl, Data0),
            {RecurseType, RecurseData};
        {false, _, Type0} -> error(badarg);
        {false, _, Module} ->
            case dnsrr:validate_data(Module:atom(), Data0) of
                true -> {Module:atom(), Data0};
                false when is_binary(Data0) ->
                    case Module:from_binary(Data0) of
                        {ok, TermData} -> {Module:atom(), TermData};
                        {domains, DataList} ->
                            case [GenTuple || GenTuple <- DataList, is_tuple(GenTuple), element(1, GenTuple) =:= compressed] of
                                [] ->
                                    Fn = fun
                                        ({domain, FunDomain, _}) -> FunDomain;
                                        (FunMember) -> FunMember
                                    end,
                                    Rdata = dnswire:finalize_resource_data([Fn(GenMember) || GenMember <- DataList], Module),
                                    {Module:atom(), Rdata};
                                _ -> error(badarg)
                            end;
                        % Should we have different error for compressed domains?
                        _ -> error(badarg)
                    end;
                false when is_list(Data0) ->
                    % Need to check if the module has from_masterfile
                    Line = lists:append([
                        ". in 0 ",
                        Module:masterfile_token(),
                        " ",
                        Data0
                    ]),
                    case dnsfile:parse_resource(Line) of
                        {ok, {_, _, _, _, ParsedData}} -> {Module:atom(), ParsedData};
                        _ -> error(badarg)
                    end;
                false -> error(badarg)
            end
    end,
    % Make sure that type can be a resource.
    % Make sure that the type+class combination is allowed
    {Domain, Type, Class, Ttl, Data}.


%% @doc Normalize ascii character case in domain labels.
-spec normalize_domain(Domain :: domain()) -> domain().
normalize_domain([]) ->
    [];
normalize_domain(['_'|Domain]) ->
    ['_'|[normalize_label(Label) || Label <- Domain]];
normalize_domain(Domain) ->
    [normalize_label(Label) || Label <- Domain].


%normalized_domain(Domain) ->
%    .


-spec normalize_question(dnslib:question()) -> dnslib:question() | no_return().
normalize_question({Domain, Type0, Class0}) ->
    Type = if
        is_integer(Type0) -> dnsrr:from_to(Type0, value, atom);
        true -> Type0
    end,
    Class = if
        is_integer(Class0) -> dnsclass:from_to(Class0, value, atom);
        true -> Class0
    end,
    case
        {
            is_integer(dnsrr:from_to(Type, atom, value)),
            is_integer(dnsclass:from_to(Class, atom, value))
        }
    of
        {true, true} -> ok;
        _ -> error(badarg)
    end,
    {normalize_domain(Domain), Type, Class}.


-spec normalize_resource(dnslib:resource()) -> dnslib:resource() | no_return().
normalize_resource({Domain, Type0, Class0, Ttl, Data}) ->
    Class = if
        is_integer(Class0) -> dnsclass:from_to(Class0, value, atom);
        true -> Class0
    end,
    Type = if
        is_integer(Type0) -> dnsrr:from_to(Type0, value, atom);
        true -> Type0
    end,
    case dnsrr:from_to(Type, atom, module) of
        Type when is_binary(Data), is_integer(Type) ->
            {
                normalize_domain(Domain),
                Type,
                Class,
                Ttl,
                Data
            };
        Type -> error(badarg);
        Module when is_binary(Data) ->
            case Module:from_binary(Data) of
                {ok, Data1} ->
                    {
                        normalize_domain(Domain),
                        Module:atom(),
                        Class,
                        Ttl,
                        dnsrr:normalize_data(Module:atom(), Data1)
                    };
                {domains, DataList} ->
                    case [GenTuple || GenTuple <- DataList, is_tuple(GenTuple), element(1, GenTuple) =:= compressed] of
                        [] ->
                            Fn = fun
                                ({domain, FunDomain, _}) -> FunDomain;
                                (FunMember) -> FunMember
                            end,
                            Rdata = dnswire:finalize_resource_data([Fn(GenMember) || GenMember <- DataList], Module),
                            {
                                normalize_domain(Domain),
                                Module:atom(),
                                Class,
                                Ttl,
                                dnsrr:normalize_data(Module:atom(), Rdata)
                            };
                        _ -> error(badarg)
                    end;
                _ -> error(badarg)
            end;
        Module ->
            {
                normalize_domain(Domain),
                Module:atom(),
                Class,
                Ttl,
                dnsrr:normalize_data(Module:atom(), Data)
            }
    end.


-spec append_domain([domain()]) ->
    {'ok', domain()} |
    {'error',
        'domain_too_long' |
        'label_too_long'  |
        'empty_label'
    }.
append_domain([]) ->
    {ok, []};
append_domain([Domain1]) ->
    {ok, Domain1};
append_domain([Domain1|Rest]) ->
    Fn = fun
        (['_'|FunDomain], FunAcc) -> lists:append(FunAcc, [<<"*">>|FunDomain]);
        (FunDomain, FunAcc) -> lists:append(FunAcc, FunDomain)
    end,
    append_domain(Domain1, lists:foldl(Fn, [], Rest)).


-spec append_domain(domain(), domain()) ->
    {'ok', domain()} |
    {'error',
        'domain_too_long' |
        'label_too_long'  |
        'empty_label'
    }.
append_domain(Domain1, ['_'|Domain2]) ->
    append_domain(Domain1, [<<"*">>|Domain2]);
append_domain(Domain1, Domain2) ->
    Domain3 = lists:append(Domain1, Domain2),
    case is_valid_domain(Domain3) of
        true -> {ok, Domain3};
        {false, Reason} -> {error, Reason}
    end.


-type list_to_domain_error() ::
    'domain_too_long' |
    'label_too_long'  |
    'empty_label'     |
    'empty_string'    |
    {'escape_out_of_range', integer()}   |
    {'invalid_escape_integer', string()}.
-spec list_to_domain(Str :: [byte(), ...]) ->
    {'ok', 'absolute' | 'relative', domain()} |
    {'error',
        list_to_domain_error() |
        {'non_ascii_codepoint', string()}
    }.
list_to_domain([]) ->
    {error, empty_string};
list_to_domain(".") ->
    {ok, absolute, []};
list_to_domain(Str) ->
    case list_to_codepoint_domain(Str) of
        {ok, _, false, Domain} -> % Catch non-ascii characters early
            [First|_] = lists:filter(fun (FunLabel) -> not lists:all(fun (FunChar) -> FunChar < 128 end, FunLabel) end, Domain),
            {error, {non_ascii_codepoint, First}};
        {ok, DomainType, true, Domain} ->
            {ok, BinDomain} = codepoint_domain_to_domain(Domain),
            {ok, DomainType, BinDomain};
        {error, _}=Tuple -> Tuple
    end.


-spec list_to_codepoint_domain(Domain :: string()) ->
    {'ok', 'absolute' | 'relative', ASCIIOnly :: boolean(), codepoint_domain()} |
    {'error', list_to_domain_error()}.
list_to_codepoint_domain([]) ->
    {error, empty_string};
list_to_codepoint_domain(".") ->
    {ok, absolute, true, []};
list_to_codepoint_domain(Str) ->
    list_to_codepoint_domain(Str, [], [], 1, true).


-spec codepoint_domain_to_domain(codepoint_domain())
    -> {'ok', domain()}
     | {'error', {'codepoint_too_large', string()}}.
codepoint_domain_to_domain(['_'|CodepointDomain]) ->
    case codepoint_domain_to_domain(CodepointDomain, []) of
        {error, _}=Tuple -> Tuple;
        {ok, Domain} -> {ok, ['_'|Domain]}
    end;
codepoint_domain_to_domain(CodepointDomain) ->
    codepoint_domain_to_domain(CodepointDomain, []).


-spec domain_to_codepoint_domain(dnslib:domain()) -> dnslib:codepoint_domain().
domain_to_codepoint_domain(['_'|Domain]) ->
    ['_'|[binary_to_list(Label) || Label <- Domain]];
domain_to_codepoint_domain(Domain) ->
    [binary_to_list(Label) || Label <- Domain].


-spec domain_to_list(Domain :: domain() | codepoint_domain()) -> string().
domain_to_list([]) ->
    ".";
domain_to_list(['_'|Domain]) ->
    [$*, $.|domain_to_list(Domain)];
domain_to_list([Head|_]=Domain) when is_binary(Head) ->
    domain_to_list(domain_to_codepoint_domain(Domain));
domain_to_list(["*"|Domain]) ->
    domain_to_list(Domain, lists:reverse("\\*."));
domain_to_list(Domain) ->
    domain_to_list(Domain, []).


-spec is_valid_domain(Domain :: domain())
    -> 'true'
     | {'false',
         'not_a_list'       |
         'domain_too_long'  |
         'label_too_long'   |
         'non_binary_label' |
         'empty_label'
       }.
is_valid_domain(Domain) when not is_list(Domain) ->
    {false, not_a_list};
is_valid_domain([]) ->
    true;
is_valid_domain(['_'|Domain]) ->
    is_valid_domain(Domain, 1);
is_valid_domain(Domain) ->
    is_valid_domain(Domain, 1).


-spec is_valid_hostname(domain()) -> boolean().
is_valid_hostname([]) ->
    false;
is_valid_hostname(Domain) ->
    [Head|Tail] = normalize_domain(Domain),
    is_valid_hostname(Head, Tail).


-spec reverse_dns_domain(inet:ip_address()) -> domain().
reverse_dns_domain(Address) ->
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
    lists:append(lists:reverse(Labels),
        case tuple_size(Address) of
            4 -> [<<"in-addr">>, <<"arpa">>];
            8 -> [<<"ip6">>, <<"arpa">>]
        end
    ).


-spec reverse_dns_question(inet:ip_address()) -> question().
reverse_dns_question(Address) when tuple_size(Address) =:= 4; tuple_size(Address) =:= 8 ->
    {reverse_dns_domain(Address), ptr, in}.


-spec list_to_ttl(string()) ->
    {'ok', 0..16#7FFFFFFF} |
    {'error',
        {'out_of_range', integer()} |
        'invalid_ttl' |
        'empty_string'
    }.
list_to_ttl([]) ->
	{error, empty_string};
list_to_ttl([$-|Str]) ->
	list_to_ttl(Str, [$-]);
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


punyencode(Domain) ->
    punyencode(Domain, []).


-spec deduplicate([dnslib:question()] | [dnslib:resource()]) -> [dnslib:question()] | [dnslib:resource()].
deduplicate([]) ->
    [];
deduplicate(Questions = [{_, _, _}|_]) ->
    deduplicate(fun dnslib:normalize_question/1, Questions, [], []);
deduplicate(Resources = [{_, _, _, _, _}|_]) ->
    deduplicate(fun dnslib:normalize_resource/1, Resources, [], []).


%%====================================================================
%% Internal functions
%%====================================================================

-spec subdomain_of(This :: domain(), OfThis :: domain()) -> boolean().
subdomain_of([], _) ->
    false;
subdomain_of(_, []) ->
    true;
subdomain_of([_], ['_']) ->
    false;
subdomain_of(_, ['_']) ->
    true;
subdomain_of([Label|This], [Label|OfThis]) ->
    subdomain_of(This, OfThis);
subdomain_of(_, _) ->
    false.


normalize_label(Label) ->
    normalize_label(Label, <<>>).

normalize_label(<<>>, Acc) ->
    Acc;
normalize_label(<<Char0, Tail/binary>>, Acc) when Char0 >= $A, Char0 =< $Z ->
    Char = Char0 + ($a - $A),
    normalize_label(Tail, <<Acc/bits, Char>>);
normalize_label(<<Char, Tail/binary>>, Acc) ->
    normalize_label(Tail, <<Acc/bits, Char>>).


list_to_codepoint_domain(_, _, _, TotalLength, _) when TotalLength > ?DOMAIN_MAX_OCTETS ->
    {error, domain_too_long};
list_to_codepoint_domain(_, Acc, _, _, _) when length(Acc) > 63 ->
    {error, label_too_long};
list_to_codepoint_domain([], [], Acc, _, ASCIIOnly) ->
    {ok, absolute, ASCIIOnly, lists:reverse(Acc)};
list_to_codepoint_domain([], [$*], [], _, ASCIIOnly) ->
    {ok, relative, ASCIIOnly, ['_']};
list_to_codepoint_domain([], Cur, Acc, _, ASCIIOnly) ->
    {ok, relative, ASCIIOnly, lists:reverse([lists:reverse(Cur)|Acc])};
list_to_codepoint_domain([$.|_], [], _, _, _) ->
    {error, empty_label};
list_to_codepoint_domain([$.|Rest], [$*], [], _, ASCIIOnly) ->
    list_to_codepoint_domain(Rest, [], ['_'], 0, ASCIIOnly);
list_to_codepoint_domain([$.|Rest], Cur, Acc, TotalLength, ASCIIOnly) ->
    list_to_codepoint_domain(Rest, [], [lists:reverse(Cur)|Acc], TotalLength+1, ASCIIOnly);
list_to_codepoint_domain([$\\, C1, C2, C3|Rest], Cur, Acc, TotalLength, ASCIIOnly)
when C1 >= $0, C1 =< $9, C2 >= $0, C2 =< $9, C3 >= $0, C3 =< $9 ->
    case list_to_integer([C1, C2, C3]) of
        Value when Value > 255 -> {error, {escape_out_of_range, Value}};
        Value -> list_to_codepoint_domain(Rest, [Value|Cur], Acc, TotalLength+1, ASCIIOnly andalso Value < 128)
    end;
list_to_codepoint_domain([$\\, C1, C2, C3|_], _, _, _, _) when C1 >= $0, C1 =< $9 ->
    {error, {invalid_escape_integer, [C1, C2, C3]}};
list_to_codepoint_domain([$\\, $*, $.|Rest], [], Acc, TotalLength, ASCIIOnly) ->
    list_to_codepoint_domain(Rest, [], [[$*]|Acc], TotalLength+2, ASCIIOnly);
list_to_codepoint_domain([$\\, Char|Rest], Cur, Acc, TotalLength, ASCIIOnly) ->
    list_to_codepoint_domain(Rest, [Char|Cur], Acc, TotalLength+1, ASCIIOnly andalso Char < 128);
list_to_codepoint_domain([Char|Rest], Cur, Acc, TotalLength, ASCIIOnly) ->
    list_to_codepoint_domain(Rest, [Char|Cur], Acc, TotalLength+1, ASCIIOnly andalso Char < 128).


domain_to_list([], Acc) ->
    lists:reverse(Acc);
domain_to_list([Label|Rest], Acc) ->
    domain_to_list(Rest, label_to_list(Label, Acc)).

label_to_list([], Acc) ->
    [$.|Acc];
label_to_list([Char|Tail], []) when Char =:= $"; Char =:= $( ->
    label_to_list(Tail, [Char, $\\]);
label_to_list([$.|Tail], Acc) ->
    label_to_list(Tail, [$., $\\|Acc]);
label_to_list([Char|Tail], Acc) when Char =< 16#20; Char =:= 127 ->
    Str0 = integer_to_list(Char),
    Str1 = lists:append(lists:reverse(Str0), [$0 || _ <- lists:seq(1,3-length(Str0))]),
    label_to_list(Tail, lists:append(Str1, [$\\|Acc]));
label_to_list([Char|Tail], Acc) ->
    label_to_list(Tail, [Char|Acc]).


is_valid_domain(_, TotalLength) when TotalLength > ?DOMAIN_MAX_OCTETS ->
    {false, domain_too_long};
is_valid_domain([], _) ->
    true;
is_valid_domain(['_'|_], _) ->
    {false, wildcard_label_not_first};
is_valid_domain([Label|_], _) when byte_size(Label) > 63 ->
    {false, label_too_long};
is_valid_domain([Label|_], _) when byte_size(Label) =:= 0 ->
    {false, empty_label};
is_valid_domain([Label|Rest], TotalLength) when is_binary(Label) ->
    is_valid_domain(Rest, TotalLength + byte_size(Label) + 1);
is_valid_domain([Label|_], _) when not is_binary(Label) ->
    {false, non_binary_label}.


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

list_to_ttl(Value, []) when is_integer(Value) andalso Value >= 0, Value =< ?MAX_TTL ->
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
list_to_ttl(Tail0, Acc0) ->
    Tail = string:(?LOWER)(string:(?TRIM)(Tail0)),
    case lists:reverse(Acc0) of
        [] when Tail =:= "max" -> list_to_ttl(?MAX_TTL, []);
        Acc ->
            try list_to_integer(Acc) of
                Value ->
                    case Tail of
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
                        _ -> {error, invalid_ttl}
                    end
            catch
                error:badarg -> {error, invalid_ttl}
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
punyencode([Label0|Rest], Acc) when is_list(Label0) ->
    {ok, Label} = punyencode_label(Label0, Label0, []),
    if
        length(Label) > 63 -> {error, label_too_long};
        true -> punyencode(Rest, [Label|Acc])
    end.

punyencode_label(Label) ->
    punyencode_label(Label, Label, []).

punyencode_label([], Label, Ascii) when length(Label) =:= length(Ascii) ->
    {ok, Label};
punyencode_label([], Label0, Ascii) ->
    Label1 = string:(?LOWER)(unicode:characters_to_nfkc_list(Label0)),
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


punyencode_bias_loop(Delta, K) when Delta > (((?PUNYCODE_BASE - ?PUNYCODE_TMIN) * ?PUNYCODE_TMAX) div 2) ->
    punyencode_bias_loop(Delta div (?PUNYCODE_BASE - ?PUNYCODE_TMIN), K + ?PUNYCODE_BASE);
punyencode_bias_loop(Delta, K) -> {Delta, K}.


punyencode_extended_choose_m_delta(_, _, _, _, Index, _, LabelLength, Acc) when Index =:= LabelLength ->
    {ok, lists:reverse(Acc)};
punyencode_extended_choose_m_delta(M0, N, Delta, Bias, Index, Label, LabelLength, Acc) ->
    M1 = lists:foldl(fun (C, FunM) when C >= N, C < FunM -> C; (_, FunM) -> FunM end, M0, Label),
    Delta1 = Delta + (M1 - N) * (Index + 1),
    punyencode_extended_find_n(M1, M1, Delta1, Bias, Index, Label, LabelLength, Label, Acc).


punyencode_extended_find_n(_, N, _, _, _, _, _, _, _) when N > 16#FFFFFFFF ->
    {error, punyencode_overflow};
punyencode_extended_find_n(_, _, Delta, _, _, _, _, _, _) when Delta > 16#FFFFFFFF ->
    {error, punyencode_overflow};
punyencode_extended_find_n(_, _, _, _, Index, _, LabelLength, _, Acc) when Index =:= LabelLength ->
    {ok, lists:reverse(Acc)};
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


codepoint_domain_to_domain([], Acc) ->
    {ok, lists:reverse(Acc)};
codepoint_domain_to_domain([Label|Rest], Acc) ->
    try list_to_binary(Label) of
        BinLabel -> codepoint_domain_to_domain(Rest, [BinLabel|Acc])
    catch
        error:badarg -> {error, {codepoint_too_large, Label}}
    end.


deduplicate(_, [], Keep, _) ->
    lists:reverse(Keep);
deduplicate(Fn, [Tuple|Rest], Keep, Hashes) ->
    Hash = erlang:phash2(Fn(Tuple)),
    case lists:member(Hash, Hashes) of
        true -> deduplicate(Fn, Rest, Keep, Hashes);
        false -> deduplicate(Fn, Rest, [Tuple|Keep], [Hash|Hashes])
    end.
