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
% This this file implements reading and parsing of DNS files.
-module(dnsfile).

-export([
    consult/1,
    consult/2,
    write_resources/2,
    write_resources/3,
    directive_origin/2,
    directive_include/2,
    directive_punyencode/2,
    directive_ttl/2,
    escape_text/1,
    indicate_domain/1
]).

-include_lib("dnslib/include/dnslib.hrl").

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

-type proto_resource() ::
    {
        dnslib:domain(),
        dnsrr:type()     | 'undefined',
        dnsclass:class() | 'undefined',
        dnslib:ttl()     | 'undefined',
        term()           | 'undefined'
    }.

-type line_part() :: string() | {string(), 'quoted'}.

-record(state, {
    max_line_length=1024 :: pos_integer(),
    line=1 :: pos_integer(),
    startline=1 :: pos_integer(),
    fn=fun line_start/2 :: function(),
    parentheses=false :: boolean(),
    entry_parts=[[]] :: [line_part()],
    path             :: string() | 'undefined',
    origin           :: dnslib:domain() | 'undefined',
    origin_str       :: string() | 'undefined',
    prevdomain       :: dnslib:domain() | 'undefined',
    prevclass        :: dnsclass:class() | 'undefined',
    prevttl          :: dnslib:ttl() | 'undefined',
    defttl           :: dnslib:ttl() | 'undefined',
    records=[]       :: [dnslib:resource()],
    include_depth=3  :: non_neg_integer(),
    included_from=[] :: [string()],
    punyencode=false :: boolean(),
    directives=#{
        "origin"     => directive_origin,
        "ttl"        => directive_ttl,
        "include"    => directive_include,
        "punyencode" => directive_punyencode
    } :: #{string() => atom()},
    type_blacklist = [
        mb,
        md,
        mf,
        mg,
        minfo,
        mr
    ] :: [dnsrr:type()],
    line_break=$\n :: [char()] | char()
}).


resolve(Str) when is_list(Str) ->
    resolve(Str, []).

resolve([], Acc) ->
	lists:reverse(Acc);
resolve([$\\, C1|Tail], Acc) ->
    resolve(Tail, [C1|Acc]);
resolve([Cur|Tail], Acc) ->
	resolve(Tail, [Cur|Acc]).


syntax_error(File, LineNumber, Details) ->
    {syntax_error, File, LineNumber, Details}.

directive_error(File, LineNumber, Details) ->
    {directive_error, File, LineNumber, Details}.

resource_record_error(File, LineNumber, Details) ->
    {resource_record_error, File, LineNumber, Details}.


-type prepare_data_error() ::
    'too_few_arguments'  |
    'too_many_arguments' |
    'too_long_text_data' |
    'no_origin'          |
    {'unexpected_quoted', string()}                                    |
    {'out_of_range', 'uint16' | 'uint32' | 'ttl', string(), integer()} |
    {'invalid_domain', dnslib:list_to_domain_error(), string()}        |
    {'invalid_integer', string()}                                      |
    {'invalid_ttl', string()}.
-spec prepare_data([line_part()], [dnsrr:masterfile_format_type() | non_neg_integer()], map()) ->
    {'ok', [string() | dnslib:domain() | integer()]} |
    {'error', prepare_data_error()}.
prepare_data(Data, Format, Ctx) ->
    prepare_data(Data, Format, Ctx, []).

prepare_data([], [], _, Acc) ->
    {ok, lists:reverse(Acc)};
prepare_data([], [_, 0], _, _) ->
    {error, too_few_arguments};
prepare_data([], [_, Int], _, Acc) when is_integer(Int) ->
    {ok, lists:reverse(Acc)};
prepare_data([], _, _, _) ->
    {error, too_few_arguments};
prepare_data(_, [], _, _) ->
    {error, too_many_arguments};
prepare_data([{Value, quoted}|_], [token|_], _, _) ->
    {error, {unexpected_quoted, Value}};
prepare_data(["@"|_], [token|_], #state{origin = undefined}, _) ->
    {error, at_no_origin};
prepare_data(["@"|RestData], Types = [token|_], State = #state{origin_str = Origin}, Acc) ->
    prepare_data(RestData, prepare_data_next_type(Types), State, [Origin|Acc]);
prepare_data([Cur|RestData], Types = [token|_], State, Acc) ->
    Result = resolve(Cur),
    prepare_data(RestData, prepare_data_next_type(Types), State, [Result|Acc]);

prepare_data([{Txt, quoted}|_], [text|_], _, _) when length(Txt) > 255 ->
    {error, too_long_text_data};
prepare_data([{Txt, quoted}|_], [qtext|_], _, _) when length(Txt) > 255 ->
    {error, too_long_text_data};
prepare_data([{Txt, quoted}|RestData], Types = [TxtType|_], State, Acc)
when TxtType =:= text; TxtType =:= text_unlimited; TxtType =:= qtext; TxtType =:= qtext_unlimited ->
    Result = resolve(Txt),
    prepare_data(RestData, prepare_data_next_type(Types), State, [Result|Acc]);
prepare_data([_|_], [qtext|_], _, _) ->
    {error, unquoted_text};
prepare_data([Txt|_], [text|_], _, _) when length(Txt) > 255 ->
    {error, too_long_text_data};
prepare_data(["@"|_], [Txt|_], #{origin := undefined}, _)
when Txt =:= text; Txt =:= text_unlimited ->
    {error, at_no_origin};
prepare_data(["@"|RestData], Types = [Txt|_], State = #state{origin_str = Origin}, Acc)
when Txt =:= text; Txt =:= text_unlimited ->
    prepare_data(RestData, prepare_data_next_type(Types), State, [Origin|Acc]);
prepare_data([Txt|RestData], Types = [TxtType|_], State, Acc)
when TxtType =:= text; TxtType =:= text_unlimited ->
    Result = resolve(Txt),
    prepare_data(RestData, prepare_data_next_type(Types), State, [Result|Acc]);

prepare_data([Cur|RestData], Types = [IntType|_], State, Acc) when IntType =:= uint16; IntType =:= uint32 ->
    try list_to_integer(resolve(Cur)) of
        Result ->
            case IntType of
                uint16 when Result >= 0, Result =< 16#FFFF ->
                    prepare_data(RestData, prepare_data_next_type(Types), State, [Result|Acc]);
                uint32 when Result >= 0, Result =< 16#FFFFFFFF ->
                    prepare_data(RestData, prepare_data_next_type(Types), State, [Result|Acc]);
                _ -> {error, {out_of_range, IntType, Cur, Result}}
            end
    catch error:badarg -> {error, {invalid_integer, Cur}}
    end;
prepare_data([Cur|RestData], Types = [ttl|_], State, Acc) ->
    case dnslib:list_to_ttl(resolve(Cur)) of
        {ok, Result} -> prepare_data(RestData, prepare_data_next_type(Types), State, [Result|Acc]);
        {error, {out_of_range, Value}} -> {error, {out_of_range, ttl, Cur, Value}};
        {error, invalid_ttl} -> {error, {invalid_ttl, Cur}}
    end;
prepare_data(["@"|_], [domain|_], #{origin := undefined}, _) ->
    {error, at_no_origin};
prepare_data(["@"|RestData], Types = [domain|_], State = #state{origin = Origin}, Acc) ->
    prepare_data(RestData, prepare_data_next_type(Types), State, [Origin|Acc]);
prepare_data([Cur|RestData], Types = [domain|_], State = #state{origin = Origin}, Acc) ->
    case dnslib:list_to_domain(Cur) of
        {_, true, _} -> {error, {wildcard_domain, Cur}};
        {absolute, _, Domain} -> prepare_data(RestData, prepare_data_next_type(Types), State, [Domain|Acc]);
        {relative, _, _} when Origin =:= undefined -> {error, relative_no_origin};
        {relative, _, Domain} ->
            case dnslib:concat(punyencode(Domain, State), Origin) of
                {ok, true, Fqdn} -> {error, {wildcard_domain, dnslib:domain_to_list(Fqdn)}};
                {ok, false, Fqdn} -> prepare_data(RestData, prepare_data_next_type(Types), State, [Fqdn|Acc]);
                {error, Reason} -> {error, {invalid_domain, Reason, Cur}}
            end;
        {error, DomainError} ->
            {error, {invalid_domain, DomainError, Cur}}
    end.


prepare_data_next_type([Cur, '...'|Rest]) ->
    [Cur, 1|Rest];
prepare_data_next_type([Cur, Count|Rest]) when is_integer(Count) ->
    [Cur, Count+1|Rest];
prepare_data_next_type([_|Type]) ->
    Type.


directive_origin([Origin0], State) ->
    case dnslib:list_to_domain(Origin0) of
        {error, Reason} -> error({invalid_domain, Reason, Origin0});
        {relative, _, _} -> error(relative_origin);
        {absolute, _, Origin1} ->
            {ok, State#state{origin=punyencode(Origin1, State), origin_str=Origin0}}
    end;
directive_origin([], _) ->
    error(no_arguments).


directive_ttl([Ttl], State) ->
    case dnslib:list_to_ttl(resolve(Ttl)) of
        {ok, Ttl1} -> {ok, State#state{defttl=Ttl1, prevttl=Ttl1}};
        {error, Reason} -> error(Reason)
    end;
directive_ttl([], _) ->
    error(no_arguments).


% Remember to verify the include depth
directive_include(_, #state{include_depth=0}) ->
    error(include_depth);
directive_include([_, {Value, quoted}], #state{}) ->
    error({unexpected_quoted, Value});
directive_include([{File0, quoted}, NewOrigin], State = #state{}) ->
    directive_include([File0, NewOrigin], State);
directive_include([File0, NewOrigin], State = #state{origin=Origin}) ->
    case dnslib:list_to_domain(NewOrigin) of
        {absolute, _, NewOrigin1} -> directive_include1(File0, NewOrigin1, State);
        {relative, _, _} when Origin =:= undefined -> error(missing_origin);
        {relative, _, NewOrigin1} ->
            case dnslib:concat(punyencode(NewOrigin1, State), Origin) of
                {ok, _, Fqdn} -> directive_include1(File0, Fqdn, State);
                {error, Reason} -> error({invalid_domain, Reason, NewOrigin})
            end;
        {error, Reason} -> error({invalid_domain, Reason, NewOrigin})
    end;
directive_include([{File0, quoted}], State) ->
    directive_include([File0], State);
directive_include([File0], State = #state{origin=Origin}) ->
    directive_include1(File0, Origin, State);
directive_include([], _) ->
    error(no_arguments).


directive_include1(Path0, Origin, State = #state{path=PrevPath}) ->
    Path = resolve(Path0),
    File = case filename:pathtype(Path) of
        absolute -> Path;
        _ -> filename:join(filename:dirname(PrevPath), Path)
    end,
    #state{
        include_depth=Depth,
        records=Records,
        prevclass=Class,
        directives=Dirs,
        punyencode=Punyencode,
        line_break=LB,
        type_blacklist=BLTypes,
        included_from=IncludedFrom
    } = State,
    TmpState = #state{
        origin=Origin,
        include_depth=Depth-1,
        prevclass=Class,
        % Should we include previous domain?
        % Should we include previous ttl?
        directives=Dirs,
        punyencode=Punyencode,
        line_break=LB,
        type_blacklist=BLTypes,
        included_from=[PrevPath|IncludedFrom],
        path=File
    },
    case consult(File, TmpState) of
        {ok, NewRecords} -> {ok, State#state{records=lists:flatten([lists:reverse(NewRecords)|Records])}};
        {error, Reason} -> error({include_error, Reason})
    end.


directive_punyencode([Arg], State0) ->
    State1 = case Arg of
        "1"     -> State0#state{punyencode=true};
        "yes"   -> State0#state{punyencode=true};
        "yep"   -> State0#state{punyencode=true};
        "true"  -> State0#state{punyencode=true};
        "0"     -> State0#state{punyencode=false};
        "no"    -> State0#state{punyencode=false};
        "nope"  -> State0#state{punyencode=false};
        "false" -> State0#state{punyencode=false};
        _ -> error({punyencode, {invalid_argument, Arg}})
    end,
    {ok, State1};
directive_punyencode(_, _) ->
    error({punyencode, invalid_number_of_arguments}).


punyencode(Domain0, #state{punyencode=true}) ->
    {ok, Domain} = dnslib:punyencode(Domain0),
    Domain;
punyencode(Domain, _) ->
    Domain.


-spec compile_entry(proto_resource(), [line_part()], map()) -> {'ok', proto_resource()}.
compile_entry(Entry, [], _) ->
    {ok, Entry};
compile_entry(_, [{Value, quoted}|_], #state{startline=LineNumber,path=File}) ->
    error(syntax_error(File, LineNumber, {unexpected_quoted, Value}));
compile_entry(Entry = {_, _, undefined, _, _}, [Class0|Parts], State) ->
    Class1 = string:to_lower(Class0),
    try_class(Entry, [Class1|Parts], State);
compile_entry(Entry = {_, _, _, undefined, _}, [Ttl0|Parts], State) ->
    Ttl1 = string:to_lower(Ttl0),
    try_ttl(Entry, [Ttl1|Parts], State);
compile_entry(Entry = {_, undefined, _, _, _}, [Type0|Parts], State) ->
    Type1 = string:to_lower(Type0),
    try_type(Entry, [Type1|Parts], State).


try_class({Domain, Type, undefined, Ttl, Data}=Entry, Parts = [Token|Rest], State) ->
    case dnsclass:from_to(Token, masterfile_token, atom) of
        Token -> try_ttl(Entry, Parts, State);
        Class -> compile_entry({Domain, Type, Class, Ttl, Data}, Rest, State)
    end.


try_ttl(Entry = {Domain, Type, Class, undefined, Data}, Parts = [Ttl0|Rest], State = #state{startline=LineNumber,path=File}) ->
    case dnslib:list_to_ttl(resolve(Ttl0)) of
        {ok, Ttl1} -> compile_entry({Domain, Type, Class, Ttl1, Data}, Rest, State);
        {error, invalid_ttl} -> try_type(Entry, Parts, State);
        {error, {out_of_range, Value}} ->
            error(resource_record_error(File, LineNumber, {out_of_range, ttl, Ttl0, Value}))
    end;
try_ttl(Entry, Parts, State) ->
    try_type(Entry, Parts, State).


try_type({Domain, undefined, Class, Ttl, undefined}, [Type0|Rest], State = #state{startline=LineNumber,path=File}) ->
    case dnsrr:from_to(Type0, masterfile_token, module) of
        Type0 -> error(resource_record_error(File, LineNumber, {invalid_token, Type0}));
        Module ->
            Atom = dnsrr:from_to(Module, module, atom),
            case prepare_data(Rest, Module:masterfile_format(), State) of
                {ok, Data} ->
                    case Module:from_masterfile(Data) of
                        {ok, ResourceData} -> {ok, {Domain, Atom, Class, Ttl, ResourceData}};
                        {error, Reason}    -> error(resource_record_error(File, LineNumber, {invalid_data, Type0, Reason}))
                    end;
                {error, Reason = {unexpected_quoted, _}} -> error(syntax_error(File, LineNumber, Reason));
                {error, Reason = {invalid_integer, _}} -> error(syntax_error(File, LineNumber, Reason));
                {error, Reason = {invalid_ttl, _}} -> error(syntax_error(File, LineNumber, Reason));
                {error, Reason = {invalid_domain, _, _}} -> error(syntax_error(File, LineNumber, Reason));
                {error, Reason} -> error(resource_record_error(File, LineNumber, {invalid_data, Type0, Reason}))
            end
    end.


-spec complete_entry(proto_resource(), #state{}) -> {'ok', dnslib:resource()}.
complete_entry({_, _, undefined, _, _}, #state{prevclass=undefined,path=File,startline=LineNumber}) ->
    error(syntax_error(File, LineNumber, missing_class));
complete_entry({_, _, _, undefined, _}, #state{prevttl=undefined,defttl=undefined,path=File,startline=LineNumber}) ->
    error(syntax_error(File, LineNumber, missing_ttl));

complete_entry({Domain, Type, undefined, Ttl, Data}, State = #state{prevclass=Class}) ->
    complete_entry({Domain, Type, Class, Ttl, Data}, State);
complete_entry({_, _, EntryClass, _, _}, #state{prevclass=Class,path=File,startline=LineNumber})
when EntryClass =/= Class, Class =/= undefined ->
    error(syntax_error(File, LineNumber, class_mismatch));
complete_entry({Domain, Type, Class, undefined, Data}, State = #state{prevttl=Ttl,defttl=undefined}) ->
    complete_entry({Domain, Type, Class, Ttl, Data}, State);
complete_entry({Domain, Type, Class, undefined, Data}, State = #state{defttl=Ttl}) ->
    complete_entry({Domain, Type, Class, Ttl, Data}, State);
complete_entry(Entry, #state{}) ->
    {ok, Entry}.


-spec handle_entry_details(dnslib:domain(), [line_part()], #state{}) ->
    {'ok', #state{}} |
    {'error',
        'missing_class' |
        'missing_ttl'   |
        'missing_type'  |
        {'out_of_range', 'ttl', string(), integer()}                           |
        {'invalid_data', Reason :: term(), dnslib:resource_type(), [string()]} |
        {'unrecognized_type', string()}
    }.
handle_entry_details(Domain, Rest, State = #state{startline=LineNumber,path=File}) ->
    {ok, Entry0} = compile_entry({Domain, undefined, undefined, undefined, undefined}, Rest, State),
    case complete_entry(Entry0, State) of
        {ok, {_, undefined, _, _, _}} -> error(resource_record_error(File, LineNumber, missing_type));
        {ok, Entry} -> check_blacklist(Entry, State)
    end.

check_blacklist(Entry = {_, Type, _, _, _} , State = #state{startline=LineNumber,path=File,type_blacklist=BL}) ->
    case lists:member(Type, BL) of
        true -> error(resource_record_error(File, LineNumber, {type_blacklisted, Type}));
        false -> check_type_class_compatibility(Entry, State)
    end.


check_type_class_compatibility(Entry = {Domain, Type, Class, Ttl, _} , State0 = #state{records=Records,startline=LineNumber,path=File}) ->
    State1 = State0#state{records=[Entry|Records], prevdomain=Domain, prevclass=Class, prevttl=Ttl},
    Module = dnsrr:from_to(Type, atom, module),
    case
        case erlang:function_exported(Module, class, 0) of
            false -> ok;
            true ->
                case Module:class() of
                    Class -> ok;
                    List when is_list(List) ->
                        case lists:member(Type, List) of
                            true -> ok;
                            false -> error
                        end;
                    _ -> error
                end
        end
    of
        ok -> {ok, State1};
        error -> error(resource_record_error(File, LineNumber, invalid_class))
    end.


-type handle_entry_error() ::
    'no_previous_domain' |
    'at_no_origin'       |
    'no_origin'          |
    'quoted_domain'      |
    {'invalid_domain', term(), string()}  |
    {'directive_error', string(), term()} |
    {'unknown_directive', string()}.
-spec handle_entry([line_part()], #state{}) ->
    {'ok', #state{}} |
    {'error', handle_entry_error()}.
handle_entry([Cur = [$$|Directive0]|Rest], State = #state{directives=Directives,startline=LineNumber,path=File}) ->
    Directive1 = string:to_lower(Directive0),
    case maps:get(Directive1, Directives, undefined) of
        undefined -> error(directive_error(File, LineNumber, {unknown_directive, Cur}));
        Handler ->
            {Module, Func, Args} = case Handler of
                Handler when is_atom(Handler) -> {?MODULE, Handler, [Rest, State]};
                {M, F} -> {M, F, [Rest, State]};
                {M, F, A} ->
                    Tmp = lists:reverse(A),
                    {M, F, lists:reverse([State, Rest|Tmp])}
            end,
            Result = try
                apply(Module, Func, Args)
            catch
                error:DirectiveError -> error(directive_error(File, LineNumber, DirectiveError))
            end,
            {ok, _} = Result
    end;
handle_entry([""|_], #state{prevdomain=undefined,path=File,startline=LineNumber}) ->
    error(syntax_error(File, LineNumber, no_previous_domain));
handle_entry(["@"|_], #state{origin=undefined,path=File,startline=LineNumber}) ->
    error(syntax_error(File, LineNumber, at_no_origin));
handle_entry([{_, quoted}|_], #state{startline=LineNumber,path=File}) ->
    error(syntax_error(File, LineNumber, quoted_domain));
handle_entry([Domain0|Rest], State = #state{origin=Origin,prevdomain=PrevDomain,startline=LineNumber,path=File}) ->
    case Domain0 of
        "@" -> handle_entry_details(Origin, Rest, State);
        ""  -> handle_entry_details(PrevDomain, Rest, State);
        _ ->
            case dnslib:list_to_domain(Domain0) of
                {absolute, _, Result} -> handle_entry_details(punyencode(Result, State), Rest, State);
                {relative, _, _} when Origin =:= undefined -> error(syntax_error(File, LineNumber, relative_no_origin));
                {relative, _, Result} ->
                    case dnslib:concat(punyencode(Result, State), Origin) of
                        {ok, _, Fqdn} -> handle_entry_details(Fqdn, Rest, State);
                        {error, Reason} -> error(syntax_error(File, LineNumber, {invalid_domain, Reason, Domain0}))
                    end;
                {error, Reason} -> error(syntax_error(File, LineNumber, {invalid_domain, Reason, Domain0}))
            end
    end.


reverse_part({Part, quoted}) ->
    {lists:reverse(Part), quoted};
reverse_part(Part) ->
    lists:reverse(Part).


-type parse_entry_error() ::
    'escape_linebreak' |
    'numeric_escape'   |
    {'invalid_escape_integer', string()} |
    {'escape_out_of_range', integer()}.

% Token start/termination
line_end(State = #state{parentheses=true, entry_parts=Parts}) ->
    {partial, State#state{entry_parts=[[]|Parts]}};
line_end(State = #state{entry_parts=Parts0}) ->
    [First|Parts1] = lists:reverse(Parts0),
    State1 = State#state{entry_parts=[[]], fn=fun line_start/2},
    Parts2 = [Part || Part <- Parts1, Part =/= []],
    case [First|Parts2] of
        [[]] -> {empty, State1};
        Parts3 -> {complete, [reverse_part(TmpPart) || TmpPart <- Parts3], State1}
    end.


% Character collection
escape([C1, C2, C3|Tail], State = #state{entry_parts=[Latest|Parts], fn=Fn, path=File, startline=LineNumber})
when C1 >= $0, C1 =< $9 ->
    try list_to_integer([C1, C2, C3], 10) of
        Value when Value > 255 -> error(syntax_error(File, LineNumber, {escape_out_of_range, [$\\, C1, C2, C3]}));
        Value -> Fn(Tail, State#state{entry_parts=[[Value, $\\|Latest]|Parts]})
    catch
        error:badarg -> error(syntax_error(File, LineNumber, {invalid_escape_integer, [$\\, C1, C2, C3]}))
    end;
escape([Char|Tail], State = #state{entry_parts=[Latest|Parts], fn=Fn}) when Char > $9; Char < $0 ->
    Fn(Tail, State#state{entry_parts=[[Char, $\\|Latest]|Parts]}).


token([], State = #state{entry_parts=Parts}) ->
    line_end(State#state{entry_parts=[[]|Parts]});
token([$\n|Rest], State = #state{entry_parts=Parts}) ->
    whitespace(Rest, State#state{entry_parts=[[]|Parts]});
token([$\t|Rest], State = #state{entry_parts=Parts}) ->
    whitespace(Rest, State#state{entry_parts=[[]|Parts]});
token([$\s|Rest], State  = #state{entry_parts=Parts}) ->
    whitespace(Rest, State#state{entry_parts=[[]|Parts]});
token([$\\|Rest], State) ->
    escape(Rest, State#state{fn=fun token/2});
token([$;|_], State) ->
    line_end(State);
token([$), C|Rest], State) when C =:= $\s; C =:= $\t; C =:= $\n ->
    whitespace(Rest, State#state{parentheses=false});
token([$)], State) ->
    line_end(State#state{parentheses=false});
token([Char|Tail], State = #state{entry_parts=[Latest|Parts]}) ->
    token(Tail, State#state{entry_parts=[[Char|Latest]|Parts]}).


quoted([], State = #state{line_break=LB,entry_parts=[Latest0|Parts]}) ->
    Latest = case LB of
        LB when is_list(LB) -> lists:flatten([lists:reverse(LB), Latest0]);
        _ -> lists:flatten([LB, Latest0])
    end,
    {partial, State#state{entry_parts=[Latest|Parts],fn=fun quoted/2}};
quoted([$\n|Rest], State) ->
    quoted(Rest, State);
quoted([$", $"|_], #state{path=File,line=LineNumber}) ->
    error(syntax_error(File, LineNumber, no_whitespace_between_quoted));
quoted([$"|Rest], State = #state{entry_parts=[Quoted|Parts]}) ->
    whitespace(Rest, State#state{entry_parts=[[]|[{Quoted, quoted}|Parts]]});
quoted([$\\|Rest], State) ->
    escape(Rest, State#state{fn=fun quoted/2});
quoted([Char|Tail], State = #state{entry_parts=[Latest|Parts]}) ->
    quoted(Tail, State#state{entry_parts=[[Char|Latest]|Parts]}).


whitespace([], State) ->
    line_end(State#state{fn=fun whitespace/2});
whitespace([$\t|Rest], State) ->
    whitespace(Rest, State);
whitespace([$\s|Rest], State) ->
    whitespace(Rest, State);
whitespace([$"|Rest], State) ->
    quoted(Rest, State);
whitespace([$\n|Rest], State) ->
    whitespace(Rest, State);
whitespace([$(|Rest], State) ->
    token(Rest, State#state{parentheses=true});
whitespace([$)|Rest], State) ->
    token(Rest, State#state{parentheses=false});
whitespace([$;|_], State) ->
    line_end(State);
whitespace(Line, State) ->
    token(Line, State).


line_start([$\s|Rest], State = #state{entry_parts=Parts}) ->
    whitespace(Rest, State#state{entry_parts=[[]|Parts]});
line_start([$\t|Rest], State = #state{entry_parts=Parts}) ->
    whitespace(Rest, State#state{entry_parts=[[]|Parts]});
line_start(Line, State) ->
    token(Line, State).


parse_entry(Line, State = #state{fn=Fn}) ->
    Fn(Line, State).


-spec parse_file(Fd :: file:io_device(), State :: #state{}) ->
    {'ok', [dnslib:resource()]} |
    {'error',
        {'invalid_resource', integer(), handle_entry_error()} |
        {'parse_error', integer(), parse_entry_error()}       |
        {'unclosed_quote', integer()}                         |
        {'unclosed_parentheses', integer()}
    }.
parse_file(Fd, State) ->
    try get_line(Fd, State)
    catch
        error:{syntax_error,          File, LineNumber, Reason} -> {error, {syntax_error,          File, LineNumber, Reason}};
        error:{directive_error,       File, LineNumber, Reason} -> {error, {directive_error,       File, LineNumber, Reason}};
        error:{resource_record_error, File, LineNumber, Reason} -> {error, {resource_record_error, File, LineNumber, Reason}}
    end.


get_line(Fd, State = #state{max_line_length=MaxLen, line=LineNumber, path=File}) ->
    case io:get_line(Fd, "") of
        eof -> parse_line(eof, Fd, State);
        {error, _} -> error(error);
        Line when length(Line) > MaxLen -> error(syntax_error(File, LineNumber, {too_long_line, length(Line), MaxLen}));
        Line -> parse_line(Line, Fd, State)
    end.


parse_line(eof, _, State = #state{startline=LineNumber, path=File}) ->
    case parse_entry([], State) of
        {complete, Parts, State1} ->
            {ok, #state{records=Records}} = handle_entry(Parts, State1),
            {ok, lists:reverse(Records)};
        {empty, #state{records=Records}} ->
            {ok, lists:reverse(Records)};
        {partial, #state{parentheses=true}} ->
            error(syntax_error(File, LineNumber, unclosed_parentheses));
        {partial, #state{}} ->
            error(syntax_error(File, LineNumber, unclosed_quotes))
    end;
parse_line(Line, Fd, State = #state{line=LineNumber}) ->
    case parse_entry(Line, State) of
        {complete, Parts, State1} ->
            {ok, State2} = handle_entry(Parts, State1),
            get_line(Fd, State2#state{line=LineNumber+1, startline=LineNumber+1});
        {partial, State1} ->
            get_line(Fd, State1#state{line=LineNumber+1});
        {empty, State1} ->
            get_line(Fd, State1#state{line=LineNumber+1, startline=LineNumber+1})
    end.


%% @doc Get DNS resource records from a file.
%%
%% Intended to be analogous to file:consult/1.
%%
%% @end
-spec consult(Filename :: string()) -> {'ok', Resources :: [dnslib:resource()]}.
consult(Filename) ->
    consult(Filename, #state{}).


-type consult_opt() ::
    {'linebreak', string()}                                |
    {'directive', string(), 'false'}                       |
    {'type_blacklist', [dnslib:resource_type()]}           |
    {'type_blacklist', [dnslib:resource_type()], 'append'} |
    {'type_whitelist', [dnslib:resource_type()]}.
-spec consult
    (Filename :: string(), Options :: [consult_opt()]) -> {'ok', Resources :: [dnslib:resource()]} | {'error', ErrorSpec :: term()};
    (Filename :: string(), State :: #state{}) -> {'ok', Resources :: [dnslib:resource()]} | {'error', ErrorSpec :: term()}.
consult(Filename, Opts) when is_list(Opts) ->
    consult(Filename, prepare_state(#state{}, Opts));
consult(Filename, State = #state{}) ->
    case filename:pathtype(Filename) of
        absolute ->
            case file:open(Filename, [read, {encoding, latin1}]) of
                {ok, Fd} ->
                    Result = parse_file(Fd, State#state{path=Filename}),
                    ok = file:close(Fd),
                    Result;
                {error, eacces} -> {error, {file_error, eacces, Filename}};
                {error, enoent} -> {error, {file_error, enoent, Filename}};
                {error, eisdir} -> {error, {file_error, eisdir, Filename}}
            end;
        _ -> consult(filename:absname(Filename), State)
    end.


prepare_state(State = #state{}, []) ->
    State;
prepare_state(State = #state{}, [{line_break, Str}|Rest]) when is_list(Str) ->
    prepare_state(State#state{line_break=Str}, Rest);
prepare_state(State = #state{}, [{class, Class}|Rest]) when is_atom(Class) ->
    true = dnslib:is_valid_resource_class(Class),
    prepare_state(State#state{prevclass=Class}, Rest);
prepare_state(State = #state{directives=Directives0}, [{directive, Str, false}|Rest]) when is_list(Str) ->
    Directives1 = maps:remove(string:to_lower(Str), Directives0),
    prepare_state(State#state{directives=Directives1}, Rest);
prepare_state(State = #state{type_blacklist=BL}, [{type_blacklist, List = [Atom|_], append}|Rest]) when is_atom(Atom) ->
    prepare_state(State#state{type_blacklist=lists:flatten([BL, List])}, Rest);
prepare_state(State = #state{}, [{type_blacklist, List = [Atom|_]}|Rest]) when is_atom(Atom) ->
    prepare_state(State#state{type_blacklist=List}, Rest);
prepare_state(State = #state{type_blacklist=BL0}, [{type_whitelist, List = [Atom|_]}|Rest]) when is_atom(Atom) ->
    BL1 = [Type || Type <- List, not lists:member(Type, BL0)],
    prepare_state(State#state{type_blacklist=BL1}, Rest);
prepare_state(State = #state{}, [{domain, Domain}|Rest]) ->
    {true, _} = dnslib:is_valid_domain(Domain),
    prepare_state(State#state{prevdomain=Domain}, Rest);
prepare_state(State = #state{}, [{origin, Domain}|Rest]) ->
    {true, false} = dnslib:is_valid_domain(Domain),
    prepare_state(State#state{origin=Domain}, Rest);
prepare_state(State = #state{}, [{ttl, Ttl}|Rest]) when is_integer(Ttl), Ttl >= 0, Ttl =< ?MAX_TTL ->
    prepare_state(State#state{prevttl=Ttl,defttl=Ttl}, Rest);
prepare_state(State = #state{}, [{max_line_length, Len}|Rest]) ->
    prepare_state(State#state{max_line_length=Len}, Rest).


%%
%% Output
%%


escape_text(Txt) ->
    escape_text(Txt, []).

escape_text(<<>>, Acc) ->
    lists:reverse(Acc);
escape_text(<<C, Rest/binary>>, Acc) ->
    escape_text(Rest, escape_char(C, Acc));
escape_text([], Acc) ->
    lists:reverse(Acc);
escape_text([C|Rest], Acc) ->
    escape_text(Rest, escape_char(C, Acc)).

escape_char($@, Acc) ->
    [$@, $\\|Acc];
escape_char($(, Acc) ->
    [$(, $\\|Acc];
escape_char($), Acc) ->
    [$), $\\|Acc];
escape_char($", Acc) ->
    [$", $\\|Acc];
escape_char($;, Acc) ->
    [$;, $\\|Acc];
escape_char($\\, Acc) ->
    [$\\, $\\|Acc];
escape_char(C, Acc) when C < $!; C > $~ ->
    lists:foldl(fun (FunChar, FunAcc) -> [FunChar|FunAcc] end, [$\\|Acc], io_lib:format("~3..0B", [C]));
escape_char(C, Acc) ->
    [C|Acc].


indicate_domain(Domain) ->
    {domain, Domain}.


write_resources(Filename, Rrs) ->
    write_resources(Filename, Rrs, #{}).


write_resources(Filename, Rrs, _Opts) ->
    % Make sure that each record has the same class
    % Order records (SOA first)
    %
    % Directives exist to optimize master files for readability and
    % shortness of expression
    %
    % If optimizations haven't been disabled, run through the resource records,
    % introducing directives and mangling Resource record data as necessary
    % to produce a shorter file
    {ok, Fd} = file:open(Filename, [write, binary]),
    ok = write_resource(Rrs, Fd, #{}),
    ok = file:close(Fd).


write_resource([], _, _) ->
    ok;
write_resource([{iodata, Line}|Rest], Fd, Map) ->
    ok = file:write(Fd, [Line, $\n]),
    write_resource(Rest, Fd, Map);
write_resource([{Domain, Type, Class, Ttl, Data}|Rest], Fd, Map) ->
    Iodata = [
        dnslib:domain_to_list(Domain),
        $\t,
        string:to_upper(dnsclass:from_to(Class, atom, masterfile_token)),
        $\t,
        integer_to_list(Ttl),
        $\t,
        string:to_upper(dnsrr:from_to(Type, atom, masterfile_token)),
        $\t,
        resource_data_to_io(Type, Data, Map)
    ],
    case Rest of
        [] -> ok = file:write(Fd, Iodata);
        _  -> ok = file:write(Fd, [Iodata, $\n])
    end,
    write_resource(Rest, Fd, Map).


resource_data_to_io(Type, Data, _) ->
    Module = dnsrr:from_to(Type, atom, module),
    List = Module:to_masterfile(Data),
    Fn = fun
        ({domain, Domain}, Acc) -> [$ , dnslib:domain_to_list(Domain)|Acc];
        (Value, Acc) -> [$ , Value|Acc]
    end,
    [_|Ret] = lists:foldl(Fn, [], List),
    lists:reverse(Ret).
