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
% This this file implements reading and parsing of DNS files.
-module(dnsfile).

-export([
    consult/1,
    consult/2,
    foldl/3,
    foldl/4,
    is_valid/1,
    is_valid/2,
    iterate_begin/1,
    iterate_begin/2,
    iterate_next/1,
    iterate_end/1,
    parse_resource/1,
    write_resources/2,
    write_resources/3,
    directive_origin/2,
    directive_include/2,
    directive_punyencode/2,
    directive_reverse_dns_pointer/2,
    directive_ttl/2,
    to_masterfile_escape_text/1,
    indicate_domain/1
]).

-include_lib("dnslib/include/dnslib.hrl").

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

-include("include/pre_otp20_string_macro.hrl").

-type proto_resource() ::
    {
        dnslib:domain(),
        dnsrr:type()     | 'undefined',
        dnsclass:class() | 'undefined',
        dnslib:ttl()     | 'undefined',
        term()           | 'undefined'
    }.

-type line_part() :: string() | {string(), 'quoted'}.

% Split static configuration fields from state?
-record(state, {
    encoding=unicode :: unicode:encoding(),
    text_encoding=unicode :: unicode:encoding(),
    max_line_length=1024 :: pos_integer(),
    line=1 :: pos_integer(),
    startline=1 :: pos_integer(),
    fn=fun line_start/2    :: function(),
    parentheses=false      :: boolean(),
    entry_parts=[[]]       :: [line_part()],
    path                   :: string()         | 'undefined',
    origin                 :: dnslib:domain()  | 'undefined',
    origin_str             :: string()         | 'undefined',
    prevdomain             :: dnslib:domain()  | 'undefined',
    prevclass={assume, in} :: dnsclass:class() | {'assume', 'in'} | 'undefined',
    prevttl                :: dnslib:ttl()     | 'undefined',
    defttl                 :: dnslib:ttl()     | 'undefined',
    include_depth=3        :: non_neg_integer(),
    included_from=[]       :: [string()],
    punyencode=false       :: boolean(),
    allow_unknown_resources=false :: boolean(),
    allow_unknown_classes=false   :: boolean(),
    reverse_dns_pointer=false :: boolean() | 'inet' | 'inet6',
    'allow_@'=true :: boolean(),
    mode=consult   :: 'consult' | 'foldl' | 'foreach',
    mode_state=[]  :: term(), % Keep foldl acc&fun and/or consult resources here...
    directives=#{
        "origin"              => directive_origin,
        "ttl"                 => directive_ttl,
        "include"             => directive_include,
        "punyencode"          => directive_punyencode,
        "reverse-dns-pointer" => directive_reverse_dns_pointer
    } :: #{string() => atom()},
    type_blacklist = [] :: [dnsrr:type()],
    line_break="\n" :: string()
}).


resolve(Str) when is_list(Str) ->
    resolve(Str, []).

resolve([], Acc) ->
	lists:reverse(Acc);
resolve([$\\, {integer, C1}|Tail], Acc) ->
    resolve(Tail, [C1|Acc]);
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

foldl_error(Class, Reason, Stacktrace) ->
    {foldl_error, Class, Reason, Stacktrace}.


-type prepare_data_error() ::
    'too_few_arguments'  |
    'too_many_arguments' |
    'too_long_text_data' |
    'no_origin'          |
    'configuration_disallows_@'                                        |
    {'unexpected_quoted', string()}                                    |
    {'out_of_range', 'uint16' | 'uint32' | 'ttl', string(), integer()} |
    {'invalid_domain', dnslib:list_to_domain_error(), string()}        |
    {'invalid_integer', string()}                                      |
    {'invalid_ttl', string()}.
-spec prepare_data([line_part()], [dnsrr:masterfile_format_type() | non_neg_integer()], #state{}) ->
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
prepare_data(["@"|_], _, #state{'allow_@'=false}, _) ->
    {error, 'configuration_disallows_@'};
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
    case prepare_data_text_to_bytelist(Txt, State) of
        {error, _}=Tuple -> Tuple;
        Result -> prepare_data(RestData, prepare_data_next_type(Types), State, [Result|Acc])
    end;
prepare_data([_|_], [qtext|_], _, _) ->
    {error, unquoted_text};
prepare_data([Txt|_], [text|_], _, _) when length(Txt) > 255 ->
    {error, too_long_text_data};
prepare_data(["@"|_], [Txt|_], #state{origin = undefined}, _)
when Txt =:= text; Txt =:= text_unlimited ->
    {error, at_no_origin};
prepare_data(["@"|RestData], Types = [Txt|_], State = #state{origin_str = Origin}, Acc)
when Txt =:= text; Txt =:= text_unlimited ->
    case prepare_data_text_to_bytelist(Origin, State) of
        {error, _}=Tuple -> Tuple;
        Result -> prepare_data(RestData, prepare_data_next_type(Types), State, [Result|Acc])
    end;
prepare_data([Txt|RestData], Types = [TxtType|_], State, Acc)
when TxtType =:= text; TxtType =:= text_unlimited ->
    case prepare_data_text_to_bytelist(Txt, State) of
        {error, _}=Tuple -> Tuple;
        Result -> prepare_data(RestData, prepare_data_next_type(Types), State, [Result|Acc])
    end;

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
prepare_data(["@"|_], [domain|_], #state{origin=undefined}, _) ->
    {error, at_no_origin};
prepare_data(["@"|RestData], Types = [domain|_], State = #state{origin = Origin}, Acc) ->
    prepare_data(RestData, prepare_data_next_type(Types), State, [Origin|Acc]);
prepare_data([Cur|RestData], Types = [domain|_], State = #state{origin = Origin}, Acc) ->
    case dnslib:list_to_codepoint_domain(Cur) of
        {ok, _, _, ['_'|_]} -> {error, {wildcard_domain, Cur}};
        % Return an error on non-ASCII characters unless there is a pipeline for handling them...
        {ok, absolute, _, Domain0} ->
            {ok, Domain1} = dnslib:codepoint_domain_to_domain(punyencode(Domain0, State)),
            prepare_data(RestData, prepare_data_next_type(Types), State, [Domain1|Acc]);
        {ok, relative, _, _} when Origin =:= undefined -> {error, relative_no_origin};
        {ok, relative, _, Domain0} ->
            {ok, Domain1} = dnslib:codepoint_domain_to_domain(punyencode(Domain0, State)),
            case dnslib:append_domain(Domain1, Origin) of
                {ok, ['_'|_]=Fqdn} -> {error, {wildcard_domain, dnslib:domain_to_list(Fqdn)}};
                {ok, Fqdn} -> prepare_data(RestData, prepare_data_next_type(Types), State, [Fqdn|Acc]);
                {error, Reason} -> {error, {invalid_domain, Reason, Cur}}
            end;
        {error, DomainError} ->
            {error, {invalid_domain, DomainError, Cur}}
    end.


text_to_bytelist_splitwith_encode_fun(Char) -> Char =/= $\\.

text_to_bytelist_splitwith_encode([], Acc, _, _) ->
    Acc;
text_to_bytelist_splitwith_encode(Text, Acc, Encoding, TextEncoding) ->
    {Head, Tail0} = lists:splitwith(fun text_to_bytelist_splitwith_encode_fun/1, Text),
    HeadBin = unicode:characters_to_binary(Head, Encoding, TextEncoding),
    case Tail0 of
        [$\\, {integer, Char}|Tail1] ->
            text_to_bytelist_splitwith_encode(Tail1, <<Acc/binary, HeadBin/binary, Char>>, Encoding, TextEncoding);
        [$\\, Char|Tail1] ->
            text_to_bytelist_splitwith_encode([Char|Tail1], <<Acc/binary, HeadBin/binary>>, Encoding, TextEncoding);
        [] -> text_to_bytelist_splitwith_encode(Tail0, <<Acc/binary, HeadBin/binary>>, Encoding, TextEncoding)
    end.


-spec prepare_data_text_to_bytelist(list(), #state{}) -> {error, text_too_long} | list().
prepare_data_text_to_bytelist(Txt, #state{text_encoding=TextEncoding,encoding=Encoding}) ->
    Bin = text_to_bytelist_splitwith_encode(Txt, <<>>, Encoding, TextEncoding),
    if
        byte_size(Bin) > 255 -> {error, text_too_long};
        true -> binary_to_list(Bin)
    end.


prepare_data_next_type([Cur, '...'|Rest]) ->
    [Cur, 1|Rest];
prepare_data_next_type([Cur, Count|Rest]) when is_integer(Count) ->
    [Cur, Count+1|Rest];
prepare_data_next_type([_|Type]) ->
    Type.


-spec directive_origin([string()], #state{}) -> {'ok', #state{}} | no_return().
directive_origin([Origin0], State) ->
    case dnslib:list_to_codepoint_domain(Origin0) of
        {ok, relative, _, _} -> error(relative_origin);
        {ok, absolute, _, Origin1} ->
            {ok, Origin2} = dnslib:codepoint_domain_to_domain(punyencode(Origin1, State)),
            {ok, State#state{origin=Origin2, origin_str=Origin0}};
        {error, Reason} -> error({invalid_domain, Reason, Origin0})
    end;
directive_origin([], _) ->
    error(no_arguments).


-spec directive_ttl([string()], #state{}) -> {'ok', #state{}} | no_return().
directive_ttl([Ttl], State) ->
    case dnslib:list_to_ttl(resolve(Ttl)) of
        {ok, Ttl1} -> {ok, State#state{defttl=Ttl1, prevttl=Ttl1}};
        {error, Reason} -> error(Reason)
    end;
directive_ttl([], _) ->
    error(no_arguments).


% Remember to verify the include depth
-spec directive_include([string()], #state{}) -> {'ok', #state{}} | no_return().
directive_include(_, #state{include_depth=0}) ->
    error(include_depth);
directive_include([_, {Value, quoted}], #state{}) ->
    error({unexpected_quoted, Value});
directive_include([{File0, quoted}, NewOrigin], State = #state{}) ->
    directive_include([File0, NewOrigin], State);
directive_include([File0, NewOrigin], State = #state{origin=Origin,origin_str=OriginStr}) ->
    case dnslib:list_to_codepoint_domain(NewOrigin) of
        {ok, absolute, _, NewOrigin1} ->
            {ok, NewOrigin2} = dnslib:codepoint_domain_to_domain(punyencode(NewOrigin1, State)),
            directive_include(File0, NewOrigin2, NewOrigin, State);
        {ok, relative, _, _} when Origin =:= undefined -> error(missing_origin);
        {ok, relative, _, NewOrigin1} ->
            {ok, NewOrigin2} = dnslib:codepoint_domain_to_domain(punyencode(NewOrigin1, State)),
            case dnslib:append_domain(NewOrigin2, Origin) of
                {ok, Fqdn} -> directive_include(File0, Fqdn, lists:append(NewOrigin, [$.|OriginStr]), State);
                {error, Reason} -> error({invalid_domain, Reason, NewOrigin})
            end;
        {error, Reason} -> error({invalid_domain, Reason, NewOrigin})
    end;
directive_include([{File0, quoted}], State) ->
    directive_include([File0], State);
directive_include([File0], State = #state{origin=Origin,origin_str=OriginStr}) ->
    directive_include(File0, Origin, OriginStr, State);
directive_include([], _) ->
    error(no_arguments).


directive_include(Path0, Origin, OriginStr, State = #state{path=PrevPath,include_depth=Depth,included_from=IncludedFrom,mode=Mode}) ->
    Path = resolve(Path0),
    File = case filename:pathtype(Path) of
        absolute -> Path;
        _ -> filename:join(filename:dirname(PrevPath), Path)
    end,
    TmpState = State#state{
        origin=Origin,
        origin_str=OriginStr,
        line=1,
        startline=1,
        fn=fun line_start/2,
        parentheses=false,
        entry_parts=[[]],
        path=File,
        include_depth=Depth-1,
        included_from=[PrevPath|IncludedFrom]
    },
    case consult_file(File, TmpState) of
        {ok, NewRecords} when Mode =:= consult -> {ok, State#state{mode_state=lists:reverse(NewRecords)}};
        {ok, NewAcc} when Mode =:= foldl ->
            #state{mode_state={Fun, _}} = State,
            {ok, State#state{mode_state={Fun, NewAcc}}};
        {error, Reason} -> error({include_error, Reason})
    end.


list_to_boolean(List) ->
    case List of
        "1"     -> true;
        "yes"   -> true;
        "yep"   -> true;
        "yup"   -> true;
        "yay"   -> true;
        "true"  -> true;
        "0"     -> false;
        "no"    -> false;
        "nope"  -> false;
        "nay"   -> false;
        "false" -> false;
        _ -> error
    end.


directive_punyencode([Arg], State) ->
    case list_to_boolean(string:(?LOWER)(Arg)) of
        error -> error({punyencode, {invalid_argument, Arg}});
        Boolean -> {ok, State#state{punyencode=Boolean}}
    end;
directive_punyencode(_, _) ->
    error({punyencode, invalid_number_of_arguments}).


% Should be a more generalizable 'encode_high' type thingy...
punyencode(Domain0, #state{punyencode=true}) ->
    {ok, Domain} = dnslib:punyencode(Domain0),
    Domain;
punyencode(Domain, _) ->
    Domain.


directive_reverse_dns_pointer([Arg0], State) ->
    Arg = string:(?LOWER)(Arg0),
    case list_to_boolean(Arg) of
        error when Arg =:= "inet" -> {ok, State#state{reverse_dns_pointer=inet}};
        error when Arg =:= "inet6" -> {ok, State#state{reverse_dns_pointer=inet6}};
        error -> error({reverse_dns_pointer, {invalid_argument, Arg0}});
        Boolean -> {ok, State#state{reverse_dns_pointer=Boolean}}
    end;
directive_reverse_dns_pointer(_, _) ->
    error({reverse_dns_pointer, invalid_number_of_arguments}).



handle_unknown_resource_data([]) ->
    {error, no_data};
handle_unknown_resource_data([[$\\, $#], BytesList|HexValues]) ->
    try list_to_integer(BytesList) of
        Bytes when Bytes >= 0, Bytes =< 16#FFFF ->
            case lists:all(fun (FunStr) -> length(FunStr) rem 2 =:= 0 end, HexValues) of
                false -> {error, invalid_resource_data};
                true ->
                    try transform_unknown_resource_data(lists:append(HexValues), Bytes, <<>>) of
                        {ok, _}=Tuple -> Tuple;
                        {error, _}=Tuple -> Tuple
                    catch
                        error:function_clause -> {error, invalid_resource_data}
                    end
            end;
        Bytes -> {error, {data_too_long, Bytes}}
    catch
        error:badarg -> {error, {bad_data_length, BytesList}}
    end;
handle_unknown_resource_data([Token|_]) ->
    {error, {invalid_unknown_resource_start_token, Token}}.


transform_unknown_resource_data([], 0, Acc) ->
    {ok, Acc};
transform_unknown_resource_data([], _, _) ->
    {error, partial_resource_data};
transform_unknown_resource_data([_], 1, _) ->
    {error, missing_resource_data_nibble};
transform_unknown_resource_data([C1, C2|Rest], Count, Acc) ->
    Byte = (transform_unknown_resource_data_hex_to_integer(C1) bsl 4) bor transform_unknown_resource_data_hex_to_integer(C2),
    transform_unknown_resource_data(Rest, Count-1, <<Acc/binary, Byte>>).


transform_unknown_resource_data_hex_to_integer(C) when C >= $0, C =< $9 ->
    C - $0;
transform_unknown_resource_data_hex_to_integer(C) when C >= $a, C =< $f ->
    C - ($a - 10);
transform_unknown_resource_data_hex_to_integer(C) when C >= $A, C =< $F ->
    C - ($A - 10).



-spec compile_entry(proto_resource(), [line_part()], #state{}) -> {'ok', proto_resource()}.
compile_entry(Entry, [], _) ->
    {ok, Entry};
compile_entry(_, [{Value, quoted}|_], #state{startline=LineNumber,path=File}) ->
    error(syntax_error(File, LineNumber, {unexpected_quoted, Value}));
compile_entry(Entry = {_, _, undefined, _, _}, [Class0|Parts], State) ->
    Class1 = string:(?LOWER)(Class0),
    try_class(Entry, [Class1|Parts], State);
compile_entry(Entry = {_, _, _, undefined, _}, [Ttl0|Parts], State) ->
    Ttl1 = string:(?LOWER)(Ttl0),
    try_ttl(Entry, [Ttl1|Parts], State);
compile_entry(Entry = {_, undefined, _, _, _}, [Type0|Parts], State) ->
    Type1 = string:(?LOWER)(Type0),
    try_type(Entry, [Type1|Parts], State).


try_class({Domain, Type, undefined, Ttl, Data}=Entry, Parts = [[$c,$l,$a,$s,$s|ClassNumber]|Rest], State = #state{startline=LineNumber,path=File,allow_unknown_classes=AllowUnknown}) ->
    try list_to_integer(ClassNumber) of
        Value when Value >= 0, Value < 16#FFFF ->
            case dnsclass:from_to(Value, value, atom) of
                Value when AllowUnknown -> compile_entry({Domain, Type, Value, Ttl, Data}, Rest, State);
                Value -> error(syntax_error(File, LineNumber, {unknown_class, Value}));
                Atom -> compile_entry({Domain, Type, Atom, Ttl, Data}, Rest, State)
            end;
        Value -> error(syntax_error(File, LineNumber, {class_out_of_range, Value}))
    catch
        error:badarg -> try_ttl(Entry, Parts, State)
    end;
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


% Why is try_type here twice?
try_type({Domain, undefined, Class, Ttl, undefined}=Tuple, [[$t,$y,$p,$e|TypeValue]|Rest], State = #state{startline=LineNumber,path=File,allow_unknown_resources=AllowUnknown}) ->
    try list_to_integer(TypeValue) of
        Type when Type >= 0, Type < 16#FFFF ->
            case dnsrr:from_to(Type, value, module) of
                Type when AllowUnknown ->
                    case handle_unknown_resource_data(Rest) of
                        {ok, Data} -> {ok, {Domain, Type, Class, Ttl, Data}};
                        {error, Reason} -> error(syntax_error(File, LineNumber, {invalid_unknown_resource, Reason}))
                    end;
                Type -> error(syntax_error(File, LineNumber, {unknown_resource_type, Type}));
                Module when is_atom(Module) ->
                    % If we know that resource, use Module:from_binary to produce internal resource representation
                    % If the data contains domain compressions, produce error
                    Atom = dnsrr:from_to(Module, module, atom),
                    case Rest of
                        [[$\\, $#]|_] ->
                            case handle_unknown_resource_data(Rest) of
                                {ok, Data} ->
                                    try Module:from_binary(Data) of
                                        {ok, Rdata} -> {ok, {Domain, Atom, Class, Ttl, Rdata}};
                                        {error, Reason} -> error(resource_record_error(File, LineNumber, Reason));
                                        {domains, DataList} ->
                                            case [GenTuple || GenTuple <- DataList, is_tuple(GenTuple), element(1, GenTuple) =:= compressed] of
                                                [] ->
                                                    Fn = fun
                                                        ({domain, FunDomain, _}) -> FunDomain;
                                                        (FunMember) -> FunMember
                                                    end,
                                                    Rdata = dnswire:finalize_resource_data([Fn(GenMember) || GenMember <- DataList], Module),
                                                    {ok, {Domain, Atom, Class, Ttl, Rdata}};
                                                _ -> error(resource_record_error(File, LineNumber, resource_contains_domain_compressions))
                                            end
                                    catch
                                        error:function_clause -> error(resource_record_error(File, LineNumber, invalid_data))
                                    end;
                                {error, Reason} -> error(syntax_error(File, LineNumber, {invalid_unknown_resource, Reason}))
                            end;
                        _ -> try_type(Tuple, [Module:masterfile_token()|Rest], State)
                    end
            end;
        Type -> error(syntax_error(File, LineNumber, {type_value_out_of_range, Type}))
    catch
        error:badarg -> error(syntax_error(File, LineNumber, {invalid_type_value, TypeValue}))
    end;
try_type({Domain, undefined, Class, Ttl, undefined}, [Type0|Rest], State = #state{startline=LineNumber,path=File}) ->
    case dnsrr:from_to(Type0, masterfile_token, module) of
        Type0 -> error(resource_record_error(File, LineNumber, {invalid_token, Type0}));
        Module ->
            Atom = dnsrr:from_to(Module, module, atom),
            case Rest of
                [[$\\, $#]|_] ->
                    case handle_unknown_resource_data(Rest) of
                        {ok, Data} ->
                            try Module:from_binary(Data) of
                                {ok, Rdata} -> {ok, {Domain, Atom, Class, Ttl, Rdata}};
                                {error, Reason} -> error(resource_record_error(File, LineNumber, {invalid_data, Type0, Reason}));
                                {domains, DataList} ->
                                    case [GenTuple || GenTuple <- DataList, is_tuple(GenTuple), element(1, GenTuple) =:= compressed] of
                                        [] ->
                                            Fn = fun
                                                ({domain, FunDomain, _}) -> FunDomain;
                                                (FunMember) -> FunMember
                                            end,
                                            Rdata = dnswire:finalize_resource_data([Fn(GenMember) || GenMember <- DataList], Module),
                                            {ok, {Domain, Atom, Class, Ttl, Rdata}};
                                        _ -> error(resource_record_error(File, LineNumber, resource_contains_domain_compressions))
                                    end
                            catch
                                error:function_clause -> error(resource_record_error(File, LineNumber, invalid_data))
                            end;
                        {error, Reason} -> error(syntax_error(File, LineNumber, {invalid_unknown_resource, Reason}))
                    end;
                _ ->
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
            end
    end.


-spec complete_entry(proto_resource(), #state{}) -> {'ok', dnslib:resource()}.
complete_entry({_, _, undefined, _, _}, #state{prevclass=undefined,path=File,startline=LineNumber}) ->
    error(syntax_error(File, LineNumber, missing_class));
complete_entry({_, _, undefined, _, _}=RR, State = #state{prevclass={assume, Class}}) ->
    complete_entry(setelement(3, RR, Class), State#state{prevclass=Class});
complete_entry({_, _, undefined, _, _}=RR, State = #state{prevclass=Class}) ->
    complete_entry(setelement(3, RR, Class), State);
complete_entry({_, _, _, undefined, _}, #state{prevttl=undefined,defttl=undefined,path=File,startline=LineNumber}) ->
    error(syntax_error(File, LineNumber, missing_ttl));

complete_entry({Domain, Type, undefined, Ttl, Data}, State = #state{prevclass=Class}) ->
    complete_entry({Domain, Type, Class, Ttl, Data}, State);
complete_entry({_, _, EntryClass, _, _}=RR, State = #state{prevclass={assume, _}}) ->
    complete_entry(RR, State#state{prevclass=EntryClass});
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


check_type_class_compatibility(Entry = {_, Type, _, _, _}, State) when is_integer(Type) ->
    entry_done(Entry, State);
check_type_class_compatibility(Entry = {Domain, Type, Class, Ttl, _}, State = #state{startline=LineNumber,path=File}) ->
    case dnsrr:class_valid_for_type(Class, Type) of
        false -> error(resource_record_error(File, LineNumber, invalid_class));
        true -> create_reverse_dns_pointer(Entry, State)
    end.


create_reverse_dns_pointer(Entry, State = #state{reverse_dns_pointer=false}) ->
    entry_done(Entry, State).
%create_reverse_dns_pointer({Domain, a, _, Ttl, Address}, State = #state{reverse_dns_pointer=CreatePointer,records=Records})
%when CreatePointer =:= inet; CreatePointer =:= true ->
%    Pointer = {dnslib:reverse_dns_domain(Address), ptr, in, Ttl, Domain}, % A can only have class IN
%    {ok, State#state{records=[Pointer|Records]}};
%create_reverse_dns_pointer({Domain, aaaa, _, Ttl, Address}, State = #state{reverse_dns_pointer=CreatePointer,records=Records})
%when CreatePointer =:= inet6; CreatePointer =:= true ->
%    Pointer = {dnslib:reverse_dns_domain(Address), ptr, in, Ttl, Domain}, % AAAA can only have class IN
%    {ok, State#state{records=[Pointer|Records]}}.


-ifdef(OTP_RELEASE).
entry_done(Entry = {Domain, _, Class, Ttl, _}, State0 = #state{mode=consult, mode_state=Records}) ->
    {ok, State0#state{mode_state=[Entry|Records], prevdomain=Domain, prevclass=Class, prevttl=Ttl}};
entry_done(Entry = {Domain, _, Class, Ttl, _}, State0 = #state{mode=foldl, mode_state={Fun, Acc0}}) ->
    try Fun(Entry, Acc0) of
        Acc1 -> {ok, State0#state{mode_state={Fun, Acc1}, prevdomain=Domain, prevclass=Class, prevttl=Ttl}}
    catch
        CatchClass:Reason:Stacktrace -> error(foldl_error(CatchClass, Reason, Stacktrace))
    end.
-else.
entry_done(Entry = {Domain, _, Class, Ttl, _}, State0 = #state{mode=consult, mode_state=Records}) ->
    {ok, State0#state{mode_state=[Entry|Records], prevdomain=Domain, prevclass=Class, prevttl=Ttl}};
entry_done(Entry = {Domain, _, Class, Ttl, _}, State0 = #state{mode=foldl, mode_state={Fun, Acc0}}) ->
    try Fun(Entry, Acc0) of
        Acc1 -> {ok, State0#state{mode_state={Fun, Acc1}, prevdomain=Domain, prevclass=Class, prevttl=Ttl}}
    catch
        CatchClass:Reason -> error(foldl_error(CatchClass, Reason, erlang:get_stacktrace()))
    end.
-endif.


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
    Directive1 = string:(?LOWER)(Directive0),
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
handle_entry([Domain0|Rest], State = #state{origin=Origin,prevdomain=PrevDomain,startline=LineNumber,path=File,'allow_@'=AllowAt}) ->
    case Domain0 of
        "@" when not AllowAt -> error(syntax_error(File, LineNumber, 'configuration_disallows_@'));
        "@" -> handle_entry_details(Origin, Rest, State);
        ""  -> handle_entry_details(PrevDomain, Rest, State);
        _ ->
            case dnslib:list_to_codepoint_domain(Domain0) of
                {ok, absolute, _, Result0} ->
                    {ok, Result1} = dnslib:codepoint_domain_to_domain(punyencode(Result0, State)),
                    handle_entry_details(Result1, Rest, State);
                {ok, relative, _, _} when Origin =:= undefined -> error(syntax_error(File, LineNumber, relative_no_origin));
                {ok, relative, _, Result0} ->
                    {ok, Result1} = dnslib:codepoint_domain_to_domain(punyencode(Result0, State)),
                    case dnslib:append_domain(Result1, Origin) of
                        {ok, Fqdn} -> handle_entry_details(Fqdn, Rest, State);
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
        Value -> Fn(Tail, State#state{entry_parts=[[{integer, Value}, $\\|Latest]|Parts]})
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
    Latest = lists:flatten([lists:reverse(LB), Latest0]),
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


parse_resource(Line) ->
    parse_resource(Line, []).

parse_resource(Line, _Opts) when is_list(_Opts) ->
    % We should also somehow disallow @ -replacement
    % and return an error on non-ASCII characters (in domains).
    State = #state{
        text_encoding=unicode,
        'allow_@'=false,
        path="fun parse_entry/1",
        origin_str=".",
        origin=[],
        directives=#{}
    },
    % What if Line contains a newline?
    try parse_entry(Line, State) of
        {complete, Parts, State1} ->
            try handle_entry(Parts, State1) of
                {ok, #state{mode_state=[Record]}} -> {ok, Record}
            catch
                error:Reason -> {error, Reason}
            end;
        {empty, _} -> {error, empty};
        {partial, _} -> {error, partial}
    catch
        error:Reason -> {error, Reason}
    end.


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
parse_file(Fd, State0) ->
    try get_line(Fd, State0) of
        {eof, State1} -> {ok, parse_file_done(State1)};
        {_, State1} -> parse_file(Fd, State1)
    catch
        error:{foldl_error, Class, Reason, Stacktrace}          -> {error, {foldl_error, Class, Reason, Stacktrace}};
        error:{syntax_error,          File, LineNumber, Reason} -> {error, {syntax_error,          File, LineNumber, Reason}};
        error:{directive_error,       File, LineNumber, Reason} -> {error, {directive_error,       File, LineNumber, Reason}};
        error:{resource_record_error, File, LineNumber, Reason} -> {error, {resource_record_error, File, LineNumber, Reason}}
    end.


get_line(Fd, State = #state{max_line_length=MaxLen, line=LineNumber, path=File}) ->
    case io:get_line(Fd, "") of
        {error, _} -> error(error);
        Line when is_list(Line), length(Line) > MaxLen -> error(syntax_error(File, LineNumber, {too_long_line, length(Line), MaxLen}));
        Line -> parse_line(Line, State)
    end.


parse_line(eof, State = #state{startline=LineNumber, path=File}) ->
    case parse_entry([], State) of
        {complete, Parts, State1} ->
            {ok, State2} = handle_entry(Parts, State1),
            {eof, State2};
        {empty, State2} ->
            {eof, State2};
        {partial, #state{parentheses=true}} ->
            error(syntax_error(File, LineNumber, unclosed_parentheses));
        {partial, #state{}} ->
            error(syntax_error(File, LineNumber, unclosed_quotes))
    end;
parse_line(Line, State = #state{line=LineNumber}) ->
    case parse_entry(Line, State) of
        {partial, State1} -> {partial, State1#state{line=LineNumber+1}};
        {empty, State1} -> {empty, State1#state{line=LineNumber+1, startline=LineNumber+1}};
        {complete, Parts, State1} ->
            {ok, State2} = handle_entry(Parts, State1),
            {complete, State2#state{line=LineNumber+1, startline=LineNumber+1}}
    end.


parse_file_done(#state{mode=consult, mode_state=Records}) ->
    lists:reverse(Records);
parse_file_done(#state{mode=foldl, mode_state={_, Acc}}) ->
    Acc.


-spec consult(Filename :: string()) -> {'ok', Resources :: [dnslib:resource()]}.
consult(Filename) ->
    consult(Filename, []).


-type consult_opt() ::
      {'line_break', string()}
    | {class, dnsrr:class()}
    | {'type_blacklist', [dnsrr:type()]}
    | {'domain', dnslib:domain()}
    | {'origin', dnslib:domain()}
    | {'ttl', dnslib:ttl()}
    | {'max_line_length', pos_integer()}
    | {'allow_unknown_resources', boolean()}
    | {'allow_unknown_classes', boolean()}
    | {'encoding', unicode:encoding()}
    | {'text_encoding', unicode:encoding()}.
-spec consult(Filename :: string(), Options :: [consult_opt()])
    -> {'ok', Resources :: [dnslib:resource()]}
     | {'error', ErrorSpec :: term()}.
consult(Filename, Opts) when is_list(Opts) ->
    case prepare_state(#state{}, Opts) of
        {ok, State} -> consult_file(Filename, State);
        {error, Reason} -> {error, {invalid_opt, Reason}}
    end.

consult_file(Filename, State = #state{encoding=Encoding}) ->
    case filename:pathtype(Filename) of
        absolute ->
            case file:open(Filename, [read, {encoding, Encoding}]) of
                {ok, Fd} ->
                    Result = parse_file(Fd, State#state{path=Filename}),
                    ok = file:close(Fd),
                    Result;
                {error, eacces} -> {error, {file_error, eacces, Filename}};
                {error, enoent} -> {error, {file_error, enoent, Filename}};
                {error, eisdir} -> {error, {file_error, eisdir, Filename}}
            end;
        _ -> consult_file(filename:absname(Filename), State)
    end.


prepare_state(State = #state{}, []) ->
    {ok, State};
prepare_state(State = #state{}, [{line_break, Str}|Rest]) when is_list(Str) ->
    prepare_state(State#state{line_break=Str}, Rest);
prepare_state(State = #state{}, [{class, explicit}|Rest]) ->
    prepare_state(State#state{prevclass=undefined}, Rest);
prepare_state(State = #state{}, [{class, Class0}|Rest]) ->
    case {is_integer(Class0), is_atom(Class0)} of
        {true, _} ->
            case dnsclass:from_to(Class0, value, atom) of
                Class0 -> prepare_state(State#state{prevclass=Class0}, Rest);
                Class -> prepare_state(State#state{prevclass=Class}, Rest)
            end;
        {_, true} ->
            case dnsclass:from_to(Class0, atom, value) of
                Class0 -> {error, {invalid_class_atom, Class0}};
                _ -> prepare_state(State#state{prevclass=Class0}, Rest)
            end
    end;
%prepare_state(State = #state{directives=Directives0}, [{directive, Str, false}|Rest]) when is_list(Str) ->
%    Directives1 = maps:remove(string:(?LOWER)(Str), Directives0),
%    prepare_state(State#state{directives=Directives1}, Rest);
prepare_state(State = #state{type_blacklist=BL}, [{type_blacklist, List}|Rest]) when is_list(List) ->
    prepare_state(State#state{type_blacklist=lists:append(BL, [dnsrr:from_to(GenType, value, atom) || GenType <- List])}, Rest);
prepare_state(State = #state{}, [{domain, Domain}|Rest]) ->
    true = dnslib:is_valid_domain(Domain),
    prepare_state(State#state{prevdomain=Domain}, Rest);
prepare_state(State = #state{}, [{origin, Domain}|Rest]) ->
    true = dnslib:is_valid_domain(Domain),
    prepare_state(State#state{origin=Domain}, Rest);
prepare_state(State = #state{}, [{ttl, Ttl}|Rest]) when is_integer(Ttl), Ttl >= 0, Ttl =< ?MAX_TTL ->
    prepare_state(State#state{prevttl=Ttl,defttl=Ttl}, Rest);
prepare_state(State = #state{}, [{max_line_length, Len}|Rest]) ->
    prepare_state(State#state{max_line_length=Len}, Rest);
prepare_state(State = #state{}, [{allow_unknown_resources, Value}|Rest]) when Value =:= true; Value =:= false ->
    prepare_state(State#state{allow_unknown_resources=Value}, Rest);
prepare_state(State = #state{}, [{allow_unknown_classes, Value}|Rest]) when Value =:= true; Value =:= false ->
    prepare_state(State#state{allow_unknown_classes=Value}, Rest);
prepare_state(State = #state{}, [{encoding, Encoding}|Rest]) ->
    prepare_state(State#state{encoding=Encoding}, Rest);
prepare_state(State = #state{}, [{text_encoding, Encoding}|Rest]) ->
    prepare_state(State#state{text_encoding=Encoding}, Rest);
prepare_state(_, [{Key, _}|_]) ->
    {error, {unknown_opt, Key}}.


foldl(Fun, Acc0, Path) -> foldl(Fun, Acc0, Path, []).

foldl(Fun, Acc0, Path, Opts) ->
    case prepare_state(#state{}, Opts) of
        {ok, State} -> consult_file(Path, State#state{mode=foldl, mode_state={Fun, Acc0}});
        {error, Reason} -> {error, {invalid_opt, Reason}}
    end.


is_valid(Path) -> is_valid(Path, []).

is_valid(Path, Opts) ->
    Fun = fun (_, _) -> nil end,
    case foldl(Fun, nil, Path, Opts) of
        {ok, nil} -> true;
        _ -> false
    end.


iterate_begin(Path) -> iterate_begin(Path, []).

iterate_begin(Path0, Opts) ->
    case prepare_state(#state{}, Opts) of
        {error, Reason} -> {error, {invalid_opt, Reason}};
        {ok, State = #state{encoding=Encoding}} ->
            Path = case filename:pathtype(Path0) of
                absolute -> Path0;
                _ -> filename:absname(Path0)
            end,
            case file:open(Path, [read, {encoding, Encoding}]) of
                {ok, Fd} -> {ok, {State, Fd}};
                {error, eacces} -> {error, {file_error, eacces, Path}};
                {error, enoent} -> {error, {file_error, enoent, Path}};
                {error, eisdir} -> {error, {file_error, eisdir, Path}}
            end
    end.


iterate_next({State, eof}=Tuple) -> eof;
iterate_next({State, Fd}) -> iterate_next(State, Fd).

iterate_next(State0, Fd) ->
    try get_line(Fd, State0) of
        {eof, State1 = #state{mode_state=[Resource]}} ->
            ok = file:close(Fd),
            {ok, Resource, {State1#state{mode_state=[]}, eof}};
        {eof, State1 = #state{mode_state=[]}} ->
            ok = file:close(Fd),
            eof;
        {complete, State1 = #state{mode_state=[Resource]}} ->
            {ok, Resource, {State1#state{mode_state=[]}, Fd}};
        {_, State1} -> iterate_next(State1, Fd)
    catch
        error:{foldl_error, Class, Reason, Stacktrace}          ->
            ok = file:close(Fd),
            {error, {foldl_error, Class, Reason, Stacktrace}};
        error:{syntax_error, File, LineNumber, Reason} ->
            ok = file:close(Fd),
            {error, {syntax_error, File, LineNumber, Reason}};
        error:{directive_error, File, LineNumber, Reason} ->
            ok = file:close(Fd),
            {error, {directive_error, File, LineNumber, Reason}};
        error:{resource_record_error, File, LineNumber, Reason} ->
            ok = file:close(Fd),
            {error, {resource_record_error, File, LineNumber, Reason}}
    end.


iterate_end({_, eof}) -> ok;
iterate_end({_, Fd}) -> ok = file:close(Fd).

%%
%% Output
%%


to_masterfile_escape_text(Txt) ->
    escape_text(Txt, [$"]).

escape_text(<<>>, Acc) ->
    lists:reverse([$"|Acc]);
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


-spec write_resources(Path :: string(), Resources :: [dnslib:resource()]) -> 'ok'.
write_resources(Filename, Rrs) ->
    write_resources(Filename, Rrs, []).

-type write_resources_opt() ::
    {'generic', boolean()}.
-spec write_resources(Path :: string(), Resources :: [dnslib:resource()], Opts :: [write_resources_opt()]) -> 'ok'.
write_resources(Filename, Rrs, Opts) ->
    % Make sure that each record has the same class
    % Order records (SOA first)
    %
    % Directives exist to optimize master files for readability and
    % shortness of expression
    %
    % If optimizations haven't been disabled, run through the resource records,
    % introducing directives and mangling Resource record data as necessary
    % to produce a shorter file
    Mode = case lists:member(append, Opts) of
        true -> append;
        false -> write
    end,
    {ok, Fd} = file:open(Filename, [write, Mode]),
    ok = write_resource(Rrs, Fd, handle_write_resources_opts(Opts)),
    ok = file:close(Fd).


handle_write_resources_opts(Opts) ->
    handle_write_resources_opts(Opts, #{
        generic => false,
        linebreak => $\n,
        whitespace => $\t
    }).

handle_write_resources_opts([], Opts) ->
    Opts;
handle_write_resources_opts([{generic, Boolean}|Rest], Opts) when Boolean =:= true; Boolean =:= false ->
    handle_write_resources_opts(Rest, Opts#{generic => Boolean});
handle_write_resources_opts([append|Rest], Opts) ->
    handle_write_resources_opts(Rest, Opts).


write_resource([], _, _) ->
    ok;
write_resource([{iodata, Line}|Rest], Fd, Opts = #{linebreak := Linebreak}) ->
    ok = file:write(Fd, [Line, Linebreak]),
    write_resource(Rest, Fd, Opts);
write_resource([{Domain, Type, Class0, Ttl, Data}|Rest], Fd, Opts = #{linebreak := Linebreak, whitespace := Whitespace, generic := Generic}) ->
    % This allows us to write files with multiple classes
    Class = case dnsclass:from_to(Class0, atom, masterfile_token) of
        _ when Generic, is_atom(Class0) -> lists:append("class", integer_to_list(dnsclass:from_to(Class0, atom, value)));
        Class0 when is_integer(Class0) -> lists:append("class", integer_to_list(Class0));
        CaseClass when is_list(CaseClass) -> CaseClass
    end,
    Iodata = [
        dnslib:domain_to_list(Domain),
        Whitespace,
        string:to_upper(Class),
        Whitespace,
        integer_to_list(Ttl),
        Whitespace,
        resource_specific(Type, Data, Opts)
    ],
    ok = file:write(Fd, [Iodata, Linebreak]),
    write_resource(Rest, Fd, Opts).


resource_specific(Type, Data, Opts = #{whitespace := Whitespace, generic := Generic}) ->
    case dnsrr:from_to(Type, atom, module) of
        Type when is_integer(Type), is_binary(Data) ->
            [
                string:to_upper(lists:append("type", integer_to_list(Type))),
                Whitespace,
                resource_data_to_io(Type, Data, Opts)
            ];
        Module ->
            case erlang:function_exported(Module, to_masterfile, 1) of
                true when not Generic ->
                    [
                        string:to_upper(dnsrr:from_to(Type, atom, masterfile_token)),
                        Whitespace,
                        resource_data_to_io(Module, Data, Opts)
                    ];
                _ -> resource_specific(Module:value(), resource_data_to_binary(Module, Data), Opts)
            end
    end.


resource_data_to_binary(Module, Data) ->
    case Module:to_binary(Data) of
        {ok, BinData} -> iolist_to_binary(BinData);
        {domains, List} ->
            Fn = fun
                ({domain, _, Domain}) -> {ok, Bin} = dnswire:domain_to_binary(Domain), Bin;
                (FunData) -> FunData
            end,
            iolist_to_binary([Fn(GenTuple) || GenTuple <- List])
    end.


resource_data_to_io(Type, Data, _) when is_integer(Type), is_binary(Data) ->
    % Produce a representation of an unknown resource type according to
    % RFC3597
    [io_lib:format("\\# ~b ", [byte_size(Data)]), resource_data_to_io_hex_unknown_data(Data, [])];
resource_data_to_io(Module, Data, _) when is_atom(Module) ->
    List = Module:to_masterfile(Data),
    Fn = fun
        ({domain, Domain}, Acc) -> [$ , dnslib:domain_to_list(Domain)|Acc];
        (Value, Acc) -> [$ , Value|Acc]
    end,
    [_|Ret] = lists:foldl(Fn, [], List),
    lists:reverse(Ret).

resource_data_to_io_hex_unknown_data(<<>>, Acc) ->
    lists:reverse(Acc);
resource_data_to_io_hex_unknown_data(<<C1_0:4, C2_0:4, Tail/binary>>, Acc) ->
    C1_1 = nibble_to_hex(C1_0),
    C2_1 = nibble_to_hex(C2_0),
    resource_data_to_io_hex_unknown_data(Tail, [C2_1, C1_1|Acc]).


nibble_to_hex(C) when C >= 10, C < 16 ->
    C + ($a - 10);
nibble_to_hex(C) when C >= 0, C < 10 ->
    C + $0.
