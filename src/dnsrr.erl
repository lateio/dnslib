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
-module(dnsrr).

-export([
    builtin/0,
    compile_dnsrr_types/0,
    from_to/3,
    class_valid_for_type/2,
    section_valid_for_type/2,
    validate_data/2,
    normalize_data/2,
    additionally/1
]).

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

-include("include/pre_otp20_string_macro.hrl").

-type type() :: atom() | 0..16#FFFF.
-type masterfile_format_type() ::
    'token'           | % String escaped, no further processing is done. Quoted strings are rejected
    'text'            | % String is escaped, and verified to be at most 255 bytes long. Quoted strings are accepted
    'text_unlimited'  | % String is escaped. No limit on length. Quoted strings are accepted
    'qtext'           | % String is escaped, and verified to be at most 255 bytes long. Only quoted strings are accepted
    'qtext_unlimited' | % String is escaped. No limit on length. Only quoted strings are accepted
    'uint16'          | % String is escaped and transformed to integer. Verified to fall into range 0..16#FFFF
    'uint32'          | % String is escaped and transformed to integer. Verified to fall into range 0..16#FFFFFFFF
    'ttl'             | % String is escaped and transformed to integer. Verified to fall into range 0..16#7FFFFFFF
                        % Some handy specifiers are allowed in ttls
    'domain'          | % String is parsed as domain. Wildcard domains are rejected
    '...'.              % Repeat the previous type until terms are exhausted

-export_type([type/0,masterfile_format_type/0]).

% What if a record is not to be looked up/resolved like an a record,
% but just adds some kind of an answer to the response?
% Add a callback like resolve() -> true | false | {'fun', atom()}. ?

% Checklist for new builtin types... add entries in dnsrr_types, builtin() here, dnslib.app.src

%-callback dnsrr_subtype() -> 'dnsrr'.

-callback masterfile_token() -> string().
-callback atom() -> type().
-callback value() -> 0..16#FFFF.
-callback class() -> [dnsclass:class()].

-callback masterfile_format() -> [masterfile_format_type(), ...].
-callback from_masterfile(list()) -> {'ok', term()} | {'error', Reason :: term()}.
-callback to_masterfile(term()) -> [iodata() | {'domain', dnslib:domain()}].

-callback to_binary(ResourceData :: term()) ->
    {'ok', iodata()} |
    {'domains', [{domain, boolean(), dnslib:domain()} | iodata()]}.

-callback from_binary(binary()) ->
    {'error', Reason :: term()} |
    {'ok', term()} |
    {'domains', [term()]}.
-callback from_binary_finalize([term()]) -> {ok, term()}.

-callback resolve() -> boolean() | {'fun', Fun :: atom()}.

-callback cacheable() -> boolean().

% Or should additionally be more of a server/zone configuration thing?
-callback additionally(Record :: dnslib:resource()) ->
      dnslib:question()
    | [dnslib:question()]
    | dnslib:resource()
    | [dnslib:resource()].

-callback message_section() -> [dnsmsg:message_section()].

-callback aka() -> [type()].

-callback valid_data(term()) -> boolean().
-callback normalize_data(term()) -> term().


-optional_callbacks([
    class/0,
    masterfile_token/0,
    masterfile_format/0,
    from_masterfile/1,
    to_masterfile/1,
    from_binary/1,
    to_binary/1,
    from_binary_finalize/1,
    resolve/0,
    cacheable/0,
    additionally/1,
    message_section/0,
    aka/0,
    valid_data/1,
    normalize_data/1
]).

builtin() ->
    [
        dnsrr_a,
        dnsrr_aaaa,
        dnsrr_all,
        dnsrr_axfr,
        dnsrr_cname,
        dnsrr_dnskey,
        dnsrr_ds,
        dnsrr_hinfo,
        dnsrr_ixfr,
        dnsrr_maila,
        dnsrr_mailb,
        dnsrr_mb,
        dnsrr_md,
        dnsrr_mf,
        dnsrr_mg,
        dnsrr_minfo,
        dnsrr_mr,
        dnsrr_mx,
        dnsrr_naptr,
        dnsrr_ns,
        dnsrr_nsec,
        dnsrr_null,
        dnsrr_opt,
        dnsrr_ptr,
        dnsrr_rrsig,
        dnsrr_soa,
        dnsrr_srv,
        dnsrr_sshfp,
        dnsrr_txt,
        dnsrr_uri,
        dnsrr_wks
    ].


-ifdef(EUNIT).
builtin_modules_sanity_test() ->
    Builtin = builtin(),
    CheckFn = fun (FunMod) ->
        FunAtom = FunMod:atom(),
        FunValue = FunMod:value(),
        not (
            from_to(FunAtom, atom, value) =:= FunValue andalso
            from_to(FunValue, value, atom) =:= FunAtom
        )
    end,
    [] = lists:filter(CheckFn, Builtin).
-endif.


compile_dnsrr_types() ->
    % Move from compile to persistent_term in OTP21...
    case application:get_env(dnslib, custom_resource_records, []) of
        [] -> ok;
        CustomRRs ->
            case check_module_collisions(CustomRRs, dnsrr_types:atom(), dnsrr_types:value(), dnsrr_types:masterfile_token()) of
                {true, Collision} -> {error, {collision, Collision}};
                false ->
                    Builtin = builtin(),
                    Abs = [
                        {attribute, 0, module, dnsrr_types},
                        {attribute, 0, export, [{atom, 0}, {value, 0}, {masterfile_token, 0}]},
                        {function, 0, atom, 0, [
                            {clause, 0, [], [], [map_form(atom, Builtin, CustomRRs)]}
                        ]},
                        {function, 0, value, 0, [
                            {clause, 0, [], [], [map_form(value, Builtin, CustomRRs)]}
                        ]},
                        {function, 0, masterfile_token, 0, [
                            {clause, 0, [], [], [map_form(masterfile_token, Builtin, CustomRRs)]}
                        ]}
                    ],
                    try compile:forms(Abs) of
                        {ok, dnsrr_types, Bin} ->
                            {module, dnsrr_types} = code:load_binary(dnsrr_types, "dnsrr_types_mem.erl", Bin),
                            ok
                    catch
                        error:Reason -> {error, Reason}
                    end
            end
    end.


check_module_collisions([], _, _, _) ->
    false;
check_module_collisions([CustomMod|Rest], AtomMap, ValueMap, MasterfileTokenMap) ->
    Atom = CustomMod:atom(),
    Value = CustomMod:value(),
    MasterfileToken = case erlang:function_exported(CustomMod, masterfile_token, 0) of
        true  -> CustomMod:masterfile_token();
        false -> false
    end,
    case {
        maps:get(Atom, AtomMap, false),
        maps:get(Value, ValueMap, false),
        maps:get(MasterfileToken, MasterfileTokenMap, false),
        if
            is_list(MasterfileToken) -> string:prefix(string:(?LOWER)(MasterfileToken), "type");
            true -> nomatch
        end
    } of
        {false, false, false, nomatch} when MasterfileToken =:= false ->
            check_module_collisions(Rest, AtomMap#{Atom => CustomMod}, ValueMap#{Value => CustomMod}, MasterfileTokenMap);
        {false, false, false, nomatch} ->
            check_module_collisions(Rest, AtomMap#{Atom => CustomMod}, ValueMap#{Value => CustomMod}, MasterfileTokenMap#{MasterfileToken => CustomMod});
        {CollidedMod, _, _, _} when CollidedMod =/= false -> {true, {atom, CustomMod, CollidedMod}};
        {_, CollidedMod, _, _} when CollidedMod =/= false -> {true, {value, CustomMod, CollidedMod}};
        {_, _, CollidedMod, _} when CollidedMod =/= false -> {true, {masterfile_token, CustomMod, CollidedMod}};
        {_, _, _, Tail} when is_list(Tail) -> {true, {masterfile_token, CustomMod, rfc3597}}
    end.


map_form(Fn, Builtin, Extension) ->
    Lambda = case Fn of
        masterfile_token ->
            fun (Module, Acc) ->
                case erlang:function_exported(Module, masterfile_token, 0) of
                    true -> [{Module:masterfile_token(), Module}|Acc];
                    false -> Acc
                end
            end;
        _ -> fun (Module, Acc) -> [{Module:Fn(), Module}|Acc] end
    end,
    BuiltinTuples = lists:keysort(1, lists:foldl(Lambda, [], Builtin)),
    ExtensionTuples = lists:keysort(1, lists:foldl(Lambda, [], Extension)),
    build_map_form(lists:keymerge(2, BuiltinTuples, ExtensionTuples), []).

-spec build_map_form(list(), [{map_field_assoc, integer(), {atom(), integer(), atom()}, {'atom', integer(), atom()}}]) ->
    {'map', integer(), [{map_field_assoc, integer(), {atom(), integer(), atom()}, {'atom', integer(), atom()}}]}.
build_map_form([], Acc) ->
    {map, 0, Acc};
build_map_form([{Key, Module}|Rest], Acc) ->
    Type = case Key of
        Key when is_atom(Key) -> atom;
        Key when is_integer(Key) -> integer;
        Key when is_list(Key) -> string
    end,
    build_map_form(Rest, [{map_field_assoc, 0, {Type, 0, Key}, {atom, 0, Module}}|Acc]).


-spec from_to(
    Value :: atom() | 0..16#FFFF | string(),
    From :: 'value' | 'module' | 'atom' | 'masterfile_token',
    To   :: 'value' | 'module' | 'atom' | 'masterfile_token' | 'masterfile_token_generic'
) -> atom() | 0..16#FFFF | string().
from_to(Value, value, module) ->
    maps:get(Value, dnsrr_types:value(), Value);
from_to(Value, value, masterfile_token) when Value >= 0, Value =< 16#FFFF ->
    case maps:get(Value, dnsrr_types:value(), Value) of
        Value -> from_to(Value, value, masterfile_token_generic);
        Module -> Module:masterfile_token()
    end;
from_to(Value, value, masterfile_token_generic) when Value >= 0, Value =< 16#FFFF ->
    "type" ++ integer_to_list(Value);
from_to(Value, atom, module) ->
    maps:get(Value, dnsrr_types:atom(), Value);
from_to(Value0, masterfile_token, To) ->
    case string:(?LOWER)(Value0) of
        [$t, $y, $p, $e|Int] ->
            try list_to_integer(Int) of
                Value when To =:= value, Value >= 0, Value =< 16#FFFF -> Value;
                Value when Value >= 0, Value =< 16#FFFF ->
                    case from_to(Value, value, To) of
                        Value -> Value0;
                        ToValue -> ToValue
                    end;
                _ -> Value0
            catch
                error:badarg -> Value0
            end;
        Value ->
            case maps:get(Value, dnsrr_types:masterfile_token(), Value0) of
                Value0 -> Value0;
                Module when To =:= module -> Module;
                Module -> from_to(Module, module, To)
            end
    end;
from_to(Module, module, value) ->
    Module:value();
from_to(Module, module, atom) ->
    Module:atom();
from_to(Module, module, masterfile_token) ->
    Module:masterfile_token();
from_to(Module, module, masterfile_token_generic) ->
    from_to(Module:value(), value, masterfile_token_generic);
from_to(Value, From, To) when From =/= To ->
    % If either From or To are not allowed, function_clause exception will result
    case from_to(Value, From, module) of
        Value -> Value;
        Module -> from_to(Module, module, To)
    end.


-spec class_valid_for_type(Class :: atom(), Type :: atom()) -> boolean().
class_valid_for_type(any, _) ->
    true;
class_valid_for_type(Class, Type) ->
    case from_to(Type, atom, module) of
        Type -> true; % If we don't know nothing about the class, don't judge the compatibility
        Module ->
            case erlang:function_exported(Module, class, 0) of
                false -> true;
                true ->
                    case Module:class() of
                        Class -> true;
                        List when is_list(List) -> lists:member(Class, List);
                        _ -> false
                    end
            end
    end.


-spec validate_data(Type :: atom(), Data :: term()) -> boolean().
validate_data(Type, Data) ->
    Module = from_to(Type, atom, module),
    case erlang:function_exported(Module, valid_data, 1) of
        false -> false;
        true ->
            try Module:valid_data(Data) of
                Boolean -> Boolean
            catch
                error:function_clause -> false
            end
    end.


-spec normalize_data(Type :: atom(), Data :: term()) -> term().
normalize_data(Type, Data) ->
    Module = from_to(Type, atom, module),
    case erlang:function_exported(Module, normalize_data, 1) of
        false -> Data;
        true -> Module:normalize_data(Data)
    end.


-spec section_valid_for_type(Section :: atom(), Type :: atom()) -> boolean().
section_valid_for_type(Section, Type) ->
    case from_to(Type, atom, module) of
        Type -> true; % If we don't know nothing about the class, don't judge the compatibility
        Module ->
            case erlang:function_exported(Module, message_section, 0) of
                false -> true;
                true ->
                    List = Module:message_section(),
                    lists:member(Section, List)
            end
    end.


additionally({_, Type, _, _, _}) when is_integer(Type) ->
    [];
additionally({_, Type, _, _, _} = Resource) ->
    Module = from_to(Type, atom, module),
    try Module:additionally(Resource) of
        Additionally -> Additionally
    catch
        error:undef -> []
    end.
