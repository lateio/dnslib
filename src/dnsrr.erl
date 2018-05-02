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
-module(dnsrr).

-export([
    builtin/0,
    compile_dnsrr_types/0,
    from_to/3,
    class_valid_for_type/2
]).

-type type() :: atom().
-type masterfile_format_type() ::
    'token'           | % String escaped, no further processing is done. Quoted strings are rejected
    'text'            | % String is escaped, and verified to be under 255 bytes. Quoted strings are accepted
    'text_unlimited'  | % String is escaped. No limit on length. Quoted strings are accepted
    'qtext'           | % String is escaped, and verified to be under 255 bytes. Only quoted strings are accepted
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

-callback masterfile_token() -> string().
-callback atom() -> type().
-callback value() -> 0..65535.
-callback class() -> dnsclass:class() | [dnsclass:class()].

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
-callback additionally(Record :: {Domain, Type, Class, Ttl, Data}) ->
    {Domain, Type, Class}              |
    [{Domain, Type, Class}]            |
    {Domain, Type, Class, Ttl, Data}   |
    [{Domain, Type, Class, Ttl, Data}].

-type msg_section() :: 'question' | 'answer' | 'nameserver' | 'additional'.
-callback can_appear_in() -> msg_section() | [msg_section()].

-callback aka() -> type() | [type()].


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
    can_appear_in/0,
    aka/0
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


compile_dnsrr_types() ->
    Builtin = builtin(),
    case application:get_env(dnslib, custom_resource_records, []) of
        [] -> ok;
        CustomRRs ->
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


from_to(Value, To, To) ->
    Value;
from_to(Value, From, module)
when From =:= value; From =:= atom; From =:= masterfile_token ->
    maps:get(Value, dnsrr_types:From(), Value);
from_to(Module, module, To)
when To =:= value; To =:= atom; To =:= masterfile_token ->
    Module:To();
from_to(Value, From, To) ->
    % If either From or To are not allowed, function_clause exception will result
    case from_to(Value, From, module) of
        Value -> Value;
        Module -> from_to(Module, module, To)
    end.


class_valid_for_type(any, _) ->
    true;
class_valid_for_type(Class, Type) ->
    case from_to(Type, atom, module) of
        Type -> unknown;
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
